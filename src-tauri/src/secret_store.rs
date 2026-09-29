//! Short-lived, process-local cache for credentials kept in the platform store.
//!
//! Cached values are zeroized when replaced, expired, invalidated, or dropped. The
//! public `get` API returns an owned `String` for compatibility with existing call
//! sites; callers should keep that unavoidable plaintext copy no longer than needed.

use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Duration,
};
#[cfg(not(test))]
use std::{sync::OnceLock, time::Instant};
use zeroize::Zeroizing;

#[cfg(not(test))]
const KEYRING_SERVICE: &str = "org.shortlink.generator";
#[cfg(not(test))]
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// Stable, non-sensitive error categories safe to show at the bridge boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretError {
    Missing,
    AccessDenied,
    Unavailable,
    Other,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "系统凭据库中找不到所需密钥",
            Self::AccessDenied => "未能访问系统凭据库，请在系统提示中允许访问",
            Self::Unavailable => "系统凭据库暂时不可用",
            Self::Other => "系统凭据库操作失败",
        })
    }
}

trait CredentialBackend: Send + Sync + 'static {
    fn get(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError>;
    fn set(&self, id: &str, kind: &str, value: &str) -> Result<(), SecretError>;
    fn delete(&self, id: &str, kind: &str) -> Result<(), SecretError>;
}

trait Clock: Send + Sync + 'static {
    fn now(&self) -> Duration;
}

#[cfg(not(test))]
struct SystemClock(Instant);

#[cfg(not(test))]
impl SystemClock {
    fn new() -> Self {
        Self(Instant::now())
    }
}

#[cfg(not(test))]
impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

#[cfg(not(test))]
struct KeyringBackend;

#[cfg(not(test))]
impl KeyringBackend {
    fn entry(id: &str, kind: &str) -> Result<keyring::Entry, SecretError> {
        keyring::Entry::new(KEYRING_SERVICE, &format!("{kind}:{id}")).map_err(map_keyring_error)
    }
}

#[cfg(not(test))]
impl CredentialBackend for KeyringBackend {
    fn get(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
        Self::entry(id, kind)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(map_keyring_error)
    }

    fn set(&self, id: &str, kind: &str, value: &str) -> Result<(), SecretError> {
        Self::entry(id, kind)?
            .set_password(value)
            .map_err(map_keyring_error)
    }

    fn delete(&self, id: &str, kind: &str) -> Result<(), SecretError> {
        match Self::entry(id, kind)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_keyring_error(error)),
        }
    }
}

fn map_keyring_error(error: keyring::Error) -> SecretError {
    match error {
        keyring::Error::NoEntry => SecretError::Missing,
        // Access denial and a locked store commonly arrive as NoStorageAccess.
        // PlatformFailure can also represent a cancelled platform prompt; both
        // categories deliberately remain distinct from a missing credential.
        keyring::Error::NoStorageAccess(_) => SecretError::AccessDenied,
        keyring::Error::PlatformFailure(_) => SecretError::Unavailable,
        keyring::Error::BadEncoding(_)
        | keyring::Error::TooLong(_, _)
        | keyring::Error::Invalid(_, _)
        | keyring::Error::Ambiguous(_) => SecretError::Other,
        _ => SecretError::Other,
    }
}

#[derive(Clone, Eq)]
struct CacheKey {
    id: String,
    kind: String,
}

impl CacheKey {
    fn new(id: &str, kind: &str) -> Self {
        Self {
            id: id.to_owned(),
            kind: kind.to_owned(),
        }
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.kind == other.kind
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.kind.hash(state);
    }
}

struct CachedSecret {
    value: Zeroizing<String>,
    expires_at: Duration,
}

enum SlotState {
    Empty,
    Loading {
        id: u64,
        waiters: usize,
        invalidated: bool,
    },
    Mutating {
        id: u64,
        invalidated: bool,
    },
    Ready(CachedSecret),
}

struct SlotInner {
    next_operation: u64,
    state: SlotState,
    completed_failures: HashMap<u64, (SecretError, usize)>,
}

struct Slot {
    inner: Mutex<SlotInner>,
    changed: Condvar,
}

impl Slot {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SlotInner {
                next_operation: 0,
                state: SlotState::Empty,
                completed_failures: HashMap::new(),
            }),
            changed: Condvar::new(),
        }
    }

    fn invalidate(&self) {
        let mut inner = lock(&self.inner);
        match &mut inner.state {
            SlotState::Loading { invalidated, .. } | SlotState::Mutating { invalidated, .. } => {
                *invalidated = true
            }
            SlotState::Empty | SlotState::Ready(_) => inner.state = SlotState::Empty,
        }
    }
}

struct SecretStore<B: CredentialBackend, C: Clock> {
    backend: Arc<B>,
    clock: C,
    ttl: Duration,
    epoch: std::sync::atomic::AtomicU64,
    slots: Mutex<HashMap<CacheKey, Arc<Slot>>>,
}

impl<B: CredentialBackend, C: Clock> SecretStore<B, C> {
    fn new(backend: Arc<B>, clock: C, ttl: Duration) -> Self {
        Self {
            backend,
            clock,
            ttl,
            epoch: std::sync::atomic::AtomicU64::new(0),
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, id: &str, kind: &str) -> Arc<Slot> {
        let mut slots = lock(&self.slots);
        slots
            .entry(CacheKey::new(id, kind))
            .or_insert_with(|| Arc::new(Slot::new()))
            .clone()
    }

    fn get(&self, id: &str, kind: &str) -> Result<String, SecretError> {
        let store_epoch = self.epoch.load(std::sync::atomic::Ordering::SeqCst);
        let slot = self.slot(id, kind);
        let mut waited_load = None;
        let load_id = loop {
            let mut inner = lock(&slot.inner);

            if let Some(waited) = waited_load {
                if let Some((error, remaining)) = inner.completed_failures.get_mut(&waited) {
                    let error = *error;
                    *remaining -= 1;
                    if *remaining == 0 {
                        inner.completed_failures.remove(&waited);
                    }
                    return Err(error);
                }
            }

            if self.epoch.load(std::sync::atomic::Ordering::SeqCst) != store_epoch {
                if waited_load.is_some_and(
                    |waited| matches!(inner.state, SlotState::Loading { id, .. } if id == waited),
                ) {
                    drop(wait(&slot.changed, inner));
                    continue;
                }
                return Err(SecretError::Unavailable);
            }

            match &mut inner.state {
                SlotState::Ready(cached) if self.clock.now() < cached.expires_at => {
                    return Ok(cached.value.as_str().to_owned());
                }
                SlotState::Ready(_) => {
                    inner.state = SlotState::Empty;
                }
                SlotState::Empty => {
                    inner.next_operation = inner.next_operation.wrapping_add(1);
                    let id = inner.next_operation;
                    inner.state = SlotState::Loading {
                        id,
                        waiters: 0,
                        invalidated: false,
                    };
                    break id;
                }
                SlotState::Loading {
                    id,
                    waiters,
                    invalidated,
                } => {
                    if waited_load == Some(*id) || *invalidated {
                        drop(wait(&slot.changed, inner));
                    } else {
                        *waiters += 1;
                        waited_load = Some(*id);
                        drop(wait(&slot.changed, inner));
                    }
                }
                SlotState::Mutating { .. } => {
                    drop(wait(&slot.changed, inner));
                }
            }
        };

        let loaded = self.backend.get(id, kind);
        let mut inner = lock(&slot.inner);
        let (waiters, invalidated) = match inner.state {
            SlotState::Loading {
                id,
                waiters,
                invalidated,
            } if id == load_id => (waiters, invalidated),
            _ => return Err(SecretError::Unavailable),
        };
        let was_invalidated =
            invalidated || self.epoch.load(std::sync::atomic::Ordering::SeqCst) != store_epoch;
        if was_invalidated {
            inner.state = SlotState::Empty;
            if waiters > 0 {
                inner
                    .completed_failures
                    .insert(load_id, (SecretError::Unavailable, waiters));
            }
            slot.changed.notify_all();
            return Err(SecretError::Unavailable);
        }

        match loaded {
            Ok(secret) => {
                let returned = secret.as_str().to_owned();
                let expires_at = self
                    .clock
                    .now()
                    .checked_add(self.ttl)
                    .unwrap_or(Duration::MAX);
                inner.state = SlotState::Ready(CachedSecret {
                    value: secret,
                    expires_at,
                });
                slot.changed.notify_all();
                Ok(returned)
            }
            Err(error) => {
                inner.state = SlotState::Empty;
                if waiters > 0 {
                    inner.completed_failures.insert(load_id, (error, waiters));
                }
                slot.changed.notify_all();
                Err(error)
            }
        }
    }

    fn set(&self, id: &str, kind: &str, value: &str) -> Result<(), SecretError> {
        let store_epoch = self.epoch.load(std::sync::atomic::Ordering::SeqCst);
        let slot = self.slot(id, kind);
        let generation = self.begin_mutation(&slot);
        let result = self.backend.set(id, kind, value);
        let mut inner = lock(&slot.inner);
        if let SlotState::Mutating { id, invalidated } = inner.state {
            if id == generation {
                inner.state = match result {
                    Ok(())
                        if !invalidated
                            && self.epoch.load(std::sync::atomic::Ordering::SeqCst)
                                == store_epoch =>
                    {
                        SlotState::Ready(CachedSecret {
                            value: Zeroizing::new(value.to_owned()),
                            expires_at: self
                                .clock
                                .now()
                                .checked_add(self.ttl)
                                .unwrap_or(Duration::MAX),
                        })
                    }
                    Ok(()) | Err(_) => SlotState::Empty,
                };
                slot.changed.notify_all();
            }
        }
        result
    }

    fn delete(&self, id: &str, kind: &str) -> Result<(), SecretError> {
        let slot = self.slot(id, kind);
        let operation = self.begin_mutation(&slot);
        let result = self.backend.delete(id, kind);
        let mut inner = lock(&slot.inner);
        if matches!(inner.state, SlotState::Mutating { id, .. } if id == operation) {
            inner.state = SlotState::Empty;
            slot.changed.notify_all();
        }
        result
    }

    fn begin_mutation(&self, slot: &Slot) -> u64 {
        let mut inner = lock(&slot.inner);
        loop {
            match inner.state {
                SlotState::Mutating { .. } => {
                    inner = wait(&slot.changed, inner);
                }
                SlotState::Loading { id, waiters, .. } => {
                    if waiters > 0 {
                        inner
                            .completed_failures
                            .insert(id, (SecretError::Unavailable, waiters));
                    }
                    inner.next_operation = inner.next_operation.wrapping_add(1);
                    let operation = inner.next_operation;
                    inner.state = SlotState::Mutating {
                        id: operation,
                        invalidated: false,
                    };
                    slot.changed.notify_all();
                    return operation;
                }
                SlotState::Empty | SlotState::Ready(_) => {
                    inner.next_operation = inner.next_operation.wrapping_add(1);
                    let operation = inner.next_operation;
                    inner.state = SlotState::Mutating {
                        id: operation,
                        invalidated: false,
                    };
                    return operation;
                }
            }
        }
    }

    fn clear_all(&self) {
        // The epoch also rejects an operation that began before this call but had
        // not installed its per-key state yet. No platform call runs under this lock.
        let slots = lock(&self.slots);
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        for slot in slots.values() {
            slot.invalidate();
        }
    }

    fn purge_expired(&self) {
        let now = self.clock.now();
        let slots = lock(&self.slots);
        for slot in slots.values() {
            let mut inner = lock(&slot.inner);
            if matches!(&inner.state, SlotState::Ready(cached) if now >= cached.expires_at) {
                inner.state = SlotState::Empty;
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condvar
        .wait(guard)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(not(test))]
fn store() -> &'static SecretStore<KeyringBackend, SystemClock> {
    static STORE: OnceLock<SecretStore<KeyringBackend, SystemClock>> = OnceLock::new();
    STORE.get_or_init(|| SecretStore::new(Arc::new(KeyringBackend), SystemClock::new(), CACHE_TTL))
}

#[cfg(not(test))]
pub(crate) fn get(id: &str, kind: &str) -> Result<String, SecretError> {
    store().get(id, kind)
}

#[cfg(not(test))]
pub(crate) fn set(id: &str, kind: &str, value: &str) -> Result<(), SecretError> {
    store().set(id, kind, value)
}

#[cfg(not(test))]
pub(crate) fn delete(id: &str, kind: &str) -> Result<(), SecretError> {
    store().delete(id, kind)
}

#[cfg(not(test))]
pub(crate) fn clear_all() {
    store().clear_all();
}

#[cfg(not(test))]
/// Drop expired plaintext even when its key is not read again. The application
/// should call this from its existing low-frequency maintenance timer.
pub(crate) fn purge_expired() {
    store().purge_expired();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            mpsc, Barrier,
        },
        thread,
        time::Duration as StdDuration,
    };

    #[derive(Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.0
                .fetch_add(duration.as_nanos().try_into().unwrap(), Ordering::SeqCst);
        }
    }

    impl Clock for Arc<ManualClock> {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Default)]
    struct MockGate {
        blocked: bool,
        entered: bool,
        open: bool,
    }

    #[derive(Default)]
    struct BlockingGate {
        state: Mutex<MockGate>,
        changed: Condvar,
    }

    impl BlockingGate {
        fn block(&self) {
            let mut state = lock(&self.state);
            state.blocked = true;
            state.entered = false;
            state.open = false;
        }

        fn enter_and_wait(&self) {
            let mut state = lock(&self.state);
            if state.blocked {
                state.entered = true;
                self.changed.notify_all();
                while !state.open {
                    state = wait(&self.changed, state);
                }
            }
        }

        fn wait_until_entered(&self) {
            let mut state = lock(&self.state);
            while !state.entered {
                state = wait(&self.changed, state);
            }
        }

        fn release(&self) {
            let mut state = lock(&self.state);
            state.open = true;
            self.changed.notify_all();
        }
    }

    #[derive(Default)]
    struct MockBackend {
        values: Mutex<HashMap<CacheKey, String>>,
        get_count: AtomicUsize,
        set_count: AtomicUsize,
        delete_count: AtomicUsize,
        get_error: Mutex<Option<SecretError>>,
        set_error: Mutex<Option<SecretError>>,
        delete_error: Mutex<Option<SecretError>>,
        get_gate: BlockingGate,
        set_gate: BlockingGate,
        delete_gate: BlockingGate,
    }

    impl MockBackend {
        fn put(&self, id: &str, kind: &str, value: &str) {
            lock(&self.values).insert(CacheKey::new(id, kind), value.to_owned());
        }

        fn block_gets(&self) {
            self.get_gate.block();
        }

        fn wait_until_get_entered(&self) {
            self.get_gate.wait_until_entered();
        }

        fn release_gets(&self) {
            self.get_gate.release();
        }
    }

    impl CredentialBackend for MockBackend {
        fn get(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            let error = *lock(&self.get_error);
            let value = lock(&self.values).get(&CacheKey::new(id, kind)).cloned();
            self.get_gate.enter_and_wait();
            if let Some(error) = error {
                return Err(error);
            }
            value.map(Zeroizing::new).ok_or(SecretError::Missing)
        }

        fn set(&self, id: &str, kind: &str, value: &str) -> Result<(), SecretError> {
            self.set_count.fetch_add(1, Ordering::SeqCst);
            self.set_gate.enter_and_wait();
            if let Some(error) = *lock(&self.set_error) {
                return Err(error);
            }
            self.put(id, kind, value);
            Ok(())
        }

        fn delete(&self, id: &str, kind: &str) -> Result<(), SecretError> {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            self.delete_gate.enter_and_wait();
            if let Some(error) = *lock(&self.delete_error) {
                return Err(error);
            }
            lock(&self.values).remove(&CacheKey::new(id, kind));
            Ok(())
        }
    }

    type TestStore = SecretStore<MockBackend, Arc<ManualClock>>;

    fn fixture(ttl: Duration) -> (Arc<TestStore>, Arc<MockBackend>, Arc<ManualClock>) {
        let backend = Arc::new(MockBackend::default());
        let clock = Arc::new(ManualClock::default());
        let store = Arc::new(SecretStore::new(backend.clone(), clock.clone(), ttl));
        (store, backend, clock)
    }

    fn success<T>(result: Result<T, SecretError>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => panic!("expected successful secret-store operation"),
        }
    }

    #[test]
    fn keyring_errors_keep_missing_separate_from_denied_or_cancelled_access() {
        assert!(map_keyring_error(keyring::Error::NoEntry) == SecretError::Missing);
        assert!(
            map_keyring_error(keyring::Error::NoStorageAccess(Box::new(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "cancelled")
            ))) == SecretError::AccessDenied
        );
        assert!(
            map_keyring_error(keyring::Error::PlatformFailure(Box::new(
                std::io::Error::other("platform failure")
            ))) == SecretError::Unavailable
        );
    }

    #[test]
    fn caches_success_with_absolute_ttl() {
        let ttl = Duration::from_secs(600);
        let (store, backend, clock) = fixture(ttl);
        backend.put("acct", "token", "one");

        assert!(success(store.get("acct", "token")) == "one");
        clock.advance(Duration::from_secs(599));
        assert!(success(store.get("acct", "token")) == "one");
        assert!(backend.get_count.load(Ordering::SeqCst) == 1);

        clock.advance(Duration::from_secs(2));
        assert!(success(store.get("acct", "token")) == "one");
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn maintenance_purges_expired_value_without_another_read() {
        let ttl = Duration::from_secs(600);
        let (store, backend, clock) = fixture(ttl);
        backend.put("acct", "token", "one");
        assert!(success(store.get("acct", "token")) == "one");

        clock.advance(ttl);
        store.purge_expired();
        backend.put("acct", "token", "two");
        assert!(success(store.get("acct", "token")) == "two");
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn concurrent_gets_share_one_backend_read() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "one");
        backend.block_gets();
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let barrier = barrier.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                store.get("acct", "token")
            }));
        }
        barrier.wait();
        backend.wait_until_get_entered();
        thread::sleep(StdDuration::from_millis(25));
        backend.release_gets();

        for handle in threads {
            assert!(success(handle.join().unwrap()) == "one");
        }
        assert!(backend.get_count.load(Ordering::SeqCst) == 1);
    }

    #[test]
    fn concurrent_waiters_share_failure_without_retrying() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        *lock(&backend.get_error) = Some(SecretError::AccessDenied);
        backend.block_gets();
        let barrier = Arc::new(Barrier::new(7));
        let mut threads = Vec::new();
        for _ in 0..6 {
            let store = store.clone();
            let barrier = barrier.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                store.get("acct", "token")
            }));
        }
        barrier.wait();
        backend.wait_until_get_entered();
        thread::sleep(StdDuration::from_millis(25));
        backend.release_gets();

        for handle in threads {
            assert!(handle.join().unwrap().unwrap_err() == SecretError::AccessDenied);
        }
        assert!(backend.get_count.load(Ordering::SeqCst) == 1);
    }

    #[test]
    fn set_updates_cache_and_failed_set_invalidates_old_value() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "old");
        assert!(success(store.get("acct", "token")) == "old");

        success(store.set("acct", "token", "new"));
        assert!(success(store.get("acct", "token")) == "new");
        assert!(backend.get_count.load(Ordering::SeqCst) == 1);

        *lock(&backend.set_error) = Some(SecretError::AccessDenied);
        assert!(store.set("acct", "token", "bad").unwrap_err() == SecretError::AccessDenied);
        assert!(success(store.get("acct", "token")) == "new");
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn delete_success_and_failure_both_invalidate_cache() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "old");
        assert!(success(store.get("acct", "token")) == "old");

        *lock(&backend.delete_error) = Some(SecretError::AccessDenied);
        assert!(store.delete("acct", "token").unwrap_err() == SecretError::AccessDenied);
        assert!(success(store.get("acct", "token")) == "old");
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);

        *lock(&backend.delete_error) = None;
        success(store.delete("acct", "token"));
        assert!(store.get("acct", "token").unwrap_err() == SecretError::Missing);
        assert!(backend.get_count.load(Ordering::SeqCst) == 3);
    }

    #[test]
    fn clear_prevents_inflight_old_value_from_refilling_cache() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "old");
        backend.block_gets();
        let reader_store = store.clone();
        let reader = thread::spawn(move || reader_store.get("acct", "token"));
        backend.wait_until_get_entered();

        store.clear_all();
        backend.put("acct", "token", "new");
        backend.release_gets();
        assert!(reader.join().unwrap().unwrap_err() == SecretError::Unavailable);
        assert!(success(store.get("acct", "token")) == "new");
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn clear_does_not_let_get_overtake_blocked_set() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "old");
        assert!(success(store.get("acct", "token")) == "old");
        backend.set_gate.block();
        let setter_store = store.clone();
        let setter = thread::spawn(move || setter_store.set("acct", "token", "new"));
        backend.set_gate.wait_until_entered();

        store.clear_all();
        let (tx, rx) = mpsc::channel();
        let reader_store = store.clone();
        thread::spawn(move || tx.send(reader_store.get("acct", "token")).unwrap());
        assert!(matches!(
            rx.recv_timeout(StdDuration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        backend.set_gate.release();
        success(setter.join().unwrap());
        assert!(success(rx.recv_timeout(StdDuration::from_secs(1)).unwrap()) == "new");
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn clear_does_not_let_get_overtake_blocked_delete() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "old");
        assert!(success(store.get("acct", "token")) == "old");
        backend.delete_gate.block();
        let deleter_store = store.clone();
        let deleter = thread::spawn(move || deleter_store.delete("acct", "token"));
        backend.delete_gate.wait_until_entered();

        store.clear_all();
        let (tx, rx) = mpsc::channel();
        let reader_store = store.clone();
        thread::spawn(move || tx.send(reader_store.get("acct", "token")).unwrap());
        assert!(matches!(
            rx.recv_timeout(StdDuration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        backend.delete_gate.release();
        success(deleter.join().unwrap());
        assert!(
            rx.recv_timeout(StdDuration::from_secs(1))
                .unwrap()
                .unwrap_err()
                == SecretError::Missing
        );
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn rotate_supersedes_inflight_load() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("acct", "token", "old");
        backend.block_gets();
        let reader_store = store.clone();
        let reader = thread::spawn(move || reader_store.get("acct", "token"));
        backend.wait_until_get_entered();

        success(store.set("acct", "token", "new"));
        backend.release_gets();
        assert!(reader.join().unwrap().unwrap_err() == SecretError::Unavailable);
        assert!(success(store.get("acct", "token")) == "new");
        assert!(backend.get_count.load(Ordering::SeqCst) == 1);
    }

    #[test]
    fn blocked_account_does_not_hold_other_accounts_global_lock() {
        let (store, backend, _) = fixture(Duration::from_secs(600));
        backend.put("slow", "token", "one");
        backend.put("fast", "token", "two");
        backend.block_gets();
        let slow_store = store.clone();
        let slow = thread::spawn(move || slow_store.get("slow", "token"));
        backend.wait_until_get_entered();

        // Open the shared mock gate only after proving the second account reached
        // its backend call. This exercises store locking, not platform behavior.
        let (tx, rx) = mpsc::channel();
        let fast_store = store.clone();
        thread::spawn(move || tx.send(fast_store.get("fast", "token")).unwrap());
        thread::sleep(StdDuration::from_millis(25));
        assert!(backend.get_count.load(Ordering::SeqCst) == 2);
        backend.release_gets();
        assert!(success(rx.recv_timeout(StdDuration::from_secs(1)).unwrap()) == "two");
        assert!(success(slow.join().unwrap()) == "one");
    }
}

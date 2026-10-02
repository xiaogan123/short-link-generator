//! macOS credential facade: five fixed operations and four fixed kinds.
//! No caller can select a Keychain service, path, raw query, or replay policy.

use crate::secret_store::SecretError;
#[cfg(not(test))]
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

const VALUE_MAX: usize = 16 * 1024;
const ACCOUNT_ID_MAX: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    CurrentRead,
    CurrentUpsert,
    CurrentDelete,
    CurrentCreateOnly,
    ExplicitLegacyRead,
}
impl Operation {
    fn is_read(self) -> bool {
        matches!(self, Self::CurrentRead | Self::ExplicitLegacyRead)
    }
    fn is_write(self) -> bool {
        matches!(self, Self::CurrentUpsert | Self::CurrentCreateOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Token,
    Selftest,
    Probe,
    SelftestPending,
}
impl Kind {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "token" => Self::Token,
            "selftest" => Self::Selftest,
            "probe" => Self::Probe,
            "selftest-pending" => Self::SelftestPending,
            _ => return None,
        })
    }
}

// No Debug implementation: Value can own plaintext.
enum Reply {
    Value(Zeroizing<String>),
    Missing,
    Committed,
    Created,
    AlreadyExists,
}

#[derive(Clone, Copy)]
enum TransportError {
    InvalidInput,
    Denied,
    Cancelled,
    Unavailable,
    IpcFailure,
    Protocol,
    LocationUnavailable,
}

// The first proven User-default location is pinned for this app process. A
// change or loss of proof blocks further credential work until restart.
struct LocationState<L> {
    pinned: Option<L>,
    blocked: bool,
}

impl<L: Copy + Eq> LocationState<L> {
    fn new() -> Self {
        Self {
            pinned: None,
            blocked: false,
        }
    }

    fn observe(&mut self, observed: Result<L, ()>) -> Result<L, SecretError> {
        if self.blocked {
            return Err(SecretError::LocationUnavailable);
        }
        match (self.pinned, observed) {
            (None, Ok(location)) => {
                self.pinned = Some(location);
                Ok(location)
            }
            (Some(expected), Ok(location)) if expected == location => Ok(expected),
            (None, Err(())) => Err(SecretError::LocationUnavailable),
            (Some(_), Err(())) | (Some(_), Ok(_)) => {
                self.blocked = true;
                Err(SecretError::LocationUnavailable)
            }
        }
    }
}

#[cfg(not(test))]
pub(crate) fn verify_location() -> Result<crate::mac_helper_ffi::Location, SecretError> {
    static SESSION: OnceLock<Mutex<LocationState<crate::mac_helper_ffi::Location>>> =
        OnceLock::new();
    let session = SESSION.get_or_init(|| Mutex::new(LocationState::new()));
    // Serialize capture with first pin and drift decisions. Never expose the
    // digest or a path through a user-visible error or log.
    let mut state = session.lock().unwrap_or_else(|e| e.into_inner());
    let result = state.observe(crate::mac_helper_ffi::capture_location().map_err(|_| ()));
    drop(state);
    if result.is_err() {
        crate::secret_store::clear_all();
    }
    result
}

trait Transport {
    fn exchange(
        &self,
        operation: Operation,
        kind: Kind,
        account_id: &str,
        value: Option<&str>,
    ) -> Result<Reply, TransportError>;
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= ACCOUNT_ID_MAX
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn call(
    transport: &impl Transport,
    operation: Operation,
    account_id: &str,
    kind: &str,
    value: Option<&str>,
) -> Result<Reply, SecretError> {
    let kind = Kind::parse(kind).ok_or(SecretError::Other)?;
    if !valid_id(account_id)
        || operation.is_write() != value.is_some()
        || value.is_some_and(|v| v.len() > VALUE_MAX)
    {
        return Err(SecretError::Other);
    }
    // A failed, cancelled, timed-out, or disconnected write is never replayed.
    // In particular, transport failure can never become Missing or start a
    // legacy read. The explicit migration loop owns any later operation.
    let reply = transport
        .exchange(operation, kind, account_id, value)
        .map_err(|error| match error {
            TransportError::InvalidInput => SecretError::Other,
            TransportError::Denied | TransportError::Cancelled => SecretError::AccessDenied,
            TransportError::Unavailable | TransportError::IpcFailure | TransportError::Protocol => {
                SecretError::Unavailable
            }
            TransportError::LocationUnavailable => SecretError::LocationUnavailable,
        })?;
    match (&reply, operation) {
        (Reply::Value(secret), op) if op.is_read() && secret.len() <= VALUE_MAX => Ok(reply),
        (Reply::Missing, op) if op.is_read() => Ok(reply),
        (Reply::Committed, Operation::CurrentUpsert | Operation::CurrentDelete) => Ok(reply),
        (Reply::Created | Reply::AlreadyExists, Operation::CurrentCreateOnly) => Ok(reply),
        _ => Err(SecretError::Unavailable),
    }
}

fn read(
    transport: &impl Transport,
    operation: Operation,
    account_id: &str,
    kind: &str,
) -> Result<Zeroizing<String>, SecretError> {
    match call(transport, operation, account_id, kind, None)? {
        Reply::Value(value) => Ok(value),
        Reply::Missing => Err(SecretError::Missing),
        _ => Err(SecretError::Unavailable),
    }
}

fn write(
    transport: &impl Transport,
    operation: Operation,
    account_id: &str,
    kind: &str,
    value: Option<&str>,
) -> Result<(), SecretError> {
    match call(transport, operation, account_id, kind, value)? {
        Reply::Committed => Ok(()),
        _ => Err(SecretError::Unavailable),
    }
}

fn create(
    transport: &impl Transport,
    account_id: &str,
    kind: &str,
    value: &str,
) -> Result<crate::credential_migration::Created, SecretError> {
    use crate::credential_migration::Created;
    match call(
        transport,
        Operation::CurrentCreateOnly,
        account_id,
        kind,
        Some(value),
    )? {
        Reply::Created => Ok(Created::New),
        Reply::AlreadyExists => Ok(Created::AlreadyExists),
        _ => Err(SecretError::Unavailable),
    }
}

#[cfg(not(test))]
struct CTransport;

#[cfg(not(test))]
impl Transport for CTransport {
    fn exchange(
        &self,
        operation: Operation,
        kind: Kind,
        account_id: &str,
        value: Option<&str>,
    ) -> Result<Reply, TransportError> {
        use crate::mac_helper_ffi as ffi;
        let location = verify_location().map_err(|_| TransportError::LocationUnavailable)?;
        let op = match operation {
            Operation::CurrentRead => ffi::Operation::CurrentRead,
            Operation::CurrentUpsert => ffi::Operation::CurrentUpsert,
            Operation::CurrentDelete => ffi::Operation::CurrentDelete,
            Operation::CurrentCreateOnly => ffi::Operation::CurrentCreateOnly,
            Operation::ExplicitLegacyRead => ffi::Operation::ExplicitLegacyRead,
        };
        let kind = match kind {
            Kind::Token => ffi::Kind::Token,
            Kind::Selftest => ffi::Kind::Selftest,
            Kind::Probe => ffi::Kind::Probe,
            Kind::SelftestPending => ffi::Kind::SelftestPending,
        };
        let response = ffi::call_once(op, kind, account_id, value, &location);
        // A default switch after the helper accepted a request still fails
        // this logical operation. Unknown writes are never replayed.
        verify_location().map_err(|_| TransportError::LocationUnavailable)?;
        if matches!(
            &response,
            Err(ffi::Error::Unavailable | ffi::Error::IpcFailure | ffi::Error::Protocol)
        ) {
            crate::secret_store::clear_all();
        }
        match response {
            Ok(ffi::Outcome::Value(secret)) => Ok(Reply::Value(secret)),
            Ok(ffi::Outcome::Missing) => Ok(Reply::Missing),
            Ok(ffi::Outcome::Committed) => Ok(Reply::Committed),
            Ok(ffi::Outcome::Created) => Ok(Reply::Created),
            Ok(ffi::Outcome::AlreadyExists) => Ok(Reply::AlreadyExists),
            Err(ffi::Error::InvalidInput) => Err(TransportError::InvalidInput),
            Err(ffi::Error::Denied) => Err(TransportError::Denied),
            Err(ffi::Error::Cancelled) => Err(TransportError::Cancelled),
            Err(ffi::Error::Unavailable) => Err(TransportError::Unavailable),
            Err(ffi::Error::IpcFailure) => Err(TransportError::IpcFailure),
            Err(ffi::Error::Protocol) => Err(TransportError::Protocol),
        }
    }
}

#[cfg(not(test))]
pub(crate) fn current_read(id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
    read(&CTransport, Operation::CurrentRead, id, kind)
}

#[cfg(not(test))]
pub(crate) fn explicit_legacy_read(id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
    read(&CTransport, Operation::ExplicitLegacyRead, id, kind)
}

#[cfg(not(test))]
pub(crate) fn current_upsert(id: &str, kind: &str, value: &str) -> Result<(), SecretError> {
    write(&CTransport, Operation::CurrentUpsert, id, kind, Some(value))
}

#[cfg(not(test))]
pub(crate) fn current_delete(id: &str, kind: &str) -> Result<(), SecretError> {
    write(&CTransport, Operation::CurrentDelete, id, kind, None)
}

#[cfg(not(test))]
pub(crate) fn current_create_only(
    id: &str,
    kind: &str,
    value: &str,
) -> Result<crate::credential_migration::Created, SecretError> {
    create(&CTransport, id, kind, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_migration::{self, MigrationBackend};
    use std::{cell::RefCell, collections::VecDeque};

    struct Mock {
        replies: RefCell<VecDeque<Result<Reply, TransportError>>>,
        calls: RefCell<Vec<(Operation, Kind)>>,
    }
    impl Mock {
        fn new(replies: Vec<Result<Reply, TransportError>>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }
    impl Transport for Mock {
        fn exchange(
            &self,
            op: Operation,
            kind: Kind,
            _: &str,
            _: Option<&str>,
        ) -> Result<Reply, TransportError> {
            self.calls.borrow_mut().push((op, kind));
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("one synthetic mock reply per call")
        }
    }
    struct Adapter(Mock);
    impl MigrationBackend for Adapter {
        fn current(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            read(&self.0, Operation::CurrentRead, id, kind)
        }
        fn legacy(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            read(&self.0, Operation::ExplicitLegacyRead, id, kind)
        }
        fn create(
            &self,
            id: &str,
            kind: &str,
            value: &str,
        ) -> Result<credential_migration::Created, SecretError> {
            create(&self.0, id, kind, value)
        }
    }

    #[test]
    fn five_fixed_operations_and_four_kinds() {
        for kind in credential_migration::KINDS {
            let mock = Mock::new(vec![Ok(Reply::Missing), Ok(Reply::Committed)]);
            assert!(matches!(
                read(&mock, Operation::CurrentRead, "Acct_1", kind),
                Err(SecretError::Missing)
            ));
            assert!(write(&mock, Operation::CurrentDelete, "Acct_1", kind, None).is_ok());
            assert_eq!(mock.calls.borrow().len(), 2);
        }
        let mock = Mock::new(vec![]);
        assert!(matches!(
            read(&mock, Operation::CurrentRead, "Acct_1", "other"),
            Err(SecretError::Other)
        ));
        assert!(mock.calls.borrow().is_empty());
    }

    #[test]
    fn id_value_and_status_boundaries_fail_before_or_after_one_call() {
        for id in [
            "",
            "a:b",
            "a/b",
            "a.b",
            "a b",
            "a\0b",
            "中文",
            &"a".repeat(65),
        ] {
            let mock = Mock::new(vec![]);
            assert!(call(&mock, Operation::CurrentRead, id, "token", None).is_err());
            assert!(mock.calls.borrow().is_empty());
        }
        for id in ["a", "A_9-z", &"a".repeat(64)] {
            let mock = Mock::new(vec![Ok(Reply::Missing)]);
            assert!(matches!(
                read(&mock, Operation::CurrentRead, id, "token"),
                Err(SecretError::Missing)
            ));
        }
        let mock = Mock::new(vec![]);
        assert!(write(
            &mock,
            Operation::CurrentUpsert,
            "acct",
            "token",
            Some(&"x".repeat(VALUE_MAX + 1))
        )
        .is_err());
        assert!(mock.calls.borrow().is_empty());
        let mock = Mock::new(vec![Ok(Reply::Committed)]);
        assert!(write(
            &mock,
            Operation::CurrentUpsert,
            "acct",
            "token",
            Some("a\0b")
        )
        .is_ok());
        assert_eq!(mock.calls.borrow().len(), 1);
    }

    #[test]
    fn denial_cancel_ipc_and_invalid_reply_never_become_missing() {
        for error in [
            TransportError::InvalidInput,
            TransportError::Denied,
            TransportError::Cancelled,
            TransportError::Unavailable,
            TransportError::IpcFailure,
            TransportError::Protocol,
            TransportError::LocationUnavailable,
        ] {
            let adapter = Adapter(Mock::new(vec![Err(error)]));
            assert!(credential_migration::migrate(&adapter, "acct").is_err());
            assert_eq!(adapter.0.calls.borrow().len(), 1);
            assert_eq!(adapter.0.calls.borrow()[0].0, Operation::CurrentRead);
        }
        for reply in [Reply::Committed, Reply::AlreadyExists] {
            let mock = Mock::new(vec![Ok(reply)]);
            assert!(matches!(
                read(&mock, Operation::CurrentRead, "acct", "token"),
                Err(SecretError::Unavailable)
            ));
        }
    }

    #[test]
    fn actual_migration_uses_legacy_only_after_missing_and_direct_readback() {
        let mut replies = Vec::new();
        for kind in credential_migration::KINDS {
            let value = Zeroizing::new(format!("synthetic-{kind}"));
            replies.extend([
                Ok(Reply::Missing),
                Ok(Reply::Value(value.clone())),
                Ok(Reply::Created),
                Ok(Reply::Value(value)),
            ]);
        }
        let adapter = Adapter(Mock::new(replies));
        assert!(credential_migration::migrate(&adapter, "acct").is_ok());
        let calls = adapter.0.calls.borrow();
        assert_eq!(calls.len(), 16);
        for chunk in calls.chunks_exact(4) {
            assert_eq!(
                [chunk[0].0, chunk[1].0, chunk[2].0, chunk[3].0],
                [
                    Operation::CurrentRead,
                    Operation::ExplicitLegacyRead,
                    Operation::CurrentCreateOnly,
                    Operation::CurrentRead
                ]
            );
        }
    }

    #[test]
    fn create_only_duplicate_and_verified_four_kind_delete() {
        let adapter = Adapter(Mock::new(vec![
            Ok(Reply::Missing),
            Ok(Reply::Value(Zeroizing::new("old".into()))),
            Ok(Reply::AlreadyExists),
            Ok(Reply::Value(Zeroizing::new("different".into()))),
        ]));
        assert!(matches!(
            credential_migration::migrate(&adapter, "acct"),
            Err(SecretError::Conflict)
        ));
        let mut replies = Vec::new();
        for _ in credential_migration::KINDS {
            replies.extend([Ok(Reply::Committed), Ok(Reply::Missing)]);
        }
        let adapter = Adapter(Mock::new(replies));
        assert!(credential_migration::remove_current_verified(
            |kind| write(&adapter.0, Operation::CurrentDelete, "acct", kind, None),
            |kind| read(&adapter.0, Operation::CurrentRead, "acct", kind)
        )
        .is_ok());
        assert_eq!(adapter.0.calls.borrow().len(), 8);
    }

    struct DriftTransport {
        state: RefCell<LocationState<u8>>,
        locations: RefCell<VecDeque<Result<u8, ()>>>,
        replies: RefCell<VecDeque<Result<Reply, TransportError>>>,
        calls: RefCell<Vec<Operation>>,
    }

    impl DriftTransport {
        fn new(
            locations: Vec<Result<u8, ()>>,
            replies: Vec<Result<Reply, TransportError>>,
        ) -> Self {
            Self {
                state: RefCell::new(LocationState::new()),
                locations: RefCell::new(locations.into()),
                replies: RefCell::new(replies.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
        fn check(&self) -> Result<(), TransportError> {
            let observed = self
                .locations
                .borrow_mut()
                .pop_front()
                .expect("location snapshot");
            self.state
                .borrow_mut()
                .observe(observed)
                .map(|_| ())
                .map_err(|_| TransportError::LocationUnavailable)
        }
    }

    impl Transport for DriftTransport {
        fn exchange(
            &self,
            operation: Operation,
            _: Kind,
            _: &str,
            _: Option<&str>,
        ) -> Result<Reply, TransportError> {
            self.check()?;
            self.calls.borrow_mut().push(operation);
            let reply = self.replies.borrow_mut().pop_front().expect("mock reply");
            self.check()?;
            reply
        }
    }

    struct DriftMigration(DriftTransport);
    impl MigrationBackend for DriftMigration {
        fn current(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            read(&self.0, Operation::CurrentRead, id, kind)
        }
        fn legacy(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, SecretError> {
            read(&self.0, Operation::ExplicitLegacyRead, id, kind)
        }
        fn create(
            &self,
            id: &str,
            kind: &str,
            value: &str,
        ) -> Result<credential_migration::Created, SecretError> {
            create(&self.0, id, kind, value)
        }
    }

    #[test]
    fn location_pin_poisoning_and_failed_resolution_do_not_retarget() {
        let mut state = LocationState::new();
        assert!(matches!(
            state.observe(Err(())),
            Err(SecretError::LocationUnavailable)
        ));
        assert!(matches!(state.observe(Ok(1)), Ok(1)));
        assert!(matches!(state.observe(Ok(1)), Ok(1)));
        assert!(matches!(
            state.observe(Ok(2)),
            Err(SecretError::LocationUnavailable)
        ));
        assert!(matches!(
            state.observe(Ok(1)),
            Err(SecretError::LocationUnavailable)
        ));
        let mut state = LocationState::new();
        assert!(matches!(state.observe(Ok(1)), Ok(1)));
        assert!(matches!(
            state.observe(Err(())),
            Err(SecretError::LocationUnavailable)
        ));
        assert!(matches!(
            state.observe(Ok(1)),
            Err(SecretError::LocationUnavailable)
        ));
    }

    #[test]
    fn migration_stops_before_legacy_or_readback_on_location_drift() {
        let adapter = DriftMigration(DriftTransport::new(
            vec![Ok(1), Ok(1), Ok(2)],
            vec![Ok(Reply::Missing)],
        ));
        assert!(matches!(
            credential_migration::migrate(&adapter, "acct"),
            Err(SecretError::LocationUnavailable)
        ));
        assert_eq!(*adapter.0.calls.borrow(), vec![Operation::CurrentRead]);

        let adapter = DriftMigration(DriftTransport::new(
            vec![Ok(1), Ok(1), Ok(1), Ok(1), Ok(1), Ok(1), Ok(2)],
            vec![
                Ok(Reply::Missing),
                Ok(Reply::Value(Zeroizing::new("synthetic".into()))),
                Ok(Reply::Created),
            ],
        ));
        assert!(matches!(
            credential_migration::migrate(&adapter, "acct"),
            Err(SecretError::LocationUnavailable)
        ));
        assert_eq!(
            *adapter.0.calls.borrow(),
            vec![
                Operation::CurrentRead,
                Operation::ExplicitLegacyRead,
                Operation::CurrentCreateOnly
            ]
        );
    }

    #[test]
    fn replacement_readback_and_four_kind_delete_stop_on_location_drift() {
        let transport = DriftTransport::new(vec![Ok(1), Ok(1), Ok(2)], vec![Ok(Reply::Committed)]);
        assert!(write(
            &transport,
            Operation::CurrentUpsert,
            "acct",
            "token",
            Some("new")
        )
        .is_ok());
        assert!(matches!(
            read(&transport, Operation::CurrentRead, "acct", "token"),
            Err(SecretError::LocationUnavailable)
        ));
        assert_eq!(*transport.calls.borrow(), vec![Operation::CurrentUpsert]);

        let transport = DriftTransport::new(
            vec![Ok(1), Ok(1), Ok(1), Ok(1), Ok(2)],
            vec![Ok(Reply::Committed), Ok(Reply::Missing)],
        );
        assert!(matches!(
            credential_migration::remove_current_verified(
                |kind| write(&transport, Operation::CurrentDelete, "acct", kind, None),
                |kind| read(&transport, Operation::CurrentRead, "acct", kind),
            ),
            Err(SecretError::LocationUnavailable)
        ));
        assert_eq!(
            *transport.calls.borrow(),
            vec![Operation::CurrentDelete, Operation::CurrentRead]
        );
    }
}

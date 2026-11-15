mod click_stats;
#[cfg(test)]
mod click_stats_tests;
mod cloud;
#[cfg(test)]
mod credential_cleanup_tests;
#[cfg(test)]
mod credential_import_tests;
#[cfg(any(target_os = "macos", target_os = "windows", test))]
mod credential_migration;
#[cfg(all(test, target_os = "macos"))]
mod credential_migration_tests;
mod domain_check;
#[cfg(test)]
mod link_create_only_tests;
mod local_check;
#[cfg(target_os = "macos")]
mod mac_credentials;
#[cfg(target_os = "macos")]
mod mac_helper_adapter;
#[cfg(all(target_os = "macos", not(test)))]
mod mac_helper_ffi;
mod model;
#[cfg(test)]
mod pending_cleanup_tests;
mod pools;
mod redirect_check;
#[cfg(test)]
mod resume_flow_tests;
mod secret_store;
#[cfg(test)]
mod selftest_resource_recovery_tests;
mod traffic_guard;
mod updater_service;
#[cfg(target_os = "windows")]
mod windows_configuration;
#[cfg(all(test, target_os = "windows"))]
mod windows_credential_native_tests;
mod worker_upgrade;
#[cfg(test)]
mod worker_upgrade_tests;

use chrono::Utc;
use cloud::{Cloud, CloudError};
use domain_check::PathRiskSnapshot;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use model::{
    Account, Candidate, Database, DnsActionView, Domain, DomainCheck, DomainCheckLevel,
    DomainDnsPreparation, DomainPreparation, Link, PendingMonitorChange, PendingPoolChange,
    PendingSelftestRotation, PendingWorkerUpgrade, Plan, PlanKind, PlanView, Pool, PoolSyncStatus,
    Resources, SelftestRotationStatus, State, WorkerUpgradePhase, Zone,
};
use rand::{distributions::Alphanumeric, Rng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
use tauri::Manager;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const MANIFEST_KEY: &str = "m:config";
const SCHEMA: u32 = 1;
fn bundled_source_hash() -> String {
    hex::encode(Sha256::digest(
        include_str!("../../edge/worker.mjs").as_bytes(),
    ))
}

pub struct AppState(Mutex<Backend>);

/// How long a foreground action waits for the one before it to finish.
const BUSY_WAIT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(8)
};
/// Shown when that wait ran out. The frontend recognizes the opening words;
/// the text must not read like a token or permission problem.
const BUSY_MESSAGE: &str =
    "上一个操作还没结束，已经等了几秒。请稍后再点一次；如果屏幕上有系统的钥匙串窗口，请先处理它。";

/// Waits at most `wait` for the backend, then gives up with `BUSY_MESSAGE`.
async fn lock_backend_within(
    state: &AppState,
    wait: Duration,
) -> Result<tokio::sync::MutexGuard<'_, Backend>, String> {
    tokio::time::timeout(wait, state.0.lock())
        .await
        .map_err(|_| BUSY_MESSAGE.to_string())
}

async fn lock_backend<'a>(
    state: &'a AppState,
    action: &str,
) -> Result<tokio::sync::MutexGuard<'a, Backend>, String> {
    if matches!(
        action,
        "refresh_domains"
            | "refresh_accounts"
            | "prepare_domain"
            | "prepare_domain_dns"
            | "prepare_change"
            | "apply_plan"
            | "check_pool_health"
            | "get_link_stats"
            | "get_stats_center"
            | "get_click_protection"
            | "selftest_link"
            | "prepare_monitor"
            | "disable_monitor"
            | "resume_monitor"
            | "import_token"
            | "remove_account"
            | "import_config"
            | "install_update"
    ) {
        lock_backend_within(state, BUSY_WAIT).await
    } else {
        Ok(state.0.lock().await)
    }
}

struct Backend {
    db: Database,
    path: PathBuf,
    plans: Vec<Plan>,
    stats_sessions: Vec<click_stats::ReadSession>,
    cloud: Cloud,
    #[cfg(target_os = "macos")]
    _credential_lease: Option<mac_credentials::ConfigurationLease>,
    #[cfg(target_os = "windows")]
    _configuration_lease: Option<windows_configuration::ConfigurationLease>,
    #[cfg(test)]
    persist_count: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_persist_at: std::sync::atomic::AtomicUsize,
}

#[derive(Clone)]
struct SelftestSnapshot {
    cloud: Cloud,
    host: String,
    path: String,
    url: String,
    cn_url: String,
    default_url: String,
    key: Zeroizing<Vec<u8>>,
    pool: Option<(Pool, String, String, String, Zeroizing<String>)>,
}

struct HealthSnapshot {
    pool: Pool,
    accounts: Vec<(String, Option<Zeroizing<String>>, String)>,
    cloud: Cloud,
}

/// The manifest and Worker settings read by `verify_resource_source`.
struct VerifiedSource {
    manifest: Value,
    settings: Value,
}

struct DomainTakeover<'a> {
    expected_path_risk: &'a PathRiskSnapshot,
    dns_mode: local_check::DnsMode,
    requires_confirmation: bool,
    acknowledged: bool,
}

fn problem(error: CloudError) -> String {
    error.message
}

/// `DomainCheck.reason` for a Cloudflare read that got no HTTP response.
const CLOUD_UNREACHABLE: &str = "cloud_unreachable";
/// `DomainCheck.reason` for a Cloudflare read answered with HTTP 401 or 403
/// (a real answer, not a network failure).
const CLOUD_REFUSED: &str = "cloud_refused";
/// `DomainCheck.reason` when this computer could not use the account's saved
/// authorization (the `本机授权` and `凭据` checks).
const CREDENTIAL: &str = "credential";
/// Where the resume buttons are: the bar above the page content on every
/// page, titled 「有 N 项变更可继续处理」.
const RESUME_BAR: &str = "页面上方“……项变更可继续处理”那一栏";
/// Check reasons that mean "the network did not let us finish", not "the
/// domain is wrong". Repeating the same check is safe and often succeeds.
const TRANSIENT_NETWORK_REASONS: [&str; 7] = [
    "dns_timeout",
    "dns_failed",
    "public_dns_timeout",
    "public_dns_failed",
    CLOUD_UNREACHABLE,
    "probe_timeout",
    "probe_transport_error",
];
/// Present in an `apply_plan` error exactly when the domain plan was kept
/// and may be confirmed again with the same plan ID (see docs/CONTRACT.md).
const PLAN_STILL_VALID: &str = "接入计划仍然有效";
/// `DomainCheck.reason` when the zone ID cached on this computer answered 404
/// (the domain was deleted and added again in Cloudflare, so its ID changed).
const ZONE_CACHE_STALE: &str = "zone_cache_stale";
/// Before a refresh: the cached zone ID is no longer known to Cloudflare.
const ZONE_ID_STALE: &str = "本机记的这个域名的编号已经过期，请重新检查域名";
/// After one automatic refresh the domain is still not found.
const ZONE_CACHE_STALE_MESSAGE: &str = "本机的域名列表过期了，已刷新仍未找到这个域名。请到 Cloudflare 确认这个域名还在所选账户里，再检查一次";

/// A Cloudflare answer (not a network failure) saying the resource is gone.
fn answered_not_found(error: &CloudError) -> bool {
    !error.network && error.message.contains("HTTP 404")
}

/// A Cloudflare answer (not a network failure) refusing the read. On the
/// `zones/{zone_id}` read this may also mean a stale cached zone ID, so the
/// preparing steps refresh the zone list once; the 403 wording stays unless
/// the refresh shows that the ID really changed or the domain is gone.
fn answered_forbidden(error: &CloudError) -> bool {
    !error.network && error.message.contains("HTTP 403")
}

/// A Cloudflare answer (not a network failure) of HTTP 401 or 403.
fn answered_refused(error: &CloudError) -> bool {
    !error.network && (error.message.contains("HTTP 401") || error.message.contains("HTTP 403"))
}

/// Why a confirmed zone read failed, where that changes the check shown.
#[derive(Clone, Copy, Default)]
struct ZoneReadFailure {
    /// `zones/{zone_id}` answered HTTP 403: the cached ID may be stale too.
    forbidden: bool,
    /// `zones/{zone_id}` answered HTTP 401 or 403.
    refused: bool,
    /// Label of the local authorization step that failed.
    credential: Option<&'static str>,
}

/// A failed check because this computer could not use the saved authorization.
fn credential_check(label: &str, message: impl Into<String>) -> DomainCheck {
    let mut check = domain_check::hard_check(label, false, message);
    check.reason = Some(CREDENTIAL.into());
    check
}

/// The ownership check for a cached zone ID that answered 404.
fn stale_zone_check() -> DomainCheck {
    let mut check = domain_check::hard_check("云端域名归属", false, ZONE_ID_STALE);
    check.reason = Some(ZONE_CACHE_STALE.into());
    check
}

/// The two ownership errors an interrupted domain removal leaves behind:
/// its route is gone, or its prefix config is gone. Only these lead to the
/// read-only check for a half-finished removal.
const DOMAIN_ROUTE_CHANGED: &str = "Worker 路由已变化，请刷新或找回";
const DOMAIN_CONFIG_LOST: &str = "云端域名配置已丢失";

/// Ends a domain-removal error that a later removal can finish.
const REMOVAL_RETRY_HINT: &str = "再点一次「移除域名」会接着做完";
/// What an interrupted domain removal left in the cloud (see
/// `Backend::removal_leftover`).
struct RemovalLeftover {
    namespace: String,
    /// Link keys of this domain still in the cloud.
    links: Vec<String>,
    /// This tool's recorded route for the domain is still there.
    route_left: bool,
}

/// Ends an account-cleanup error that a later cleanup can finish.
const CLEANUP_RETRY_HINT: &str = "再点一次「删除云端短链接服务」会接着做完";
/// An account cleanup that stopped before deleting anything in the cloud.
const CLEANUP_NOTHING_DELETED: &str = "云端没有删除任何东西";

/// A failed Worker delete in an account cleanup: the note kept on the record
/// (`None` ends the record) and the error. `nothing_deleted` is true when this
/// run started the record and deleted nothing in the cloud before.
fn cleanup_worker_delete_failure(
    error: &CloudError,
    nothing_deleted: bool,
) -> (Option<&'static str>, String) {
    if error.uncertain {
        return (
            Some("Worker 删除结果不确定，请核对后继续清理"),
            format!("{}；{CLEANUP_RETRY_HINT}", error.message),
        );
    }
    // A connection that never opened sent nothing: not a refusal.
    if error.network {
        return if nothing_deleted {
            (
                None,
                format!(
                    "连不上云端，删除云端跳转服务的请求没有发出去；{CLEANUP_NOTHING_DELETED}。网络恢复后{CLEANUP_RETRY_HINT}"
                ),
            )
        } else {
            (
                Some("连不上云端，云端跳转服务还没删，网络恢复后再点一次「删除云端短链接服务」"),
                format!(
                    "连不上云端，删除云端跳转服务的请求没有发出去，云端跳转服务还没删。网络恢复后{CLEANUP_RETRY_HINT}"
                ),
            )
        };
    }
    if nothing_deleted {
        (
            None,
            format!("{}；{CLEANUP_NOTHING_DELETED}", error.message),
        )
    } else {
        (
            Some("Worker 删除被拒绝，账号清理尚未完成"),
            error.message.clone(),
        )
    }
}

/// Key names an account cleanup may let go together with the namespace: the
/// manifest, the monitor cursor, health records and platform address copies.
/// A link (`l:`), a prefix config (`c:`) or anything unknown is never one.
fn cleanup_may_remove_key(key: &str) -> bool {
    key == MANIFEST_KEY
        || key == "m:monitor:cursor"
        || key.strip_prefix("h:").is_some_and(pools::valid_id)
        || key.strip_prefix("p:").is_some_and(pools::valid_id)
}
/// Replaces the marker and what follows it when a network-only review failure
/// could not keep the plan (it expired while the review was running).
const PLAN_GONE_TAIL: &str = "这份接入计划已经过期，云端没有任何改动，请重新检查域名。";

fn has_reason(checks: &[DomainCheck], reason: &str) -> bool {
    checks
        .iter()
        .any(|check| check.reason.as_deref() == Some(reason))
}

fn is_transient_network_reason(reason: &str) -> bool {
    TRANSIENT_NETWORK_REASONS.contains(&reason)
}

fn is_transient_network_check(check: &DomainCheck) -> bool {
    check
        .reason
        .as_deref()
        .is_some_and(is_transient_network_reason)
}

/// True when there is at least one error and every error is a network one.
fn only_transient_errors(checks: &[DomainCheck]) -> bool {
    let mut errors = checks
        .iter()
        .filter(|check| check.level == DomainCheckLevel::Error)
        .peekable();
    errors.peek().is_some() && errors.all(is_transient_network_check)
}

/// Pause before the confirm-time review is repeated after a network failure.
const REVIEW_RETRY_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_secs(1)
};

/// A confirm-time review that already took this long is not repeated at once:
/// the network is down rather than hiccuping, and the user should hear now.
const REVIEW_RETRY_WINDOW: Duration = Duration::from_secs(12);

/// A failed preflight read. No HTTP response is a network problem worth one
/// more try; a Cloudflare error response keeps its own wording.
fn cloud_read_failure(label: &str, context: &str, error: CloudError) -> DomainCheck {
    if error.network {
        // Kept short: the dialog and the confirm error quote this text inside
        // their own "try once more" sentence.
        let mut check =
            domain_check::hard_check(label, false, "暂时连不上 Cloudflare，这是网络问题");
        check.reason = Some(CLOUD_UNREACHABLE.into());
        check
    } else {
        let refused = answered_refused(&error);
        let mut check =
            domain_check::hard_check(label, false, format!("{context}{}", problem(error)));
        if refused {
            check.reason = Some(CLOUD_REFUSED.into());
        }
        check
    }
}

/// Shown when no usable account is selected for a domain that has candidates.
/// A chosen account that does not hold the domain is told which one does.
fn account_choice_message(choice: Option<&str>, candidates: &[Candidate]) -> String {
    match choice {
        Some(_) => {
            let mut labels: Vec<&str> = candidates.iter().map(|c| c.label.as_str()).collect();
            labels.dedup();
            format!(
                "这个域名在账户「{}」下，不在你选的账户里；请把上面的账户改成它再检查",
                labels.join("」或「")
            )
        }
        None => "请选择此域名所属的账号".to_string(),
    }
}
/// Outcome of the read checks an account must pass before it is imported.
enum ImportAccessError {
    /// Cloudflare refused this token for this account.
    Denied(String),
    /// The check could not be completed (network, rate limit, service error).
    Failed(String),
}
/// True when a cloud read failed because the request was refused, as opposed
/// to a network, rate-limit or service failure.
fn is_access_refusal(message: &str) -> bool {
    message.contains("错误码")
        || ["HTTP 400", "HTTP 401", "HTTP 403", "HTTP 404"]
            .iter()
            .any(|status| message.contains(status))
}
fn dns_write_error(error: CloudError) -> String {
    if error.message.contains("HTTP 403") {
        "Cloudflare 拒绝修改 DNS（HTTP 403）。请检查此令牌的 DNS 编辑权限和域名授权范围，补齐授权后再继续；已有功能仍可使用。".into()
    } else {
        error.message
    }
}
fn now() -> String {
    Utc::now().to_rfc3339()
}
fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn random_name(prefix: &str) -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    format!("{prefix}-{suffix}")
}
fn keyring_get(id: &str, kind: &str) -> Result<String, String> {
    #[cfg(test)]
    {
        mock_key_reads()
            .lock()
            .expect("test reads")
            .push(format!("{kind}:{id}"));
        return mock_keys()
            .lock()
            .expect("test key store")
            .get(&format!("{kind}:{id}"))
            .cloned()
            .ok_or_else(|| "系统凭据库中找不到所需密钥".into());
    }
    #[cfg(not(test))]
    {
        secret_store::get(id, kind).map_err(|error| error.to_string())
    }
}
fn keyring_set(id: &str, kind: &str, value: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        mock_key_mutations()
            .lock()
            .unwrap()
            .push(format!("set:{kind}:{id}"));
        if mock_key_set_failures()
            .lock()
            .expect("test key set failures")
            .contains(&format!("{kind}:{id}"))
        {
            return Err("测试注入：系统凭据保存失败".into());
        }
        let stored = if mock_key_set_failures()
            .lock()
            .unwrap()
            .contains(&format!("readback-mismatch:{kind}:{id}"))
        {
            "synthetic-conflicting-readback"
        } else {
            value
        };
        mock_keys()
            .lock()
            .expect("test key store")
            .insert(format!("{kind}:{id}"), stored.to_string());
        Ok(())
    }
    #[cfg(not(test))]
    {
        secret_store::set(id, kind, value).map_err(|error| error.to_string())
    }
}
fn keyring_delete(id: &str, kind: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        mock_key_mutations()
            .lock()
            .unwrap()
            .push(format!("delete:{kind}:{id}"));
        if mock_key_set_failures()
            .lock()
            .unwrap()
            .contains(&format!("delete:{kind}:{id}"))
        {
            return Err("测试注入：系统凭据删除失败".into());
        }
        if mock_key_set_failures()
            .lock()
            .unwrap()
            .contains(&format!("swallow-delete:{kind}:{id}"))
        {
            return Ok(());
        }
        mock_keys()
            .lock()
            .expect("test key store")
            .remove(&format!("{kind}:{id}"));
        Ok(())
    }
    #[cfg(not(test))]
    {
        secret_store::delete(id, kind).map_err(|error| error.to_string())
    }
}
fn keyring_get_optional(id: &str, kind: &str) -> Result<Option<String>, String> {
    #[cfg(test)]
    {
        mock_key_reads()
            .lock()
            .expect("test reads")
            .push(format!("optional:{kind}:{id}"));
        Ok(mock_keys()
            .lock()
            .expect("test key store")
            .get(&format!("{kind}:{id}"))
            .cloned())
    }
    #[cfg(not(test))]
    {
        match secret_store::get(id, kind) {
            Ok(value) => Ok(Some(value)),
            Err(secret_store::SecretError::Missing) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

async fn write_explicit_token(id: &str, value: &str, replace: bool) -> Result<(), String> {
    let id = id.to_owned();
    let value = Zeroizing::new(value.to_owned());
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        {
            if !replace {
                if let Some(existing) = mock_keys()
                    .lock()
                    .expect("keys")
                    .get(&format!("token:{id}"))
                {
                    return if existing == value.as_str() {
                        Ok(())
                    } else {
                        Err("本机凭据冲突，未覆盖".into())
                    };
                }
            }
            keyring_set(&id, "token", &value)?;
            if keyring_get(&id, "token")? != value.as_str() {
                return Err("本机凭据读回不一致".into());
            }
            Ok(())
        }
        #[cfg(not(test))]
        {
            secret_store::set_explicit_token(&id, &value, replace)
                .map_err(|error| error.to_string())
        }
    })
    .await
    .map_err(|_| "本机凭据保存任务未完成".to_string())?
}

async fn remove_current_credentials(id: &str) -> Result<(), String> {
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || {
        #[cfg(all(target_os = "macos", not(test)))]
        {
            secret_store::remove_current_account(&id).map_err(|error| error.to_string())
        }
        #[cfg(test)]
        {
            use credential_migration::MigrationBackend;
            credential_migration::remove_current_verified(
                |kind| {
                    keyring_delete(&id, kind).map_err(|_| secret_store::SecretError::Unavailable)
                },
                |kind| MockMigration.current(&id, kind),
            )
            .map_err(|error| error.to_string())
        }
        #[cfg(all(target_os = "windows", not(test)))]
        {
            secret_store::remove_current_account(&id).map_err(|error| error.to_string())
        }
        #[cfg(all(not(any(target_os = "macos", target_os = "windows")), not(test)))]
        {
            keyring_delete(&id, "token")?;
            keyring_delete(&id, "selftest")?;
            let _ = keyring_delete(&id, "probe");
            Ok(())
        }
    })
    .await
    .map_err(|_| "本机凭据移除任务未完成".to_string())?
}

#[cfg(test)]
fn mock_legacy_keys() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static KEYS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
fn mock_key_mutations() -> &'static std::sync::Mutex<Vec<String>> {
    static CALLS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
    CALLS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

#[cfg(test)]
struct MockMigration;
#[cfg(test)]
impl credential_migration::MigrationBackend for MockMigration {
    fn current(
        &self,
        id: &str,
        kind: &str,
    ) -> Result<Zeroizing<String>, secret_store::SecretError> {
        mock_key_reads()
            .lock()
            .unwrap()
            .push(format!("current:{kind}:{id}"));
        let failures = mock_key_set_failures().lock().unwrap();
        if failures.contains(&format!("read-denied:{kind}:{id}")) {
            return Err(secret_store::SecretError::AccessDenied);
        }
        if failures.contains(&format!("read-unavailable:{kind}:{id}")) {
            return Err(secret_store::SecretError::Unavailable);
        }
        drop(failures);
        mock_keys()
            .lock()
            .unwrap()
            .get(&format!("{kind}:{id}"))
            .cloned()
            .map(Zeroizing::new)
            .ok_or(secret_store::SecretError::Missing)
    }
    fn legacy(&self, id: &str, kind: &str) -> Result<Zeroizing<String>, secret_store::SecretError> {
        mock_key_reads()
            .lock()
            .unwrap()
            .push(format!("legacy:{kind}:{id}"));
        mock_legacy_keys()
            .lock()
            .unwrap()
            .get(&format!("{kind}:{id}"))
            .cloned()
            .map(Zeroizing::new)
            .ok_or(secret_store::SecretError::Missing)
    }
    fn create(
        &self,
        id: &str,
        kind: &str,
        value: &str,
    ) -> Result<credential_migration::Created, secret_store::SecretError> {
        mock_key_mutations()
            .lock()
            .unwrap()
            .push(format!("create:{kind}:{id}"));
        let key = format!("{kind}:{id}");
        if mock_key_set_failures().lock().unwrap().contains(&key) {
            return Err(secret_store::SecretError::Unavailable);
        }
        let mut keys = mock_keys().lock().unwrap();
        if keys.contains_key(&key) {
            return Ok(credential_migration::Created::AlreadyExists);
        }
        keys.insert(key, value.to_owned());
        Ok(credential_migration::Created::New)
    }
}

fn clear_credential_cache() {
    #[cfg(not(test))]
    secret_store::clear_all();
}

#[cfg(test)]
fn mock_keys() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static KEYS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
fn mock_key_reads() -> &'static std::sync::Mutex<Vec<String>> {
    static READS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
    READS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

#[cfg(test)]
fn mock_key_set_failures() -> &'static std::sync::Mutex<HashSet<String>> {
    static FAILURES: std::sync::OnceLock<std::sync::Mutex<HashSet<String>>> =
        std::sync::OnceLock::new();
    FAILURES.get_or_init(|| std::sync::Mutex::new(HashSet::new()))
}

async fn read_account_token(account_id: &str) -> Result<Zeroizing<String>, String> {
    let id = account_id.to_owned();
    // Native authorization can wait for user input. Keep it off async runtime workers;
    // do not time out the prompt and leave a second authorization queued behind it.
    tokio::task::spawn_blocking(move || keyring_get(&id, "token").map(Zeroizing::new))
        .await
        .map_err(|_| "系统授权未完成，请稍后重试".to_string())?
}

async fn read_optional_staged_selftest(
    account_id: &str,
) -> Result<Option<Zeroizing<String>>, String> {
    let id = account_id.to_owned();
    tokio::task::spawn_blocking(move || {
        keyring_get_optional(&id, "selftest-pending").map(|value| value.map(Zeroizing::new))
    })
    .await
    .map_err(|_| "系统授权未完成，请稍后重试".to_string())?
}

fn field<'a>(payload: &'a Value, name: &str) -> Result<&'a str, String> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("缺少参数：{name}"))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn validate_prefix(value: &str) -> Result<(), String> {
    if (1..=12).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        Ok(())
    } else {
        Err("前缀只能用 1–12 位小写字母、数字或连字符".into())
    }
}
fn validate_slug(value: &str) -> Result<(), String> {
    if (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        Ok(())
    } else {
        Err("短码只能用 1–32 位字母、数字、下划线或连字符".into())
    }
}
fn validate_target(value: &str) -> Result<(), String> {
    if value.bytes().any(|c| c <= 32 || c == 127 || c == b'\\') {
        return Err("目标网址不能包含空白、控制字符或反斜杠".into());
    }
    let parsed = url::Url::parse(value).map_err(|_| "目标网址无效".to_string())?;
    if value.len() > 2048 || parsed.as_str().len() > 2048 {
        return Err("目标网址过长，转换为标准网址后不能超过 2048 个字符".into());
    }
    if parsed.port() == Some(0) {
        return Err("目标网址的端口不能为 0，请核对网址".into());
    }
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("目标网址必须是完整的 HTTPS 地址，且不能包含账号信息或片段".into());
    }
    Ok(())
}
fn canonical_target(value: &str) -> Result<String, String> {
    validate_target(value)?;
    url::Url::parse(value)
        .map(|url| url.to_string())
        .map_err(|_| "目标网址无效".to_string())
}
fn monitor_endpoint(value: &str) -> Result<String, String> {
    let canonical = canonical_target(value)?;
    let url = url::Url::parse(&canonical).map_err(|_| "监测地址无效")?;
    let host = url
        .host_str()
        .ok_or("监测服务缺少主机名")?
        .to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.')
        || host.ends_with('.')
        || url.query().is_some()
        || [".localhost", ".local", ".internal", ".test", ".invalid"]
            .iter()
            .any(|t| host.ends_with(t))
    {
        return Err("监测服务必须是公开 HTTPS 域名，且不能带查询参数".into());
    }
    Ok(canonical)
}
fn validate_monitor_config(value: &Value) -> Result<(), String> {
    let endpoint = value["endpoint"].as_str().ok_or("监测服务地址缺失")?;
    monitor_endpoint(endpoint)?;
    let ids = value["poolIds"].as_array().ok_or("监测平台地址清单无效")?;
    if ids.len() > 256 || value.to_string().len() > 16_384 {
        return Err("监测平台地址清单超过 Worker 上限".into());
    }
    let mut unique = HashSet::new();
    for id in ids {
        let id = id.as_str().ok_or("监测平台地址清单无效")?;
        if !pools::valid_id(id) || !unique.insert(id) {
            return Err("监测平台地址清单无效".into());
        }
    }
    Ok(())
}
fn valid_cleanup_metadata(key: &str, raw: &str) -> bool {
    if key == "m:monitor:cursor" {
        return raw
            .parse::<u64>()
            .is_ok_and(|value| value <= 9_007_199_254_740_991 && value.to_string() == raw);
    }
    if !key.strip_prefix("h:").is_some_and(pools::valid_id) || raw.len() > 16_384 {
        return false;
    }
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    pools::valid_health(&value)
        && value.as_object().is_some_and(|o| o.len() == 3)
        && value["revision"]
            .as_str()
            .is_some_and(|revision| chrono::DateTime::parse_from_rfc3339(revision).is_ok())
        && value["targets"].as_object().is_some_and(|targets| {
            targets
                .values()
                .all(|target| target.as_object().is_some_and(|o| o.len() == 4))
        })
}

/// A platform address copy may be removed by account cleanup only when its ID
/// is valid, its value is a readable copy, and the same pool still exists in
/// the local pool library (so the definition is not lost).
fn valid_cleanup_pool_copy(pool_id: &str, raw: &str, local: &[Pool]) -> bool {
    if !pools::valid_id(pool_id) || raw.len() > 262_144 {
        return false;
    }
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    value
        .as_object()
        .is_some_and(|o| o.get("version") == Some(&json!(1)))
        && local.iter().any(|pool| pool.id == pool_id)
}

fn normalize_host(input: &str) -> Result<String, String> {
    let value = input.trim();
    let url = url::Url::parse(
        if value.contains("://") {
            value.to_string()
        } else {
            format!("https://{value}")
        }
        .as_str(),
    )
    .map_err(|_| "域名格式无效".to_string())?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("请输入域名或 HTTP(S) 地址".into());
    }
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return Err("域名不能包含账号信息或端口".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "缺少域名".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') || host.len() > 253 {
        return Err("请输入有效的域名".into());
    }
    Ok(host)
}
fn value_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| "云端响应缺少必要字段".to_string())
}
fn kv_link(link: &Link) -> Value {
    if let (Some(pool_id), Some(code)) = (&link.pool_id, &link.code) {
        json!({"poolId":pool_id,"code":code,"updated":link.updated})
    } else {
        json!({"rules":[{"countries":["CN"],"url":link.cn_url}],
            "default":link.default_url,"updated":link.updated})
    }
}
fn remote_matches_link(remote: &Value, link: &Link) -> bool {
    if let (Some(pool_id), Some(code)) = (&link.pool_id, &link.code) {
        remote["poolId"].as_str() == Some(pool_id) && remote["code"].as_str() == Some(code)
    } else {
        remote["rules"][0]["url"].as_str() == Some(&link.cn_url)
            && remote["default"].as_str() == Some(&link.default_url)
    }
}
fn link_from_remote(
    remote: &Value,
    domain_id: &str,
    slug: &str,
    pools: &[Pool],
) -> Result<Link, String> {
    if let Some(pool_id) = remote["poolId"].as_str() {
        let code = remote["code"]
            .as_str()
            .ok_or("按平台地址生成的链接缺少邀请码")?;
        if !pools::valid_code(code) {
            return Err("邀请码无效".into());
        }
        let pool = pools
            .iter()
            .find(|p| p.id == pool_id)
            .ok_or("找不到链接引用的平台地址")?;
        let candidate = pool
            .candidates
            .iter()
            .find(|c| c.enabled)
            .ok_or("这组平台地址没有已启用的大陆备用地址")?;
        pools::compose(&model::Template::from(candidate), code)?;
        pools::compose(&pool.official, code)?;
        return Ok(Link {
            domain_id: domain_id.into(),
            slug: slug.into(),
            cn_url: String::new(),
            default_url: String::new(),
            updated: remote["updated"].as_str().unwrap_or("").into(),
            pool_id: Some(pool_id.into()),
            code: Some(code.into()),
        });
    }
    let cn = remote["rules"][0]["url"]
        .as_str()
        .ok_or("链接缺少大陆目标")?;
    let default = remote["default"].as_str().ok_or("链接缺少默认目标")?;
    validate_target(cn)?;
    validate_target(default)?;
    Ok(Link {
        domain_id: domain_id.into(),
        slug: slug.into(),
        cn_url: cn.into(),
        default_url: default.into(),
        updated: remote["updated"].as_str().unwrap_or("").into(),
        pool_id: None,
        code: None,
    })
}
fn route_pattern(host: &str, prefix: &str) -> String {
    format!("{host}/{prefix}/*")
}

fn journal_matches(entry: &str, id: &str) -> bool {
    entry == id
        || entry
            .strip_prefix(id)
            .is_some_and(|rest| rest.starts_with('：'))
}
fn set_journal_note(pending: &mut [String], id: &str, detail: &str) -> Result<String, String> {
    let note = format!("{id}：{detail}");
    let item = pending
        .iter_mut()
        .find(|entry| journal_matches(entry, id))
        .ok_or_else(|| "待处理记录里已经没有这一条".to_string())?;
    *item = note.clone();
    Ok(note)
}
fn clear_journal(pending: &mut Vec<String>, id: &str) -> Result<(), String> {
    let before = pending.len();
    pending.retain(|entry| !journal_matches(entry, id));
    if pending.len() == before {
        return Err("待处理记录里已经没有这一条".into());
    }
    Ok(())
}
/// Last eight characters of an account ID, to name an account that has no
/// local label. Account IDs are not secret.
fn id_tail(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    chars[chars.len().saturating_sub(8)..].iter().collect()
}
/// Removes earlier save/delete records for one link (for example an uncertain
/// write) once a later write for the same host and slug has succeeded. The
/// trailing " (" keeps `ab` from matching `abc`. `current` is left in place.
fn clear_link_leftovers(pending: &mut Vec<String>, host: &str, slug: &str, current: &str) {
    let prefixes = [
        format!("保存链接 {host} / {slug} ("),
        format!("删除链接 {host} / {slug} ("),
    ];
    pending.retain(|entry| {
        journal_matches(entry, current) || !prefixes.iter().any(|p| entry.starts_with(p))
    });
}
/// A host this tool fully set up earlier (prefix config and route) that is
/// not on this computer: only recovery brings it back together with links.
const NEEDS_RECOVERY_MESSAGE: &str = "云端已有此主机名的配置和转发规则（可能还有链接），不能覆盖。请先找回：在“Cloudflare 账户”页打开该账户的“管理账户”，点“从 Cloudflare 找回配置”";
/// Marks a note naming cloud resources that a failed first setup could not
/// undo. Automatic clean-up keeps such records so the names stay visible until
/// the user has checked them and dismisses the record.
const UNDO_INCOMPLETE: &str = "本次建出的云端资源没能全部撤销";
/// A new account's first setup got no clear answer and everything this run may
/// have created was deleted again. Also shown after an HTTP 5xx or 408, so it
/// does not claim a network cut.
const UNDONE_FIRST_SETUP: &str = "这一步没有收到明确的答复，已撤销本次创建，请再试一次";
/// Note kept on an add-domain record whose reused prefix config brought back
/// links this computer does not list; recovery imports them and settles it.
fn revived_links_note(count: usize) -> String {
    format!(
        "云端还留着这个主机名以前的 {count} 条短链接，现在重新生效了，本机列表里还看不到。请到该账户的「管理账户」点「从 Cloudflare 找回配置」把它们找回来"
    )
}
/// Refusal to save a link whose platform address copy `p:{id}` is recorded as
/// synced but missing in the cloud.
const POOL_COPY_MISSING_FOR_LINK: &str = "这条链接用的平台地址在云端的副本不见了。请到「平台地址」页点这组地址的「编辑地址」，不用改内容，直接保存一次，再回来保存链接";
/// Recovery found two routes of this tool for one host and stopped before
/// changing anything on this computer.
fn duplicate_route_message(host: &str, first: &str, second: &str) -> String {
    format!(
        "域名 {host} 上有两条本工具的转发规则（{first}、{second}），没法确定该用哪一条，所以这次没有找回，本机记录没有改动。请联系维护的人处理"
    )
}
/// Note on an add-domain record whose undo after a failure did not finish.
const ROLLBACK_INCOMPLETE: &str = "失败且回滚未完全成功，需要人工核对";
/// True for a record that is the only place naming cloud resources a failed
/// or interrupted first setup may have left behind: an `UNDO_INCOMPLETE`
/// note, or any new-account add-domain record (planned KV and Worker names),
/// whatever its note says: a run that stopped while creating, uploading or
/// writing the manifest, or whose answer or rollback was unclear, may have
/// left them. A record whose undo finished is ended, not kept. Automatic
/// clean-up keeps these until the user dismisses them; the existing-account
/// form names no resources and is not one.
fn names_leftover_resources(entry: &str) -> bool {
    if entry.contains(UNDO_INCOMPLETE) {
        return true;
    }
    let id = entry.split_once('：').map_or(entry, |(id, _)| id);
    id.starts_with("添加域名 ") && id.contains("（计划 KV ")
}
/// A pending record asked to be dismissed is no longer there.
const RECORD_GONE: &str = "这条记录已经不在了，可能已经被自动清掉。请点一下「刷新数据」看最新情况";
/// Both forms of an add-domain record for one host (existing account, and new
/// account with planned resource names).
fn add_domain_prefixes(host: &str) -> Vec<String> {
    vec![format!("添加域名 {host} ("), format!("添加域名 {host}（")]
}
/// Removes earlier records starting with one of `prefixes` once a later
/// operation on the same host succeeded. `current` is left in place.
fn clear_domain_leftovers(pending: &mut Vec<String>, prefixes: &[String], current: &str) {
    pending.retain(|entry| {
        journal_matches(entry, current)
            || names_leftover_resources(entry)
            || !prefixes.iter().any(|p| entry.starts_with(p))
    });
}
/// Host named by an add/remove-domain or save/delete-link record.
fn journal_host(entry: &str) -> Option<&str> {
    let rest = ["添加域名 ", "移除域名 ", "保存链接 ", "删除链接 "]
        .iter()
        .find_map(|p| entry.strip_prefix(p))?;
    let end = rest.find([' ', '（']).unwrap_or(rest.len());
    Some(&rest[..end])
}
/// True when the stored link value equals `link` apart from `updated`, which
/// a retry always renews.
fn same_link_content(raw: &str, link: &Link) -> bool {
    let Ok(Value::Object(mut remote)) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    let Value::Object(mut wanted) = kv_link(link) else {
        return false;
    };
    remote.remove("updated");
    wanted.remove("updated");
    remote == wanted
}
fn selftest_rotation_prefix(account_id: &str) -> String {
    format!("重置自检密钥 {account_id} (")
}
/// Pattern of a route of `script` for exactly `host` whose pattern is not the
/// one this tool would create for `prefix`, if any.
fn own_route_under_other_directory<'a>(
    routes: &'a [Value],
    script: &str,
    host: &str,
    prefix: &str,
) -> Option<&'a str> {
    let exact = route_pattern(host, prefix);
    routes
        .iter()
        .filter(|route| route["script"].as_str() == Some(script))
        .filter_map(|route| route["pattern"].as_str())
        .find(|pattern| {
            *pattern != exact
                && pattern
                    .split_once('/')
                    .is_some_and(|(route_host, _)| route_host == host)
        })
}

/// Refusal for a leftover route of this tool under another directory: names
/// the route and, when it is one this tool creates, the directory to use.
fn stray_route_message(host: &str, pattern: &str) -> String {
    match pattern
        .strip_prefix(&format!("{host}/"))
        .and_then(|rest| rest.strip_suffix("/*"))
        .filter(|old| validate_prefix(old).is_ok())
    {
        Some(old) => format!(
            "这个域名上还留着本工具以前建的转发规则 {pattern}（上次移除没做完）。请把链接目录改成「{old}」再检查，添加时会直接沿用它"
        ),
        None => format!(
            "这个域名上还留着本工具的转发规则 {pattern}，和要添加的链接目录对不上，不能自动沿用。本次没有做任何改动，请联系维护的人"
        ),
    }
}

fn route_conflict(pattern: &str, host: &str, prefix: &str) -> bool {
    let p = pattern
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (route_host, route_path) = p.split_once('/').unwrap_or((p, ""));
    let route_host = route_host.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let host_hit = if route_host == "*" {
        true
    } else if let Some(suffix) = route_host.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}"))
    } else if let Some(suffix) = route_host.strip_prefix('*') {
        host.ends_with(suffix)
    } else {
        route_host == host
    };
    if !host_hit {
        return false;
    }
    let wanted = format!("{prefix}/");
    let base = route_path.trim_end_matches('*');
    base.is_empty() || wanted.starts_with(base) || base.starts_with(&wanted) || base == prefix
}

impl Backend {
    fn load(path: PathBuf) -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        let lease =
            mac_credentials::ConfigurationLease::acquire(path.parent().ok_or("配置目录无效")?)?;
        #[cfg(target_os = "windows")]
        let windows_lease = windows_configuration::ConfigurationLease::acquire(
            path.parent().ok_or("配置目录无效")?,
        )?;
        let db: Database = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| "无法读取本机配置".to_string())?;
            serde_json::from_slice(&bytes).map_err(|_| "本机配置格式无效".to_string())?
        } else {
            Database::default()
        };
        #[cfg(target_os = "macos")]
        if db
            .accounts
            .iter()
            .any(|a| !matches!(a.mac_credential_schema, 0 | 2))
        {
            return Err("本机凭据格式版本不受支持".into());
        }
        #[cfg(all(not(test), target_os = "macos"))]
        secret_store::register_routes(&db.accounts);
        Ok(Self {
            #[cfg(target_os = "macos")]
            _credential_lease: Some(lease),
            #[cfg(target_os = "windows")]
            _configuration_lease: Some(windows_lease),
            db,
            path,
            plans: Vec::new(),
            stats_sessions: Vec::new(),
            cloud: Cloud::new()?,
            #[cfg(test)]
            persist_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_persist_at: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn persist(&self) -> Result<(), String> {
        #[cfg(test)]
        {
            let count = self
                .persist_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            if self
                .fail_persist_at
                .load(std::sync::atomic::Ordering::SeqCst)
                == count
            {
                self.fail_persist_at
                    .store(0, std::sync::atomic::Ordering::SeqCst);
                return Err("测试注入：本机配置保存失败".into());
            }
        }
        let dir = self
            .path
            .parent()
            .ok_or_else(|| "配置目录无效".to_string())?;
        fs::create_dir_all(dir).map_err(|_| "无法创建配置目录".to_string())?;
        let bytes =
            serde_json::to_vec_pretty(&self.db).map_err(|_| "无法序列化配置".to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        use std::io::Write;
        let mut file = fs::File::create(&tmp).map_err(|_| "无法保存配置".to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "无法保存配置".to_string())?;
        drop(file);
        fs::rename(&tmp, &self.path).map_err(|_| "无法提交配置".to_string())
    }
    fn state(&self) -> Value {
        let mut state = serde_json::to_value(State::from(&self.db)).unwrap_or(Value::Null);
        state["appVersion"] = json!(env!("CARGO_PKG_VERSION"));
        state
    }
    fn account(&self, id: &str) -> Result<&Account, String> {
        self.db
            .accounts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| "找不到此账号".into())
    }
    fn publish_credential_routes(&self) {
        #[cfg(all(not(test), target_os = "macos"))]
        secret_store::register_routes(&self.db.accounts);
    }

    fn require_credentials(&self, id: &str) -> Result<(), String> {
        let account = self.account(id)?;
        if account.token_import_pending {
            return Err(format!(
                "账户「{}」：此账号的令牌导入尚未完成，请重试原令牌或明确更新该账号令牌",
                account.label
            ));
        }
        if cfg!(target_os = "macos") && account.mac_credential_schema != 2 {
            return Err(format!(
                "账户「{}」：{}",
                account.label,
                secret_store::SecretError::MigrationRequired
            ));
        }
        Ok(())
    }
    fn require_many_credentials<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), String> {
        for id in ids {
            self.require_credentials(id)?;
        }
        Ok(())
    }
    fn require_plan_credentials(&self, kind: &PlanKind) -> Result<(), String> {
        let ids: Vec<String> = match kind {
            PlanKind::MigrateCredentials { .. } | PlanKind::DismissPendingOperation { .. } => {
                return Ok(())
            }
            PlanKind::UpgradeWorker { account_id, .. }
            | PlanKind::SetClickStats { account_id, .. }
            | PlanKind::SetClickProtection { account_id, .. }
            | PlanKind::ResumeWorkerUpgrade { account_id } => {
                return self.require_credentials(account_id);
            }
            PlanKind::DismissWorkerUpgrade { account_id } => {
                return self.account(account_id).map(|_| ())
            }
            PlanKind::Domain { account_id, .. }
            | PlanKind::DomainDns { account_id, .. }
            | PlanKind::EnableMonitor { account_id, .. }
            | PlanKind::DisableMonitor { account_id }
            | PlanKind::CleanupAccount { account_id }
            | PlanKind::RecoverAccount { account_id }
            | PlanKind::RotateSelftest { account_id }
            | PlanKind::ResumeSelftestRotation { account_id }
            | PlanKind::RecoverSelftestResources { account_id }
            | PlanKind::RecoverSelftestRotation { account_id } => vec![account_id.clone()],
            PlanKind::SaveLink { domain_id, .. }
            | PlanKind::DeleteLink { domain_id, .. }
            | PlanKind::RemoveDomain { domain_id } => {
                vec![self.domain(domain_id)?.account_id.clone()]
            }
            PlanKind::SavePool { pool } => pool.account_ids.clone(),
            // Deletion checks remote leftovers on every configured resource account.
            PlanKind::DeletePool { .. } => self
                .db
                .accounts
                .iter()
                .filter(|a| a.resources.is_some())
                .map(|a| a.id.clone())
                .collect(),
        };
        for id in &ids {
            self.require_no_worker_upgrade(id)?;
        }
        self.require_many_credentials(ids.iter().map(String::as_str))
    }
    async fn migrate_credentials(&mut self, id: &str) -> Result<(), String> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = id;
            Err("此系统不需要本机授权迁移".into())
        }
        #[cfg(target_os = "macos")]
        {
            if self.account(id)?.mac_credential_schema != 0 {
                return Err("此账户不需要本机授权迁移".into());
            }
            let account_id = id.to_owned();
            tokio::task::spawn_blocking(move || {
                #[cfg(not(test))]
                {
                    secret_store::migrate_account(&account_id)
                }
                #[cfg(test)]
                {
                    credential_migration::migrate(&MockMigration, &account_id)
                }
            })
            .await
            .map_err(|_| "更新本机授权任务未完成".to_string())?
            .map_err(|error| {
                format!("{error}；已保存的新条目和旧条目均已保留，未修改云端或恢复记录")
            })?;
            let index = self
                .db
                .accounts
                .iter()
                .position(|a| a.id == id)
                .ok_or("找不到此账号")?;
            self.db.accounts[index].mac_credential_schema = 2;
            if let Err(error) = self.persist() {
                self.db.accounts[index].mac_credential_schema = 0;
                clear_credential_cache();
                return Err(error);
            }
            self.publish_credential_routes();
            Ok(())
        }
    }

    fn domain(&self, id: &str) -> Result<&Domain, String> {
        self.db
            .domains
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| "找不到此域名".into())
    }
    fn make_plan(
        &mut self,
        title: &str,
        steps: Vec<String>,
        warnings: Vec<String>,
        kind: PlanKind,
    ) -> PlanView {
        self.plans.retain(|p| p.expires_at > Instant::now());
        let domain_takeover_confirmation = match &kind {
            PlanKind::Domain {
                host,
                prefix,
                requires_takeover_confirmation: true,
                ..
            } => Some(format!(
                "我确认接管 {host}/{prefix}/ 及其下级网页：这些路径将改由短链接处理，未创建的短链接会返回 HTTP 404，当前探测到的内容或跳转可能不再可用。"
            )),
            _ => None,
        };
        let view = PlanView {
            id: random_id(),
            title: title.into(),
            steps,
            warnings,
            expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            domain_takeover_confirmation,
            credential_migration_confirmation: matches!(&kind, PlanKind::MigrateCredentials {..})
                .then(|| "我确认更新本机授权。系统可能需要我授权访问已保存的令牌或检测密钥；已有记录会保留，云端配置和待处理恢复记录不变。".into()),
        };
        let snapshot = self.database_snapshot();
        self.plans.push(Plan {
            view: view.clone(),
            kind,
            expires_at: Instant::now() + Duration::from_secs(300),
            snapshot,
        });
        view
    }
    fn database_snapshot(&self) -> String {
        let bytes = serde_json::to_vec(&self.db).expect("serializable local state");
        hex::encode(Sha256::digest(bytes))
    }
    fn journal_start(&mut self, name: &str) -> Result<(), String> {
        self.db.pending_operations.push(name.to_string());
        self.persist()
    }
    fn journal_end(&mut self, name: &str) -> Result<(), String> {
        let before = self.db.pending_operations.clone();
        clear_journal(&mut self.db.pending_operations, name)?;
        if let Err(e) = self.persist() {
            self.db.pending_operations = before;
            return Err(e);
        }
        Ok(())
    }
    fn journal_note(&mut self, old: &str, detail: &str) -> Result<String, String> {
        let note = set_journal_note(&mut self.db.pending_operations, old, detail)?;
        self.persist()?;
        Ok(note)
    }
    fn journal_end_dns(&mut self, host: &str, current: &str) -> Result<(), String> {
        let prefix = format!("修复 DNS {host} (");
        let before = self.db.pending_operations.clone();
        self.db
            .pending_operations
            .retain(|entry| !journal_matches(entry, current) && !entry.starts_with(&prefix));
        if let Err(error) = self.persist() {
            self.db.pending_operations = before;
            return Err(error);
        }
        Ok(())
    }

    fn has_legacy_selftest_rotation(&self, account_id: &str) -> bool {
        self.db.has_legacy_selftest_rotation(account_id)
    }

    fn has_selftest_rotation(&self, account_id: &str) -> bool {
        self.db
            .pending_selftest_rotations
            .iter()
            .any(|pending| pending.account_id == account_id)
            || self.has_legacy_selftest_rotation(account_id)
    }

    /// The `key_missing` text for a domain whose self-test got no snapshot.
    fn selftest_unavailable_message(&self, domain_id: &str) -> &'static str {
        selftest_key_missing_message(
            self.domain(domain_id)
                .is_ok_and(|domain| self.has_selftest_rotation(&domain.account_id)),
        )
    }

    fn persist_rotation_mutation(
        &mut self,
        mutation: impl FnOnce(&mut Database) -> Result<(), String>,
    ) -> Result<(), String> {
        let before = self.db.clone();
        if let Err(error) = mutation(&mut self.db) {
            self.db = before;
            return Err(error);
        }
        if let Err(error) = self.persist() {
            self.db = before;
            return Err(error);
        }
        Ok(())
    }

    fn update_selftest_rotation(
        &mut self,
        account_id: &str,
        status: SelftestRotationStatus,
        note: &str,
    ) -> Result<(), String> {
        self.persist_rotation_mutation(|db| {
            let pending = db
                .pending_selftest_rotations
                .iter_mut()
                .find(|pending| pending.account_id == account_id)
                .ok_or_else(|| "自检密钥恢复记录不存在".to_string())?;
            pending.status = status;
            let journal = pending.journal.clone();
            set_journal_note(&mut db.pending_operations, &journal, note)?;
            if let Some(account) = db.accounts.iter_mut().find(|a| a.id == account_id) {
                account.needs_selftest_key = true;
            }
            Ok(())
        })
    }

    async fn import_token(
        &mut self,
        token: &str,
        replace: bool,
        expected_account_id: Option<&str>,
    ) -> Result<Value, String> {
        if !(35..=100).contains(&token.len())
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err("令牌格式不像 Cloudflare API 令牌".into());
        }
        if let Some(expected) = expected_account_id {
            if !replace {
                return Err("更新指定账号的访问令牌时必须确认替换".into());
            }
            if !valid_id(expected)
                || self
                    .db
                    .accounts
                    .iter()
                    .all(|account| account.id != expected)
            {
                return Err("找不到要更新访问令牌的账号".into());
            }
        }
        let verify = self
            .cloud
            .get(token, "user/tokens/verify")
            .await
            .map_err(problem)?;
        if verify["result"]["status"].as_str() != Some("active") {
            return Err("令牌未处于启用状态".into());
        }
        let accounts = self
            .cloud
            .list_pages(token, "accounts")
            .await
            .map_err(problem)?;
        if accounts.is_empty() {
            return Err("令牌未列出任何可用账号".into());
        }
        if let Some(expected) = expected_account_id {
            if !accounts
                .iter()
                .any(|account| account["id"].as_str() == Some(expected))
            {
                return Err("这个访问令牌不属于所选账号，请为该账号创建并粘贴新令牌".into());
            }
        }
        // A token can list several accounts. A plain import only adds the ones
        // that are not connected yet: completed accounts are skipped and keep
        // their saved token, and an account the token cannot manage is left out
        // without blocking the others. Replacing a saved token always goes
        // through the account-scoped update (`expected_account_id`).
        let mut imported = Vec::new();
        let mut skipped = Vec::new();
        let mut rejected = Vec::new();
        // With several accounts a failure must say which one it was.
        let several = expected_account_id.is_none() && accounts.len() > 1;
        for remote in accounts.into_iter().filter(|account| {
            expected_account_id.is_none_or(|expected| account["id"].as_str() == Some(expected))
        }) {
            let id = value_str(&remote, "id")?.to_owned();
            let cloudflare_name = value_str(&remote, "name")?.trim().to_owned();
            if !valid_id(&id) {
                return Err("云端账号标识无效".into());
            }
            if cloudflare_name.is_empty() || cloudflare_name.chars().count() > 256 {
                return Err("云端账号名称无效".into());
            }
            if expected_account_id.is_none() {
                if let Some(existing) = self
                    .db
                    .accounts
                    .iter()
                    .find(|a| a.id == id && !a.token_import_pending)
                {
                    skipped.push(json!({"id": id, "label": existing.label}));
                    continue;
                }
            }
            match self.check_import_access(token, &id).await {
                Ok(zones) => imported.push((id, cloudflare_name, zones)),
                Err(ImportAccessError::Denied(reason)) if expected_account_id.is_none() => {
                    rejected.push(json!({"id": id, "name": cloudflare_name, "reason": reason}));
                }
                Err(ImportAccessError::Failed(reason)) if several => {
                    return Err(format!(
                        "读取账户「{cloudflare_name}」时出错：{reason}。这次一个账户都没有导入，请稍后再导入一次"
                    ));
                }
                Err(ImportAccessError::Denied(reason) | ImportAccessError::Failed(reason)) => {
                    return Err(reason);
                }
            }
        }
        if imported.is_empty() {
            let names = |items: &[Value], key: &str| {
                items
                    .iter()
                    .filter_map(|item| item[key].as_str())
                    .map(|name| format!("「{name}」"))
                    .collect::<Vec<_>>()
                    .join("、")
            };
            let kept = if skipped.is_empty() {
                String::new()
            } else {
                format!(
                    "已导入过的账号{}保持不变，保存的令牌没有改动。",
                    names(&skipped, "label")
                )
            };
            if rejected.is_empty() {
                return Err(format!(
                    "这个令牌里的账号都已经导入过，没有新账号可导入。{kept}要给某个账号换令牌，请在账户列表打开它的“管理账户”，选择“更换本机令牌”"
                ));
            }
            let reasons = rejected
                .iter()
                .map(|item| {
                    format!(
                        "账号「{}」：{}",
                        item["name"].as_str().unwrap_or_default(),
                        item["reason"].as_str().unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("；");
            return Err(format!(
                "没有导入任何账号。{reasons}。{kept}请在 Cloudflare 补齐这个令牌的权限后重试"
            ));
        }
        let report = json!({
            "imported": imported
                .iter()
                .map(|(id, name, _)| json!({"id": id, "name": name}))
                .collect::<Vec<_>>(),
            "skipped": skipped,
            "rejected": rejected,
        });
        let before_import = self.db.clone();
        // Commit a visible, credential-gated account before any secret write.
        // A crash, denied/readback failure, or final commit failure can then be
        // recovered with a same-token retry or an explicitly scoped replacement.
        // No token or token-derived digest is stored in local configuration.
        let mut writes = Vec::new();
        for (id, cloudflare_name, zones) in imported {
            // Only the account-scoped update may overwrite a saved credential;
            // it already required `replace` and an existing local account.
            let allow_replace = replace && expected_account_id == Some(id.as_str());
            writes.push((id.clone(), allow_replace));
            if let Some(account) = self.db.accounts.iter_mut().find(|a| a.id == id) {
                account.cloudflare_name = Some(cloudflare_name);
                account.zone_count = zones.len();
                account.zones = zones;
                account.checked_at = Some(now());
                account.token_import_pending = true;
            } else {
                let label: String = cloudflare_name.chars().take(64).collect();
                self.db.accounts.push(Account {
                    id,
                    label,
                    mac_credential_schema: if cfg!(target_os = "macos") { 2 } else { 0 },
                    token_import_pending: true,
                    cloudflare_name: Some(cloudflare_name),
                    zone_count: zones.len(),
                    checked_at: Some(now()),
                    has_resources: false,
                    needs_selftest_key: false,
                    monitor_enabled: false,
                    monitor_endpoint: None,
                    needs_monitor_key: false,
                    zones,
                    resources: None,
                });
            }
        }
        if let Err(error) = self.persist() {
            self.db = before_import;
            return Err(error);
        }
        self.publish_credential_routes();
        let staged = self.db.clone();
        // Existing unknown entries still use create-only. A pending account can
        // only replace a different token through its explicit account update UI.
        for (id, allow_replace) in &writes {
            if let Err(error) = write_explicit_token(id, token, *allow_replace).await {
                return Err(format!(
                    "{error}；账号导入未完成，可重试原令牌，或在该账号中明确更新令牌"
                ));
            }
        }
        for (id, _) in writes {
            if let Some(account) = self.db.accounts.iter_mut().find(|a| a.id == id) {
                account.token_import_pending = false;
            }
        }
        if let Err(error) = self.persist() {
            self.db = staged;
            return Err(format!(
                "{error}；令牌已保存，账号仍待恢复，请重试或明确更新该账号令牌"
            ));
        }
        self.publish_credential_routes();
        let mut state = self.state();
        state["importReport"] = report;
        Ok(state)
    }

    /// Checks the read access an imported account needs and returns its zones.
    /// A refusal for this account is reported separately from a network or
    /// service failure, so one unmanageable account does not look like a
    /// missing permission on every account, and an outage is not reported as
    /// a permission problem.
    async fn check_import_access(
        &self,
        token: &str,
        id: &str,
    ) -> Result<Vec<Zone>, ImportAccessError> {
        let classify = |message: String, denied: &str| {
            if is_access_refusal(&message) {
                ImportAccessError::Denied(denied.to_string())
            } else {
                ImportAccessError::Failed(message)
            }
        };
        self.cloud
            .get(token, &format!("accounts/{id}/workers/scripts"))
            .await
            .map_err(|error| classify(problem(error), "令牌缺少 Workers 脚本读取权限"))?;
        self.cloud
            .get(token, &format!("accounts/{id}/storage/kv/namespaces"))
            .await
            .map_err(|error| classify(problem(error), "令牌缺少 Workers KV 存储权限"))?;
        let zones = self
            .fetch_zones(token, id)
            .await
            .map_err(|error| classify(error, "令牌缺少域名读取权限"))?;
        if let Some(zone) = zones.first() {
            self.cloud
                .get(token, &format!("zones/{}/workers/routes", zone.id))
                .await
                .map_err(|error| classify(problem(error), "令牌缺少 Workers 路由读取权限"))?;
        }
        Ok(zones)
    }

    async fn fetch_zones(&self, token: &str, account_id: &str) -> Result<Vec<Zone>, String> {
        let path = format!("zones?account.id={}", cloud::encode(account_id));
        self.cloud
            .list_pages(token, &path)
            .await
            .map_err(problem)?
            .into_iter()
            .map(|v| {
                Ok(Zone {
                    id: value_str(&v, "id")?.to_owned(),
                    name: value_str(&v, "name")?.to_ascii_lowercase(),
                    status: value_str(&v, "status")?.to_owned(),
                    account_id: account_id.to_owned(),
                })
            })
            .collect()
    }

    async fn refresh_accounts(&mut self, choice: Option<&str>) -> Result<Value, String> {
        if let Some(id) = choice {
            self.account(id)?;
        }
        self.require_many_credentials(
            self.db
                .accounts
                .iter()
                .filter(|a| choice.is_none_or(|id| a.id == id))
                .map(|a| a.id.as_str()),
        )?;
        let mut refreshed = self.db.accounts.clone();
        for item in refreshed
            .iter_mut()
            .filter(|item| choice.is_none_or(|id| item.id == id))
        {
            let id = item.id.clone();
            let token = read_account_token(&id)
                .await
                .map_err(|error| format!("无法刷新账户「{}」：{error}", item.label))?;
            let account = self
                .cloud
                .get(&token, &format!("accounts/{id}"))
                .await
                .map_err(|error| format!("无法刷新账户「{}」：{}", item.label, problem(error)))?;
            let cloudflare_name = value_str(&account["result"], "name")?.trim().to_owned();
            if cloudflare_name.is_empty() || cloudflare_name.chars().count() > 256 {
                return Err("云端账号名称无效".into());
            }
            let zones = self
                .fetch_zones(&token, &id)
                .await
                .map_err(|error| format!("无法刷新账户「{}」的域名：{error}", item.label))?;
            item.cloudflare_name = Some(cloudflare_name);
            item.zone_count = zones.len();
            item.zones = zones;
            item.checked_at = Some(now());
        }
        let previous = std::mem::replace(&mut self.db.accounts, refreshed);
        if let Err(error) = self.persist() {
            self.db.accounts = previous;
            return Err(error);
        }
        Ok(self.state())
    }

    async fn refresh_domains(&mut self, choice: Option<&str>) -> Result<Value, String> {
        let id = match choice {
            Some(id) => {
                self.account(id)?;
                id.to_owned()
            }
            None if self.db.accounts.len() == 1 => self.db.accounts[0].id.clone(),
            None => return Err("请选择要刷新域名的 Cloudflare 账户".into()),
        };
        self.require_credentials(&id)?;
        let label = self.account(&id)?.label.clone();
        let token = read_account_token(&id)
            .await
            .map_err(|error| format!("无法读取账户「{label}」：{error}；未刷新域名列表"))?;
        let zones = tokio::time::timeout(Duration::from_secs(60), self.fetch_zones(&token, &id))
            .await
            .map_err(|_| format!("账户「{label}」的域名读取超时，原列表已保留；请检查网络后重试"))?
            .map_err(|error| format!("无法刷新账户「{label}」的域名：{error}"))?;
        let index = self
            .db
            .accounts
            .iter()
            .position(|account| account.id == id)
            .ok_or("找不到此账号")?;
        let previous = self.db.accounts[index].clone();
        self.db.accounts[index].zone_count = zones.len();
        self.db.accounts[index].zones = zones;
        self.db.accounts[index].checked_at = Some(now());
        if let Err(error) = self.persist() {
            self.db.accounts[index] = previous;
            return Err(error);
        }
        Ok(self.state())
    }

    fn candidates(&self, host: &str) -> Vec<Candidate> {
        let mut all: Vec<_> = self
            .db
            .accounts
            .iter()
            .flat_map(|a| {
                a.zones.iter().filter_map(|z| {
                    if host == z.name || host.ends_with(&format!(".{}", z.name)) {
                        Some((
                            z.name.len(),
                            Candidate {
                                account_id: a.id.clone(),
                                label: a.label.clone(),
                                zone_id: z.id.clone(),
                                status: z.status.clone(),
                            },
                        ))
                    } else {
                        None
                    }
                })
            })
            .collect();
        let max = all.iter().map(|(n, _)| *n).max().unwrap_or(0);
        all.retain(|(n, _)| *n == max);
        all.into_iter().map(|(_, c)| c).collect()
    }

    async fn domain_candidates(
        &mut self,
        host: &str,
        choice: Option<&str>,
    ) -> Result<Vec<Candidate>, String> {
        if let Some(id) = choice {
            self.account(id)?;
        }
        let cached = self.candidates(host);
        let selected: Vec<_> = cached
            .iter()
            .filter(|candidate| choice.is_none_or(|id| candidate.account_id == id))
            .collect();
        if !selected.is_empty()
            && selected
                .iter()
                .all(|candidate| candidate.status == "active")
        {
            return Ok(cached);
        }
        // A cache miss does not prove that a newly added zone is absent. Refresh
        // accessible zones before reporting a missing domain; never widen token access.
        let lookup_choice = choice.map(str::to_owned)
            .or_else(|| (cached.len() == 1).then(|| cached[0].account_id.clone()))
            .or_else(|| (self.db.accounts.len() == 1).then(|| self.db.accounts[0].id.clone()))
            .ok_or("请先选择此域名所属的 Cloudflare 账户，再检查或刷新域名；这样只需读取一个账户的授权")?;
        let accounts: Vec<_> = self
            .db
            .accounts
            .iter()
            .filter(|account| account.id == lookup_choice)
            .map(|account| (account.id.clone(), account.label.clone()))
            .collect();
        self.require_many_credentials(accounts.iter().map(|(id, _)| id.as_str()))?;
        let mut refreshed = Vec::new();
        for (id, label) in accounts {
            let token = read_account_token(&id)
                .await
                .map_err(|error| format!("无法刷新账户「{label}」的域名：{error}"))?;
            let zones = self.fetch_zones(&token, &id).await.map_err(|error| {
                format!("无法刷新账户「{label}」的域名：{error}；可选择此域名所属账户后重试")
            })?;
            refreshed.push((id, zones));
        }
        // Commit the cache only after every selected account was read successfully.
        let previous = self.db.accounts.clone();
        for (id, zones) in refreshed {
            if let Some(account) = self.db.accounts.iter_mut().find(|account| account.id == id) {
                account.zone_count = zones.len();
                account.zones = zones;
                account.checked_at = Some(now());
            }
        }
        if let Err(error) = self.persist() {
            self.db.accounts = previous;
            return Err(error);
        }
        Ok(self.candidates(host))
    }

    /// Re-reads one account's zones after its cached zone ID answered 404 or
    /// 403 and returns the fresh candidates for `host`. Local data changes only after
    /// the read succeeded.
    async fn refresh_stale_zone(
        &mut self,
        host: &str,
        account_id: &str,
    ) -> Result<Vec<Candidate>, String> {
        let label = self.account(account_id)?.label.clone();
        let token = read_account_token(account_id)
            .await
            .map_err(|error| format!("无法刷新账户「{label}」的域名：{error}"))?;
        let zones = self
            .fetch_zones(&token, account_id)
            .await
            .map_err(|error| format!("无法刷新账户「{label}」的域名：{error}"))?;
        let previous = self.db.accounts.clone();
        if let Some(account) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            account.zone_count = zones.len();
            account.zones = zones;
            account.checked_at = Some(now());
        }
        if let Err(error) = self.persist() {
            self.db.accounts = previous;
            return Err(error);
        }
        Ok(self.candidates(host))
    }

    async fn confirmed_zone_token(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
    ) -> Result<(Zeroizing<String>, String), String> {
        self.confirmed_zone_token_detailed(account_id, zone_id, host)
            .await
            .0
    }

    /// `confirmed_zone_token`, plus why it failed when that matters for the
    /// check shown: see `ZoneReadFailure`.
    async fn confirmed_zone_token_detailed(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
    ) -> (Result<(Zeroizing<String>, String), String>, ZoneReadFailure) {
        let mut failure = ZoneReadFailure::default();
        let result = self
            .confirmed_zone_token_inner(account_id, zone_id, host, &mut failure)
            .await;
        (result, failure)
    }

    async fn confirmed_zone_token_inner(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        failure: &mut ZoneReadFailure,
    ) -> Result<(Zeroizing<String>, String), String> {
        if let Err(error) = self.require_credentials(account_id) {
            failure.credential = Some("本机授权");
            return Err(error);
        }
        let account = self.account(account_id)?;
        let zone = account
            .zones
            .iter()
            .find(|zone| {
                zone.id == zone_id
                    && zone.status == "active"
                    && (host == zone.name || host.ends_with(&format!(".{}", zone.name)))
            })
            .ok_or("域名所属区域未启用，或不属于此账号")?;
        let token = match read_account_token(account_id).await {
            Ok(token) => token,
            Err(error) => {
                failure.credential = Some("凭据");
                return Err(error);
            }
        };
        let remote = self
            .cloud
            .get(&token, &format!("zones/{zone_id}"))
            .await
            .map_err(|error| {
                if answered_not_found(&error) {
                    ZONE_ID_STALE.to_string()
                } else {
                    failure.forbidden = answered_forbidden(&error);
                    failure.refused = answered_refused(&error);
                    problem(error)
                }
            })?;
        if remote["result"]["status"] != "active"
            || remote["result"]["id"].as_str() != Some(zone_id)
            || remote["result"]["account"]["id"].as_str() != Some(account_id)
        {
            return Err("无法确认域名所属区域已启用且归属此账号".into());
        }
        Ok((token, zone.name.clone()))
    }

    async fn exact_dns_records(
        &self,
        token: &str,
        zone_id: &str,
        host: &str,
    ) -> Result<Vec<domain_check::DnsRecordFingerprint>, (String, bool)> {
        // The flag is true when Cloudflare answered the read with 401 or 403.
        let path = format!("zones/{zone_id}/dns_records?name={}", cloud::encode(host));
        let items = self.cloud.list_pages(token, &path).await.map_err(|error| {
            let refused = answered_refused(&error);
            (problem(error), refused)
        })?;
        domain_check::dns_fingerprint(&items, host).map_err(|message| (message, false))
    }

    async fn placeholder_is_safe(
        &self,
        token: &str,
        zone_id: &str,
        zone_name: &str,
        host: &str,
        expected: &[domain_check::DnsRecordFingerprint],
    ) -> Result<(), (String, bool)> {
        // The flag is true when Cloudflare answered the read with 401 or 403.
        let all = self.full_dns_records(token, zone_id).await?;
        let observed = domain_check::dns_fingerprint(&all, host).map_err(|message| {
            (
                format!("完整 DNS 清单格式无效：{message}；请重新检查"),
                false,
            )
        })?;
        if observed != expected {
            return Err(("DNS 记录已变化，请重新检查并生成新计划".into(), false));
        }
        if let Some(message) = domain_check::placeholder_conflict(&all, host, zone_name) {
            return Err((message, false));
        }
        Ok(())
    }

    /// Every DNS record of the zone, for the safety checks before a DNS fix.
    /// The flag is true when Cloudflare answered the read with 401 or 403.
    async fn full_dns_records(
        &self,
        token: &str,
        zone_id: &str,
    ) -> Result<Vec<Value>, (String, bool)> {
        self.cloud
            .list_pages(token, &format!("zones/{zone_id}/dns_records"))
            .await
            .map_err(|error| {
                let refused = answered_refused(&error);
                (problem(error), refused)
            })
    }

    async fn proxy_is_safe(
        &self,
        token: &str,
        zone_id: &str,
        zone_name: &str,
        host: &str,
        expected: &[domain_check::DnsRecordFingerprint],
    ) -> Result<(), (String, bool)> {
        // The flag is true when Cloudflare answered the read with 401 or 403.
        let all = self.full_dns_records(token, zone_id).await?;
        let observed =
            domain_check::dns_fingerprint(&all, host).map_err(|message| (message, false))?;
        if observed != expected {
            return Err(("DNS 记录已变化，请重新检查并生成新计划".into(), false));
        }
        if let Some(message) = domain_check::proxy_conflict(&all, host, zone_name) {
            return Err((message, false));
        }
        Ok(())
    }

    async fn prepare_domain_dns(&mut self, payload: &Value) -> Result<Value, String> {
        let host = normalize_host(field(payload, "input")?)?;
        let choice = payload["accountId"].as_str();
        let mut candidates = self.domain_candidates(&host, choice).await?;
        let selected = if candidates.len() == 1 && choice.is_none() {
            candidates.first()
        } else {
            choice.and_then(|id| {
                candidates
                    .iter()
                    .find(|candidate| candidate.account_id == id)
            })
        };
        let mut refreshed = None;
        let mut checks = Vec::new();
        let mut dns_status = "conflict".to_string();
        let mut actions = Vec::new();
        let mut plan = None;
        if candidates.is_empty() {
            checks.push(domain_check::hard_check(
                "域名归属",
                false,
                "已从 Cloudflare 刷新，但当前令牌可见的域名中仍未找到它。请确认所属账户、域名已添加到 Cloudflare，以及令牌允许访问这个新域名",
            ));
        } else if selected.is_none() {
            checks.push(domain_check::hard_check(
                "账号选择",
                false,
                account_choice_message(choice, &candidates),
            ));
        } else if let Some(candidate) = selected {
            let mut candidate = candidate.clone();
            let (mut confirmed, mut failure) = self
                .confirmed_zone_token_detailed(&candidate.account_id, &candidate.zone_id, &host)
                .await;
            // A 403 may be a stale ID too; if the refresh does not show a new
            // ID or a missing domain, the original 403 error is shown.
            let refusal = if failure.forbidden {
                confirmed.as_ref().err().cloned()
            } else {
                None
            };
            if refusal.is_some() || confirmed.as_ref().err().is_some_and(|m| m == ZONE_ID_STALE) {
                // The cached zone ID may be gone: refresh this account once
                // and match the domain again.
                confirmed = match self.refresh_stale_zone(&host, &candidate.account_id).await {
                    // The original 403 stays, with its reason.
                    Err(error) => Err(refusal.unwrap_or(error)),
                    Ok(fresh) => {
                        let listed = fresh
                            .iter()
                            .find(|c| c.account_id == candidate.account_id)
                            .cloned();
                        let next = listed
                            .as_ref()
                            .filter(|c| c.zone_id != candidate.zone_id)
                            .cloned();
                        refreshed = Some(fresh);
                        match (next, refusal) {
                            (Some(next), _) => {
                                candidate = next;
                                let (result, again) = self
                                    .confirmed_zone_token_detailed(
                                        &candidate.account_id,
                                        &candidate.zone_id,
                                        &host,
                                    )
                                    .await;
                                failure = again;
                                result
                            }
                            (None, Some(refusal)) if listed.is_some() => Err(refusal),
                            (None, _) => {
                                failure = ZoneReadFailure::default();
                                Err(ZONE_CACHE_STALE_MESSAGE.into())
                            }
                        }
                    }
                };
                if confirmed.as_ref().err().is_some_and(|m| m == ZONE_ID_STALE) {
                    confirmed = Err(ZONE_CACHE_STALE_MESSAGE.into());
                }
            }
            match confirmed {
                Err(message) => match failure.credential {
                    Some(label) => checks.push(credential_check(label, message)),
                    None => {
                        let mut check = domain_check::hard_check("云端域名归属", false, message);
                        if failure.refused {
                            check.reason = Some(CLOUD_REFUSED.into());
                        }
                        checks.push(check);
                    }
                },
                Ok((token, zone_name)) => {
                    checks.push(domain_check::hard_check(
                        "云端域名归属",
                        true,
                        "云端确认域名所属区域已启用",
                    ));
                    match self
                        .exact_dns_records(&token, &candidate.zone_id, &host)
                        .await
                    {
                        Err((message, refused)) => {
                            dns_status = "readFailed".into();
                            let mut check = domain_check::hard_check(
                                "DNS",
                                false,
                                format!("无法读取 DNS 记录：{message}"),
                            );
                            if refused {
                                check.reason = Some(CLOUD_REFUSED.into());
                            }
                            checks.push(check);
                        }
                        Ok(records) => match domain_check::assess_dns(&records) {
                            domain_check::DnsAssessment::Ready => {
                                // A prior request may have succeeded despite a lost response.
                                // Current ownership and DNS were just read from the provider;
                                // resolve only this host's local note, without another write.
                                let prefix = format!("修复 DNS {host} (");
                                if self
                                    .db
                                    .pending_operations
                                    .iter()
                                    .any(|entry| entry.starts_with(&prefix))
                                {
                                    self.journal_end_dns(&host, "")?;
                                }
                                dns_status = "ready".into();
                                checks.push(domain_check::hard_check(
                                    "DNS",
                                    true,
                                    "该主机名的地址记录均已通过 Cloudflare 代理，无需修复",
                                ));
                            }
                            domain_check::DnsAssessment::Missing => {
                                match self
                                    .placeholder_is_safe(
                                        &token,
                                        &candidate.zone_id,
                                        &zone_name,
                                        &host,
                                        &records,
                                    )
                                    .await
                                {
                                    Ok(()) => {
                                        dns_status = "missing".into();
                                        checks.push(DomainCheck {
                                            reason: None,
                                            label: "DNS".into(),
                                            ok: true,
                                            message: "这个域名还没有用于打开网址的解析，可以补齐；现有邮件及验证设置会保留".into(),
                                            level: DomainCheckLevel::Warning,
                                        });
                                        actions.push(DnsActionView {
                                            kind: "createPlaceholder".into(),
                                            record_type: "AAAA".into(),
                                            name: host.clone(),
                                        });
                                        plan = Some(self.make_plan(
                                            "补齐网站解析",
                                            vec![format!(
                                                "仅在 {host} 仍无 A、AAAA 或 CNAME 地址记录、现有非网站记录未变化且无通配符或 NS 子域委派时，创建 AAAA 记录 100:: 并开启 Cloudflare 代理"
                                            )],
                                            vec![format!(
                                                "此操作会让 {host} 整个主机名的 HTTP/HTTPS 流量进入 Cloudflare；不会修改其他主机名、邮件记录或已有记录，完成后仍需单独添加短链接目录"
                                            )],
                                            PlanKind::DomainDns {
                                                account_id: candidate.account_id.clone(),
                                                zone_id: candidate.zone_id.clone(),
                                                host: host.clone(),
                                                snapshot: domain_check::DnsSnapshot::Missing(records),
                                            },
                                        ));
                                    }
                                    Err((message, refused)) => {
                                        dns_status = "conflict".into();
                                        let mut check =
                                            domain_check::hard_check("DNS", false, message);
                                        if refused {
                                            check.reason = Some(CLOUD_REFUSED.into());
                                        }
                                        checks.push(check);
                                    }
                                }
                            }
                            domain_check::DnsAssessment::DnsOnly(pending) => {
                                match self
                                    .proxy_is_safe(
                                        &token,
                                        &candidate.zone_id,
                                        &zone_name,
                                        &host,
                                        &records,
                                    )
                                    .await
                                {
                                    Err((message, refused)) => {
                                        dns_status = "conflict".into();
                                        let mut check =
                                            domain_check::hard_check("DNS", false, message);
                                        if refused {
                                            check.reason = Some(CLOUD_REFUSED.into());
                                        }
                                        checks.push(check);
                                    }
                                    Ok(()) => {
                                        dns_status = "dnsOnly".into();
                                        checks.push(DomainCheck {
                                            reason: None,
                                            label: "DNS".into(),
                                            ok: true,
                                            message: format!(
                                        "该主机名有 {} 条可代理地址记录尚未开启 Cloudflare 代理",
                                        pending.len()
                                    ),
                                            level: DomainCheckLevel::Warning,
                                        });
                                        actions.extend(pending.iter().map(|record| {
                                            DnsActionView {
                                                kind: "enableProxy".into(),
                                                record_type: record.record_type.clone(),
                                                name: host.clone(),
                                            }
                                        }));
                                        let steps = pending
                                    .iter()
                                    .map(|record| {
                                        format!(
                                            "仅为 {host} 的 {} 记录开启 Cloudflare 代理，保留现有记录内容",
                                            record.record_type
                                        )
                                    })
                                    .collect();
                                        plan = Some(self.make_plan(
                                    "开启现有 DNS 记录代理",
                                    steps,
                                    vec![format!(
                                        "此操作会让 {host} 整个主机名的 HTTP/HTTPS 流量进入 Cloudflare；不会更改记录内容、邮件记录或其他主机名，完成后仍需单独添加短链接目录"
                                    )],
                                    PlanKind::DomainDns {
                                        account_id: candidate.account_id.clone(),
                                        zone_id: candidate.zone_id.clone(),
                                        host: host.clone(),
                                        snapshot: domain_check::DnsSnapshot::EnableProxy(records),
                                    },
                                ));
                                    }
                                }
                            }
                            domain_check::DnsAssessment::Unsupported(message) => {
                                dns_status = "unsupported".into();
                                checks.push(domain_check::hard_check("DNS", false, message));
                            }
                            domain_check::DnsAssessment::Conflict(message) => {
                                dns_status = "conflict".into();
                                checks.push(domain_check::hard_check("DNS", false, message));
                            }
                        },
                    }
                }
            }
        }
        if let Some(fresh) = refreshed {
            candidates = fresh;
        }
        Ok(serde_json::to_value(DomainDnsPreparation {
            host,
            candidates,
            checks,
            dns_status,
            actions,
            can_apply: plan.is_some(),
            plan,
        })
        .unwrap_or(Value::Null))
    }

    async fn preflight(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        prefix: &str,
        planned_probe_segment: Option<&str>,
        dns_mode: local_check::DnsMode,
    ) -> (Vec<DomainCheck>, Option<PathRiskSnapshot>) {
        let mut refused = false;
        self.preflight_inner(
            account_id,
            zone_id,
            host,
            prefix,
            planned_probe_segment,
            dns_mode,
            &mut refused,
        )
        .await
    }

    /// `preflight`, plus whether the `zones/{zone_id}` read was answered with
    /// HTTP 403 (its check keeps the original wording and reason then).
    async fn preflight_detailed(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        prefix: &str,
        dns_mode: local_check::DnsMode,
    ) -> (Vec<DomainCheck>, Option<PathRiskSnapshot>, bool) {
        let mut refused = false;
        let (checks, risk) = self
            .preflight_inner(
                account_id,
                zone_id,
                host,
                prefix,
                None,
                dns_mode,
                &mut refused,
            )
            .await;
        (checks, risk, refused)
    }

    #[allow(clippy::too_many_arguments)]
    async fn preflight_inner(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        prefix: &str,
        planned_probe_segment: Option<&str>,
        dns_mode: local_check::DnsMode,
        refused: &mut bool,
    ) -> (Vec<DomainCheck>, Option<PathRiskSnapshot>) {
        let mut checks = Vec::new();
        if let Err(error) = self.require_credentials(account_id) {
            checks.push(credential_check("本机授权", error));
            return (checks, None);
        }
        let account = match self.account(account_id) {
            Ok(v) => v,
            Err(e) => {
                checks.push(domain_check::hard_check("账号", false, e));
                return (checks, None);
            }
        };
        let zone = account.zones.iter().find(|z| {
            z.id == zone_id && (host == z.name || host.ends_with(&format!(".{}", z.name)))
        });
        let active = zone.is_some_and(|z| z.status == "active");
        checks.push(domain_check::hard_check(
            "域名归属状态",
            active,
            match zone {
                _ if active => "域名所属区域已启用".to_string(),
                Some(zone) => format!(
                    "这个域名在 Cloudflare 还没生效（当前状态：{}）。请先到 Cloudflare 按提示把域名服务器改好，生效后再来添加",
                    zone.status
                ),
                None => "域名所属区域未启用，或不属于此账号".to_string(),
            },
        ));
        if !active {
            return (checks, None);
        }
        let token = match read_account_token(account_id).await {
            Ok(t) => t,
            Err(e) => {
                checks.push(credential_check("凭据", e));
                return (checks, None);
            }
        };
        // The three reads are independent; send them together. Results are
        // still shown in order and a failed earlier step hides later ones.
        let zone_path = format!("zones/{zone_id}");
        let dns_path = format!("zones/{zone_id}/dns_records?name={}", cloud::encode(host));
        let routes_path = format!("zones/{zone_id}/workers/routes");
        let (remote_zone, dns, routes) = tokio::join!(
            self.cloud.get(&token, &zone_path),
            self.cloud.list_pages(&token, &dns_path),
            self.cloud.get(&token, &routes_path),
        );
        let remote_zone = match remote_zone {
            Ok(value) => value,
            Err(error) if answered_not_found(&error) => {
                checks.push(stale_zone_check());
                return (checks, None);
            }
            Err(error) => {
                *refused = answered_forbidden(&error);
                checks.push(cloud_read_failure("云端域名归属", "", error));
                return (checks, None);
            }
        };
        let remote_active = remote_zone["result"]["status"] == "active"
            && remote_zone["result"]["id"].as_str() == Some(zone_id)
            && remote_zone["result"]["account"]["id"].as_str() == Some(account_id);
        checks.push(domain_check::hard_check(
            "云端域名归属",
            remote_active,
            if remote_active {
                "云端确认域名所属区域已启用"
            } else {
                "无法确认域名所属区域已启用且归属此账号"
            },
        ));
        if !remote_active {
            return (checks, None);
        }
        let dns_check = match dns {
            Err(error) => cloud_read_failure("DNS", "无法读取 DNS 记录：", error),
            Ok(items) => {
                let (ok, message) = match domain_check::classify_dns_records(&items, host) {
                Ok(domain_check::DnsClassification::Ready) => (true, "DNS 已代理".into()),
                Ok(domain_check::DnsClassification::Missing) => (
                    false,
                    "这个域名还没有用于打开网址的解析，可以先检查 DNS 并补齐；现有邮件及验证设置会保留".into(),
                ),
                Ok(domain_check::DnsClassification::NeedsProxy) => (
                    false,
                    "该主机名有地址记录尚未开启 Cloudflare 代理；可先准备 DNS 修复计划"
                        .into(),
                ),
                Ok(domain_check::DnsClassification::Unsupported(message))
                | Ok(domain_check::DnsClassification::Conflict(message)) => (false, message),
                Err(message) => (false, format!("DNS 记录格式无效：{message}")),
                };
                domain_check::hard_check("DNS", ok, message)
            }
        };
        checks.push(dns_check);
        let routes_check = match routes {
            Err(error) => cloud_read_failure("转发规则", "无法读取云端转发规则：", error),
            Ok(v) => {
                let Some(arr) = v["result"].as_array() else {
                    checks.push(domain_check::hard_check(
                        "转发规则",
                        false,
                        "云端转发规则列表格式无效",
                    ));
                    return (checks, None);
                };
                let overlapping: Vec<&Value> = arr
                    .iter()
                    .filter(|r| {
                        r["pattern"]
                            .as_str()
                            .is_some_and(|p| route_conflict(p, host, prefix))
                    })
                    .collect();
                // The exact route this tool would create for this account is
                // what an unfinished earlier attempt leaves behind. Anything
                // else overlapping stays a conflict.
                let own_script = account.resources.as_ref().map(|r| r.script.as_str());
                let pattern = route_pattern(host, prefix);
                let leftover = overlapping.len() == 1
                    && own_script.is_some()
                    && overlapping[0]["script"].as_str() == own_script
                    && overlapping[0]["pattern"].as_str() == Some(pattern.as_str());
                // This tool's route for exactly this host under another
                // directory: what an interrupted removal leaves behind. A
                // second route for the host would break recovery for good.
                let stray = own_script.and_then(|script| {
                    own_route_under_other_directory(arr, script, host, prefix).map(str::to_owned)
                });
                if overlapping.is_empty() && stray.is_none() {
                    domain_check::hard_check("转发规则", true, "没有发现重叠的转发规则")
                } else if !overlapping.is_empty() && !leftover {
                    domain_check::hard_check("转发规则", false, "现有转发规则与此前缀重叠")
                } else if let Some(stray) = stray {
                    let namespace = account
                        .resources
                        .as_ref()
                        .map(|r| r.namespace.clone())
                        .unwrap_or_default();
                    match self
                        .cloud
                        .read_value(&token, account_id, &namespace, &format!("c:{host}"))
                        .await
                    {
                        Err(error) => {
                            cloud_read_failure("转发规则", "无法读取云端前缀配置：", error)
                        }
                        Ok(Some(_)) => {
                            domain_check::hard_check("转发规则", false, NEEDS_RECOVERY_MESSAGE)
                        }
                        Ok(None) => domain_check::hard_check(
                            "转发规则",
                            false,
                            stray_route_message(host, &stray),
                        ),
                    }
                } else {
                    let namespace = account
                        .resources
                        .as_ref()
                        .map(|r| r.namespace.clone())
                        .unwrap_or_default();
                    match self
                        .cloud
                        .read_value(&token, account_id, &namespace, &format!("c:{host}"))
                        .await
                    {
                        Err(error) => {
                            cloud_read_failure("转发规则", "无法读取云端前缀配置：", error)
                        }
                        Ok(Some(_)) => {
                            domain_check::hard_check("转发规则", false, NEEDS_RECOVERY_MESSAGE)
                        }
                        Ok(None) => domain_check::hard_check(
                            "转发规则",
                            true,
                            "发现本工具上次没做完留下的转发规则，接入时会直接沿用",
                        ),
                    }
                }
            }
        };
        checks.push(routes_check);
        if checks
            .iter()
            .any(|check| check.level == DomainCheckLevel::Error)
        {
            return (checks, None);
        }
        let probe_segment = planned_probe_segment
            .map(str::to_owned)
            .unwrap_or_else(|| random_name("probe"));
        let root_url = format!("https://{host}/{prefix}/");
        let child_url = format!("https://{host}/{prefix}/{probe_segment}");
        let (root_result, child_result) = tokio::join!(
            self.cloud.probe_with_mode(&root_url, None, dns_mode),
            self.cloud.probe_with_mode(&child_url, None, dns_mode)
        );
        let (root_check, root) =
            domain_check::classify_probe_detailed("短链接目录", &root_url, None, root_result);
        let (child_check, child) = domain_check::classify_probe_detailed(
            "随机测试链接",
            &child_url,
            Some(&probe_segment),
            child_result,
        );
        checks.push(root_check);
        checks.push(child_check);
        (
            checks,
            Some(PathRiskSnapshot {
                root,
                child,
                probe_segment,
            }),
        )
    }

    async fn prepare_domain(&mut self, payload: &Value) -> Result<Value, String> {
        let dns_mode = requested_dns_mode(payload)?;
        let host = normalize_host(field(payload, "input")?)?;
        let prefix = payload["prefix"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                let suggestions = ["go", "out", "to", "visit", "link", "r", "jump"];
                suggestions[rand::thread_rng().gen_range(0..suggestions.len())].to_string()
            });
        validate_prefix(&prefix)?;
        if self.db.domains.iter().any(|domain| domain.host == host) {
            return Ok(serde_json::to_value(DomainPreparation {
                host,
                prefix,
                dns_mode: dns_mode.as_str().into(),
                candidates: Vec::new(),
                checks: vec![domain_check::hard_check(
                    "本机配置",
                    false,
                    "这个主机名已经添加；请查看已有域名或直接创建短链接",
                )],
                can_apply: false,
                plan: None,
            })
            .unwrap_or(Value::Null));
        }
        let choice = payload["accountId"].as_str();
        let mut candidates = self.domain_candidates(&host, choice).await?;
        let selected = if candidates.len() == 1 && choice.is_none() {
            candidates.first()
        } else {
            choice.and_then(|id| candidates.iter().find(|c| c.account_id == id))
        };
        let mut refreshed = None;
        let mut checks = Vec::new();
        let mut plan = None;
        if candidates.is_empty() {
            checks.push(domain_check::hard_check(
                "域名归属",
                false,
                "已从 Cloudflare 刷新，但当前令牌可见的域名中仍未找到它。请确认所属账户、域名已添加到 Cloudflare，以及令牌允许访问这个新域名",
            ));
        } else if selected.is_none() {
            checks.push(domain_check::hard_check(
                "账号选择",
                false,
                account_choice_message(choice, &candidates),
            ));
        } else if let Some(c) = selected {
            let mut c = c.clone();
            let (mut next_checks, mut path_risk, refused) = self
                .preflight_detailed(&c.account_id, &c.zone_id, &host, &prefix, dns_mode)
                .await;
            if refused || has_reason(&next_checks, ZONE_CACHE_STALE) {
                // The cached zone ID may be gone: refresh this account once
                // and match the domain again. After a 403 the original checks
                // stay unless the refresh shows a new ID or a missing domain.
                match self.refresh_stale_zone(&host, &c.account_id).await {
                    Err(error) => {
                        if !refused {
                            next_checks =
                                vec![domain_check::hard_check("云端域名归属", false, error)];
                        }
                    }
                    Ok(fresh) => {
                        let listed = fresh.iter().find(|f| f.account_id == c.account_id).cloned();
                        let next = listed.as_ref().filter(|f| f.zone_id != c.zone_id).cloned();
                        refreshed = Some(fresh);
                        if let Some(next) = next {
                            c = next;
                            (next_checks, path_risk, _) = self
                                .preflight_detailed(
                                    &c.account_id,
                                    &c.zone_id,
                                    &host,
                                    &prefix,
                                    dns_mode,
                                )
                                .await;
                        } else if refused && listed.is_none() {
                            next_checks.retain(|check| check.label != "云端域名归属");
                            next_checks.push(stale_zone_check());
                        }
                    }
                }
                for check in next_checks
                    .iter_mut()
                    .filter(|check| check.reason.as_deref() == Some(ZONE_CACHE_STALE))
                {
                    check.message = ZONE_CACHE_STALE_MESSAGE.into();
                }
            }
            checks = next_checks;
            if !checks
                .iter()
                .any(|check| check.level == DomainCheckLevel::Error)
            {
                let path_risk = path_risk.ok_or("路径预检结果不完整")?;
                let requires_takeover_confirmation = path_risk.requires_takeover_confirmation();
                let has_resources = self.account(&c.account_id)?.resources.is_some();
                let mut steps = Vec::new();
                if !has_resources {
                    steps.push("创建此账号专用的云端转发程序和链接存储，并设置自检密钥".into());
                }
                steps.push(format!(
                    "将 {host}/{prefix}/ 目录根及其所有下级网页交由短链接处理；未创建的短链接返回 HTTP 404"
                ));
                steps.push(format!("写入 {host} 的前缀配置"));
                steps.push(format!(
                    "仅为 {} 添加转发规则",
                    route_pattern(&host, &prefix)
                ));
                let mut warnings = vec!["边缘配置传播可能需要一段时间".into()];
                if dns_mode == local_check::DnsMode::Public {
                    steps.push("使用公共 DNS 检查目录；确认后仍按此方式重新核对，不更改本机 DNS 或 VPN 设置".into());
                }
                if requires_takeover_confirmation {
                    warnings.push(
                        "路径预检只说明当前 HTTP 响应；接入只创建指定目录的 Worker 路由，不修改 DNS、重定向规则或访问策略，也不保证绕过先于 Worker 执行的 Cloudflare 规则。配置提交后，请创建短链接并使用现有签名自检验证最终跳转。".into(),
                    );
                }
                plan = Some(self.make_plan(
                    "添加域名",
                    steps,
                    warnings,
                    PlanKind::Domain {
                        account_id: c.account_id.clone(),
                        zone_id: c.zone_id.clone(),
                        host: host.clone(),
                        prefix: prefix.clone(),
                        path_risk,
                        dns_mode,
                        requires_takeover_confirmation,
                    },
                ));
            }
        }
        if let Some(fresh) = refreshed {
            candidates = fresh;
        }
        Ok(serde_json::to_value(DomainPreparation {
            host,
            prefix,
            dns_mode: dns_mode.as_str().into(),
            candidates,
            checks,
            can_apply: plan.is_some(),
            plan,
        })
        .unwrap_or(Value::Null))
    }

    fn token_template() -> String {
        let permissions = json!([
            {"key":"workers_scripts","type":"edit"},
            {"key":"workers_kv_storage","type":"edit"},
            {"key":"workers_routes","type":"edit"},
            {"key":"zone","type":"read"},
            {"key":"dns","type":"edit"},
            {"key":"account_settings","type":"read"},
            {"key":"account_analytics","type":"read"}
        ]);
        format!(
            "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys={}&accountId=*&zoneId=all&name={}",
            cloud::encode(&permissions.to_string()),
            cloud::encode(&format!("短连接生成器 {}", Utc::now().format("%Y-%m-%d")))
        )
    }

    fn prepare_change(&mut self, payload: &Value) -> Result<Value, String> {
        let kind = field(payload, "kind")?;
        let (title, steps, warnings, plan_kind) = match kind {
            "migrate_credentials" => {
                if !cfg!(target_os = "macos") {
                    return Err("此系统不需要本机授权迁移".into());
                }
                let id = field(payload, "accountId")?.to_owned();
                let account = self.account(&id)?;
                if account.mac_credential_schema != 0 {
                    return Err("此账户不需要本机授权迁移".into());
                }
                (
                    "更新本机授权",
                    vec![
                        "仅复制本机凭据，并直接从系统凭据库读回核对".into(),
                        "完成后请自行重试原操作；不会自动执行云端操作".into(),
                    ],
                    vec![
                        "系统可能逐项请求授权；应用不会索要系统密码".into(),
                        "旧版凭据保留；后续在新版改密后请继续使用新版".into(),
                    ],
                    PlanKind::MigrateCredentials { account_id: id },
                )
            }
            "save_link" => {
                let create_only = match payload.get("createOnly") {
                    None => false,
                    Some(Value::Bool(value)) => *value,
                    Some(_) => return Err("createOnly 必须为布尔值".into()),
                };
                let domain_id = field(payload, "domainId")?.to_owned();
                let domain = self.domain(&domain_id)?;
                let (slug, existing) =
                    self.resolve_link_name(&domain_id, field(payload, "slug")?, create_only)?;
                let (cn_url, default_url, pool_id, code) = if let Some(pool_id) =
                    payload["poolId"].as_str().filter(|s| !s.is_empty())
                {
                    let code = field(payload, "code")?;
                    if !pools::valid_code(code) {
                        return Err("邀请码无效".into());
                    }
                    let pool = self
                        .db
                        .pools
                        .iter()
                        .find(|p| p.id == pool_id)
                        .ok_or("找不到此平台地址")?;
                    if self
                        .db
                        .pending_pool_changes
                        .iter()
                        .any(|p| p.pool.id == pool_id)
                    {
                        return Err("这组平台地址有未完成的更新，请先继续处理后再创建链接".into());
                    }
                    if self
                        .db
                        .pending_monitor_changes
                        .iter()
                        .any(|p| p.account_id == domain.account_id)
                    {
                        return Err("此域名账户的检测设置尚未完成，请先继续处理".into());
                    }
                    let candidate = pool
                        .candidates
                        .iter()
                        .find(|c| c.enabled)
                        .ok_or("这组平台地址没有已启用的大陆备用地址")?;
                    (
                        pools::compose(&model::Template::from(candidate), code)?,
                        pools::compose(&pool.official, code)?,
                        Some(pool_id.to_owned()),
                        Some(code.to_owned()),
                    )
                } else {
                    (
                        canonical_target(field(payload, "cnUrl")?)?,
                        canonical_target(field(payload, "defaultUrl")?)?,
                        None,
                        None,
                    )
                };
                (
                    if create_only {
                        "另存为新链接"
                    } else {
                        "保存链接"
                    },
                    vec![if let (Some(pool_id), Some(code)) = (&pool_id, &code) {
                        let pool_name = self
                            .db
                            .pools
                            .iter()
                            .find(|pool| pool.id == *pool_id)
                            .map(|pool| pool.name.as_str())
                            .unwrap_or(pool_id);
                        format!(
                            "为 {} 的短码 {} 保存平台地址“{}”和邀请码 {}；自动将所需平台配置同步到此域名所属账户",
                            domain.host, slug, pool_name, code
                        )
                    } else {
                        format!("为 {} 的短码 {} 保存大陆与默认跳转地址", domain.host, slug)
                    }],
                    if create_only {
                        vec!["已有链接保持不变，新名称会生成另一条短链接".into()]
                    } else if existing {
                        vec!["这会覆盖现有链接目标".into()]
                    } else {
                        vec![]
                    },
                    PlanKind::SaveLink {
                        domain_id,
                        slug,
                        create_only,
                        exact_edit: existing,
                        cn_url,
                        default_url,
                        pool_id,
                        code,
                    },
                )
            }
            "upgrade_worker"
            | "resume_worker_upgrade"
            | "dismiss_worker_upgrade"
            | "enable_click_stats"
            | "enable_click_protection"
            | "disable_click_protection"
            | "disable_click_stats" => {
                return self.prepare_worker_upgrade(kind, field(payload, "accountId")?);
            }
            "save_pool" => {
                let mut pool: Pool = serde_json::from_value(payload["pool"].clone())
                    .map_err(|_| "平台地址数据格式无效".to_string())?;
                if pool.id.is_empty() {
                    pool.id = random_id();
                }
                // The platform library is global. Account IDs are deployment
                // receipts maintained here, never an authorization list supplied
                // by the form. Preserve every prior deployment and live reference.
                pool.account_ids = self
                    .db
                    .pools
                    .iter()
                    .find(|p| p.id == pool.id)
                    .map(|p| p.account_ids.clone())
                    .unwrap_or_default();
                for link in self
                    .db
                    .links
                    .iter()
                    .filter(|l| l.pool_id.as_deref() == Some(pool.id.as_str()))
                {
                    let account_id = self.domain(&link.domain_id)?.account_id.clone();
                    if !pool.account_ids.contains(&account_id) {
                        pool.account_ids.push(account_id);
                    }
                }
                if self
                    .db
                    .pending_pool_changes
                    .iter()
                    .any(|p| p.pool.id == pool.id)
                {
                    return Err("此平台地址有未完成同步，请先恢复该操作".into());
                }
                if self.db.pending_monitor_changes.iter().any(|m| {
                    pool.account_ids.contains(&m.account_id)
                        || self
                            .db
                            .pools
                            .iter()
                            .find(|p| p.id == pool.id)
                            .is_some_and(|old| old.account_ids.contains(&m.account_id))
                }) {
                    return Err("相关账号的监测配置尚未完成，请先恢复".into());
                }
                pool.updated = now();
                pool.sync_status.clear();
                pools::validate_pool(&pool)?;
                for id in &pool.account_ids {
                    self.account(id)?;
                }
                let refs = self
                    .db
                    .links
                    .iter()
                    .filter(|l| l.pool_id.as_deref() == Some(&pool.id))
                    .count();
                let accounts = pool.account_ids.len();
                (
                    "保存平台地址",
                    vec![format!(
                        "保存全局平台地址“{}”，所有账户和域名均可选用；更新已使用的 {accounts} 个账户，现有 {refs} 条链接会使用新地址",
                        pool.name
                    )],
                    if refs > 0 {
                        vec!["变更将影响全部使用这组平台地址的链接".into()]
                    } else {
                        vec![]
                    },
                    PlanKind::SavePool { pool },
                )
            }
            "resume_pool_sync" => {
                let pool_id = field(payload, "poolId")?;
                let pending = self
                    .db
                    .pending_pool_changes
                    .iter()
                    .find(|p| p.pool.id == pool_id && !p.deleting)
                    .ok_or("此平台地址没有未完成同步")?;
                (
                    "恢复平台地址同步",
                    vec![format!(
                        "继续核对并同步 {} 个账号",
                        pending.pool.account_ids.len()
                    )],
                    vec!["仅覆盖先前确认版本或同一次操作的目标版本".into()],
                    PlanKind::SavePool {
                        pool: pending.pool.clone(),
                    },
                )
            }
            "delete_pool" => {
                let pool_id = field(payload, "poolId")?.to_owned();
                let pool = self
                    .db
                    .pools
                    .iter()
                    .find(|p| p.id == pool_id)
                    .ok_or("找不到此平台地址")?;
                if self
                    .db
                    .pending_monitor_changes
                    .iter()
                    .any(|m| pool.account_ids.contains(&m.account_id))
                {
                    return Err("相关账号的监测配置尚未完成，请先恢复".into());
                }
                if self
                    .db
                    .pending_pool_changes
                    .iter()
                    .any(|p| p.pool.id == pool_id && !p.deleting)
                {
                    return Err("平台地址同步尚未完成，不能删除".into());
                }
                if self
                    .db
                    .links
                    .iter()
                    .any(|l| l.pool_id.as_deref() == Some(&pool_id))
                {
                    return Err("仍有链接引用此平台地址".into());
                }
                (
                    "删除平台地址",
                    vec![format!(
                        "从 {} 个账号删除平台地址“{}”的云端配置",
                        pool.account_ids.len(),
                        pool.name
                    )],
                    vec!["云端若仍存在引用，操作将被拒绝".into()],
                    PlanKind::DeletePool { pool_id },
                )
            }
            "delete_link" => {
                let domain_id = field(payload, "domainId")?.to_owned();
                let slug = field(payload, "slug")?.to_owned();
                validate_slug(&slug)?;
                let domain = self.domain(&domain_id)?;
                if !self
                    .db
                    .links
                    .iter()
                    .any(|l| l.domain_id == domain_id && l.slug == slug)
                {
                    return Err("找不到此链接".into());
                }
                (
                    "删除链接",
                    vec![format!("删除 {} 上的短码 {slug}", domain.host)],
                    vec!["链接将停止跳转".into()],
                    PlanKind::DeleteLink { domain_id, slug },
                )
            }
            "remove_domain" => {
                let id = field(payload, "domainId")?.to_owned();
                let domain = self.domain(&id)?;
                let count = self.db.links.iter().filter(|l| l.domain_id == id).count();
                (
                    "移除域名",
                    vec![
                        format!(
                            "删除 {} 的转发规则",
                            route_pattern(&domain.host, &domain.prefix)
                        ),
                        format!("删除此前缀配置和 {count} 条链接记录"),
                    ],
                    vec![
                        "同名链接即使已在其他设备更新，也会一并删除；请确认这些短链接不再需要"
                            .into(),
                        "边缘节点可能暂时保留已缓存的配置".into(),
                    ],
                    PlanKind::RemoveDomain { domain_id: id },
                )
            }
            "cleanup_account" => {
                let id = field(payload, "accountId")?.to_owned();
                let account = self.account(&id)?;
                if self.has_selftest_rotation(&id) {
                    return Err(format!(
                        "此账号的自检密钥轮换尚未完成，请先用{RESUME_BAR}里这个账户的按钮把它做完"
                    ));
                }
                let resources = account.resources.as_ref().ok_or("此账号没有已登记资源")?;
                if self.db.domains.iter().any(|d| d.account_id == id) {
                    return Err("此账号还有域名，请先移除域名".into());
                }
                (
                    "清理账号资源",
                    vec![
                        "确认没有域名、业务记录、监测任务或未知数据后，清理已验证的遗留检测结果、轮转位置，以及本机平台地址库中仍有定义的平台地址副本".into(),
                        format!("删除专用转发程序 Worker：{}", resources.script),
                        format!("删除专用链接存储 KV：{}", resources.namespace),
                    ],
                    vec!["此操作会永久删除账号专用云端资源".into()],
                    PlanKind::CleanupAccount { account_id: id },
                )
            }
            "recover_account" => {
                let id = field(payload, "accountId")?.to_owned();
                self.account(&id)?;
                if self.has_selftest_rotation(&id) {
                    return Err(format!(
                        "此账号的自检密钥轮换尚未完成，请先用{RESUME_BAR}里这个账户的按钮把它做完"
                    ));
                }
                (
                    "从账号找回",
                    vec![
                        "只读检查账号里的转发程序、链接存储和转发规则，并验证归属".into(),
                        "恢复本机域名和链接清单".into(),
                    ],
                    vec![],
                    PlanKind::RecoverAccount { account_id: id },
                )
            }
            "rotate_selftest" => {
                let id = field(payload, "accountId")?.to_owned();
                let account = self.account(&id)?;
                if account.resources.is_none() {
                    return Err("账号尚未创建专用转发程序".into());
                }
                if self.has_selftest_rotation(&id) {
                    return Err(format!("此账号已有未完成的自检密钥轮换，请先用{RESUME_BAR}里这个账户的按钮把它做完"));
                }
                (
                    "重置自检密钥",
                    vec![
                        "先把新密钥安全暂存到系统凭据库".into(),
                        "验证云端资源后更新转发程序密钥".into(),
                        "确认云端成功后启用本机密钥".into(),
                    ],
                    vec!["其他设备保存的旧自检密钥将失效".into()],
                    PlanKind::RotateSelftest { account_id: id },
                )
            }
            "resume_selftest_rotation" => {
                let id = field(payload, "accountId")?.to_owned();
                let pending = self
                    .db
                    .pending_selftest_rotations
                    .iter()
                    .find(|pending| pending.account_id == id)
                    .ok_or("此账号没有可恢复的自检密钥轮换")?;
                let account = self.account(&id)?;
                let resources = account.resources.as_ref().ok_or("账号没有 Worker")?;
                if pending.script != resources.script || pending.namespace != resources.namespace {
                    return Err("账号云端资源已变化，不能继续旧的自检密钥轮换".into());
                }
                (
                    "恢复自检密钥轮换",
                    vec![
                        "读取系统凭据库中上次安全暂存的同一密钥".into(),
                        if pending.status == SelftestRotationStatus::CloudApplied {
                            "云端已确认更新，仅完成本机密钥启用".into()
                        } else {
                            "重新核对云端资源并用同一暂存密钥完成更新".into()
                        },
                    ],
                    vec!["仅在确认此计划后继续，不会在后台自动重试".into()],
                    PlanKind::ResumeSelftestRotation { account_id: id },
                )
            }
            "recover_selftest_resources" => {
                let id = field(payload, "accountId")?.to_owned();
                self.require_selftest_resource_recovery(&id)?;
                (
                    "找回检测服务配置",
                    vec![
                        "只读检查并验证属于此账户的唯一 Worker 和 KV 资源组合".into(),
                        "仅在本机登记已验证的资源定位，保留原有日志和密钥".into(),
                    ],
                    vec!["本次不会更换检测密钥；后续密钥恢复仍需单独查看并确认计划".into()],
                    PlanKind::RecoverSelftestResources { account_id: id },
                )
            }
            "recover_selftest_rotation" => {
                let id = field(payload, "accountId")?.to_owned();
                let account = self.account(&id)?;
                let resources = account.resources.as_ref().ok_or("本机缺少检测服务配置，请先用页面上方“……项变更可继续处理”那一栏里的「找回本机检测配置」按钮；若没有这个按钮，请先到页面上方「查看待处理记录」里核对其他记录")?;
                let missing_staging = self
                    .db
                    .pending_selftest_rotations
                    .iter()
                    .find(|pending| pending.account_id == id)
                    .filter(|pending| pending.status == SelftestRotationStatus::StagingMissing);
                if missing_staging.is_none() && !self.has_legacy_selftest_rotation(&id) {
                    return Err("此账号没有需要旧版恢复的自检密钥操作".into());
                }
                if missing_staging.is_some_and(|pending| {
                    pending.script != resources.script || pending.namespace != resources.namespace
                }) {
                    return Err("账号云端资源已变化，不能恢复旧的自检密钥轮换".into());
                }
                (
                    "重新建立自检密钥",
                    vec![
                        "原操作没有可恢复的暂存密钥，将生成新密钥并先安全暂存".into(),
                        "验证云端资源后用新密钥覆盖无法确认的旧值".into(),
                        "确认云端成功后启用本机密钥".into(),
                    ],
                    vec![
                        "此恢复会使其他设备保存的旧自检密钥失效".into(),
                        "仅在确认此计划后写入云端".into(),
                    ],
                    PlanKind::RecoverSelftestRotation { account_id: id },
                )
            }
            "dismiss_pending_operation" => {
                let entry = field(payload, "entry")?.to_owned();
                self.require_dismissable(&entry)?;
                (
                    "清除待处理记录",
                    vec![
                        "只从本机删除这条记录，不改动云端".into(),
                        format!("要清除的记录：{entry}"),
                    ],
                    vec!["请先确认这条记录对应的云端状态已经核对过".into()],
                    PlanKind::DismissPendingOperation { entry },
                )
            }
            _ => return Err("不支持此变更类型".into()),
        };
        self.require_plan_credentials(&plan_kind)?;
        let view = self.make_plan(title, steps, warnings, plan_kind);
        serde_json::to_value(view).map_err(|_| "无法建立操作计划".into())
    }

    async fn dispatch(&mut self, action: &str, payload: &Value) -> Result<Value, String> {
        match action {
            "get_state" => Ok(self.state()),
            "get_link_stats" => self.get_link_stats(payload).await,
            "get_stats_center" => self.get_stats_center(payload).await,
            "get_click_protection" => self.get_click_protection(payload).await,
            "token_template" => Ok(Value::String(Self::token_template())),
            "import_token" => {
                let expected_account_id = match payload.get("expectedAccountId") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
                    _ => return Err("指定账号标识无效".into()),
                };
                self.import_token(
                    field(payload, "token")?,
                    payload["replace"].as_bool().unwrap_or(false),
                    expected_account_id,
                )
                .await
            }
            "rename_account" => {
                let id = field(payload, "accountId")?;
                let label = field(payload, "label")?.trim();
                if label.is_empty() || label.chars().count() > 64 {
                    return Err("备注名需为 1–64 个字符".into());
                }
                let index = self
                    .db
                    .accounts
                    .iter()
                    .position(|a| a.id == id)
                    .ok_or("找不到此账号")?;
                let previous =
                    std::mem::replace(&mut self.db.accounts[index].label, label.to_owned());
                if let Err(error) = self.persist() {
                    self.db.accounts[index].label = previous;
                    return Err(error);
                }
                Ok(self.state())
            }
            "remove_account" => {
                let id = field(payload, "accountId")?;
                self.account(id)?;
                self.require_no_worker_upgrade(id)?;
                if self
                    .db
                    .pending_monitor_changes
                    .iter()
                    .any(|p| p.account_id == id)
                    || self.db.pending_pool_changes.iter().any(|p| {
                        p.pool.account_ids.iter().any(|a| a == id)
                            || p.previous
                                .as_ref()
                                .is_some_and(|old| old.account_ids.iter().any(|a| a == id))
                    })
                    || self.has_selftest_rotation(id)
                {
                    return Err(format!(
                        "此账号有未完成的云端操作，请先用{RESUME_BAR}里的按钮把它做完"
                    ));
                }
                remove_current_credentials(id).await?;
                let previous = self.db.clone();
                let domain_ids: HashSet<_> = self
                    .db
                    .domains
                    .iter()
                    .filter(|d| d.account_id == id)
                    .map(|d| d.id.clone())
                    .collect();
                self.db.links.retain(|l| !domain_ids.contains(&l.domain_id));
                self.db.domains.retain(|d| d.account_id != id);
                for pool in &mut self.db.pools {
                    pool.account_ids.retain(|account| account != id);
                    pool.sync_status.retain(|status| status.account_id != id);
                }
                self.db.accounts.retain(|a| a.id != id);
                self.plans.clear();
                if let Err(error) = self.persist() {
                    self.db = previous;
                    return Err(format!(
                        "{error}；本机凭据已删除，但账户记录没能移除。请再点一次“确认本机移除”；如果仍然失败，请在该账户的“管理账户”中选择“更换本机令牌”重新保存令牌"
                    ));
                }
                self.publish_credential_routes();
                Ok(self.state())
            }
            "refresh_accounts" | "refresh_domains" => {
                let choice = match payload.get("accountId") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(id)) if !id.is_empty() => Some(id.as_str()),
                    _ => return Err("请选择有效的 Cloudflare 账户".into()),
                };
                if action == "refresh_domains" {
                    self.refresh_domains(choice).await
                } else {
                    self.refresh_accounts(choice).await
                }
            }
            "prepare_domain" => self.prepare_domain(payload).await,
            "prepare_domain_dns" => self.prepare_domain_dns(payload).await,
            "prepare_change" => self.prepare_change(payload),
            "prepare_monitor" => {
                self.require_credentials(field(payload, "accountId")?)?;
                let account_id = field(payload, "accountId")?.to_owned();
                if self.db.pending_pool_changes.iter().any(|p| {
                    p.pool.account_ids.contains(&account_id)
                        || p.previous
                            .as_ref()
                            .is_some_and(|old| old.account_ids.contains(&account_id))
                }) {
                    return Err("此账号的平台地址操作尚未完成，请先恢复".into());
                }
                if self
                    .db
                    .pending_monitor_changes
                    .iter()
                    .any(|p| p.account_id == account_id)
                {
                    return Err("此账号监测配置尚未完成，请使用恢复监测操作".into());
                }
                let endpoint = monitor_endpoint(field(payload, "endpoint")?)?;
                let secret = field(payload, "secret")?.to_owned();
                if !(32..=256).contains(&secret.len())
                    || secret.bytes().any(|b| !(0x21..=0x7e).contains(&b))
                {
                    return Err("监测密钥需为 32–256 个无空白的可打印 ASCII 字符".into());
                }
                let account = self.account(&account_id)?;
                if account.resources.is_none() {
                    return Err("此账号尚未创建专用转发程序和链接存储".into());
                }
                if account.monitor_enabled {
                    return Err("监测已启用，请先关闭再更换设置".into());
                }
                let pool_count = self
                    .db
                    .pools
                    .iter()
                    .filter(|p| p.account_ids.contains(&account_id))
                    .count();
                let pool_ids: Vec<_> = self
                    .db
                    .pools
                    .iter()
                    .filter(|p| p.account_ids.contains(&account_id))
                    .map(|p| p.id.clone())
                    .collect();
                validate_monitor_config(&json!({"endpoint":endpoint,"poolIds":pool_ids}))?;
                let enabled_targets: usize = self
                    .db
                    .pools
                    .iter()
                    .filter(|p| p.account_ids.contains(&account_id))
                    .map(|p| p.candidates.iter().filter(|c| c.enabled).count())
                    .sum();
                let mut warnings =
                    vec!["服务位置由提供方保证；应用仅验证签名，不证明其位于中国大陆".into()];
                if enabled_targets > 60 {
                    warnings.push(format!(
                    "此账号有 {enabled_targets} 个大陆备用地址；每轮最多检查 20 个，轮转间隔可能使结果超出一小时有效期"
                ));
                }
                let view = self.make_plan(
                    "启用可选监测",
                    vec![
                        format!("配置监测服务 {endpoint}"),
                        format!(
                            "设置云端监测密钥并同步 {pool_count} 组平台地址；每 15 分钟运行一次监测"
                        ),
                    ],
                    warnings,
                    PlanKind::EnableMonitor {
                        account_id,
                        endpoint,
                        secret: Zeroizing::new(secret),
                    },
                );
                serde_json::to_value(view).map_err(|_| "无法建立监测计划".into())
            }
            "disable_monitor" => {
                self.require_credentials(field(payload, "accountId")?)?;
                let account_id = field(payload, "accountId")?.to_owned();
                if self
                    .db
                    .pending_monitor_changes
                    .iter()
                    .any(|p| p.account_id == account_id && p.enabled)
                {
                    return Err("启用监测尚未完成，请先恢复该操作".into());
                }
                let account = self.account(&account_id)?;
                if !account.monitor_enabled {
                    return Err("监测尚未启用".into());
                }
                let view = self.make_plan(
                    "关闭可选监测",
                    vec![
                        "关闭每 15 分钟运行的监测任务，并删除云端监测配置与专用密钥".into(),
                        "保留现有链接和平台地址".into(),
                    ],
                    vec![],
                    PlanKind::DisableMonitor { account_id },
                );
                serde_json::to_value(view).map_err(|_| "无法建立监测计划".into())
            }
            "resume_monitor" => {
                self.require_credentials(field(payload, "accountId")?)?;
                let account_id = field(payload, "accountId")?;
                let pending = self
                    .db
                    .pending_monitor_changes
                    .iter()
                    .find(|p| p.account_id == account_id)
                    .cloned()
                    .ok_or("此账号没有未完成监测操作")?;
                let kind = if pending.enabled {
                    PlanKind::EnableMonitor {
                        account_id: account_id.into(),
                        endpoint: pending.endpoint,
                        secret: Zeroizing::new(keyring_get(account_id, "probe")?),
                    }
                } else {
                    PlanKind::DisableMonitor {
                        account_id: account_id.into(),
                    }
                };
                let view = self.make_plan(
                    "恢复监测配置",
                    vec!["核对云端现状并继续上次已确认的操作".into()],
                    vec!["密钥不会显示在计划或备份中".into()],
                    kind,
                );
                serde_json::to_value(view).map_err(|_| "无法建立监测计划".into())
            }
            "apply_plan" => {
                let id = field(payload, "planId")?;
                let index = self
                    .plans
                    .iter()
                    .position(|p| p.view.id == id)
                    .ok_or("计划不存在或已被使用")?;
                let plan = self.plans.remove(index);
                if plan.expires_at <= Instant::now() {
                    return Err("计划已过期，请重新预检".into());
                }
                if plan.snapshot != self.database_snapshot() {
                    return Err("本机配置已变化，请重新确认操作计划".into());
                }
                let acknowledge_domain_takeover = payload["acknowledgeDomainTakeover"]
                    .as_bool()
                    .unwrap_or(false);
                if matches!(&plan.kind, PlanKind::MigrateCredentials { .. })
                    && payload["acknowledgeCredentialMigration"].as_bool() != Some(true)
                {
                    return Err("请明确确认更新本机授权；尚未读取任何旧凭据".into());
                }
                // A domain review that failed only on the network leaves the
                // plan reusable (same ID, expiry and snapshot); see CONTRACT.md.
                let retained = matches!(&plan.kind, PlanKind::Domain { .. }).then(|| Plan {
                    view: plan.view.clone(),
                    kind: plan.kind.clone(),
                    expires_at: plan.expires_at,
                    snapshot: plan.snapshot.clone(),
                });
                if let Err(error) = self.apply(plan.kind, acknowledge_domain_takeover).await {
                    let Some((head, _)) = error.split_once(PLAN_STILL_VALID) else {
                        return Err(error);
                    };
                    if let Some(retained) = retained {
                        if retained.expires_at > Instant::now()
                            && retained.snapshot == self.database_snapshot()
                        {
                            self.plans.push(retained);
                            return Err(error);
                        }
                    }
                    // The plan ran out during the review and is gone: the text
                    // must not keep the marker or invite another confirm.
                    return Err(format!("{head}{PLAN_GONE_TAIL}"));
                }
                Ok(self.state())
            }
            "selftest_link" => Err("自检调用路径无效".into()),
            "export_config" => self.export_config(),
            "import_config" => self.import_config(field(payload, "json")?).await,
            _ => Err("不支持此操作".into()),
        }
    }

    async fn apply_domain_dns(
        &mut self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        snapshot: domain_check::DnsSnapshot,
    ) -> Result<(), String> {
        self.require_no_worker_upgrade(account_id)?;
        let (token, zone_name) = self.confirmed_zone_token(account_id, zone_id, host).await?;
        let current = self
            .exact_dns_records(&token, zone_id, host)
            .await
            .map_err(|(message, _)| message)?;
        match &snapshot {
            domain_check::DnsSnapshot::Missing(expected) => {
                if &current != expected {
                    return Err("DNS 记录已变化，请重新准备修复计划".into());
                }
                self.placeholder_is_safe(&token, zone_id, &zone_name, host, expected)
                    .await
                    .map_err(|(message, _)| message)?;
            }
            domain_check::DnsSnapshot::EnableProxy(expected) => {
                if &current != expected {
                    return Err("DNS 记录已变化，请重新准备修复计划".into());
                }
                if !matches!(
                    domain_check::assess_dns(&current),
                    domain_check::DnsAssessment::DnsOnly(_)
                ) {
                    return Err("DNS 代理状态已变化，请重新准备修复计划".into());
                }
                self.proxy_is_safe(&token, zone_id, &zone_name, host, expected)
                    .await
                    .map_err(|(message, _)| message)?;
            }
        }

        let journal = format!("修复 DNS {host} ({})", random_id());
        self.journal_start(&journal)?;
        match snapshot {
            domain_check::DnsSnapshot::Missing(_) => {
                let result = self
                    .cloud
                    .post(
                        &token,
                        &format!("zones/{zone_id}/dns_records"),
                        json!({"type":"AAAA","name":host,"content":"100::","ttl":1,"proxied":true}),
                    )
                    .await;
                let response = match result {
                    Ok(value) => value,
                    Err(error) => {
                        if error.uncertain {
                            self.journal_note(
                                &journal,
                                "创建占位记录的结果不确定，请重新读取 DNS 后处理",
                            )?;
                        } else {
                            self.journal_end(&journal)?;
                        }
                        return Err(dns_write_error(error));
                    }
                };
                let result = &response["result"];
                if result["name"].as_str() != Some(host)
                    || result["type"] != "AAAA"
                    || result["content"] != "100::"
                    || result["proxied"] != true
                {
                    self.journal_note(
                        &journal,
                        "占位记录已提交但响应无法核实，请重新读取 DNS 后处理",
                    )?;
                    return Err("DNS 占位记录已提交，但云端响应无法核实；请到页面上方「查看待处理记录」里核对".into());
                }
                self.journal_end_dns(host, &journal)?;
            }
            domain_check::DnsSnapshot::EnableProxy(expected) => {
                let pending: Vec<_> = expected
                    .into_iter()
                    .filter(|record| {
                        matches!(record.record_type.as_str(), "A" | "AAAA" | "CNAME")
                            && !record.proxied
                    })
                    .collect();
                let total = pending.len();
                for (index, record) in pending.iter().enumerate() {
                    let latest = self
                        .cloud
                        .get(
                            &token,
                            &format!("zones/{zone_id}/dns_records/{}", record.id),
                        )
                        .await;
                    let latest = match latest {
                        Ok(value) => value,
                        Err(error) => {
                            if index == 0 {
                                self.journal_end(&journal)?;
                            } else {
                                self.journal_note(
                                    &journal,
                                    &format!("已开启 {index}/{total} 条记录，读取后续记录失败；请重新准备计划"),
                                )?;
                            }
                            return Err(problem(error));
                        }
                    };
                    let fingerprint = match domain_check::dns_fingerprint(
                        &[latest["result"].clone()],
                        host,
                    ) {
                        Ok(value) => value,
                        Err(message) => {
                            if index == 0 {
                                self.journal_end(&journal)?;
                            } else {
                                self.journal_note(
                                    &journal,
                                    &format!("已开启 {index}/{total} 条记录，后续记录响应无效；请重新准备计划"),
                                )?;
                            }
                            return Err(message);
                        }
                    };
                    if fingerprint.len() != 1 || fingerprint[0] != *record {
                        if index == 0 {
                            self.journal_end(&journal)?;
                        } else {
                            self.journal_note(
                                &journal,
                                &format!("已开启 {index}/{total} 条记录，后续记录状态变化；请重新准备计划完成其余记录"),
                            )?;
                        }
                        return Err("DNS 记录在应用过程中发生变化；已完成的代理设置保持不变，请重新准备计划".into());
                    }
                    let result = self
                        .cloud
                        .patch(
                            &token,
                            &format!("zones/{zone_id}/dns_records/{}", record.id),
                            json!({"proxied":true}),
                        )
                        .await;
                    let response = match result {
                        Ok(value) => value,
                        Err(error) => {
                            if error.uncertain || index > 0 {
                                self.journal_note(
                                    &journal,
                                    &format!("已开启 {index}/{total} 条记录，后续写入失败或结果不确定；请重新读取 DNS 后完成其余记录"),
                                )?;
                            } else {
                                self.journal_end(&journal)?;
                            }
                            return Err(dns_write_error(error));
                        }
                    };
                    let updated = match domain_check::dns_fingerprint(
                        &[response["result"].clone()],
                        host,
                    ) {
                        Ok(value) => value,
                        Err(_) => {
                            self.journal_note(
                                &journal,
                                &format!(
                                    "已提交第 {} 条记录但响应格式无效，请重新读取 DNS 后处理",
                                    index + 1
                                ),
                            )?;
                            return Err(
                                    "DNS 代理设置已提交，但云端响应无法核实；请到页面上方「查看待处理记录」里核对"
                                        .into(),
                                );
                        }
                    };
                    if updated.len() != 1
                        || updated[0].id != record.id
                        || updated[0].record_type != record.record_type
                        || updated[0].content != record.content
                        || !updated[0].proxied
                    {
                        self.journal_note(
                            &journal,
                            &format!(
                                "已提交第 {} 条记录但响应无法核实，请重新读取 DNS 后处理",
                                index + 1
                            ),
                        )?;
                        return Err(
                            "DNS 代理设置已提交，但云端响应无法核实；请到页面上方「查看待处理记录」里核对".into()
                        );
                    }
                    self.journal_note(
                        &journal,
                        &format!("已开启 {}/{} 条记录，正在处理其余记录", index + 1, total),
                    )?;
                }
                self.journal_end_dns(host, &journal)?;
            }
        }
        Ok(())
    }

    fn export_config(&self) -> Result<Value, String> {
        let value = json!({
            "schema":SCHEMA,
            "accounts":self.db.accounts.iter().map(|a| json!({"id":a.id,"label":a.label})).collect::<Vec<_>>(),
            "domains":self.db.domains.iter().map(|d| json!({"accountId":d.account_id,
                "host":d.host,"prefix":d.prefix})).collect::<Vec<_>>(),
            "pools":self.db.pools.iter().map(|p| json!({"id":p.id,"name":p.name,
                "official":p.official,"candidates":p.candidates,"updated":p.updated,
                "accountIds":p.account_ids})).collect::<Vec<_>>(),
            "links":self.db.links.iter().map(|l| {
                let host = self.domain(&l.domain_id).map(|d| d.host.as_str()).unwrap_or("");
                if let (Some(pool_id),Some(code)) = (&l.pool_id,&l.code) {
                    json!({"host":host,"slug":l.slug,"poolId":pool_id,"code":code})
                } else {
                    json!({"host":host,"slug":l.slug,"cnUrl":l.cn_url,
                        "defaultUrl":l.default_url})
                }
            }).collect::<Vec<_>>()
        });
        serde_json::to_string_pretty(&value)
            .map(Value::String)
            .map_err(|_| "导出配置失败".into())
    }

    async fn import_config(&mut self, json_text: &str) -> Result<Value, String> {
        if !self.db.pending_monitor_changes.is_empty()
            || !self.db.pending_pool_changes.is_empty()
            || !self.db.pending_selftest_rotations.is_empty()
            || !self.db.pending_worker_upgrades.is_empty()
            || self
                .db
                .accounts
                .iter()
                .any(|account| self.has_legacy_selftest_rotation(&account.id))
        {
            return Err("请先恢复未完成的云端操作再导入备份".into());
        }
        if json_text.len() > 2_000_000 {
            return Err("配置文件过大".into());
        }
        let doc: Value =
            serde_json::from_str(json_text).map_err(|_| "配置文件不是有效 JSON".to_string())?;
        if doc["schema"].as_u64() != Some(SCHEMA as u64) {
            return Err("配置版本不受支持".into());
        }
        let object = doc.as_object().ok_or("配置顶层格式无效")?;
        if object
            .keys()
            .any(|k| !["schema", "accounts", "domains", "links", "pools"].contains(&k.as_str()))
        {
            return Err("配置含有不允许的字段".into());
        }
        let entries = doc["domains"].as_array().ok_or("域名列表无效")?;
        let link_entries = doc["links"].as_array().ok_or("链接列表无效")?;
        let empty_pools = Vec::new();
        let pool_entries = doc["pools"].as_array().unwrap_or(&empty_pools);
        let account_entries = doc["accounts"].as_array().ok_or("账号列表无效")?;
        if entries.len() > 500 || link_entries.len() > 20_000 || pool_entries.len() > 256 {
            return Err("配置条目过多".into());
        }
        let mut labels = Vec::new();
        for item in account_entries {
            if item
                .as_object()
                .is_none_or(|o| o.keys().any(|k| !["id", "label"].contains(&k.as_str())))
            {
                return Err("账号条目含有不允许的字段".into());
            }
            let id = field(item, "id")?;
            let label = field(item, "label")?.trim();
            if label.is_empty() || label.chars().count() > 64 {
                return Err("账号备注名无效".into());
            }
            if self.account(id).is_err() {
                return Err(format!(
                    "备份中的账户「{label}」（ID 末尾 {}）尚未导入本机。请先导入该账户的令牌，再导入这份备份；本机配置未改变",
                    id_tail(id)
                ));
            }
            labels.push((id.to_owned(), label.to_owned()));
        }
        let mut credential_accounts = HashSet::new();
        for item in entries {
            credential_accounts.insert(field(item, "accountId")?.to_owned());
        }
        for item in pool_entries {
            let ids = item["accountIds"]
                .as_array()
                .ok_or("备份平台地址账号无效")?;
            for id in ids {
                credential_accounts.insert(id.as_str().ok_or("备份平台地址账号无效")?.to_owned());
            }
        }
        let mut missing: Vec<_> = credential_accounts
            .iter()
            .filter(|id| self.account(id).is_err())
            .map(|id| id_tail(id))
            .collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(format!(
                "备份中的域名或平台地址属于尚未导入本机的账户（ID 末尾 {}）。请先导入该账户的令牌，再导入这份备份；本机配置未改变",
                missing.join("、")
            ));
        }
        self.require_many_credentials(credential_accounts.iter().map(String::as_str))?;
        // Import only records that already exist on the remote account; never write remote data.
        let mut recovered_domains = Vec::new();
        for item in entries {
            if item.as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !["accountId", "host", "prefix"].contains(&k.as_str()))
            }) {
                return Err("域名条目含有不允许的字段".into());
            }
            let account_id = field(item, "accountId")?;
            let host = normalize_host(field(item, "host")?)?;
            let prefix = field(item, "prefix")?;
            validate_prefix(prefix)?;
            let checked: Result<Domain, String> = async {
                let account = self.account(account_id)?;
                let zone = account
                    .zones
                    .iter()
                    .filter(|z| {
                        z.status == "active"
                            && (host == z.name || host.ends_with(&format!(".{}", z.name)))
                    })
                    .max_by_key(|z| z.name.len())
                    .ok_or("备份域名未归属已启用区域")?;
                let token = keyring_get(account_id, "token")?;
                let routes = self
                    .cloud
                    .get(&token, &format!("zones/{}/workers/routes", zone.id))
                    .await
                    .map_err(problem)?;
                let pattern = route_pattern(&host, prefix);
                let route = routes["result"]
                    .as_array()
                    .and_then(|arr| {
                        arr.iter()
                            .find(|r| r["pattern"].as_str() == Some(pattern.as_str()))
                    })
                    .ok_or("备份中的域名路由在云端不存在")?;
                let resources = account.resources.as_ref().ok_or("请先从账号找回云端资源")?;
                if route["script"].as_str() != Some(resources.script.as_str()) {
                    return Err("域名路由不属于已验证的 Worker".into());
                }
                let config = self
                    .cloud
                    .read_value(
                        &token,
                        account_id,
                        &resources.namespace,
                        &format!("c:{host}"),
                    )
                    .await
                    .map_err(problem)?
                    .ok_or("云端缺少域名前缀记录")?;
                let config: Value =
                    serde_json::from_str(&config).map_err(|_| "云端域名配置无效".to_string())?;
                if config["prefix"].as_str() != Some(prefix) {
                    return Err("云端域名前缀与备份不同".into());
                }
                let route_id = value_str(route, "id")?.to_owned();
                let domain_id = self
                    .db
                    .domains
                    .iter()
                    .find(|d| d.host == host)
                    .map(|d| {
                        if d.account_id != account_id {
                            return Err("同一主机名已有另一账号的本机配置".to_string());
                        }
                        if d.prefix != prefix || d.zone_id != zone.id || d.route_id != route_id {
                            return Err(
                                "本机已有该域名的不同前缀或路由；请先处理本机配置冲突，再导入备份"
                                    .to_string(),
                            );
                        }
                        Ok(d.id.clone())
                    })
                    .transpose()?
                    .unwrap_or_else(random_id);
                Ok(Domain {
                    id: domain_id,
                    account_id: account_id.into(),
                    zone_id: zone.id.clone(),
                    host: host.clone(),
                    prefix: prefix.into(),
                    route_id,
                })
            }
            .await;
            recovered_domains.push(checked.map_err(|e| {
                format!("备份中的域名 {host}/{prefix}：{e}。没有导入任何内容，本机配置未改变")
            })?);
        }
        let mut recovered_links = Vec::new();
        let mut recovered_pools = Vec::new();
        for item in pool_entries {
            let mut pool: Pool =
                serde_json::from_value(item.clone()).map_err(|_| "备份平台地址格式无效")?;
            pool.sync_status.clear();
            pools::validate_pool(&pool)?;
            for id in &pool.account_ids {
                let account = self.account(id)?;
                let checked: Result<(), String> = async {
                    let resources = account
                        .resources
                        .as_ref()
                        .ok_or("备份平台地址账号缺少云端资源")?;
                    let token = keyring_get(id, "token")?;
                    let raw = self
                        .cloud
                        .read_value(&token, id, &resources.namespace, &format!("p:{}", pool.id))
                        .await
                        .map_err(problem)?
                        .ok_or("云端缺少备份平台地址")?;
                    let remote: Value =
                        serde_json::from_str(&raw).map_err(|_| "云端平台地址格式无效")?;
                    if !pools::matching_cloud_value(&pool, &remote) {
                        return Err("云端平台地址与备份不同".into());
                    }
                    Ok(())
                }
                .await;
                checked.map_err(|e| {
                    format!(
                        "备份中的平台地址「{}」（账户「{}」）：{e}。没有导入任何内容，本机配置未改变",
                        pool.name, account.label
                    )
                })?;
                pool.sync_status.push(PoolSyncStatus {
                    account_id: id.clone(),
                    status: "synced".into(),
                    message: "已核对".into(),
                });
            }
            recovered_pools.push(pool);
        }
        for item in link_entries {
            if item.as_object().is_none_or(|o| {
                o.keys().any(|k| {
                    !["host", "slug", "cnUrl", "defaultUrl", "poolId", "code"].contains(&k.as_str())
                })
            }) {
                return Err("链接条目含有不允许的字段".into());
            }
            let host = normalize_host(field(item, "host")?)?;
            let domain = recovered_domains
                .iter()
                .find(|d| d.host == host)
                .ok_or_else(|| {
                    format!(
                        "备份中的链接 {host} / {}：备份里没有它所属的域名。没有导入任何内容，本机配置未改变",
                        item["slug"].as_str().unwrap_or_default()
                    )
                })?;
            let slug = field(item, "slug")?;
            validate_slug(slug)?;
            let checked: Result<(Link, Value), String> = async {
                let resources = self
                    .account(&domain.account_id)?
                    .resources
                    .as_ref()
                    .ok_or("缺少资源")?;
                let token = keyring_get(&domain.account_id, "token")?;
                let value = self
                    .cloud
                    .read_value(
                        &token,
                        &domain.account_id,
                        &resources.namespace,
                        &format!("l:{host}:{slug}"),
                    )
                    .await
                    .map_err(problem)?
                    .ok_or("云端缺少备份链接")?;
                let value: Value =
                    serde_json::from_str(&value).map_err(|_| "云端链接数据无效".to_string())?;
                let link = if let Some(pool_id) = item["poolId"].as_str() {
                    let code = field(item, "code")?;
                    if value["poolId"].as_str() != Some(pool_id)
                        || value["code"].as_str() != Some(code)
                    {
                        return Err("云端按平台地址生成的链接与备份不同".into());
                    }
                    if !recovered_pools
                        .iter()
                        .any(|p| p.id == pool_id && p.account_ids.contains(&domain.account_id))
                    {
                        return Err("备份平台地址未包含链接所属账号".into());
                    }
                    link_from_remote(&value, &domain.id, slug, &recovered_pools)?
                } else {
                    let cn = field(item, "cnUrl")?;
                    let default = field(item, "defaultUrl")?;
                    validate_target(cn)?;
                    validate_target(default)?;
                    if value["rules"][0]["url"].as_str() != Some(cn)
                        || value["default"].as_str() != Some(default)
                    {
                        return Err("云端链接目标与备份不同".into());
                    }
                    link_from_remote(&value, &domain.id, slug, &recovered_pools)?
                };
                if !remote_matches_link(&value, &link) {
                    return Err("云端链接目标与备份不同".into());
                }
                Ok((link, value))
            }
            .await;
            recovered_links.push(checked.map_err(|e| {
                format!(
                    "备份中的链接 {host}/{}/{slug}：{e}。没有导入任何内容，本机配置未改变",
                    domain.prefix
                )
            })?);
        }
        for pool in &recovered_pools {
            if let Some(existing) = self.db.pools.iter().find(|p| p.id == pool.id) {
                if pools::cloud_value(existing) != pools::cloud_value(pool) {
                    return Err(format!(
                        "本机已有不同版本的同名平台地址「{}」；请先处理本机配置冲突，再导入备份。本机配置未改变",
                        existing.name
                    ));
                }
            }
        }
        let mut staged_db = self.db.clone();
        let mut pools_added = 0;
        let mut domains_added = 0;
        let mut links_added = 0;
        let mut links_existing = 0;
        let mut links_differing = 0;
        for pool in recovered_pools {
            if let Some(existing) = staged_db.pools.iter_mut().find(|p| p.id == pool.id) {
                for id in &pool.account_ids {
                    if !existing.account_ids.contains(id) {
                        existing.account_ids.push(id.clone());
                    }
                }
                for status in pool.sync_status {
                    existing
                        .sync_status
                        .retain(|s| s.account_id != status.account_id);
                    existing.sync_status.push(status);
                }
            } else {
                staged_db.pools.push(pool);
                pools_added += 1;
            }
        }
        for domain in recovered_domains {
            if !staged_db.domains.iter().any(|d| d.host == domain.host) {
                staged_db.domains.push(domain);
                domains_added += 1;
            }
        }
        // Existing local links are kept as they are. They are counted, and the
        // ones that differ from the cloud value just verified are reported.
        for (link, cloud_value) in recovered_links {
            if let Some(domain) = staged_db.domains.iter().find(|d| d.id == link.domain_id) {
                if let Some(existing) = staged_db
                    .links
                    .iter()
                    .find(|l| l.domain_id == domain.id && l.slug == link.slug)
                {
                    links_existing += 1;
                    if !remote_matches_link(&cloud_value, existing) {
                        links_differing += 1;
                    }
                } else {
                    staged_db.links.push(link);
                    links_added += 1;
                }
            }
        }
        for (id, label) in labels {
            if let Some(account) = staged_db.accounts.iter_mut().find(|a| a.id == id) {
                account.label = label;
            }
        }
        let previous_db = std::mem::replace(&mut self.db, staged_db);
        if let Err(error) = self.persist() {
            self.db = previous_db;
            return Err(error);
        }
        // One-time summary for this response only; it is not saved locally.
        let mut state = self.state();
        state["configImportReport"] = json!({
            "domainsAdded": domains_added,
            "linksAdded": links_added,
            "poolsAdded": pools_added,
            "linksExisting": links_existing,
            "linksDiffering": links_differing,
        });
        Ok(state)
    }

    async fn ensure_domain_owned(&self, domain: &Domain, token: &str) -> Result<Resources, String> {
        let account = self.account(&domain.account_id)?;
        let resources = account.resources.clone().ok_or("账号资源未登记")?;
        let VerifiedSource { manifest, settings } = self
            .verify_resource_source(token, &account.id, &resources)
            .await?;
        if !account.zones.iter().any(|z| {
            z.id == domain.zone_id
                && z.status == "active"
                && (domain.host == z.name || domain.host.ends_with(&format!(".{}", z.name)))
        }) {
            return Err("区域状态或域名归属已变化".into());
        }
        if manifest["schema"] != SCHEMA
            || manifest["script"] != resources.script
            || manifest["namespace"] != resources.namespace
            || manifest["accountId"] != account.id
        {
            return Err("云端资源清单与本机不一致".into());
        }
        let bindings = settings["result"]["bindings"]
            .as_array()
            .ok_or("无法验证 Worker 绑定")?;
        if !bindings.iter().any(|b| {
            b["type"] == "kv_namespace"
                && b["name"] == "LINKS"
                && b["namespace_id"] == resources.namespace
        }) {
            return Err("Worker 未绑定预期 KV".into());
        }
        let routes = self
            .cloud
            .get(token, &format!("zones/{}/workers/routes", domain.zone_id))
            .await
            .map_err(problem)?;
        let expected = route_pattern(&domain.host, &domain.prefix);
        if !routes["result"].as_array().is_some_and(|arr| {
            arr.iter().any(|r| {
                r["id"].as_str() == Some(domain.route_id.as_str())
                    && r["pattern"].as_str() == Some(expected.as_str())
                    && r["script"].as_str() == Some(resources.script.as_str())
            })
        }) {
            return Err(DOMAIN_ROUTE_CHANGED.into());
        }
        let config = self
            .cloud
            .read_value(
                token,
                &account.id,
                &resources.namespace,
                &format!("c:{}", domain.host),
            )
            .await
            .map_err(problem)?
            .ok_or(DOMAIN_CONFIG_LOST)?;
        let config: Value =
            serde_json::from_str(&config).map_err(|_| "云端域名配置损坏".to_string())?;
        if config["prefix"].as_str() != Some(domain.prefix.as_str()) {
            return Err("云端前缀与本机不一致".into());
        }
        Ok(resources)
    }

    /// Checks the owned manifest, Worker bindings and Worker source. Returns
    /// the manifest and Worker settings it read so callers need not read them
    /// again.
    async fn verify_resource_source(
        &self,
        token: &str,
        account_id: &str,
        resources: &Resources,
    ) -> Result<VerifiedSource, String> {
        self.require_no_worker_upgrade(account_id)?;
        let manifest = self
            .cloud
            .read_value(token, account_id, &resources.namespace, MANIFEST_KEY)
            .await
            .map_err(problem)?
            .ok_or("云端资源清单缺失")?;
        let manifest: Value =
            serde_json::from_str(&manifest).map_err(|_| "云端资源清单损坏".to_string())?;
        let expected_hash = manifest["sourceHash"]
            .as_str()
            .ok_or("资源清单缺少脚本校验值")?;
        if manifest["schema"] != SCHEMA
            || manifest["accountId"] != account_id
            || manifest["script"] != resources.script
            || manifest["namespace"] != resources.namespace
            || expected_hash.len() != 64
            || !expected_hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("云端资源归属或脚本校验值无效".into());
        }
        let settings = self
            .cloud
            .script_settings(token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let bindings = settings["result"]["bindings"]
            .as_array()
            .ok_or("无法读取 Worker 绑定")?;
        let missing_key_recovery = self.account(account_id)?.needs_selftest_key;
        let mut names = HashSet::new();
        let expected = (1..=6).contains(&bindings.len())
            && bindings.iter().any(|b| {
                b["type"] == "kv_namespace"
                    && b["name"] == "LINKS"
                    && b["namespace_id"] == resources.namespace
            })
            && (missing_key_recovery
                || bindings
                    .iter()
                    .any(|b| b["type"] == "secret_text" && b["name"] == "SELFTEST_KEY"))
            && bindings.iter().all(|b| {
                let name = b["name"].as_str().unwrap_or("");
                names.insert(name)
                    && match name {
                        "LINKS" => {
                            b["type"] == "kv_namespace" && b["namespace_id"] == resources.namespace
                        }
                        "SELFTEST_KEY" | "PROBE_KEY" => b["type"] == "secret_text",
                        "CLICK_EVENTS" => click_stats::valid_binding(b, &resources.namespace),
                        traffic_guard::LIMITER | traffic_guard::DISABLED => {
                            traffic_guard::normalize(b, &resources.namespace).is_some()
                        }
                        _ => false,
                    }
            });
        if !expected {
            return Err("Worker 绑定已变化，停止操作".into());
        }
        let content = self
            .cloud
            .script_content(token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        if hex::encode(Sha256::digest(&content)) != expected_hash {
            return Err("Worker 内容已变化，停止操作".into());
        }
        Ok(VerifiedSource { manifest, settings })
    }

    async fn apply(
        &mut self,
        kind: PlanKind,
        acknowledge_domain_takeover: bool,
    ) -> Result<(), String> {
        self.require_plan_credentials(&kind)?;
        match kind {
            PlanKind::UpgradeWorker {
                account_id,
                target_hash,
            } => {
                self.apply_worker_upgrade(&account_id, &target_hash, None, None)
                    .await
            }
            PlanKind::SetClickStats {
                account_id,
                target_hash,
                enabled,
            } => {
                self.apply_worker_upgrade(&account_id, &target_hash, Some(enabled), None)
                    .await
            }
            PlanKind::SetClickProtection {
                account_id,
                target_hash,
                enabled,
            } => {
                self.apply_worker_upgrade(&account_id, &target_hash, None, Some(enabled))
                    .await
            }
            PlanKind::ResumeWorkerUpgrade { account_id } => {
                self.resume_worker_upgrade(&account_id).await
            }
            PlanKind::DismissWorkerUpgrade { account_id } => {
                self.dismiss_worker_upgrade(&account_id)
            }
            PlanKind::MigrateCredentials { account_id } => {
                self.migrate_credentials(&account_id).await
            }
            PlanKind::Domain {
                account_id,
                zone_id,
                host,
                prefix,
                path_risk,
                dns_mode,
                requires_takeover_confirmation,
            } => {
                self.apply_domain(
                    &account_id,
                    &zone_id,
                    &host,
                    &prefix,
                    DomainTakeover {
                        expected_path_risk: &path_risk,
                        dns_mode,
                        requires_confirmation: requires_takeover_confirmation,
                        acknowledged: acknowledge_domain_takeover,
                    },
                )
                .await
            }
            PlanKind::DomainDns {
                account_id,
                zone_id,
                host,
                snapshot,
            } => {
                self.apply_domain_dns(&account_id, &zone_id, &host, snapshot)
                    .await
            }
            PlanKind::SaveLink {
                domain_id,
                slug,
                create_only,
                exact_edit,
                cn_url,
                default_url,
                pool_id,
                code,
            } => {
                // Copying to a new name must never become an edit if state
                // changes after preparation. Keep this check before credentials
                // or any platform/link cloud writes.
                let exact_exists = self
                    .db
                    .links
                    .iter()
                    .any(|link| link.domain_id == domain_id && link.slug == slug);
                if create_only && exact_exists
                    || !exact_edit
                        && self.db.links.iter().any(|link| {
                            link.domain_id == domain_id && link.slug.eq_ignore_ascii_case(&slug)
                        })
                {
                    return Err("此域名下已存在同名链接，请换一个名称；已有链接未修改".into());
                }
                if exact_edit && !exact_exists {
                    return Err("原链接已变化，请重新准备保存计划".into());
                }
                self.apply_save_link(
                    &domain_id,
                    &slug,
                    &cn_url,
                    &default_url,
                    pool_id.as_deref(),
                    code.as_deref(),
                )
                .await
            }
            PlanKind::SavePool { pool } => self.apply_save_pool(pool).await,
            PlanKind::DeletePool { pool_id } => self.apply_delete_pool(&pool_id).await,
            PlanKind::EnableMonitor {
                account_id,
                endpoint,
                secret,
            } => {
                self.apply_enable_monitor(&account_id, &endpoint, &secret)
                    .await
            }
            PlanKind::DisableMonitor { account_id } => {
                self.apply_disable_monitor(&account_id).await
            }
            PlanKind::DeleteLink { domain_id, slug } => {
                self.apply_delete_link(&domain_id, &slug).await
            }
            PlanKind::RemoveDomain { domain_id } => self.apply_remove_domain(&domain_id).await,
            PlanKind::CleanupAccount { account_id } => self.apply_cleanup(&account_id).await,
            PlanKind::RecoverAccount { account_id } => self.recover_account(&account_id).await,
            PlanKind::RotateSelftest { account_id } => self.apply_rotate(&account_id).await,
            PlanKind::ResumeSelftestRotation { account_id } => {
                self.resume_selftest_rotation(&account_id).await
            }
            PlanKind::RecoverSelftestRotation { account_id } => {
                self.apply_legacy_selftest_recovery(&account_id).await
            }
            PlanKind::RecoverSelftestResources { account_id } => {
                self.recover_selftest_resources(&account_id).await
            }
            PlanKind::DismissPendingOperation { entry } => self.dismiss_pending_operation(&entry),
        }
    }

    /// A plain pending record may be dismissed by its exact text; records
    /// with their own recovery entry must be handled there.
    fn require_dismissable(&self, entry: &str) -> Result<(), String> {
        if !self.db.pending_operations.iter().any(|e| e == entry) {
            return Err(RECORD_GONE.into());
        }
        if let Some(hint) = self.db.dedicated_recovery_hint(entry) {
            return Err(hint);
        }
        Ok(())
    }

    fn dismiss_pending_operation(&mut self, entry: &str) -> Result<(), String> {
        self.require_dismissable(entry)?;
        let index = self
            .db
            .pending_operations
            .iter()
            .position(|e| e == entry)
            .ok_or(RECORD_GONE)?;
        let removed = self.db.pending_operations.remove(index);
        if let Err(error) = self.persist() {
            self.db.pending_operations.insert(index, removed);
            return Err(error);
        }
        Ok(())
    }

    async fn apply_domain(
        &mut self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        prefix: &str,
        takeover: DomainTakeover<'_>,
    ) -> Result<(), String> {
        if takeover.requires_confirmation && !takeover.acknowledged {
            return Err("请先明确确认接管该短链接目录及其下级网页".into());
        }
        if self.db.domains.iter().any(|d| d.host == host) {
            return Err("这个主机名已经添加".into());
        }
        // Nothing below writes a journal, local state or cloud data until the
        // review passes; a network-only failure therefore keeps the plan valid.
        let review_started = Instant::now();
        let mut review = self
            .preflight(
                account_id,
                zone_id,
                host,
                prefix,
                Some(&takeover.expected_path_risk.probe_segment),
                takeover.dns_mode,
            )
            .await;
        if only_transient_errors(&review.0) && review_started.elapsed() < REVIEW_RETRY_WINDOW {
            tokio::time::sleep(REVIEW_RETRY_DELAY).await;
            review = self
                .preflight(
                    account_id,
                    zone_id,
                    host,
                    prefix,
                    Some(&takeover.expected_path_risk.probe_segment),
                    takeover.dns_mode,
                )
                .await;
        }
        let (checks, current_path_risk) = review;
        let errors: Vec<&DomainCheck> = checks
            .iter()
            .filter(|check| check.level == DomainCheckLevel::Error)
            .collect();
        if let Some(first) = errors.first() {
            if only_transient_errors(&checks) {
                return Err(format!(
                    "网络检查没有完成（{}：{}）。{PLAN_STILL_VALID}，云端没有任何改动，可以直接再点一次确认。",
                    first.label, first.message
                ));
            }
            let failed = errors
                .iter()
                .find(|check| !is_transient_network_check(check))
                .unwrap_or(first);
            return Err(format!(
                "复核没有通过（{}：{}）。云端没有任何改动，请重新检查域名。",
                failed.label, failed.message
            ));
        }
        let current_path_risk = current_path_risk.ok_or("路径预检状态已变化，请重新检查域名")?;
        if !current_path_risk.can_replace(takeover.expected_path_risk) {
            return Err(
                "路径响应状态已变化，请重新检查域名并确认接管范围；云端没有任何改动".into(),
            );
        }
        let token = read_account_token(account_id).await?;
        let existing = self.account(account_id)?.resources.clone();
        // Leftovers of an earlier unfinished attempt on this host that this
        // run can safely continue from (existing resources only).
        let mut reuse_config = false;
        let mut adopt_route = None::<String>;
        // Links left in the cloud under a reused prefix config: they serve
        // again once the route exists, but this computer does not list them.
        let mut revived_links = 0_usize;
        if let Some(r) = &existing {
            let VerifiedSource { manifest, settings } =
                self.verify_resource_source(&token, account_id, r).await?;
            if manifest["schema"] != SCHEMA
                || manifest["accountId"] != account_id
                || manifest["script"] != r.script
                || manifest["namespace"] != r.namespace
            {
                return Err("云端资源归属与本机不一致".into());
            }
            if !settings["result"]["bindings"].as_array().is_some_and(|bs| {
                bs.iter().any(|b| {
                    b["type"] == "kv_namespace"
                        && b["name"] == "LINKS"
                        && b["namespace_id"] == r.namespace
                })
            }) {
                return Err("Worker 的 KV 绑定已变化".into());
            }
            let config = self
                .cloud
                .read_value(&token, account_id, &r.namespace, &format!("c:{host}"))
                .await
                .map_err(problem)?;
            let routes = self
                .cloud
                .get(&token, &format!("zones/{zone_id}/workers/routes"))
                .await
                .map_err(problem)?;
            let routes = routes["result"]
                .as_array()
                .ok_or("云端转发规则列表格式无效")?;
            let own_routes: Vec<&Value> = routes
                .iter()
                .filter(|route| route["script"].as_str() == Some(r.script.as_str()))
                .collect();
            let route_for_host = own_routes.iter().any(|route| {
                route["pattern"]
                    .as_str()
                    .and_then(|p| p.split_once('/'))
                    .is_some_and(|(route_host, _)| route_host == host)
            });
            let exact_route = own_routes
                .iter()
                .find(|route| {
                    route["pattern"].as_str() == Some(route_pattern(host, prefix).as_str())
                })
                .and_then(|route| route["id"].as_str())
                .filter(|id| valid_id(id))
                .map(str::to_owned);
            match config {
                // Both halves exist: a complete earlier setup, maybe with links.
                Some(_) if route_for_host => return Err(NEEDS_RECOVERY_MESSAGE.into()),
                // Only the prefix config: left by an attempt that stopped
                // before its route, or by a route that went away while links
                // stayed. Keep it when the prefix is the same.
                Some(raw) => {
                    let links = self
                        .cloud
                        .list_keys(&token, account_id, &r.namespace, &format!("l:{host}:"))
                        .await
                        .map_err(problem)?;
                    let stored = serde_json::from_str::<Value>(&raw).ok();
                    reuse_config = stored
                        .as_ref()
                        .is_some_and(|v| *v == json!({"prefix":prefix}));
                    if !links.is_empty() {
                        let old = stored
                            .as_ref()
                            .filter(|v| v.as_object().is_some_and(|o| o.len() == 1))
                            .and_then(|v| v["prefix"].as_str())
                            .filter(|old| validate_prefix(old).is_ok());
                        match old {
                            _ if reuse_config => revived_links = links.len(),
                            Some(old) => {
                                return Err(format!(
                                    "云端还留着这个主机名以前的 {} 条短链接，它们用的链接目录是「{old}」。请把链接目录改成「{old}」再添加；本次没有做任何改动",
                                    links.len()
                                ))
                            }
                            None => {
                                return Err(format!(
                                    "云端还留着这个主机名以前的 {} 条短链接，但它的前缀配置看不懂，不能确定它们用的链接目录。本次没有做任何改动，请联系维护的人",
                                    links.len()
                                ))
                            }
                        }
                    }
                }
                // Only this tool's exact route: adopt it instead of a second.
                // An interrupted removal whose config rollback failed may
                // have left the host's links: they serve again once the
                // config is written, so count them like the branch above.
                None if exact_route.is_some() => {
                    let links = self
                        .cloud
                        .list_keys(&token, account_id, &r.namespace, &format!("l:{host}:"))
                        .await
                        .map_err(problem)?;
                    revived_links = links.len();
                    adopt_route = exact_route;
                }
                // This tool's route for the host under another directory: a
                // second route for the same host would break recovery.
                None => {
                    if let Some(stray) =
                        own_route_under_other_directory(routes, &r.script, host, prefix)
                    {
                        return Err(stray_route_message(host, stray));
                    }
                }
            }
        }
        let names = if existing.is_none() {
            // Read-only check before any journal or write: if this account
            // already holds this app's Worker/KV (for example after removing the
            // account locally), creating another set would break recovery.
            let owned = self
                .owned_manifest_candidates(account_id, &token)
                .await
                .map_err(|error| {
                    format!(
                        "无法确认此账号云端是否已有本工具创建的转发程序：{error}。为避免重复创建，本次没有做任何改动，请稍后重试"
                    )
                })?;
            // Recovery needs the Worker each manifest names. If that Worker is
            // gone, recovery cannot succeed, so name what is left instead of
            // sending the user to a recovery that always fails.
            for found in &owned {
                match self
                    .cloud
                    .script_settings(&token, account_id, &found.script)
                    .await
                {
                    Ok(_) => {}
                    Err(error) if error.message.contains("HTTP 404") => {
                        return Err(format!(
                            "此账号云端留有本工具以前创建的链接存储（KV 命名空间 ID 末尾 {}），但配套的转发程序 {} 已经不存在，无法自动找回。请到 Cloudflare 后台的 KV 页面核对这个命名空间，确认里面的短链接不再需要后删除它，再回来添加域名；本次没有做任何改动",
                            id_tail(&found.namespace),
                            found.script
                        ));
                    }
                    Err(error) => {
                        return Err(format!(
                            "无法确认此账号云端是否已有本工具创建的转发程序：{}。为避免重复创建，本次没有做任何改动，请稍后重试",
                            error.message
                        ));
                    }
                }
            }
            if !owned.is_empty() {
                return Err("此账号云端已有本工具创建的转发程序和链接存储。为避免重复创建，请先在“Cloudflare 账户”页打开该账户的“管理账户”，点“从 Cloudflare 找回配置”，再添加域名；本次没有做任何改动".into());
            }
            let scripts = self
                .cloud
                .list_pages(&token, &format!("accounts/{account_id}/workers/scripts"))
                .await
                .map_err(problem)?;
            let script = (0..5)
                .map(|_| random_name("edge"))
                .find(|name| {
                    !scripts
                        .iter()
                        .any(|s| s["id"].as_str() == Some(name.as_str()))
                })
                .ok_or("无法生成未占用的 Worker 名称")?;
            Some((random_name("links"), script))
        } else {
            None
        };
        let journal = if let Some((namespace_name, script)) = &names {
            format!(
                "添加域名 {host}（计划 KV {namespace_name}，Worker {script}，{}）",
                random_id()
            )
        } else {
            format!("添加域名 {host} ({})", random_id())
        };
        self.journal_start(&journal)?;
        let mut created_namespace = None::<String>;
        let mut created_script = None::<String>;
        let mut wrote_config = false;
        let mut route_id = None::<String>;
        let mut staged_key = false;
        // True while a new account's KV, Worker or manifest write is in
        // flight: an uncertain answer there is undone, not left behind.
        let mut creating = false;
        let mut resources = existing.clone();
        let operation: Result<(), CloudError> = async {
            if resources.is_none() {
                let (namespace_name, script) = names.clone().expect("new account resource names");
                creating = true;
                let ns = self
                    .cloud
                    .post(
                        &token,
                        &format!("accounts/{account_id}/storage/kv/namespaces"),
                        json!({"title":namespace_name}),
                    )
                    .await?;
                let namespace = ns["result"]["id"]
                    .as_str()
                    .ok_or_else(|| CloudError {
                        message: "命名空间响应缺少标识".into(),
                        uncertain: true,
                        network: false,
                    })?
                    .to_owned();
                created_namespace = Some(namespace.clone());
                creating = false;
                self.journal_note(&journal, "已建 KV，正在上传 Worker")
                    .map_err(|m| CloudError {
                        message: m,
                        uncertain: true,
                        network: false,
                    })?;
                let mut key = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                let key_hex = hex::encode(key);
                keyring_set(account_id, "selftest", &key_hex).map_err(|m| CloudError {
                    message: m,
                    uncertain: false,
                    network: false,
                })?;
                staged_key = true;
                creating = true;
                self.cloud
                    .upload_script(&token, account_id, &script, &namespace, &key_hex)
                    .await?;
                created_script = Some(script.clone());
                creating = false;
                self.journal_note(&journal, "已建 Worker，正在写资源清单")
                    .map_err(|m| CloudError {
                        message: m,
                        uncertain: true,
                        network: false,
                    })?;
                let manifest = json!({"schema":SCHEMA,"accountId":account_id,
                    "script":script,"namespace":namespace,"sourceHash":bundled_source_hash()});
                creating = true;
                self.cloud
                    .write_value(
                        &token,
                        account_id,
                        &namespace,
                        MANIFEST_KEY,
                        &manifest.to_string(),
                    )
                    .await?;
                creating = false;
                resources = Some(Resources { script, namespace });
            }
            let r = resources.as_ref().expect("created or existing");
            let config_key = format!("c:{host}");
            let config_value = json!({"prefix":prefix}).to_string();
            if !reuse_config {
                if let Err(error) = self
                    .cloud
                    .write_value(&token, account_id, &r.namespace, &config_key, &config_value)
                    .await
                {
                    if !error.uncertain {
                        return Err(error);
                    }
                    // Look before concluding: the write may have landed.
                    match self
                        .cloud
                        .read_value(&token, account_id, &r.namespace, &config_key)
                        .await
                    {
                        Ok(Some(value)) if value == config_value => {}
                        Ok(None) => {
                            return Err(CloudError {
                                message: "这一步没有收到明确的答复，查看后发现前缀配置没有写进云端，请再试一次".into(),
                                uncertain: false,
                                network: false,
                            })
                        }
                        _ => return Err(error),
                    }
                }
                wrote_config = true;
            }
            self.journal_note(&journal, "已写前缀配置，正在创建路由")
                .map_err(|m| CloudError {
                    message: m,
                    uncertain: true,
                    network: false,
                })?;
            if let Some(id) = &adopt_route {
                // This tool's own leftover route for exactly this directory.
                route_id = Some(id.clone());
                return Ok(());
            }
            let pattern = route_pattern(host, prefix);
            let created = match self
                .cloud
                .post(
                    &token,
                    &format!("zones/{zone_id}/workers/routes"),
                    json!({"pattern":pattern,"script":r.script}),
                )
                .await
            {
                Ok(route) => route["result"]["id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| CloudError {
                        message: "路由响应缺少标识".into(),
                        uncertain: true,
                        network: false,
                    }),
                Err(error) => Err(error),
            };
            route_id = Some(match created {
                Ok(id) => id,
                Err(error) if error.uncertain => {
                    // Look before concluding: the route may exist already.
                    match self
                        .find_own_route(&token, zone_id, &pattern, &r.script)
                        .await
                    {
                        Ok(Some(id)) => id,
                        Ok(None) => {
                            return Err(CloudError {
                                message: "这一步没有收到明确的答复，查看后发现转发规则没有建成，请再试一次".into(),
                                uncertain: false,
                                network: false,
                            })
                        }
                        Err(_) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            });
            Ok(())
        }
        .await;
        if let Err(error) = operation {
            if error.uncertain && creating {
                // A new account's first resources: undo whatever this run may
                // have created, so a retry does not pile up unused sets.
                let (namespace_name, script) = names.clone().expect("new account resource names");
                let gone = |result: Result<Value, CloudError>| match result {
                    Ok(_) => true,
                    Err(error) => error.message.contains("HTTP 404"),
                };
                let mut left = Vec::new();
                if staged_key
                    && !gone(
                        self.cloud
                            .delete(
                                &token,
                                &format!("accounts/{account_id}/workers/scripts/{script}"),
                            )
                            .await,
                    )
                {
                    left.push(format!("Worker {script}"));
                }
                // Without the create answer the KV is found by its planned title.
                let namespaces = match &created_namespace {
                    Some(id) => Ok(vec![id.clone()]),
                    None => self
                        .cloud
                        .list_pages(
                            &token,
                            &format!("accounts/{account_id}/storage/kv/namespaces"),
                        )
                        .await
                        .map(|items| {
                            items
                                .iter()
                                .filter(|ns| ns["title"].as_str() == Some(namespace_name.as_str()))
                                .filter_map(|ns| ns["id"].as_str())
                                .filter(|id| valid_id(id))
                                .map(str::to_owned)
                                .collect()
                        }),
                };
                match namespaces {
                    Ok(ids) => {
                        for id in ids {
                            let path = format!("accounts/{account_id}/storage/kv/namespaces/{id}");
                            if !gone(self.cloud.delete(&token, &path).await) {
                                left.push(format!("KV {namespace_name}（ID {id}）"));
                            }
                        }
                    }
                    Err(_) => left.push(format!("KV {namespace_name}")),
                }
                if left.is_empty() {
                    if staged_key {
                        let _ = keyring_delete(account_id, "selftest");
                    }
                    self.journal_end(&journal)?;
                    return Err(UNDONE_FIRST_SETUP.into());
                }
                self.journal_note(
                    &journal,
                    &format!(
                        "云端结果不确定，需要人工核对；{UNDO_INCOMPLETE}，可能还留着 {}，请到 Cloudflare 后台核对后删除",
                        left.join("、")
                    ),
                )?;
                return Err(format!(
                    "{}。这次建出的云端资源没能全部撤销，它们的名称写在页面上方「查看待处理记录」里",
                    error.message
                ));
            }
            if error.uncertain {
                self.journal_note(&journal, "云端结果不确定，需要人工核对")?;
                return Err(error.message);
            }
            let mut compensation_ok = true;
            if let Some(id) = &route_id {
                compensation_ok &= self
                    .cloud
                    .delete(&token, &format!("zones/{zone_id}/workers/routes/{id}"))
                    .await
                    .is_ok();
            }
            if wrote_config {
                if let Some(r) = &resources {
                    compensation_ok &= self
                        .cloud
                        .delete_value(&token, account_id, &r.namespace, &format!("c:{host}"))
                        .await
                        .is_ok();
                }
            }
            if let Some(script) = &created_script {
                compensation_ok &= self
                    .cloud
                    .delete(
                        &token,
                        &format!("accounts/{account_id}/workers/scripts/{script}"),
                    )
                    .await
                    .is_ok();
            }
            if let Some(namespace) = &created_namespace {
                compensation_ok &= self
                    .cloud
                    .delete(
                        &token,
                        &format!("accounts/{account_id}/storage/kv/namespaces/{namespace}"),
                    )
                    .await
                    .is_ok();
            }
            if compensation_ok {
                if created_namespace.is_some() {
                    let _ = keyring_delete(account_id, "selftest");
                }
                self.journal_end(&journal)?;
                return Err(error.message);
            }
            self.journal_note(&journal, ROLLBACK_INCOMPLETE)?;
            return Err(format!(
                "{}；回滚未完成，请到页面上方「查看待处理记录」里核对",
                error.message
            ));
        }
        let r = resources.ok_or("资源创建结果不完整")?;
        if let Some(account) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            account.resources = Some(r);
            account.has_resources = true;
            account.needs_selftest_key = false;
        }
        self.db.domains.push(Domain {
            id: random_id(),
            account_id: account_id.into(),
            zone_id: zone_id.into(),
            host: host.into(),
            prefix: prefix.into(),
            route_id: route_id.ok_or("路由创建结果不完整")?,
        });
        // The host is now set up: earlier unresolved attempts to add it are
        // settled in the same commit.
        let before_operations = self.db.pending_operations.clone();
        clear_domain_leftovers(
            &mut self.db.pending_operations,
            &add_domain_prefixes(host),
            &journal,
        );
        if let Err(error) = self.persist() {
            self.db.pending_operations = before_operations;
            return Err(error);
        }
        if revived_links > 0 {
            // Recovery imports those links and settles this record.
            self.journal_note(&journal, &revived_links_note(revived_links))?;
            return Ok(());
        }
        self.journal_end(&journal)
    }

    /// ID of this tool's route for exactly `pattern` in a zone, if any.
    async fn find_own_route(
        &self,
        token: &str,
        zone_id: &str,
        pattern: &str,
        script: &str,
    ) -> Result<Option<String>, CloudError> {
        let routes = self
            .cloud
            .get(token, &format!("zones/{zone_id}/workers/routes"))
            .await?;
        let items = routes["result"].as_array().ok_or_else(|| CloudError {
            message: "云端转发规则列表格式无效".into(),
            uncertain: false,
            network: false,
        })?;
        Ok(items
            .iter()
            .find(|route| {
                route["pattern"].as_str() == Some(pattern)
                    && route["script"].as_str() == Some(script)
            })
            .and_then(|route| route["id"].as_str())
            .filter(|id| valid_id(id))
            .map(str::to_owned))
    }

    async fn apply_save_link(
        &mut self,
        domain_id: &str,
        slug: &str,
        cn: &str,
        default: &str,
        pool_id: Option<&str>,
        code: Option<&str>,
    ) -> Result<(), String> {
        let (slug, exact_edit) = self.resolve_link_name(domain_id, slug, false)?;
        let slug = slug.as_str();
        validate_target(cn)?;
        validate_target(default)?;
        let domain = self.domain(domain_id)?.clone();
        self.require_no_worker_upgrade(&domain.account_id)?;
        let token = keyring_get(&domain.account_id, "token")?;
        let resources = self.ensure_domain_owned(&domain, &token).await?;
        let mut listed_same_name = false;
        if !exact_edit {
            let prefix = format!("l:{}:", domain.host);
            let keys = self
                .cloud
                .list_keys(&token, &domain.account_id, &resources.namespace, &prefix)
                .await
                .map_err(problem)?;
            // An exact same name is decided below, after reading its value:
            // it may be this very save that already went through.
            listed_same_name = keys
                .iter()
                .any(|key| key.strip_prefix(&prefix) == Some(slug));
            if keys.iter().any(|key| {
                key.strip_prefix(&prefix)
                    .is_some_and(|remote| remote != slug && remote.eq_ignore_ascii_case(slug))
            }) {
                return Err(
                    "云端已存在大小写相同的链接名称，请先找回或换一个名称；已有链接未修改".into(),
                );
            }
        }
        if let (Some(_), Some(code)) = (pool_id, code) {
            if !pools::valid_code(code) {
                return Err("邀请码无效".into());
            }
        }
        let key = format!("l:{}:{slug}", domain.host);
        let previous = self
            .cloud
            .read_value(&token, &domain.account_id, &resources.namespace, &key)
            .await
            .map_err(problem)?;
        let mut link = Link {
            domain_id: domain_id.into(),
            slug: slug.into(),
            cn_url: if pool_id.is_some() {
                String::new()
            } else {
                cn.into()
            },
            default_url: if pool_id.is_some() {
                String::new()
            } else {
                default.into()
            },
            updated: now(),
            pool_id: pool_id.map(str::to_owned),
            code: code.map(str::to_owned),
        };
        // The cloud already holds exactly what this save would write: an
        // earlier attempt went through although its answer was lost.
        let already_saved = previous
            .as_deref()
            .is_some_and(|raw| same_link_content(raw, &link));
        if !already_saved {
            if listed_same_name {
                return Err(format!(
                    "云端已有同名链接 {} / {slug}，内容和这次要保存的不一样。请在“Cloudflare 账户”页打开该账户的“管理账户”，点“从 Cloudflare 找回配置”核对；已有链接未修改",
                    domain.host
                ));
            }
            let local_previous = self
                .db
                .links
                .iter()
                .find(|l| l.domain_id == domain_id && l.slug == slug);
            if previous.is_some() != local_previous.is_some() {
                return Err("云端链接与本机记录不一致，请先找回".into());
            }
            if let (Some(raw), Some(local)) = (&previous, local_previous) {
                let remote: Value =
                    serde_json::from_str(raw).map_err(|_| "云端链接格式无效".to_string())?;
                if !remote_matches_link(&remote, local) {
                    return Err("云端链接目标已变化，请先找回".into());
                }
            }
        }
        if let Some(pool_id) = pool_id {
            self.ensure_pool_on_account(pool_id, &domain.account_id, &token, &resources)
                .await?;
        }
        if already_saved {
            if let Some(updated) = previous
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .and_then(|remote| remote["updated"].as_str().map(str::to_owned))
            {
                link.updated = updated;
            }
            return self.finish_saved_link(&domain.host, link, None);
        }
        let journal = format!("保存链接 {} / {} ({})", domain.host, slug, random_id());
        self.journal_start(&journal)?;
        if let Err(e) = self
            .cloud
            .write_value(
                &token,
                &domain.account_id,
                &resources.namespace,
                &key,
                &kv_link(&link).to_string(),
            )
            .await
        {
            if !e.uncertain {
                self.journal_end(&journal)?;
                return Err(e.message);
            }
            // Read the value straight back: an identical value means the
            // write went through although its answer was lost.
            let landed = self
                .cloud
                .read_value(&token, &domain.account_id, &resources.namespace, &key)
                .await
                .ok()
                .flatten()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .is_some_and(|remote| remote == kv_link(&link));
            if !landed {
                self.journal_note(&journal, "写入结果不确定，需要人工核对")?;
                return Err(e.message);
            }
        }
        self.finish_saved_link(&domain.host, link, Some(&journal))
    }

    /// Records a link the cloud is known to hold and settles older records
    /// for the same link in the same commit, then ends `journal` if given.
    fn finish_saved_link(
        &mut self,
        host: &str,
        link: Link,
        journal: Option<&str>,
    ) -> Result<(), String> {
        let (domain_id, slug) = (link.domain_id.clone(), link.slug.clone());
        // Edit in place so the list keeps its order; drop any older duplicates.
        if let Some(index) = self
            .db
            .links
            .iter()
            .position(|l| l.domain_id == domain_id && l.slug == slug)
        {
            self.db.links[index] = link;
            let mut seen = 0;
            self.db.links.retain(|l| {
                if l.domain_id == domain_id && l.slug == slug {
                    seen += 1;
                    seen == 1
                } else {
                    true
                }
            });
        } else {
            self.db.links.push(link);
        }
        // This write was checked against the cloud and succeeded, so older
        // unresolved records for the same link are settled in the same commit.
        let before_operations = self.db.pending_operations.clone();
        clear_link_leftovers(
            &mut self.db.pending_operations,
            host,
            &slug,
            journal.unwrap_or_default(),
        );
        if let Err(error) = self.persist() {
            self.db.pending_operations = before_operations;
            return Err(error);
        }
        match journal {
            Some(journal) => self.journal_end(journal),
            None => Ok(()),
        }
    }

    async fn ensure_pool_on_account(
        &mut self,
        pool_id: &str,
        account_id: &str,
        token: &str,
        resources: &Resources,
    ) -> Result<(), String> {
        if self
            .db
            .pending_pool_changes
            .iter()
            .any(|p| p.pool.id == pool_id)
        {
            return Err("这组平台地址有未完成的更新，请先继续处理".into());
        }
        if self
            .db
            .pending_monitor_changes
            .iter()
            .any(|p| p.account_id == account_id)
        {
            return Err("此账户的检测设置尚未完成，请先继续处理".into());
        }
        let previous = self
            .db
            .pools
            .iter()
            .find(|p| p.id == pool_id)
            .cloned()
            .ok_or("找不到平台地址")?;
        let mut pool = previous.clone();
        if !pool.account_ids.iter().any(|id| id == account_id) {
            pool.account_ids.push(account_id.to_owned());
        }
        pools::validate_pool(&pool)?;
        let key = format!("p:{pool_id}");
        let remote = self
            .cloud
            .read_value(token, account_id, &resources.namespace, &key)
            .await
            .map_err(problem)?;
        if let Some(raw) = &remote {
            let value: Value = serde_json::from_str(raw).map_err(|_| "云端平台地址格式无效")?;
            if !pools::matching_cloud_value(&pool, &value) {
                return Err(
                    "云端平台地址与本机版本不同，请先找回或恢复同步，软件不会覆盖它".into(),
                );
            }
        } else if previous
            .sync_status
            .iter()
            .any(|s| s.account_id == account_id && s.status == "synced")
        {
            // Saving the pool again through 「编辑地址」 re-creates the copy
            // (`apply_save_pool`), the same way out as the patrol names.
            return Err(POOL_COPY_MISSING_FOR_LINK.into());
        }
        let monitor = self
            .monitor_config_for(account_id, token, &resources.namespace, pool_id)
            .await?;
        let mut monitor_update = None;
        if let Some(mut projected) = monitor {
            let ids = projected["poolIds"]
                .as_array_mut()
                .ok_or("检测平台清单无效")?;
            if !ids.iter().any(|id| id.as_str() == Some(pool_id)) {
                ids.push(Value::String(pool_id.to_owned()));
                validate_monitor_config(&projected)?;
                monitor_update = Some(projected);
            }
        }
        if remote.is_some()
            && monitor_update.is_none()
            && previous.account_ids.iter().any(|id| id == account_id)
            && previous
                .sync_status
                .iter()
                .any(|s| s.account_id == account_id && s.status == "synced")
        {
            return Ok(());
        }
        pool.sync_status.retain(|s| s.account_id != account_id);
        pool.sync_status.push(PoolSyncStatus {
            account_id: account_id.to_owned(),
            status: "unsynced".into(),
            message: "正在配置到当前域名账户".into(),
        });
        let journal = format!(
            "首次同步平台地址 {} / {} ({})",
            pool_id,
            account_id,
            random_id()
        );
        let before = self.db.clone();
        self.db.pending_operations.push(journal.clone());
        self.db.pending_pool_changes.push(PendingPoolChange {
            pool: pool.clone(),
            previous: Some(previous),
            journal: journal.clone(),
            deleting: false,
        });
        self.db.pools.retain(|p| p.id != pool_id);
        self.db.pools.push(pool.clone());
        // Persist resumable intent before the first cloud mutation. Other accounts
        // are not read or modified by first use on this domain.
        if let Err(error) = self.persist() {
            self.db = before;
            return Err(error);
        }
        if remote.is_none() {
            if let Err(error) = self
                .cloud
                .write_value(
                    token,
                    account_id,
                    &resources.namespace,
                    &key,
                    &pools::cloud_value(&pool).to_string(),
                )
                .await
            {
                // A definite refusal wrote nothing: undo this operation's journal,
                // pending change and pool status so other links are not blocked.
                if !error.uncertain {
                    let pending = std::mem::replace(&mut self.db, before);
                    if let Err(persist_error) = self.persist() {
                        self.db = pending;
                        return Err(format!(
                            "{}；{persist_error}，平台地址的待处理记录未能清除，请用{RESUME_BAR}里的「继续同步」按钮继续处理",
                            error.message
                        ));
                    }
                    return Err(format!(
                        "{}；平台地址没有配置到此账户，短链接未保存，可稍后重试",
                        error.message
                    ));
                }
                let status = self
                    .db
                    .pools
                    .iter_mut()
                    .find(|p| p.id == pool_id)
                    .and_then(|p| {
                        p.sync_status
                            .iter_mut()
                            .find(|s| s.account_id == account_id)
                    })
                    .ok_or("平台同步状态丢失")?;
                status.status = if error.uncertain { "unknown" } else { "failed" }.into();
                status.message = "配置尚未完成，请继续处理平台更新后再保存链接".into();
                self.journal_note(&journal, "平台地址写入尚未确认；短链接未保存")?;
                return Err(error.message);
            }
        }
        if let Some(monitor) = monitor_update {
            if let Err(error) = self
                .cloud
                .write_value(
                    token,
                    account_id,
                    &resources.namespace,
                    "m:monitor",
                    &monitor.to_string(),
                )
                .await
            {
                self.journal_note(&journal, "平台地址已配置，检测清单尚未确认；短链接未保存")?;
                return Err(error.message);
            }
        }
        let before_finish = self.db.clone();
        let status = self
            .db
            .pools
            .iter_mut()
            .find(|p| p.id == pool_id)
            .and_then(|p| {
                p.sync_status
                    .iter_mut()
                    .find(|s| s.account_id == account_id)
            })
            .ok_or("平台同步状态丢失")?;
        status.status = "synced".into();
        status.message = "已用于此账户".into();
        self.db
            .pending_pool_changes
            .retain(|p| p.pool.id != pool_id);
        if let Err(error) = self.journal_end(&journal) {
            self.db = before_finish;
            return Err(error);
        }
        Ok(())
    }

    async fn monitor_config_for(
        &self,
        id: &str,
        token: &str,
        namespace: &str,
        changing_pool: &str,
    ) -> Result<Option<Value>, String> {
        let account = self.account(id)?;
        if !account.monitor_enabled {
            return Ok(None);
        }
        let raw = self
            .cloud
            .read_value(token, id, namespace, "m:monitor")
            .await
            .map_err(problem)?
            .ok_or("监测配置在云端缺失")?;
        let value: Value = serde_json::from_str(&raw).map_err(|_| "监测配置格式无效")?;
        validate_monitor_config(&value)?;
        let expected: std::collections::HashSet<_> = self
            .db
            .pools
            .iter()
            .filter(|p| p.account_ids.contains(&id.to_string()))
            .map(|p| p.id.as_str())
            .collect();
        let actual: Vec<&str> = value["poolIds"]
            .as_array()
            .ok_or("监测平台地址清单无效")?
            .iter()
            .map(|v| v.as_str().ok_or("监测平台地址清单无效"))
            .collect::<Result<_, _>>()?;
        let actual_set = actual
            .iter()
            .copied()
            .filter(|p| *p != changing_pool)
            .collect::<std::collections::HashSet<_>>();
        let expected_set = expected
            .iter()
            .copied()
            .filter(|p| *p != changing_pool)
            .collect::<std::collections::HashSet<_>>();
        if value["endpoint"].as_str() != account.monitor_endpoint.as_deref()
            || actual
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != actual.len()
            || actual_set != expected_set
        {
            return Err("云端监测配置与本机不同，停止更改".into());
        }
        Ok(Some(value))
    }

    async fn apply_save_pool(&mut self, mut pool: Pool) -> Result<(), String> {
        self.require_many_credentials(pool.account_ids.iter().map(String::as_str))?;
        if self
            .db
            .pending_monitor_changes
            .iter()
            .any(|m| pool.account_ids.contains(&m.account_id))
        {
            return Err("相关账号监测操作尚未完成".into());
        }
        pools::validate_pool(&pool)?;
        let pending = self
            .db
            .pending_pool_changes
            .iter()
            .find(|p| p.pool.id == pool.id)
            .cloned();
        if pending.as_ref().is_some_and(|p| {
            p.deleting
                || pools::cloud_value(&p.pool) != pools::cloud_value(&pool)
                || p.pool.account_ids != pool.account_ids
        }) {
            return Err("存在不同的未完成平台地址操作".into());
        }
        let old = pending
            .as_ref()
            .map(|p| p.previous.clone())
            .unwrap_or_else(|| self.db.pools.iter().find(|p| p.id == pool.id).cloned());
        if let Some(previous) = &old {
            if previous
                .account_ids
                .iter()
                .any(|id| !pool.account_ids.contains(id))
            {
                return Err("不能从已有平台地址直接移除账号，请先删除引用".into());
            }
        }
        struct Target {
            account: String,
            label: String,
            token: String,
            namespace: String,
            monitor: Option<Value>,
            already_desired: bool,
        }
        let mut targets = Vec::new();
        for id in &pool.account_ids {
            let account = self.account(id)?;
            let Some(resources) = &account.resources else {
                continue;
            };
            let checked: Result<Target, String> = async {
                let token = keyring_get(id, "token")?;
                self.verify_resource_source(&token, id, resources).await?;
                let monitor = self
                    .monitor_config_for(id, &token, &resources.namespace, &pool.id)
                    .await?;
                if let Some(mut projected) = monitor.clone() {
                    let ids = projected["poolIds"]
                        .as_array_mut()
                        .ok_or("监测平台地址清单无效")?;
                    if !ids.iter().any(|entry| entry.as_str() == Some(&pool.id)) {
                        ids.push(Value::String(pool.id.clone()));
                    }
                    validate_monitor_config(&projected)?;
                }
                let remote = self
                    .cloud
                    .read_value(&token, id, &resources.namespace, &format!("p:{}", pool.id))
                    .await
                    .map_err(problem)?;
                if let Some(raw) = remote {
                    let value: Value =
                        serde_json::from_str(&raw).map_err(|_| "云端平台地址格式无效")?;
                    let already_desired =
                        pending.is_some() && pools::matching_cloud_value(&pool, &value);
                    let owned = already_desired
                        || old.as_ref().is_some_and(|prior| {
                            prior.account_ids.contains(id)
                                && pools::matching_cloud_value(prior, &value)
                        });
                    if !owned {
                        return Err("云端已有不同的同名平台地址，停止覆盖".into());
                    }
                    Ok(Target {
                        account: id.clone(),
                        label: account.label.clone(),
                        token,
                        namespace: resources.namespace.clone(),
                        monitor,
                        already_desired,
                    })
                } else {
                    // Nothing is there, so nothing can be overwritten. This
                    // also re-creates a copy that went missing while this
                    // computer still records it as synced: visitors cannot
                    // open its links until it is written again.
                    Ok(Target {
                        account: id.clone(),
                        label: account.label.clone(),
                        token,
                        namespace: resources.namespace.clone(),
                        monitor,
                        already_desired: false,
                    })
                }
            }
            .await;
            targets.push(checked.map_err(|e| format!("账户「{}」：{e}", account.label))?);
        }
        pool.sync_status = pool
            .account_ids
            .iter()
            .map(|id| PoolSyncStatus {
                account_id: id.clone(),
                status: "unsynced".into(),
                message: "尚未写入此账号".into(),
            })
            .collect();
        let journal = pending
            .as_ref()
            .map(|p| p.journal.clone())
            .unwrap_or_else(|| format!("同步平台地址 {} ({})", pool.id, random_id()));
        // Only a fresh start can be undone locally: on a retry an earlier
        // attempt may already have changed the cloud.
        let rollback = pending.is_none().then(|| self.db.clone());
        let mut wrote_any = false;
        if pending.is_none() {
            self.journal_start(&journal)?;
            self.db.pending_pool_changes.push(PendingPoolChange {
                pool: pool.clone(),
                previous: old.clone(),
                journal: journal.clone(),
                deleting: false,
            });
        }
        self.db.pools.retain(|p| p.id != pool.id);
        self.db.pools.push(pool.clone());
        self.persist()?;
        let value = pools::cloud_value(&pool).to_string();
        for target in targets {
            let result = if target.already_desired {
                Ok(())
            } else {
                self.cloud
                    .write_value(
                        &target.token,
                        &target.account,
                        &target.namespace,
                        &format!("p:{}", pool.id),
                        &value,
                    )
                    .await
            };
            let status = self
                .db
                .pools
                .iter_mut()
                .find(|p| p.id == pool.id)
                .and_then(|p| {
                    p.sync_status
                        .iter_mut()
                        .find(|s| s.account_id == target.account)
                })
                .ok_or("平台地址同步状态丢失")?;
            match result {
                Ok(()) => wrote_any = true,
                Err(e) if !e.uncertain && !wrote_any && rollback.is_some() => {
                    // The very first write was refused: the cloud is unchanged,
                    // so this operation's records are dropped again.
                    let before = rollback.expect("checked above");
                    let pending = std::mem::replace(&mut self.db, before);
                    if let Err(persist_error) = self.persist() {
                        self.db = pending;
                        return Err(format!(
                            "账户「{}」：{}；{persist_error}，平台地址的待处理记录未能清除，请用{RESUME_BAR}里的「继续同步」按钮继续处理",
                            target.label, e.message
                        ));
                    }
                    return Err(format!(
                        "账户「{}」：{}；云端没有任何改动，这组平台地址没有保存，处理好原因后可以重新保存",
                        target.label, e.message
                    ));
                }
                Err(e) => {
                    status.status = if e.uncertain { "unknown" } else { "failed" }.into();
                    status.message = e.message.clone();
                    self.persist()?;
                    self.journal_note(&journal, "账号同步未完成，需要核对云端状态")?;
                    return Err(format!("账户「{}」：{}", target.label, e.message));
                }
            }
            if let Some(mut monitor) = target.monitor {
                let ids = monitor["poolIds"]
                    .as_array_mut()
                    .ok_or("监测平台地址清单无效")?;
                if !ids.iter().any(|id| id.as_str() == Some(&pool.id)) {
                    ids.push(Value::String(pool.id.clone()));
                    if let Err(e) = self
                        .cloud
                        .write_value(
                            &target.token,
                            &target.account,
                            &target.namespace,
                            "m:monitor",
                            &monitor.to_string(),
                        )
                        .await
                    {
                        status.status = "unknown".into();
                        status.message = "平台地址已写入，监测清单未确认".into();
                        self.persist()?;
                        self.journal_note(&journal, "平台地址已写入，但监测清单未同步")?;
                        return Err(format!("账户「{}」：{}", target.label, e.message));
                    }
                }
            }
            status.status = "synced".into();
            status.message = "已同步".into();
            self.persist()?;
        }
        let before_finish = self.db.clone();
        self.db
            .pending_pool_changes
            .retain(|p| p.pool.id != pool.id);
        if let Err(e) = self.journal_end(&journal) {
            self.db = before_finish;
            return Err(e);
        }
        Ok(())
    }

    async fn apply_delete_pool(&mut self, pool_id: &str) -> Result<(), String> {
        self.require_many_credentials(
            self.db
                .accounts
                .iter()
                .filter(|a| a.resources.is_some())
                .map(|a| a.id.as_str()),
        )?;
        let pending = self
            .db
            .pending_pool_changes
            .iter()
            .find(|p| p.pool.id == pool_id)
            .cloned();
        if pending.as_ref().is_some_and(|p| !p.deleting) {
            return Err("平台地址同步尚未完成，不能删除".into());
        }
        let pool = self
            .db
            .pools
            .iter()
            .find(|p| p.id == pool_id)
            .cloned()
            .ok_or("找不到平台地址")?;
        if self
            .db
            .pending_monitor_changes
            .iter()
            .any(|m| pool.account_ids.contains(&m.account_id))
        {
            return Err("相关账号监测操作尚未完成".into());
        }
        if self
            .db
            .links
            .iter()
            .any(|l| l.pool_id.as_deref() == Some(pool_id))
        {
            return Err("仍有本机链接引用此平台地址".into());
        }
        struct Target {
            account: String,
            label: String,
            token: String,
            namespace: String,
            monitor: Option<Value>,
            already_deleted: bool,
        }
        let mut targets = Vec::new();
        for account in &self.db.accounts {
            let id = &account.id;
            let Some(resources) = &account.resources else {
                continue;
            };
            let checked: Result<Option<Target>, String> = async {
                let token = keyring_get(id, "token")?;
                self.verify_resource_source(&token, id, resources).await?;
                let monitor = if pool.account_ids.contains(id) {
                    self.monitor_config_for(id, &token, &resources.namespace, pool_id)
                        .await?
                } else {
                    None
                };
                let keys = self
                    .cloud
                    .list_keys(&token, id, &resources.namespace, "l:")
                    .await
                    .map_err(problem)?;
                for key in keys {
                    let raw = self
                        .cloud
                        .read_value(&token, id, &resources.namespace, &key)
                        .await
                        .map_err(problem)?
                        .ok_or("云端链接记录在核对时消失")?;
                    let value: Value =
                        serde_json::from_str(&raw).map_err(|_| "云端链接格式无效")?;
                    if value["poolId"].as_str() == Some(pool_id) {
                        return Err("云端仍有链接引用此平台地址".into());
                    }
                }
                let raw = self
                    .cloud
                    .read_value(&token, id, &resources.namespace, &format!("p:{pool_id}"))
                    .await
                    .map_err(problem)?;
                if let Some(raw) = raw {
                    if !pool.account_ids.contains(id) {
                        return Err("另一账号存在同名平台地址，停止删除".into());
                    }
                    let value: Value =
                        serde_json::from_str(&raw).map_err(|_| "云端平台地址格式无效")?;
                    if !pools::matching_cloud_value(&pool, &value) {
                        return Err("云端平台地址已变化，停止删除".into());
                    }
                    Ok(Some(Target {
                        account: id.clone(),
                        label: account.label.clone(),
                        token,
                        namespace: resources.namespace.clone(),
                        monitor,
                        already_deleted: false,
                    }))
                } else if pool.account_ids.contains(id)
                    && (pending.is_some()
                        || pool
                            .sync_status
                            .iter()
                            .any(|s| s.account_id == *id && s.status == "synced"))
                {
                    // Gone already: an earlier attempt deleted it, or the copy
                    // went missing while recorded as synced.
                    Ok(Some(Target {
                        account: id.clone(),
                        label: account.label.clone(),
                        token,
                        namespace: resources.namespace.clone(),
                        monitor,
                        already_deleted: true,
                    }))
                } else if pool
                    .sync_status
                    .iter()
                    .any(|s| s.account_id == *id && s.status == "synced")
                {
                    Err("已同步平台地址在云端缺失，请先核对".into())
                } else {
                    Ok(None)
                }
            }
            .await;
            if let Some(target) = checked.map_err(|e| format!("账户「{}」：{e}", account.label))?
            {
                targets.push(target);
            }
        }
        let journal = pending
            .as_ref()
            .map(|p| p.journal.clone())
            .unwrap_or_else(|| format!("删除平台地址 {} ({})", pool_id, random_id()));
        if pending.is_none() {
            self.journal_start(&journal)?;
            self.db.pending_pool_changes.push(PendingPoolChange {
                pool: pool.clone(),
                previous: Some(pool.clone()),
                journal: journal.clone(),
                deleting: true,
            });
            self.persist()?;
        }
        for target in targets {
            if !target.already_deleted {
                if let Err(e) = self
                    .cloud
                    .delete_value(
                        &target.token,
                        &target.account,
                        &target.namespace,
                        &format!("p:{pool_id}"),
                    )
                    .await
                {
                    self.journal_note(&journal, "云端删除未完成，需要核对所有账号")?;
                    return Err(format!("账户「{}」：{}", target.label, e.message));
                }
            }
            if let Some(mut monitor) = target.monitor {
                let ids = monitor["poolIds"]
                    .as_array_mut()
                    .ok_or("监测平台地址清单无效")?;
                ids.retain(|id| id.as_str() != Some(pool_id));
                if let Err(e) = self
                    .cloud
                    .write_value(
                        &target.token,
                        &target.account,
                        &target.namespace,
                        "m:monitor",
                        &monitor.to_string(),
                    )
                    .await
                {
                    self.journal_note(&journal, "平台地址已删除，但监测清单未同步")?;
                    return Err(format!("账户「{}」：{}", target.label, e.message));
                }
            }
            if let Some(status) = self
                .db
                .pools
                .iter_mut()
                .find(|p| p.id == pool_id)
                .and_then(|p| {
                    p.sync_status
                        .iter_mut()
                        .find(|s| s.account_id == target.account)
                })
            {
                status.status = "deleting".into();
                status.message = "已删除云端记录".into();
            }
            self.persist()?;
        }
        let before_finish = self.db.clone();
        self.db.pools.retain(|p| p.id != pool_id);
        self.db
            .pending_pool_changes
            .retain(|p| p.pool.id != pool_id);
        if let Err(e) = self.journal_end(&journal) {
            self.db = before_finish;
            return Err(e);
        }
        Ok(())
    }

    async fn apply_enable_monitor(
        &mut self,
        account_id: &str,
        endpoint: &str,
        secret: &str,
    ) -> Result<(), String> {
        let account = self.account(account_id)?.clone();
        let pending = self
            .db
            .pending_monitor_changes
            .iter()
            .find(|p| p.account_id == account_id)
            .cloned();
        if pending
            .as_ref()
            .is_some_and(|p| !p.enabled || p.endpoint != endpoint)
        {
            return Err("存在不同的未完成监测操作".into());
        }
        if account.monitor_enabled {
            return Err("监测已启用".into());
        }
        let resources = account.resources.ok_or("账号缺少专用 Worker/KV")?;
        let token = keyring_get(account_id, "token")?;
        self.verify_resource_source(&token, account_id, &resources)
            .await?;
        let schedule = self
            .cloud
            .schedules(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let schedules = schedule["result"]["schedules"]
            .as_array()
            .ok_or("计划任务列表格式无效")?;
        let schedule_ready = schedules.len() == 1 && schedules[0]["cron"] == "*/15 * * * *";
        if !schedules.is_empty() && !(pending.is_some() && schedule_ready) {
            return Err("Worker 已有计划任务，停止覆盖".into());
        }
        let current_config = self
            .cloud
            .read_value(&token, account_id, &resources.namespace, "m:monitor")
            .await
            .map_err(problem)?;
        let pool_ids: Vec<_> = self
            .db
            .pools
            .iter()
            .filter(|p| p.account_ids.iter().any(|id| id == account_id))
            .map(|p| p.id.clone())
            .collect();
        let config = json!({"endpoint":endpoint,"poolIds":pool_ids});
        validate_monitor_config(&config)?;
        if let Some(raw) = &current_config {
            let remote: Value = serde_json::from_str(raw).map_err(|_| "监测配置格式无效")?;
            if pending.is_none() || remote != config {
                return Err("云端已有不同监测配置，停止覆盖".into());
            }
        }
        if pending.is_none() {
            keyring_set(account_id, "probe", secret)?;
        } else if keyring_get(account_id, "probe")?.as_str() != secret {
            return Err("本机监测密钥与未完成操作不同".into());
        }
        let journal = pending
            .as_ref()
            .map(|p| p.journal.clone())
            .unwrap_or_else(|| format!("启用监测 {} ({})", account_id, random_id()));
        // Only a fresh start can be undone locally: on a retry an earlier
        // attempt may already have changed the cloud.
        let rollback = pending.is_none().then(|| self.db.clone());
        if pending.is_none() {
            self.journal_start(&journal)?;
            self.db.pending_monitor_changes.push(PendingMonitorChange {
                account_id: account_id.into(),
                endpoint: endpoint.into(),
                enabled: true,
                journal: journal.clone(),
            });
            self.persist()?;
        }
        if let Err(e) = self
            .cloud
            .set_probe_secret(&token, account_id, &resources.script, secret)
            .await
        {
            // A definite refusal of the very first write changed nothing in
            // the cloud: drop this operation's records instead of leaving a
            // "continue" entry that can only be refused again.
            if let (false, Some(before)) = (e.uncertain, rollback) {
                let pending = std::mem::replace(&mut self.db, before);
                if let Err(persist_error) = self.persist() {
                    self.db = pending;
                    return Err(format!(
                        "{}；{persist_error}，启用监测的待处理记录未能清除，请用{RESUME_BAR}里的「继续处理监测」按钮继续处理",
                        e.message
                    ));
                }
                return Err(format!(
                    "{}；云端没有任何改动，监测没有启用，处理好原因后可以重新启用",
                    e.message
                ));
            }
            self.journal_note(&journal, "Worker 密钥写入未完成")?;
            return Err(e.message);
        }
        if current_config.is_none() {
            if let Err(e) = self
                .cloud
                .write_value(
                    &token,
                    account_id,
                    &resources.namespace,
                    "m:monitor",
                    &config.to_string(),
                )
                .await
            {
                self.journal_note(&journal, "监测配置写入未完成")?;
                return Err(e.message);
            }
        }
        if !schedule_ready {
            if let Err(e) = self
                .cloud
                .set_schedules(&token, account_id, &resources.script, true)
                .await
            {
                self.journal_note(&journal, "计划任务创建未完成")?;
                return Err(e.message);
            }
        }
        let before_finish = self.db.clone();
        let account = self
            .db
            .accounts
            .iter_mut()
            .find(|a| a.id == account_id)
            .ok_or("账号不存在")?;
        account.monitor_enabled = true;
        account.monitor_endpoint = Some(endpoint.into());
        account.needs_monitor_key = false;
        self.db
            .pending_monitor_changes
            .retain(|p| p.account_id != account_id);
        if let Err(e) = self.journal_end(&journal) {
            self.db = before_finish;
            return Err(e);
        }
        Ok(())
    }

    async fn apply_disable_monitor(&mut self, account_id: &str) -> Result<(), String> {
        let account = self.account(account_id)?.clone();
        let pending = self
            .db
            .pending_monitor_changes
            .iter()
            .find(|p| p.account_id == account_id)
            .cloned();
        if pending.as_ref().is_some_and(|p| p.enabled) {
            return Err("启用监测尚未完成".into());
        }
        if !account.monitor_enabled {
            return Err("监测尚未启用".into());
        }
        let resources = account.resources.ok_or("账号缺少专用 Worker/KV")?;
        let token = keyring_get(account_id, "token")?;
        self.verify_resource_source(&token, account_id, &resources)
            .await?;
        let schedule = self
            .cloud
            .schedules(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let schedules = schedule["result"]["schedules"]
            .as_array()
            .ok_or("计划任务列表格式无效")?;
        let schedule_ready = schedules.len() == 1 && schedules[0]["cron"] == "*/15 * * * *";
        if !schedule_ready && !(pending.is_some() && schedules.is_empty()) {
            return Err("Worker 计划任务已变化，停止删除".into());
        }
        let raw = self
            .cloud
            .read_value(&token, account_id, &resources.namespace, "m:monitor")
            .await
            .map_err(problem)?;
        if let Some(raw) = &raw {
            let config: Value = serde_json::from_str(raw).map_err(|_| "云端监测配置无效")?;
            if config["endpoint"].as_str() != account.monitor_endpoint.as_deref() {
                return Err("云端监测服务已变化，停止删除".into());
            }
        } else if pending.is_none() {
            return Err("云端监测配置缺失".into());
        }
        let settings = self
            .cloud
            .script_settings(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let bindings = settings["result"]["bindings"]
            .as_array()
            .ok_or("Worker 绑定格式无效")?;
        let has_probe = bindings
            .iter()
            .any(|b| b["type"] == "secret_text" && b["name"] == "PROBE_KEY");
        if !has_probe && pending.is_none() && !account.needs_monitor_key {
            return Err("Worker 监测密钥已变化，停止删除".into());
        }
        let journal = pending
            .as_ref()
            .map(|p| p.journal.clone())
            .unwrap_or_else(|| format!("关闭监测 {} ({})", account_id, random_id()));
        if pending.is_none() {
            self.journal_start(&journal)?;
            self.db.pending_monitor_changes.push(PendingMonitorChange {
                account_id: account_id.into(),
                endpoint: account.monitor_endpoint.clone().unwrap_or_default(),
                enabled: false,
                journal: journal.clone(),
            });
            self.persist()?;
        }
        if schedule_ready {
            if let Err(e) = self
                .cloud
                .set_schedules(&token, account_id, &resources.script, false)
                .await
            {
                self.journal_note(&journal, "计划任务关闭未完成")?;
                return Err(e.message);
            }
        }
        if raw.is_some() {
            if let Err(e) = self
                .cloud
                .delete_value(&token, account_id, &resources.namespace, "m:monitor")
                .await
            {
                self.journal_note(&journal, "监测配置删除未完成")?;
                return Err(e.message);
            }
        }
        if has_probe {
            if let Err(e) = self
                .cloud
                .delete_probe_secret(&token, account_id, &resources.script)
                .await
            {
                self.journal_note(&journal, "Worker 监测密钥删除未完成")?;
                return Err(e.message);
            }
        }
        let _ = keyring_delete(account_id, "probe");
        let before_finish = self.db.clone();
        let account = self
            .db
            .accounts
            .iter_mut()
            .find(|a| a.id == account_id)
            .ok_or("账号不存在")?;
        account.monitor_enabled = false;
        account.monitor_endpoint = None;
        account.needs_monitor_key = false;
        self.db
            .pending_monitor_changes
            .retain(|p| p.account_id != account_id);
        if let Err(e) = self.journal_end(&journal) {
            self.db = before_finish;
            return Err(e);
        }
        Ok(())
    }

    async fn apply_delete_link(&mut self, domain_id: &str, slug: &str) -> Result<(), String> {
        let domain = self.domain(domain_id)?.clone();
        let token = keyring_get(&domain.account_id, "token")?;
        let resources = self.ensure_domain_owned(&domain, &token).await?;
        let key = format!("l:{}:{slug}", domain.host);
        let previous = self
            .cloud
            .read_value(&token, &domain.account_id, &resources.namespace, &key)
            .await
            .map_err(problem)?
            .ok_or_else(|| {
                format!(
                    "云端没有链接 {} / {slug}，可能上次删除已生效。请在“Cloudflare 账户”页打开该账户的“管理账户”，点“从 Cloudflare 找回配置”核对",
                    domain.host
                )
            })?;
        let local = self
            .db
            .links
            .iter()
            .find(|l| l.domain_id == domain_id && l.slug == slug)
            .ok_or("本机链接不存在")?
            .clone();
        let remote: Value =
            serde_json::from_str(&previous).map_err(|_| "云端链接格式无效".to_string())?;
        if !remote_matches_link(&remote, &local) {
            return Err("云端链接目标已变化，请先找回".into());
        }
        let journal = format!("删除链接 {} / {} ({})", domain.host, slug, random_id());
        self.journal_start(&journal)?;
        if let Err(e) = self
            .cloud
            .delete_value(&token, &domain.account_id, &resources.namespace, &key)
            .await
        {
            if e.uncertain {
                self.journal_note(&journal, "删除结果不确定，需要人工核对")?;
            } else {
                self.journal_end(&journal)?;
            }
            return Err(e.message);
        }
        let before_links = self.db.links.clone();
        let before_operations = self.db.pending_operations.clone();
        self.db
            .links
            .retain(|l| l.domain_id != domain_id || l.slug != slug);
        clear_link_leftovers(
            &mut self.db.pending_operations,
            &domain.host,
            slug,
            &journal,
        );
        if let Err(e) = self.persist() {
            self.db.pending_operations = before_operations;
            let restored = self
                .cloud
                .write_value(
                    &token,
                    &domain.account_id,
                    &resources.namespace,
                    &key,
                    &previous,
                )
                .await
                .is_ok();
            if restored {
                // Restore the list exactly, keeping the link at its position.
                self.db.links = before_links;
                self.journal_end(&journal)?;
            } else {
                self.journal_note(&journal, "本机保存失败且云端恢复失败")?;
            }
            return Err(e);
        }
        self.journal_end(&journal)
    }

    async fn apply_remove_domain(&mut self, domain_id: &str) -> Result<(), String> {
        let domain = self.domain(domain_id)?.clone();
        let token = keyring_get(&domain.account_id, "token")?;
        let resources = match self.ensure_domain_owned(&domain, &token).await {
            Ok(resources) => resources,
            // An earlier removal may already have deleted the prefix config
            // or the route (its answer was lost). Any other failure, such as
            // a network error, is reported as it is without more reads.
            Err(error) if error != DOMAIN_ROUTE_CHANGED && error != DOMAIN_CONFIG_LOST => {
                return Err(error);
            }
            Err(error) => {
                return match self.removal_leftover(&domain, &token).await {
                    Some(leftover) => {
                        self.finish_interrupted_removal(&domain, &token, leftover)
                            .await
                    }
                    None => Err(error),
                };
            }
        };
        let keys = self
            .cloud
            .list_keys(
                &token,
                &domain.account_id,
                &resources.namespace,
                &format!("l:{}:", domain.host),
            )
            .await
            .map_err(problem)?;
        let expected: HashSet<String> = self
            .db
            .links
            .iter()
            .filter(|l| l.domain_id == domain_id)
            .map(|l| format!("l:{}:{}", domain.host, l.slug))
            .collect();
        // Fewer links than this computer lists is what an earlier removal
        // that stopped while deleting links leaves (or links deleted from
        // another computer): continue with the rest. No earlier record is
        // asked for, so a record cleared by hand costs nothing. A key this
        // computer does not list is never deleted.
        if keys.iter().any(|k| !expected.contains(k)) {
            return Err("云端链接清单与本机不同，请先找回再移除".into());
        }
        // The key list above only serves to refuse keys this computer does
        // not list. What to delete is read key by key from this computer's
        // own list, so a key list that lags behind a recent save or delete
        // neither leaves a link behind nor stops the removal.
        let mut wanted: Vec<&String> = expected.iter().collect();
        wanted.sort();
        let mut saved = Vec::new();
        for key in wanted {
            if let Some(value) = self
                .cloud
                .read_value(&token, &domain.account_id, &resources.namespace, key)
                .await
                .map_err(problem)?
            {
                saved.push((key.clone(), value));
            }
        }
        let config_key = format!("c:{}", domain.host);
        let config = self
            .cloud
            .read_value(
                &token,
                &domain.account_id,
                &resources.namespace,
                &config_key,
            )
            .await
            .map_err(problem)?
            .ok_or("域名配置已消失")?;
        let journal = format!("移除域名 {} ({})", domain.host, random_id());
        self.journal_start(&journal)?;
        let mut deleted = Vec::new();
        for (key, value) in &saved {
            match self
                .cloud
                .delete_value(&token, &domain.account_id, &resources.namespace, key)
                .await
            {
                Ok(()) => deleted.push((key.clone(), value.clone())),
                Err(e) => {
                    if e.uncertain {
                        // The next removal continues from here (the subset
                        // rule above, or `removal_leftover`).
                        self.journal_note(&journal, "链接删除结果不确定")?;
                        return Err(format!("{}；{REMOVAL_RETRY_HINT}", e.message));
                    }
                    let restored = self
                        .restore_values(&token, &domain.account_id, &resources.namespace, &deleted)
                        .await;
                    if restored {
                        self.journal_end(&journal)?;
                    } else {
                        self.journal_note(&journal, "回滚链接失败")?;
                    }
                    return Err(e.message);
                }
            }
        }
        if let Err(e) = self
            .cloud
            .delete_value(
                &token,
                &domain.account_id,
                &resources.namespace,
                &config_key,
            )
            .await
        {
            if e.uncertain {
                self.journal_note(&journal, "前缀配置删除结果不确定")?;
                return Err(format!("{}；{REMOVAL_RETRY_HINT}", e.message));
            }
            let restored = self
                .restore_values(&token, &domain.account_id, &resources.namespace, &deleted)
                .await;
            if restored {
                self.journal_end(&journal)?;
            } else {
                self.journal_note(&journal, "回滚链接失败")?;
            }
            return Err(e.message);
        }
        if let Err(e) = self
            .cloud
            .delete(
                &token,
                &format!(
                    "zones/{}/workers/routes/{}",
                    domain.zone_id, domain.route_id
                ),
            )
            .await
        {
            if e.uncertain {
                self.journal_note(&journal, "路由删除结果不确定")?;
                return Err(format!("{}；{REMOVAL_RETRY_HINT}", e.message));
            }
            let restored = self
                .restore_values(&token, &domain.account_id, &resources.namespace, &deleted)
                .await
                && self
                    .cloud
                    .write_value(
                        &token,
                        &domain.account_id,
                        &resources.namespace,
                        &config_key,
                        &config,
                    )
                    .await
                    .is_ok();
            if restored {
                self.journal_end(&journal)?;
            } else {
                self.journal_note(&journal, "回滚域名配置失败")?;
            }
            return Err(e.message);
        }
        self.forget_removed_domain(&domain, &journal)
    }

    /// Drops a domain the cloud no longer serves, together with its links,
    /// and settles earlier unresolved removals of the same host in the same
    /// commit; then ends `journal`.
    fn forget_removed_domain(&mut self, domain: &Domain, journal: &str) -> Result<(), String> {
        let before = self.db.clone();
        self.db.links.retain(|l| l.domain_id != domain.id);
        self.db.domains.retain(|d| d.id != domain.id);
        clear_domain_leftovers(
            &mut self.db.pending_operations,
            &[format!("移除域名 {} (", domain.host)],
            journal,
        );
        if let Err(error) = self.persist() {
            self.db = before;
            return Err(error);
        }
        self.journal_end(journal)
    }

    /// Read-only: when a removal of `domain` stopped after its prefix config
    /// was deleted, says what is left to do: links still in the cloud (only
    /// keys of this domain's local links) and whether this tool's route for
    /// it is still there. `None` means the cloud is not in that state (or
    /// could not be read), so the normal checks apply.
    async fn removal_leftover(&self, domain: &Domain, token: &str) -> Option<RemovalLeftover> {
        let resources = self.account(&domain.account_id).ok()?.resources.clone()?;
        self.verify_resource_source(token, &domain.account_id, &resources)
            .await
            .ok()?;
        let config_key = format!("c:{}", domain.host);
        let config = self
            .cloud
            .read_value(token, &domain.account_id, &resources.namespace, &config_key)
            .await
            .ok()?;
        if config.is_some() {
            return None;
        }
        // Links go before the prefix config. Links left without the config
        // (for example a route delete was refused and the config could not be
        // put back) are finished only when every key is one of this domain's
        // local links. No earlier record is asked for: the user is removing
        // this domain, and a record cleared by hand must not leave a domain
        // that can neither be removed nor recovered.
        let links = self
            .cloud
            .list_keys(
                token,
                &domain.account_id,
                &resources.namespace,
                &format!("l:{}:", domain.host),
            )
            .await
            .ok()?;
        if !links.is_empty() {
            let local: HashSet<String> = self
                .db
                .links
                .iter()
                .filter(|l| l.domain_id == domain.id)
                .map(|l| format!("l:{}:{}", domain.host, l.slug))
                .collect();
            if links.iter().any(|key| !local.contains(key)) {
                return None;
            }
        }
        let routes = self
            .cloud
            .get(token, &format!("zones/{}/workers/routes", domain.zone_id))
            .await
            .ok()?;
        let routes = routes["result"].as_array()?;
        let route_left = match routes
            .iter()
            .find(|r| r["id"].as_str() == Some(domain.route_id.as_str()))
        {
            None => false,
            Some(route)
                if route["script"].as_str() == Some(resources.script.as_str())
                    && route["pattern"].as_str()
                        == Some(route_pattern(&domain.host, &domain.prefix).as_str()) =>
            {
                true
            }
            // The recorded route now belongs to something else: leave it.
            Some(_) => return None,
        };
        Some(RemovalLeftover {
            namespace: resources.namespace,
            links,
            route_left,
        })
    }

    /// Finishes a removal whose prefix config is already gone: deletes the
    /// links still left, then this tool's route if it is still there, then
    /// forgets the domain locally. An uncertain delete keeps the record; a
    /// definite failure reports the error and keeps the earlier record.
    async fn finish_interrupted_removal(
        &mut self,
        domain: &Domain,
        token: &str,
        leftover: RemovalLeftover,
    ) -> Result<(), String> {
        let journal = format!("移除域名 {} ({})", domain.host, random_id());
        self.journal_start(&journal)?;
        for key in &leftover.links {
            if let Err(e) = self
                .cloud
                .delete_value(token, &domain.account_id, &leftover.namespace, key)
                .await
            {
                if !answered_not_found(&e) {
                    if e.uncertain {
                        self.journal_note(&journal, "链接删除结果不确定")?;
                        return Err(format!("{}；{REMOVAL_RETRY_HINT}", e.message));
                    }
                    self.journal_end(&journal)?;
                    return Err(e.message);
                }
            }
        }
        if leftover.route_left {
            if let Err(e) = self
                .cloud
                .delete(
                    token,
                    &format!(
                        "zones/{}/workers/routes/{}",
                        domain.zone_id, domain.route_id
                    ),
                )
                .await
            {
                if !answered_not_found(&e) {
                    if e.uncertain {
                        self.journal_note(&journal, "路由删除结果不确定")?;
                        return Err(format!("{}；{REMOVAL_RETRY_HINT}", e.message));
                    }
                    self.journal_end(&journal)?;
                    return Err(e.message);
                }
            }
        }
        self.forget_removed_domain(domain, &journal)
    }

    async fn restore_values(
        &self,
        token: &str,
        account: &str,
        namespace: &str,
        values: &[(String, String)],
    ) -> bool {
        let mut all_ok = true;
        for (key, value) in values.iter().rev() {
            all_ok &= self
                .cloud
                .write_value(token, account, namespace, key, value)
                .await
                .is_ok();
        }
        all_ok
    }

    async fn apply_cleanup(&mut self, account_id: &str) -> Result<(), String> {
        if self.has_selftest_rotation(account_id) {
            return Err(format!(
                "此账号的自检密钥轮换尚未完成，请先用{RESUME_BAR}里这个账户的按钮把它做完"
            ));
        }
        if self.account(account_id)?.monitor_enabled
            || self
                .db
                .pending_monitor_changes
                .iter()
                .any(|p| p.account_id == account_id)
            || self.db.pending_pool_changes.iter().any(|p| {
                p.pool.account_ids.iter().any(|id| id == account_id)
                    || p.previous
                        .as_ref()
                        .is_some_and(|p| p.account_ids.iter().any(|id| id == account_id))
            })
        {
            return Err("请先关闭监测并恢复此账号未完成的平台或监测操作".into());
        }
        if self.db.domains.iter().any(|d| d.account_id == account_id) {
            return Err("此账号仍有域名".into());
        }
        let resources = self
            .account(account_id)?
            .resources
            .clone()
            .ok_or("没有可清理资源")?;
        let token = keyring_get(account_id, "token")?;
        let prefix = format!("清理账号 {account_id} (");
        let pending = self
            .db
            .pending_operations
            .iter()
            .find(|entry| entry.starts_with(&prefix))
            .map(|entry| entry.split('：').next().unwrap_or(entry).to_owned());
        // An earlier cleanup of this account checked the cloud data and got
        // as far as deleting the Worker: finish the remaining steps.
        if let Some(journal) = &pending {
            if let Err(error) = self
                .cloud
                .script_settings(&token, account_id, &resources.script)
                .await
            {
                if answered_not_found(&error) {
                    return self
                        .resume_cleanup(account_id, &resources, &token, journal)
                        .await;
                }
            }
        }
        self.verify_resource_source(&token, account_id, &resources)
            .await?;
        let manifest = self
            .cloud
            .read_value(&token, account_id, &resources.namespace, MANIFEST_KEY)
            .await
            .map_err(problem)?
            .ok_or("云端资源清单缺失")?;
        let parsed: Value =
            serde_json::from_str(&manifest).map_err(|_| "资源清单损坏".to_string())?;
        if parsed["accountId"] != account_id
            || parsed["script"] != resources.script
            || parsed["namespace"] != resources.namespace
        {
            return Err("资源归属无法确认".into());
        }
        let keys = self
            .cloud
            .list_keys(&token, account_id, &resources.namespace, "")
            .await
            .map_err(problem)?;
        // Any link (l:) or other record stops cleanup. A platform address copy
        // (p:) is allowed only when it is checked below against the local pool
        // library, so no unique data is deleted.
        if keys.iter().collect::<HashSet<_>>().len() != keys.len()
            || keys.iter().any(|key| !cleanup_may_remove_key(key))
        {
            return Err("KV 仍有业务或未知配置记录，停止清理".into());
        }
        let mut metadata = Vec::new();
        for key in keys.iter().filter(|key| key.as_str() != MANIFEST_KEY) {
            let raw = self
                .cloud
                .read_value(&token, account_id, &resources.namespace, key)
                .await
                .map_err(problem)?
                .ok_or("检测记录在核对中消失，请重新准备清理")?;
            if let Some(pool_id) = key.strip_prefix("p:") {
                if !valid_cleanup_pool_copy(pool_id, &raw, &self.db.pools) {
                    return Err(format!(
                        "此账号 KV 中仍有平台地址副本 {pool_id}，但本机没有这组平台地址或副本格式无法确认，停止清理；云端未改动"
                    ));
                }
            } else if !valid_cleanup_metadata(key, &raw) {
                return Err("遗留检测数据格式无法确认，停止清理".into());
            }
            metadata.push((key.clone(), raw));
        }
        let schedule = self
            .cloud
            .schedules(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        if !schedule["result"]["schedules"]
            .as_array()
            .is_some_and(|items| items.is_empty())
        {
            return Err("Worker 仍有计划任务或状态无法确认，停止清理".into());
        }
        let fresh_zones = self.fetch_zones(&token, account_id).await?;
        for zone in &fresh_zones {
            let routes = self
                .cloud
                .get(&token, &format!("zones/{}/workers/routes", zone.id))
                .await
                .map_err(problem)?;
            let items = routes["result"].as_array().ok_or("云端路由列表格式无效")?;
            if let Some(route) = items
                .iter()
                .find(|r| r["script"].as_str() == Some(resources.script.as_str()))
            {
                // Also what a skipped leftover of an interrupted removal
                // looks like, so the text names the rule and the way out.
                return Err(format!(
                    "还有转发规则 {} 指向这个账户的云端跳转服务，所以这次没有清理。请先点「从 Cloudflare 找回配置」，把找回的域名移除；如果找回后列表里没有这个域名，就把它用同样的目录重新添加一次再移除。然后再点「删除云端短链接服务」",
                    route["pattern"].as_str().unwrap_or("（未知）")
                ));
            }
        }
        let latest_keys = self
            .cloud
            .list_keys(&token, account_id, &resources.namespace, "")
            .await
            .map_err(problem)?;
        if latest_keys.iter().collect::<HashSet<_>>() != keys.iter().collect::<HashSet<_>>()
            || latest_keys.len() != keys.len()
        {
            return Err("云端记录清单在核对中变化，停止清理".into());
        }
        // Recheck the entire reviewed set before the first mutation, then each
        // record immediately before its scoped deletion. Provider writes are
        // still not a cross-resource atomic transaction.
        for (key, expected) in &metadata {
            if self
                .cloud
                .read_value(&token, account_id, &resources.namespace, key)
                .await
                .map_err(problem)?
                .as_ref()
                != Some(expected)
            {
                return Err("检测记录在核对中变化，停止清理".into());
            }
        }
        let journal = pending
            .clone()
            .unwrap_or_else(|| format!("清理账号 {} ({})", account_id, random_id()));
        if pending.is_none() {
            let previous = self.db.pending_operations.clone();
            if let Err(error) = self.journal_start(&journal) {
                self.db.pending_operations = previous;
                return Err(error);
            }
        } else {
            // An earlier persistence failure may have left only an in-memory
            // journal. Every retry must make its intent durable before DELETE.
            self.persist()?;
        }
        // This run started the journal and nothing in the cloud has been
        // deleted yet: a failure then ends the journal again instead of
        // leaving a record that only a finished cleanup could clear.
        let started_here = pending.is_none();
        let mut deleted_any = false;
        for (key, expected) in &metadata {
            let latest = self
                .cloud
                .read_value(&token, account_id, &resources.namespace, key)
                .await;
            match latest {
                Ok(Some(raw)) if &raw == expected => {}
                _ => {
                    if started_here && !deleted_any {
                        self.journal_end(&journal)?;
                        return Err(format!(
                            "遗留检测数据无法再次核实，停止清理；{CLEANUP_NOTHING_DELETED}"
                        ));
                    }
                    self.journal_note(
                        &journal,
                        "遗留检测数据读取失败或已变化；尚未删除 Worker/KV，请重新核对",
                    )?;
                    return Err(format!(
                        "遗留检测数据无法再次核实，停止清理；{CLEANUP_RETRY_HINT}"
                    ));
                }
            }
            // A platform address copy goes away with the namespace. Deleting it
            // here would leave the pool reported as synced but missing in the
            // cloud if a later step fails, blocking every edit of that pool.
            if key.starts_with("p:") {
                continue;
            }
            if let Err(error) = self
                .cloud
                .delete_value(&token, account_id, &resources.namespace, key)
                .await
            {
                if started_here && !deleted_any && !error.uncertain {
                    self.journal_end(&journal)?;
                    return Err(format!("{}；{CLEANUP_NOTHING_DELETED}", error.message));
                }
                self.journal_note(
                    &journal,
                    "遗留检测数据删除未完成或结果不确定；尚未删除 Worker/KV，可重新核对后继续清理",
                )?;
                return Err(format!("{}；{CLEANUP_RETRY_HINT}", error.message));
            }
            deleted_any = true;
        }
        if let Err(e) = self
            .cloud
            .delete(
                &token,
                &format!("accounts/{account_id}/workers/scripts/{}", resources.script),
            )
            .await
        {
            let (note, message) = cleanup_worker_delete_failure(&e, started_here && !deleted_any);
            match note {
                None => self.journal_end(&journal)?,
                Some(note) => {
                    self.journal_note(&journal, note)?;
                }
            }
            return Err(message);
        }
        self.journal_note(&journal, "Worker 已删，正在删除 KV")?;
        if let Err(e) = self
            .cloud
            .delete(
                &token,
                &format!(
                    "accounts/{account_id}/storage/kv/namespaces/{}",
                    resources.namespace
                ),
            )
            .await
        {
            self.journal_note(&journal, "Worker 已删除，KV 删除未完成或结果不确定")?;
            return Err(format!(
                "{}；Worker 已删除，KV 还没删完。{CLEANUP_RETRY_HINT}",
                e.message
            ));
        }
        self.finish_cleanup(account_id, &journal)
    }

    /// Continues a cleanup whose Worker is already deleted: the earlier run
    /// checked that the KV held only removable records. Deletes the KV if it
    /// is still there, then finishes locally.
    async fn resume_cleanup(
        &mut self,
        account_id: &str,
        resources: &Resources,
        token: &str,
        journal: &str,
    ) -> Result<(), String> {
        self.require_no_worker_upgrade(account_id)?;
        // An earlier persistence failure may have left only an in-memory
        // journal. Make the intent durable before the next DELETE.
        self.persist()?;
        let kv_path = format!(
            "accounts/{account_id}/storage/kv/namespaces/{}",
            resources.namespace
        );
        let namespaces = self
            .cloud
            .list_pages(
                token,
                &format!("accounts/{account_id}/storage/kv/namespaces"),
            )
            .await
            .map_err(|e| {
                format!(
                    "{}；Worker 已删除，KV 还没删完。{CLEANUP_RETRY_HINT}",
                    e.message
                )
            })?;
        if namespaces
            .iter()
            .any(|ns| ns["id"].as_str() == Some(resources.namespace.as_str()))
        {
            // The Worker may also have been deleted outside this app after an
            // earlier cleanup stopped before its own delete. Look at the key
            // names once more: a link or prefix config is never deleted here.
            match self
                .cloud
                .list_keys(token, account_id, &resources.namespace, "")
                .await
            {
                Ok(keys) if keys.iter().all(|key| cleanup_may_remove_key(key)) => {}
                Ok(_) => {
                    return Err(
                        "云端跳转服务已经删除，但这个账户的云端存储里还有链接或域名记录，为了不误删没有动它。请联系维护的人核对后处理"
                            .into(),
                    )
                }
                // Gone between the two reads: nothing is left to delete.
                Err(e) if answered_not_found(&e) => {
                    return self.finish_cleanup(account_id, journal)
                }
                Err(e) => {
                    return Err(format!(
                        "{}；Worker 已删除，KV 还没删完。{CLEANUP_RETRY_HINT}",
                        e.message
                    ))
                }
            }
            self.journal_note(journal, "Worker 已删，正在删除 KV")?;
            if let Err(e) = self.cloud.delete(token, &kv_path).await {
                if !answered_not_found(&e) {
                    self.journal_note(journal, "Worker 已删除，KV 删除未完成或结果不确定")?;
                    return Err(format!(
                        "{}；Worker 已删除，KV 还没删完。{CLEANUP_RETRY_HINT}",
                        e.message
                    ));
                }
            }
        }
        self.finish_cleanup(account_id, journal)
    }

    /// Local end of an account cleanup once the Worker and KV are gone.
    fn finish_cleanup(&mut self, account_id: &str, journal: &str) -> Result<(), String> {
        keyring_delete(account_id, "selftest")
            .map_err(|e| format!("{e}；云端已清理完。{CLEANUP_RETRY_HINT}"))?;
        let before_finish = self.db.clone();
        for pool in &mut self.db.pools {
            pool.account_ids.retain(|id| id != account_id);
            pool.sync_status
                .retain(|status| status.account_id != account_id);
        }
        if let Some(a) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            a.resources = None;
            a.has_resources = false;
            a.needs_selftest_key = false;
        }
        if let Err(error) = self.journal_end(journal) {
            self.db = before_finish;
            return Err(error);
        }
        Ok(())
    }

    async fn apply_rotate(&mut self, account_id: &str) -> Result<(), String> {
        self.start_selftest_rotation(account_id, false).await
    }

    async fn apply_legacy_selftest_recovery(&mut self, account_id: &str) -> Result<(), String> {
        self.start_selftest_rotation(account_id, true).await
    }

    async fn start_selftest_rotation(
        &mut self,
        account_id: &str,
        recovering_legacy: bool,
    ) -> Result<(), String> {
        self.require_credentials(account_id)?;
        let resources = self
            .account(account_id)?
            .resources
            .clone()
            .ok_or("账号没有 Worker")?;
        let missing_staging = self
            .db
            .pending_selftest_rotations
            .iter()
            .find(|pending| pending.account_id == account_id)
            .is_some_and(|pending| pending.status == SelftestRotationStatus::StagingMissing);
        if self
            .db
            .pending_selftest_rotations
            .iter()
            .any(|pending| pending.account_id == account_id)
            && !(recovering_legacy && missing_staging)
        {
            return Err(format!(
                "此账号已有未完成的自检密钥轮换，请先用{RESUME_BAR}里这个账户的按钮把它做完"
            ));
        }
        if !missing_staging && recovering_legacy != self.has_legacy_selftest_rotation(account_id) {
            return Err(if recovering_legacy {
                "此账号没有需要旧版恢复的自检密钥操作"
            } else {
                "此账号有未完成的旧版自检密钥操作，请先用页面上方“……项变更可继续处理”那一栏里这个账户的按钮把它做完"
            }
            .into());
        }

        let mut key = Zeroizing::new([0_u8; 32]);
        rand::thread_rng().fill_bytes(&mut *key);
        let new_hex = Zeroizing::new(hex::encode(key.as_slice()));
        keyring_set(account_id, "selftest-pending", &new_hex)?;

        let saved = if missing_staging {
            self.persist_rotation_mutation(|db| {
                let pending = db
                    .pending_selftest_rotations
                    .iter_mut()
                    .find(|pending| pending.account_id == account_id)
                    .ok_or_else(|| "自检密钥恢复记录不存在".to_string())?;
                pending.status = SelftestRotationStatus::Staged;
                let journal = pending.journal.clone();
                set_journal_note(
                    &mut db.pending_operations,
                    &journal,
                    "已重新安全暂存密钥，等待确认云端更新",
                )?;
                Ok(())
            })
        } else {
            let journal = format!("重置自检密钥 {} ({})", account_id, random_id());
            let pending = PendingSelftestRotation {
                account_id: account_id.into(),
                script: resources.script,
                namespace: resources.namespace,
                journal: journal.clone(),
                status: SelftestRotationStatus::Staged,
            };
            self.persist_rotation_mutation(|db| {
                db.pending_selftest_rotations.push(pending);
                db.pending_operations.push(journal);
                Ok(())
            })
        };
        if let Err(error) = saved {
            let _ = keyring_delete(account_id, "selftest-pending");
            return Err(error);
        }

        self.resume_selftest_rotation(account_id).await
    }

    fn rotation_failure(
        &mut self,
        account_id: &str,
        status: SelftestRotationStatus,
        note: &str,
        error: String,
    ) -> String {
        match self.update_selftest_rotation(account_id, status, note) {
            Ok(()) => error,
            Err(persist_error) => format!("{error}；恢复状态保存失败：{persist_error}"),
        }
    }

    async fn resume_selftest_rotation(&mut self, account_id: &str) -> Result<(), String> {
        self.require_credentials(account_id)?;
        let pending = self
            .db
            .pending_selftest_rotations
            .iter()
            .find(|pending| pending.account_id == account_id)
            .cloned()
            .ok_or("此账号没有可恢复的自检密钥轮换")?;
        let resources = self
            .account(account_id)?
            .resources
            .clone()
            .ok_or("账号没有 Worker")?;
        if pending.script != resources.script || pending.namespace != resources.namespace {
            return Err("账号云端资源已变化，不能继续旧的自检密钥轮换".into());
        }

        let staged = match read_optional_staged_selftest(account_id).await {
            Ok(Some(staged)) => staged,
            Ok(None) => {
                return Err(self.rotation_failure(
                    account_id,
                    SelftestRotationStatus::StagingMissing,
                    "安全暂存密钥缺失，需要明确确认后重新建立",
                    "系统凭据库中找不到安全暂存密钥".into(),
                ));
            }
            Err(error) => {
                return Err(self.rotation_failure(
                    account_id,
                    pending.status.clone(),
                    "无法读取安全暂存密钥，已停止恢复",
                    error,
                ));
            }
        };

        if pending.status != SelftestRotationStatus::CloudApplied {
            let token = read_account_token(account_id).await.map_err(|error| {
                self.rotation_failure(
                    account_id,
                    SelftestRotationStatus::DefinitiveFailure,
                    "读取访问令牌失败，尚未写入云端",
                    error,
                )
            })?;
            if let Err(error) = self
                .verify_resource_source(&token, account_id, &resources)
                .await
            {
                return Err(self.rotation_failure(
                    account_id,
                    SelftestRotationStatus::DefinitiveFailure,
                    "云端资源预检失败，尚未更新密钥",
                    error,
                ));
            }
            let manifest = match self
                .cloud
                .read_value(&token, account_id, &resources.namespace, MANIFEST_KEY)
                .await
            {
                Ok(Some(manifest)) => manifest,
                Ok(None) => {
                    return Err(self.rotation_failure(
                        account_id,
                        SelftestRotationStatus::DefinitiveFailure,
                        "云端资源清单缺失，尚未更新密钥",
                        "云端资源清单缺失".into(),
                    ));
                }
                Err(error) => {
                    return Err(self.rotation_failure(
                        account_id,
                        SelftestRotationStatus::DefinitiveFailure,
                        "读取云端资源清单失败，尚未更新密钥",
                        error.message,
                    ));
                }
            };
            let parsed: Value = match serde_json::from_str(&manifest) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return Err(self.rotation_failure(
                        account_id,
                        SelftestRotationStatus::DefinitiveFailure,
                        "云端资源清单损坏，尚未更新密钥",
                        "云端资源清单损坏".into(),
                    ));
                }
            };
            if parsed["accountId"] != account_id
                || parsed["script"] != resources.script
                || parsed["namespace"] != resources.namespace
            {
                return Err(self.rotation_failure(
                    account_id,
                    SelftestRotationStatus::DefinitiveFailure,
                    "云端资源归属不匹配，尚未更新密钥",
                    "云端资源归属不匹配".into(),
                ));
            }
            if let Err(error) = self
                .cloud
                .script_settings(&token, account_id, &resources.script)
                .await
            {
                return Err(self.rotation_failure(
                    account_id,
                    SelftestRotationStatus::DefinitiveFailure,
                    "读取 Worker 绑定失败，尚未更新密钥",
                    error.message,
                ));
            }
            if let Err(error) = self
                .cloud
                .rotate_secret(&token, account_id, &resources.script, &staged)
                .await
            {
                let (status, note) = if error.uncertain {
                    (
                        SelftestRotationStatus::Uncertain,
                        "云端密钥更新结果不确定，等待人工确认恢复",
                    )
                } else {
                    (
                        SelftestRotationStatus::DefinitiveFailure,
                        "云端拒绝密钥更新，等待人工确认恢复",
                    )
                };
                return Err(self.rotation_failure(account_id, status, note, error.message));
            }
            self.update_selftest_rotation(
                account_id,
                SelftestRotationStatus::CloudApplied,
                "云端密钥已更新，正在启用本机密钥",
            )?;
        }

        if let Err(error) = keyring_set(account_id, "selftest", &staged) {
            return Err(self.rotation_failure(
                account_id,
                SelftestRotationStatus::CloudApplied,
                "云端已更新，本机密钥启用失败",
                error,
            ));
        }

        let prefix = selftest_rotation_prefix(account_id);
        self.persist_rotation_mutation(|db| {
            if !db
                .pending_selftest_rotations
                .iter()
                .any(|pending| pending.account_id == account_id)
            {
                return Err("自检密钥恢复记录不存在".into());
            }
            db.pending_selftest_rotations
                .retain(|pending| pending.account_id != account_id);
            db.pending_operations
                .retain(|entry| !entry.starts_with(&prefix));
            let account = db
                .accounts
                .iter_mut()
                .find(|account| account.id == account_id)
                .ok_or_else(|| "找不到此账号".to_string())?;
            account.needs_selftest_key = false;
            Ok(())
        })?;
        let _ = keyring_delete(account_id, "selftest-pending");
        Ok(())
    }

    /// Read-only: lists the account's KV namespaces and returns those holding
    /// an ownership manifest of this app for this account. A namespace without
    /// a manifest is skipped; a failed list or read is an error.
    async fn owned_manifest_candidates(
        &self,
        account_id: &str,
        token: &str,
    ) -> Result<Vec<Resources>, String> {
        let namespaces = self
            .cloud
            .list_pages(
                token,
                &format!("accounts/{account_id}/storage/kv/namespaces"),
            )
            .await
            .map_err(problem)?;
        let mut candidates = Vec::new();
        for ns in namespaces {
            let Some(id) = ns["id"].as_str() else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let Some(raw) = self
                .cloud
                .read_value(token, account_id, id, MANIFEST_KEY)
                .await
                .map_err(problem)?
            else {
                continue;
            };
            let Ok(manifest) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let Some(script) = manifest["script"].as_str() else {
                continue;
            };
            if manifest["schema"] != SCHEMA
                || manifest["accountId"] != account_id
                || manifest["namespace"] != id
                || !valid_id(script)
            {
                continue;
            }
            candidates.push(Resources {
                script: script.into(),
                namespace: id.into(),
            });
        }
        Ok(candidates)
    }

    async fn discover_owned_resources(
        &self,
        account_id: &str,
        token: &str,
    ) -> Result<Resources, String> {
        let mut matches = Vec::new();
        for resources in self.owned_manifest_candidates(account_id, token).await? {
            // A matching ownership manifest is a candidate, not permission to
            // ignore an unreadable or altered Worker and choose another one.
            self.verify_resource_source(token, account_id, &resources)
                .await?;
            matches.push(resources);
        }
        if matches.len() != 1 {
            return Err("未找到唯一且已验证的 Worker/KV 资源组合".into());
        }
        let resources = matches.remove(0);
        Ok(resources)
    }

    fn require_selftest_resource_recovery(&self, account_id: &str) -> Result<(), String> {
        self.require_no_worker_upgrade(account_id)?;
        self.require_credentials(account_id)?;
        if !self.db.can_recover_selftest_resources(account_id) {
            return Err(
                "仅能为缺少本机检测配置的旧版恢复记录找回资源；请先到页面上方「查看待处理记录」里核对该账户的其他记录".into(),
            );
        }
        Ok(())
    }

    async fn recover_selftest_resources(&mut self, account_id: &str) -> Result<(), String> {
        self.require_selftest_resource_recovery(account_id)?;
        let token = read_account_token(account_id).await?;
        let resources = self.discover_owned_resources(account_id, &token).await?;
        self.require_selftest_resource_recovery(account_id)?;
        let index = self
            .db
            .accounts
            .iter()
            .position(|a| a.id == account_id)
            .ok_or("找不到此账号")?;
        let previous = self.db.accounts[index].clone();
        self.db.accounts[index].resources = Some(resources);
        self.db.accounts[index].has_resources = true;
        if let Err(error) = self.persist() {
            self.db.accounts[index] = previous;
            return Err(error);
        }
        Ok(())
    }

    async fn recover_account(&mut self, account_id: &str) -> Result<(), String> {
        self.require_no_worker_upgrade(account_id)?;
        self.require_credentials(account_id)?;
        if !self.db.pending_monitor_changes.is_empty()
            || !self.db.pending_pool_changes.is_empty()
            || self.has_selftest_rotation(account_id)
        {
            return Err("请先恢复未完成的云端操作再找回账号".into());
        }
        let token = keyring_get(account_id, "token")?;
        self.account(account_id)?;
        let resources = self.discover_owned_resources(account_id, &token).await?;
        // Cached zones are only UI hints. Recovery replaces this account's
        // domain/link records, so discovery must use the current visible zones.
        let fresh_zones = self.fetch_zones(&token, account_id).await?;
        let mut zone_ids = HashSet::new();
        let mut zone_names = HashSet::new();
        for zone in &fresh_zones {
            if !valid_id(&zone.id)
                || normalize_host(&zone.name).as_deref() != Ok(zone.name.as_str())
                || !zone_ids.insert(zone.id.as_str())
                || !zone_names.insert(zone.name.as_str())
            {
                return Err("云端域名区域清单无效或重复，停止找回".into());
            }
        }
        if self.db.domains.iter().any(|domain| {
            domain.account_id == account_id && !zone_ids.contains(domain.zone_id.as_str())
        }) {
            return Err("当前令牌可见的区域未覆盖本机已登记域名，停止找回以保留现有记录".into());
        }
        let mut recovered_domains = Vec::new();
        // Host -> pattern of this tool's first route seen for it.
        let mut recovered_hosts = std::collections::HashMap::<String, String>::new();
        for zone in &fresh_zones {
            let owner = self
                .cloud
                .get(&token, &format!("zones/{}", zone.id))
                .await
                .map_err(problem)?;
            if owner["result"]["id"].as_str() != Some(zone.id.as_str())
                || owner["result"]["account"]["id"].as_str() != Some(account_id)
            {
                return Err("无法确认找回域名区域归属此账号".into());
            }
            let routes = self
                .cloud
                .get(&token, &format!("zones/{}/workers/routes", zone.id))
                .await
                .map_err(problem)?;
            let Some(items) = routes["result"].as_array() else {
                return Err("路由列表格式无效".into());
            };
            for route in items {
                if route["script"].as_str() != Some(resources.script.as_str()) {
                    continue;
                }
                let pattern = route["pattern"]
                    .as_str()
                    .ok_or("此 Worker 的路由格式无法确认，停止找回")?;
                let (host, path) = pattern
                    .split_once('/')
                    .ok_or("此 Worker 的路由格式无法确认，停止找回")?;
                let prefix = path
                    .strip_suffix("/*")
                    .ok_or("此 Worker 的路由格式无法确认，停止找回")?;
                let route_id = value_str(route, "id")?;
                if normalize_host(host).as_deref() != Ok(host)
                    || validate_prefix(prefix).is_err()
                    || !(host == zone.name || host.ends_with(&format!(".{}", zone.name)))
                    || !valid_id(route_id)
                {
                    return Err("此 Worker 的路由无效或主机名重复，停止找回以保留现有记录".into());
                }
                // Two routes of this tool for one host: recovery cannot tell
                // which one to keep. Nothing local has changed yet.
                if let Some(first) = recovered_hosts.get(host) {
                    return Err(duplicate_route_message(host, first, pattern));
                }
                recovered_hosts.insert(host.to_owned(), pattern.to_owned());
                let Some(raw) = self
                    .cloud
                    .read_value(
                        &token,
                        account_id,
                        &resources.namespace,
                        &format!("c:{host}"),
                    )
                    .await
                    .map_err(problem)?
                else {
                    // A route whose prefix config is gone is what an
                    // interrupted removal leaves behind. It serves nothing;
                    // skip it and recover the other domains, unless this
                    // computer lists the domain for this account and links of
                    // the host are still there: skipping would drop the local
                    // copy of the domain and its links. A host this computer
                    // does not list has nothing local to lose.
                    let links = self
                        .cloud
                        .list_keys(
                            &token,
                            account_id,
                            &resources.namespace,
                            &format!("l:{host}:"),
                        )
                        .await
                        .map_err(problem)?;
                    if !links.is_empty()
                        && self
                            .db
                            .domains
                            .iter()
                            .any(|d| d.host == host && d.account_id == account_id)
                    {
                        return Err(format!(
                            "域名 {host} 的转发规则还在，但前缀配置已经不在，云端还留着它的短链接。为了不丢本机记录，这次没有找回。如果这个域名本来就是要移除的，请到「域名管理」对它再点一次「移除域名」；否则请联系维护的人"
                        ));
                    }
                    continue;
                };
                let config: Value =
                    serde_json::from_str(&raw).map_err(|_| "前缀记录格式无效".to_string())?;
                if config["prefix"].as_str() != Some(prefix) {
                    return Err("路由与前缀记录不一致".into());
                }
                recovered_domains.push(Domain {
                    id: random_id(),
                    account_id: account_id.into(),
                    zone_id: zone.id.clone(),
                    host: host.into(),
                    prefix: prefix.into(),
                    route_id: route_id.into(),
                });
            }
        }
        let mut recovered_pools = self.db.pools.clone();
        for pool in &mut recovered_pools {
            pool.account_ids.retain(|id| id != account_id);
            pool.sync_status
                .retain(|status| status.account_id != account_id);
        }
        let mut remote_pool_ids = HashSet::new();
        let pool_keys = self
            .cloud
            .list_keys(&token, account_id, &resources.namespace, "p:")
            .await
            .map_err(problem)?;
        for key in pool_keys {
            let id = key.strip_prefix("p:").ok_or("平台地址键无效")?;
            if !pools::valid_id(id) || !remote_pool_ids.insert(id.to_owned()) {
                return Err("平台地址键无效".into());
            }
            let raw = self
                .cloud
                .read_value(&token, account_id, &resources.namespace, &key)
                .await
                .map_err(problem)?
                .ok_or("平台地址键在扫描中消失")?;
            let value: Value = serde_json::from_str(&raw).map_err(|_| "平台地址记录格式无效")?;
            if value["version"] != 1 {
                return Err("平台地址版本不受支持".into());
            }
            let official: model::Template = serde_json::from_value(value["official"].clone())
                .map_err(|_| "平台地址默认模板无效")?;
            let candidates: Vec<model::PoolCandidate> =
                serde_json::from_value(value["candidates"].clone())
                    .map_err(|_| "大陆备用地址模板无效")?;
            let updated = value["revision"].as_str().ok_or("平台地址修订号无效")?;
            let mut pool = Pool {
                id: id.into(),
                name: format!("平台地址 {id}"),
                official,
                candidates,
                updated: updated.into(),
                account_ids: vec![account_id.into()],
                sync_status: vec![PoolSyncStatus {
                    account_id: account_id.into(),
                    status: "synced".into(),
                    message: "已找回".into(),
                }],
            };
            pools::validate_pool(&pool)?;
            if let Some(existing) = recovered_pools.iter_mut().find(|p| p.id == id) {
                if pools::cloud_value(existing) != pools::cloud_value(&pool) {
                    return Err("多个账号的同名平台地址配置不一致".into());
                }
                if !existing.account_ids.contains(&account_id.to_string()) {
                    existing.account_ids.push(account_id.into());
                }
                existing.sync_status.retain(|s| s.account_id != account_id);
                existing.sync_status.append(&mut pool.sync_status);
            } else {
                recovered_pools.push(pool);
            }
        }
        let mut recovered_links = Vec::new();
        for domain in &recovered_domains {
            let keys = self
                .cloud
                .list_keys(
                    &token,
                    account_id,
                    &resources.namespace,
                    &format!("l:{}:", domain.host),
                )
                .await
                .map_err(problem)?;
            for key in keys {
                let slug = key
                    .strip_prefix(&format!("l:{}:", domain.host))
                    .ok_or("链接键格式无效")?;
                validate_slug(slug)?;
                let raw = self
                    .cloud
                    .read_value(&token, account_id, &resources.namespace, &key)
                    .await
                    .map_err(problem)?
                    .ok_or("链接记录缺失")?;
                let data: Value =
                    serde_json::from_str(&raw).map_err(|_| "链接记录格式无效".to_string())?;
                if let Some(pool_id) = data["poolId"].as_str() {
                    if !remote_pool_ids.contains(pool_id) {
                        return Err("云端链接使用的平台地址不属于此账号".into());
                    }
                }
                recovered_links.push(link_from_remote(&data, &domain.id, slug, &recovered_pools)?);
            }
        }
        let monitor_raw = self
            .cloud
            .read_value(&token, account_id, &resources.namespace, "m:monitor")
            .await
            .map_err(problem)?;
        let schedule = self
            .cloud
            .schedules(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let schedules = schedule["result"]["schedules"]
            .as_array()
            .ok_or("计划任务列表格式无效")?;
        let (monitor_enabled, monitor_endpoint) = if let Some(raw) = monitor_raw {
            let config: Value = serde_json::from_str(&raw).map_err(|_| "监测配置格式无效")?;
            validate_monitor_config(&config)?;
            let endpoint =
                monitor_endpoint(config["endpoint"].as_str().ok_or("监测服务地址缺失")?)?;
            let ids = config["poolIds"].as_array().ok_or("监测平台地址清单无效")?;
            let actual: std::collections::HashSet<&str> = ids
                .iter()
                .map(|v| v.as_str().ok_or("监测平台地址清单无效"))
                .collect::<Result<_, _>>()?;
            let expected: std::collections::HashSet<&str> = recovered_pools
                .iter()
                .filter(|p| p.account_ids.contains(&account_id.to_string()))
                .map(|p| p.id.as_str())
                .collect();
            if schedules.len() != 1
                || schedules[0]["cron"] != "*/15 * * * *"
                || actual.len() != ids.len()
                || actual != expected
            {
                return Err("云端监测配置与计划任务不一致，停止找回".into());
            }
            (true, Some(endpoint))
        } else {
            if !schedules.is_empty() {
                return Err("Worker 有未登记计划任务，停止找回".into());
            }
            (false, None)
        };
        let key_missing = keyring_get_optional(account_id, "selftest")?.is_none();
        let monitor_key_missing =
            monitor_enabled && keyring_get_optional(account_id, "probe")?.is_none();
        let before_finish = self.db.clone();
        // Recovery has just compared this account with the cloud, so earlier
        // add/remove-domain and save/delete-link records for hosts in its
        // zones are settled in the same commit.
        let other_hosts: HashSet<String> = self
            .db
            .domains
            .iter()
            .filter(|d| d.account_id != account_id)
            .map(|d| d.host.clone())
            .collect();
        self.db.pending_operations.retain(|entry| {
            names_leftover_resources(entry)
                || !journal_host(entry).is_some_and(|host| {
                    !other_hosts.contains(host)
                        && fresh_zones.iter().any(|zone| {
                            host == zone.name || host.ends_with(&format!(".{}", zone.name))
                        })
                })
        });
        let old_ids: HashSet<_> = self
            .db
            .domains
            .iter()
            .filter(|d| d.account_id == account_id)
            .map(|d| d.id.clone())
            .collect();
        self.db.links.retain(|l| !old_ids.contains(&l.domain_id));
        self.db.domains.retain(|d| d.account_id != account_id);
        self.db.domains.extend(recovered_domains);
        self.db.links.extend(recovered_links);
        self.db.pools = recovered_pools;
        if let Some(a) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            a.zone_count = fresh_zones.len();
            a.zones = fresh_zones;
            a.checked_at = Some(now());
            a.resources = Some(resources);
            a.has_resources = true;
            a.needs_selftest_key = key_missing;
            a.monitor_enabled = monitor_enabled;
            a.monitor_endpoint = monitor_endpoint;
            a.needs_monitor_key = monitor_key_missing;
        }
        if let Err(error) = self.persist() {
            self.db = before_finish;
            return Err(error);
        }
        Ok(())
    }

    fn selftest_snapshot(
        &self,
        domain_id: &str,
        slug: &str,
    ) -> Result<Option<SelftestSnapshot>, String> {
        validate_slug(slug)?;
        let domain = self.domain(domain_id)?;
        self.require_credentials(&domain.account_id)?;
        if self.has_selftest_rotation(&domain.account_id) {
            return Ok(None);
        }
        let link = self
            .db
            .links
            .iter()
            .find(|l| l.domain_id == domain_id && l.slug == slug)
            .ok_or("找不到此链接")?;
        let Some(key_hex) = keyring_get_optional(&domain.account_id, "selftest")? else {
            return Ok(None);
        };
        let key_hex = Zeroizing::new(key_hex);
        let bytes = hex::decode(key_hex.as_str()).map_err(|_| "自检密钥格式无效".to_string())?;
        if bytes.len() != 32 {
            return Err("自检密钥长度无效".into());
        }
        let path = format!("/{}/{}", domain.prefix, slug);
        let url = format!("https://{}{}", domain.host, path);
        let pool = if let (Some(pool_id), Some(code)) = (&link.pool_id, &link.code) {
            let pool = self
                .db
                .pools
                .iter()
                .find(|p| p.id == *pool_id)
                .cloned()
                .ok_or("找不到平台地址")?;
            let namespace = self
                .account(&domain.account_id)?
                .resources
                .as_ref()
                .ok_or("账号资源缺失")?
                .namespace
                .clone();
            Some((
                pool,
                code.clone(),
                domain.account_id.clone(),
                namespace,
                Zeroizing::new(keyring_get(&domain.account_id, "token")?),
            ))
        } else {
            None
        };
        let (cn_url, default_url) = if let Some((pool, code, _, _, _)) = &pool {
            let candidate = pool
                .candidates
                .iter()
                .find(|c| c.enabled)
                .ok_or("这组平台地址没有已启用的大陆备用地址")?;
            (
                pools::compose(&model::Template::from(candidate), code)?,
                pools::compose(&pool.official, code)?,
            )
        } else {
            (link.cn_url.clone(), link.default_url.clone())
        };
        Ok(Some(SelftestSnapshot {
            cloud: self.cloud.clone(),
            host: domain.host.clone(),
            path,
            url,
            cn_url,
            default_url,
            key: Zeroizing::new(bytes),
            pool,
        }))
    }

    fn health_snapshot(&self, pool_id: &str) -> Result<HealthSnapshot, String> {
        let pool = self
            .db
            .pools
            .iter()
            .find(|p| p.id == pool_id)
            .cloned()
            .ok_or("找不到平台地址")?;
        // Check every enabled account before reading even the first token.
        for id in &pool.account_ids {
            let account = self.account(id)?;
            if account.resources.is_some() && account.monitor_enabled {
                self.require_credentials(id)?;
            }
        }
        let mut accounts = Vec::new();
        for id in &pool.account_ids {
            let account = self.account(id)?;
            if let Some(resources) = &account.resources {
                // Disabled monitoring produces a local status row, so it must
                // not require access to this account's system credential item.
                let token = if account.monitor_enabled {
                    self.require_credentials(id)?;
                    Some(Zeroizing::new(keyring_get(id, "token")?))
                } else {
                    None
                };
                accounts.push((id.clone(), token, resources.namespace.clone()));
            }
        }
        Ok(HealthSnapshot {
            pool,
            accounts,
            cloud: self.cloud.clone(),
        })
    }

    fn target_snapshot(
        &self,
        domain_id: &str,
        slug: &str,
    ) -> Result<Vec<(String, String)>, String> {
        let link = self
            .db
            .links
            .iter()
            .find(|l| l.domain_id == domain_id && l.slug == slug)
            .ok_or("找不到此链接")?;
        if let (Some(pool_id), Some(code)) = (&link.pool_id, &link.code) {
            let pool = self
                .db
                .pools
                .iter()
                .find(|p| &p.id == pool_id)
                .ok_or("找不到平台地址")?;
            let mut targets = vec![("官网链接".into(), pools::compose(&pool.official, code)?)];
            for (index, c) in pool.candidates.iter().filter(|c| c.enabled).enumerate() {
                targets.push((
                    format!("大陆访问地址 {}", index + 1),
                    pools::compose(&model::Template::from(c), code)?,
                ));
            }
            Ok(targets)
        } else {
            Ok(vec![
                ("大陆访问地址".into(), link.cn_url.clone()),
                (
                    "默认链接（中国大陆以外访客）".into(),
                    link.default_url.clone(),
                ),
            ])
        }
    }
}

async fn run_pool_health(snapshot: HealthSnapshot) -> Result<Value, String> {
    let mut accounts = Vec::new();
    for id in &snapshot.pool.account_ids {
        let Some((_, token, namespace)) = snapshot
            .accounts
            .iter()
            .find(|(account, _, _)| account == id)
        else {
            accounts.push(
                json!({"accountId":id,"source":"unconfigured","checkedAt":null,
                "status":"unknown","candidates":[]}),
            );
            continue;
        };
        let Some(token) = token else {
            accounts.push(json!({"accountId":id,"source":"unconfigured","checkedAt":null,
                "status":"unknown","candidates":snapshot.pool.candidates.iter().map(|c|
                    json!({"id":c.id,"status":"unknown","checkedAt":null,"message":"未启用大陆监测"}))
                    .collect::<Vec<_>>() }));
            continue;
        };
        let remote_pool = snapshot
            .cloud
            .read_value(token, id, namespace, &format!("p:{}", snapshot.pool.id))
            .await;
        let synced = remote_pool
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .is_some_and(|value| pools::matching_cloud_value(&snapshot.pool, &value));
        if !synced {
            accounts.push(json!({"accountId":id,"source":"unknown","checkedAt":null,
                "status":"unknown","candidates":snapshot.pool.candidates.iter().map(|c|
                    json!({"id":c.id,"status":"unknown","checkedAt":null,"message":"平台地址云端版本未确认"}))
                    .collect::<Vec<_>>() }));
            continue;
        }
        let raw = snapshot
            .cloud
            .read_value(token, id, namespace, &format!("h:{}", snapshot.pool.id))
            .await;
        let parsed = raw
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str::<Value>(&v).ok())
            .filter(pools::valid_health);
        let revision_ok = parsed
            .as_ref()
            .is_some_and(|v| v["revision"].as_str() == Some(&snapshot.pool.updated));
        let checked_at = parsed
            .as_ref()
            .and_then(|v| v["checkedAt"].as_i64())
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|v| v.to_rfc3339());
        let mut candidates = Vec::new();
        for c in &snapshot.pool.candidates {
            let record = parsed.as_ref().map(|v| &v["targets"][&c.id]);
            let definitive = record.and_then(|v| v["checkedAt"].as_i64());
            let fresh = revision_ok
                && definitive.is_some_and(|ts| {
                    ts <= Utc::now().timestamp() && Utc::now().timestamp() - ts <= 3600
                });
            let status = if fresh {
                record
                    .and_then(|v| v["state"].as_str())
                    .filter(|s| matches!(*s, "healthy" | "unhealthy"))
                    .unwrap_or("unknown")
            } else {
                "unknown"
            };
            let at = definitive
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                .map(|v| v.to_rfc3339());
            candidates.push(json!({"id":c.id,"status":status,"checkedAt":at,
                "message":if fresh {"监测服务上次确认结果"} else {"缺少当前修订的近期确认结果"}}));
        }
        let status = if candidates.iter().any(|c| c["status"] == "unhealthy") {
            "unhealthy"
        } else if candidates.iter().all(|c| c["status"] == "healthy") {
            "healthy"
        } else {
            "unknown"
        };
        accounts.push(
            json!({"accountId":id,"source":if parsed.is_some(){"mainland_provider"}else{"unknown"},
            "checkedAt":checked_at,"status":status,"candidates":candidates}),
        );
    }
    Ok(json!({"poolId":snapshot.pool.id,"accounts":accounts}))
}

/// Self-test summary when an attempt loop ended on a network failure.
const SELFTEST_NETWORK_MESSAGE: &str = "网络没连通，自检没有完成。请检查网络或代理后再检测一次";

/// Pause between signed self-test attempts.
const REGION_RETRY_PAUSE: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_secs(5)
};

async fn run_region_test(
    snapshot: &SelftestSnapshot,
    country: &str,
    label: &str,
    expected: Option<&str>,
    dns_mode: local_check::DnsMode,
) -> Result<DomainCheck, String> {
    let mut pending = false;
    // The latest attempt's network failure, if it ended with one.
    let mut network_failure: Option<cloud::ProbeError> = None;
    for attempt in 0..5 {
        let seconds = Utc::now().timestamp();
        let text = format!(
            "{}|{}|{}|{}",
            snapshot.host, snapshot.path, seconds, country
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&snapshot.key)
            .map_err(|_| "自检密钥无效".to_string())?;
        mac.update(text.as_bytes());
        let header = format!(
            "{seconds}.{country}.{}",
            hex::encode(mac.finalize().into_bytes())
        );
        let result = tokio::time::timeout(Duration::from_secs(6), async {
            match dns_mode {
                local_check::DnsMode::System => {
                    snapshot.cloud.probe(&snapshot.url, Some(header)).await
                }
                local_check::DnsMode::Public => {
                    snapshot
                        .cloud
                        .probe_with_mode(&snapshot.url, Some(header), dns_mode)
                        .await
                }
            }
        })
        .await;
        match result {
            Ok(Ok((302, Some(location)))) if expected == Some(location.as_str()) => {
                return Ok(domain_check::hard_check(
                    label,
                    true,
                    "302 与 Location 均正确",
                ))
            }
            Ok(Ok((503, None))) if expected.is_none() => {
                return Ok(domain_check::hard_check(
                    label,
                    false,
                    "云端监测记录显示所有大陆备用地址暂时不可用，转发返回 HTTP 503",
                ));
            }
            Ok(Err(error))
                if error
                    .reason
                    .is_some_and(|reason| !is_transient_network_reason(reason)) =>
            {
                // Resolver/address guard failures are definitive for this mode.
                // Preserve their typed cause; never retry them as propagation.
                return Ok(domain_check::classify_probe_detailed(
                    label,
                    &snapshot.url,
                    None,
                    Err(error),
                )
                .0);
            }
            Ok(Err(error)) if error.reason.is_some() => {
                // Timeouts and connection failures are worth another attempt.
                pending = true;
                network_failure = Some(error);
            }
            Err(_) => {
                pending = true;
                network_failure = Some(cloud::probe_timeout());
            }
            Ok(Ok((404, _))) | Ok(Err(_)) => {
                pending = true;
                network_failure = None;
            }
            _ => {
                pending = false;
                network_failure = None;
            }
        }
        if attempt < 4 {
            tokio::time::sleep(REGION_RETRY_PAUSE).await;
        }
    }
    if let Some(error) = network_failure {
        // Still a network failure after every attempt: say so, with its reason,
        // rather than suggesting that the edge is still propagating.
        return Ok(domain_check::classify_probe_detailed(label, &snapshot.url, None, Err(error)).0);
    }
    Ok(domain_check::hard_check(
        label,
        false,
        if pending {
            "边缘配置可能仍在传播或网络暂时不可用"
        } else {
            "响应状态或 Location 与预期不符"
        },
    ))
}

async fn run_selftest(snapshot: SelftestSnapshot) -> Result<Value, String> {
    run_selftest_with_mode(snapshot, local_check::DnsMode::System).await
}

async fn run_selftest_with_mode(
    snapshot: SelftestSnapshot,
    dns_mode: local_check::DnsMode,
) -> Result<Value, String> {
    let expected_cn = if let Some((pool, code, account, namespace, token)) = &snapshot.pool {
        let health = snapshot
            .cloud
            .read_value(token, account, namespace, &format!("h:{}", pool.id))
            .await
            .map_err(problem)?
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .filter(pools::valid_health);
        chosen_cn_target(pool, code, health.as_ref(), Utc::now().timestamp())?
    } else {
        Some(snapshot.cn_url.clone())
    };
    let Some(expected_cn) = expected_cn else {
        let (other, cn) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::try_join!(
                run_region_test(
                    &snapshot,
                    "US",
                    "其他地区",
                    Some(&snapshot.default_url),
                    dns_mode
                ),
                run_region_test(&snapshot, "CN", "中国大陆", None, dns_mode)
            )
        })
        .await
        .map_err(|_| "自检超时")??;
        return Ok(
            json!({"status":"failed","message":"云端监测记录显示所有已启用的大陆备用地址暂时不可用",
            "checks":[other,cn]}),
        );
    };
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::try_join!(
            run_region_test(
                &snapshot,
                "US",
                "其他地区",
                Some(&snapshot.default_url),
                dns_mode
            ),
            run_region_test(&snapshot, "CN", "中国大陆", Some(&expected_cn), dns_mode)
        )
    })
    .await;
    let checks = match result {
        Ok(Ok((other, cn))) => vec![other, cn],
        Ok(Err(e)) => return Err(e),
        Err(_) => vec![
            domain_check::hard_check("其他地区", false, "自检超时，请稍后重试"),
            domain_check::hard_check("中国大陆", false, "自检超时，请稍后重试"),
        ],
    };
    // A probe that never got through the network proves nothing about the
    // route: it stays "pending", never "failed", and is not called propagation.
    let network = checks
        .iter()
        .any(|c| !c.ok && is_transient_network_check(c));
    let status = if checks.iter().all(|c| c.ok) {
        "passed"
    } else if network
        || checks
            .iter()
            .any(|c| c.message.contains("传播") || c.message.contains("超时"))
    {
        "pending"
    } else {
        "failed"
    };
    Ok(json!({"status":status,
            "message":match status {"passed"=>"两个地区的跳转均通过自检",
                "pending" if network=>SELFTEST_NETWORK_MESSAGE,
                "pending"=>"边缘配置可能仍在传播","failed"=>"自检失败，请检查转发规则和目标地址",
                _=>""},"checks":checks}))
}

fn chosen_cn_target(
    pool: &Pool,
    code: &str,
    health: Option<&Value>,
    now: i64,
) -> Result<Option<String>, String> {
    pool.candidates
        .iter()
        .filter(|c| c.enabled)
        .find(|candidate| {
            let target = health
                .filter(|h| h["revision"].as_str() == Some(&pool.updated))
                .map(|h| &h["targets"][&candidate.id]);
            !target.is_some_and(|t| {
                t["state"] == "unhealthy"
                    && t["checkedAt"]
                        .as_i64()
                        .is_some_and(|ts| ts <= now && now - ts <= 3600)
            })
        })
        .map(|candidate| pools::compose(&model::Template::from(candidate), code))
        .transpose()
}

fn requested_dns_mode(payload: &Value) -> Result<local_check::DnsMode, String> {
    match payload.get("dnsMode") {
        None => Ok(local_check::DnsMode::System),
        Some(Value::String(value)) if value == "system" => Ok(local_check::DnsMode::System),
        Some(Value::String(value)) if value == "public" => Ok(local_check::DnsMode::Public),
        _ => Err("不支持的域名查询方式，请重新检测".into()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UpdateAction {
    Check,
    Install,
    Cancel,
}

fn update_action(action: &str) -> Option<UpdateAction> {
    match action {
        "check_update" => Some(UpdateAction::Check),
        "install_update" => Some(UpdateAction::Install),
        "cancel_update" => Some(UpdateAction::Cancel),
        _ => None,
    }
}

#[tauri::command]
async fn dispatch(
    request: Value,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<Value, String> {
    let action = field(&request, "action")?.to_string();
    let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
    match update_action(&action) {
        Some(UpdateAction::Check) => return updater_service::check(&app).await,
        Some(UpdateAction::Install) => return updater_service::install(&app, &state).await,
        Some(UpdateAction::Cancel) => return app.state::<updater_service::Service>().cancel(),
        None => {}
    }
    if action == "check_pool_health" {
        let snapshot = {
            let backend = lock_backend(&state, &action).await?;
            backend.health_snapshot(field(&payload, "poolId")?)?
        };
        return run_pool_health(snapshot).await;
    }
    if action == "check_link_redirect" {
        return redirect_check::check_link_redirect(
            &state,
            field(&payload, "domainId")?,
            field(&payload, "slug")?,
        )
        .await;
    }
    if action == "check_link_targets" {
        let mode = requested_dns_mode(&payload)?;
        let targets = {
            let backend = state.0.lock().await;
            backend.target_snapshot(field(&payload, "domainId")?, field(&payload, "slug")?)?
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut stream = futures_util::stream::iter(targets.iter().cloned().enumerate().map(
            |(index, (label, url))| async move {
                let result = tokio::time::timeout(Duration::from_secs(15), async {
                    match mode {
                        local_check::DnsMode::System => local_check::check(&label, &url).await,
                        local_check::DnsMode::Public => {
                            local_check::check_with_mode(&label, &url, mode).await
                        }
                    }
                })
                .await
                .unwrap_or_else(|_| local_check::timeout_result_with_mode(&label, &url, mode));
                (index, result)
            },
        ))
        .buffer_unordered(3);
        let mut slots = vec![None; targets.len()];
        while let Ok(Some((index, result))) = tokio::time::timeout_at(deadline, stream.next()).await
        {
            slots[index] = Some(result);
        }
        let checks: Vec<Value> = slots
            .into_iter()
            .enumerate()
            .map(|(i, entry)| {
                entry.unwrap_or_else(|| {
                    local_check::timeout_result_with_mode(&targets[i].0, &targets[i].1, mode)
                })
            })
            .collect();
        return Ok(json!({"checkedAt":now(),"checks":checks,"dnsMode":mode.as_str()}));
    }
    if action == "selftest_link" {
        let mode = requested_dns_mode(&payload)?;
        let (snapshot, key_missing) = {
            let backend = lock_backend(&state, &action).await?;
            let domain_id = field(&payload, "domainId")?;
            let snapshot = backend.selftest_snapshot(domain_id, field(&payload, "slug")?)?;
            (snapshot, backend.selftest_unavailable_message(domain_id))
        };
        return match snapshot {
            Some(snapshot) => match mode {
                local_check::DnsMode::System => run_selftest(snapshot).await,
                local_check::DnsMode::Public => run_selftest_with_mode(snapshot, mode).await,
            },
            None => Ok(json!({"status":"key_missing","message":key_missing,"checks":[] })),
        };
    }
    let mut backend = lock_backend(&state, &action).await?;
    backend.dispatch(&action, &payload).await
}

/// Why a self-test cannot run without a key, and where to go next.
fn selftest_key_missing_message(rotation_pending: bool) -> &'static str {
    if rotation_pending {
        // Resetting is refused while an earlier key update is unfinished.
        "这个账户的检测密钥上次没更新完，现在不能检测，也不用重置密钥。请先到页面上方“……项变更可继续处理”那一栏找到这个账户，点它旁边的按钮（「继续修复」「查看修复计划」或「找回本机检测配置」）把它做完，再检测"
    } else {
        "本机没有自检密钥，请先单独确认重置密钥"
    }
}

/// Name of the app in the Dock and the window title.
const APP_NAME: &str = "短连接生成器";
/// Both names of the app, for the startup failure text.
const APP_NAMES: &str = "短连接生成器（窗口里叫“短链接工作台”）";

/// What the user reads when local startup fails, by cause. Kept free of UI
/// calls so every branch can be tested. The app is called 短连接生成器 in the
/// Dock and the window title and 短链接工作台 inside the window.
fn startup_failure_message(error: &str) -> String {
    if error.contains("另一个本机客户端正在运行") {
        return format!(
            "{APP_NAMES}已经开着了，请切换到已打开的窗口；如果找不到，请退出后重新打开。"
        );
    }
    // Only a newer version writes a credential format this one does not know.
    if error.contains("本机凭据格式版本不受支持") {
        return format!(
            "{APP_NAMES}读不了本机的配置文件（{error}）。配置文件没有被改动。它可能是更新的版本写的，请安装最新版；如果还是打不开，请联系维护的人。"
        );
    }
    // Reinstalling does not change the configuration file.
    if ["无法读取本机配置", "本机配置格式无效"]
        .iter()
        .any(|cause| error.contains(cause))
    {
        return format!(
            "{APP_NAMES}读不了本机的配置文件（{error}）。配置文件没有被改动，重新安装也不会改变它。请联系维护的人处理。"
        );
    }
    format!("{APP_NAMES}没能打开：{error}")
}

/// Shows why startup failed, then exits once the user closes the message.
/// The open windows are hidden first so nothing half-started can be used.
/// The dialog runs on the event loop; `blocking_show` must not be used here
/// because setup runs on the main thread.
fn show_startup_failure(app: &tauri::App, error: &str) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
    for window in app.webview_windows().values() {
        let _ = window.hide();
    }
    let handle = app.handle().clone();
    app.dialog()
        .message(startup_failure_message(error))
        .title(format!("{APP_NAME}没能打开"))
        .kind(MessageDialogKind::Error)
        .show(move |_| handle.exit(1));
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            if let (Some(pubkey), Some(endpoint)) = (
                option_env!("SLG_UPDATER_PUBLIC_KEY"),
                option_env!("SLG_UPDATER_ENDPOINT"),
            ) {
                if !pubkey.is_empty() && endpoint.starts_with("https://") {
                    app.handle()
                        .plugin(tauri_plugin_updater::Builder::new().pubkey(pubkey).build())?;
                }
            }
            let dir = app.path().app_data_dir()?;
            let backend = match Backend::load(dir.join("state.json")) {
                Ok(backend) => backend,
                Err(error) => {
                    show_startup_failure(app, &error);
                    return Ok(());
                }
            };
            app.manage(AppState(Mutex::new(backend)));
            app.manage(updater_service::Service::default());
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut timer = tokio::time::interval(Duration::from_secs(30));
                loop {
                    timer.tick().await;
                    #[cfg(not(test))]
                    secret_store::purge_expired();
                    let state = handle.state::<AppState>();
                    let mut backend = state.0.lock().await;
                    backend
                        .plans
                        .retain(|plan| plan.expires_at > Instant::now());
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) {
                clear_credential_cache();
                let handle = window.app_handle().clone();
                // Finish a current cloud operation safely before clearing its plans.
                tauri::async_runtime::spawn(async move {
                    // Absent only when startup failed and the app is exiting.
                    if let Some(state) = handle.try_state::<AppState>() {
                        state.0.lock().await.plans.clear();
                    }
                    clear_credential_cache();
                });
            }
        })
        .invoke_handler(tauri::generate_handler![dispatch])
        .build(tauri::generate_context!())
        .expect("application failed to start")
        .run(|handle, event| {
            if matches!(
                event,
                tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
            ) {
                clear_credential_cache();
                if let Some(state) = handle.try_state::<AppState>() {
                    if let Ok(mut backend) = state.0.try_lock() {
                        backend.plans.clear();
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{header_regex, method, path, path_regex, query_param, query_param_is_missing},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn updater_actions_have_distinct_lock_routes() {
        assert_eq!(update_action("check_update"), Some(UpdateAction::Check));
        assert_eq!(update_action("install_update"), Some(UpdateAction::Install));
        assert_eq!(update_action("refresh_accounts"), None);

        let (_server, mut backend, _guard) = fixture().await;
        for action in ["check_update", "install_update"] {
            assert_eq!(
                backend.dispatch(action, &json!({})).await,
                Err("不支持此操作".to_string())
            );
        }

        let state = AppState(Mutex::new(backend));
        let busy_guard = state.0.lock().await;
        let install_lock = tokio::time::timeout(
            Duration::from_secs(5),
            lock_backend(&state, "install_update"),
        )
        .await;
        assert!(matches!(install_lock, Ok(Err(_))));
        drop(busy_guard);
        assert!(lock_backend(&state, "install_update").await.is_ok());
    }

    #[tokio::test]
    async fn import_rejects_existing_domain_with_different_verified_route() {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        let before = backend.database_snapshot();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([{"id":"new-route","pattern":"example.com/new/*",
                "script":"edge-one"}])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"prefix":"new"}"#))
            .mount(&server)
            .await;
        let backup = json!({"schema":SCHEMA,"accounts":[{"id":"acct1","label":"Example"}],
            "domains":[{"accountId":"acct1","host":"example.com","prefix":"new"}],
            "links":[{"host":"example.com","slug":"guide","cnUrl":"https://example.org/cn",
                "defaultUrl":"https://example.org/default"}]});

        let error = backend
            .import_config(&backup.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("本机已有该域名的不同前缀或路由"));
        assert_eq!(backend.database_snapshot(), before);
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn failed_import_persist_does_not_commit_staged_database_later() {
        let (_server, mut backend, _guard) = fixture().await;
        let before = backend.database_snapshot();
        let original_label = backend.db.accounts[0].label.clone();
        backend
            .fail_persist_at
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let backup = json!({"schema":SCHEMA,"accounts":[{"id":"acct1","label":"Changed"}],
            "domains":[],"links":[]});

        let error = backend
            .import_config(&backup.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("本机配置保存失败"));
        assert_eq!(backend.database_snapshot(), before);
        backend.persist().unwrap();
        let persisted: Database =
            serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(persisted.accounts[0].label, original_label);
    }

    #[tokio::test]
    async fn successful_import_commits_staged_database() {
        let (_server, mut backend, _guard) = fixture().await;
        let backup = json!({"schema":SCHEMA,"accounts":[{"id":"acct1","label":"Changed"}],
            "domains":[],"links":[]});

        backend.import_config(&backup.to_string()).await.unwrap();
        assert_eq!(backend.db.accounts[0].label, "Changed");
        let persisted: Database =
            serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(persisted.accounts[0].label, "Changed");
    }

    pub(super) fn url_link(slug: &str, cn: &str, default: &str) -> Link {
        Link {
            domain_id: "domain1".into(),
            slug: slug.into(),
            cn_url: cn.into(),
            default_url: default.into(),
            updated: "2026-01-01T00:00:00Z".into(),
            pool_id: None,
            code: None,
        }
    }

    async fn mount_import_domain(server: &MockServer, links: &[(&str, &str, &str)]) {
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([{"id":"route1","pattern":"example.com/go/*",
                "script":"edge-one"}])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"prefix":"go"}"#))
            .mount(server)
            .await;
        for (slug, cn, default) in links {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3A{slug}"
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(kv_link(&url_link(slug, cn, default))),
                )
                .mount(server)
                .await;
        }
    }

    #[tokio::test]
    async fn import_reports_added_existing_and_differing_links_without_overwriting() {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(url_link(
            "same",
            "https://example.org/a",
            "https://example.org/b",
        ));
        backend.db.links.push(url_link(
            "diff",
            "https://example.org/local-cn",
            "https://example.org/local-default",
        ));
        mount_import_domain(
            &server,
            &[
                ("same", "https://example.org/a", "https://example.org/b"),
                ("diff", "https://example.org/c", "https://example.org/d"),
                ("new", "https://example.org/e", "https://example.org/f"),
            ],
        )
        .await;
        let backup = json!({"schema":SCHEMA,"accounts":[{"id":"acct1","label":"Example"}],
            "domains":[{"accountId":"acct1","host":"example.com","prefix":"go"}],
            "links":[
                {"host":"example.com","slug":"same","cnUrl":"https://example.org/a",
                    "defaultUrl":"https://example.org/b"},
                {"host":"example.com","slug":"diff","cnUrl":"https://example.org/c",
                    "defaultUrl":"https://example.org/d"},
                {"host":"example.com","slug":"new","cnUrl":"https://example.org/e",
                    "defaultUrl":"https://example.org/f"}]});
        let state = backend.import_config(&backup.to_string()).await.unwrap();
        assert_eq!(
            state["configImportReport"],
            json!({"domainsAdded":0,"linksAdded":1,"poolsAdded":0,
                "linksExisting":2,"linksDiffering":1})
        );
        let diff = backend.db.links.iter().find(|l| l.slug == "diff").unwrap();
        assert_eq!(diff.cn_url, "https://example.org/local-cn");
        assert_eq!(backend.db.links.len(), 3);
        let raw = fs::read_to_string(&backend.path).unwrap();
        assert!(!raw.contains("configImportReport"));
        assert!(!raw.contains("linksDiffering"));
        let persisted: Database = serde_json::from_str(&raw).unwrap();
        assert_eq!(persisted.links.len(), 3);
        // The report is one-time: a later state read does not carry it.
        assert!(backend.state().get("configImportReport").is_none());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn import_errors_name_the_account_domain_or_link() {
        let (server, mut backend, _guard) = fixture().await;
        let before = backend.database_snapshot();
        let missing_account = json!({"schema":SCHEMA,
            "accounts":[{"id":"acctgone0000abcd1234","label":"旧账户"}],
            "domains":[],"links":[]});
        let error = backend
            .import_config(&missing_account.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("「旧账户」"), "{error}");
        assert!(error.contains("abcd1234"));
        assert!(error.contains("尚未导入本机"));

        let missing_owner = json!({"schema":SCHEMA,"accounts":[],
            "domains":[{"accountId":"acct9","host":"example.com","prefix":"go"}],"links":[]});
        let error = backend
            .import_config(&missing_owner.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("尚未导入本机的账户"), "{error}");
        assert!(error.contains("acct9"));

        backend.db.accounts[0].token_import_pending = true;
        let pending_owner = json!({"schema":SCHEMA,"accounts":[],
            "domains":[{"accountId":"acct1","host":"example.com","prefix":"go"}],"links":[]});
        let error = backend
            .import_config(&pending_owner.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("账户「账号 1」"), "{error}");
        assert!(error.contains("令牌导入尚未完成"));
        backend.db.accounts[0].token_import_pending = false;

        let missing_route = json!({"schema":SCHEMA,"accounts":[],
            "domains":[{"accountId":"acct1","host":"example.com","prefix":"other"}],"links":[]});
        mount_import_domain(&server, &[]).await;
        let error = backend
            .import_config(&missing_route.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("example.com/other"), "{error}");
        assert!(error.contains("备份中的域名路由在云端不存在"));

        let missing_link = json!({"schema":SCHEMA,"accounts":[],
            "domains":[{"accountId":"acct1","host":"example.com","prefix":"go"}],
            "links":[{"host":"example.com","slug":"gone","cnUrl":"https://example.org/a",
                "defaultUrl":"https://example.org/b"}]});
        let error = backend
            .import_config(&missing_link.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("example.com/go/gone"), "{error}");
        assert!(error.contains("云端缺少备份链接"));

        mount_import_domain(
            &server,
            &[("moved", "https://example.org/c", "https://example.org/d")],
        )
        .await;
        let changed_link = json!({"schema":SCHEMA,"accounts":[],
            "domains":[{"accountId":"acct1","host":"example.com","prefix":"go"}],
            "links":[{"host":"example.com","slug":"moved","cnUrl":"https://example.org/a",
                "defaultUrl":"https://example.org/b"}]});
        let error = backend
            .import_config(&changed_link.to_string())
            .await
            .unwrap_err();
        assert!(error.contains("example.com/go/moved"), "{error}");
        assert!(error.contains("云端链接目标与备份不同"));
        assert_eq!(backend.database_snapshot(), before);
        assert!(!error.contains("test-token-value"));
    }

    pub(super) fn ok(result: Value) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_json(json!({"success":true,"result":result,"result_info":{"cursor":""}}))
    }
    pub(super) struct FixtureGuard {
        _dir: tempfile::TempDir,
        _lock: tokio::sync::OwnedMutexGuard<()>,
    }
    pub(super) async fn fixture() -> (MockServer, Backend, FixtureGuard) {
        static LOCK: std::sync::OnceLock<std::sync::Arc<tokio::sync::Mutex<()>>> =
            std::sync::OnceLock::new();
        let guard = LOCK
            .get_or_init(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        mock_keys().lock().unwrap().clear();
        mock_legacy_keys().lock().unwrap().clear();
        mock_key_set_failures().lock().unwrap().clear();
        keyring_set("acct1", "token", "test-token-value").unwrap();
        keyring_set("acct1", "selftest", &"a1".repeat(32)).unwrap();
        mock_key_reads().lock().unwrap().clear();
        mock_key_mutations().lock().unwrap().clear();
        let account = Account {
            id: "acct1".into(),
            label: "账号 1".into(),
            mac_credential_schema: 2,
            token_import_pending: false,
            cloudflare_name: Some("Example Account".into()),
            zone_count: 1,
            checked_at: Some(now()),
            has_resources: true,
            needs_selftest_key: false,
            monitor_enabled: false,
            monitor_endpoint: None,
            needs_monitor_key: false,
            zones: vec![Zone {
                id: "zone1".into(),
                name: "example.com".into(),
                status: "active".into(),
                account_id: "acct1".into(),
            }],
            resources: Some(Resources {
                script: "edge-one".into(),
                namespace: "ns1".into(),
            }),
        };
        let backend = Backend {
            db: Database {
                accounts: vec![account],
                domains: vec![],
                links: vec![],
                pools: vec![],
                pending_pool_changes: vec![],
                pending_monitor_changes: vec![],
                pending_selftest_rotations: vec![],
                pending_worker_upgrades: vec![],
                pending_operations: vec![],
            },
            path: dir.path().join("state.json"),
            plans: vec![],
            stats_sessions: Vec::new(),
            cloud: Cloud::for_test(&format!("{}/client/v4/", server.uri())),
            #[cfg(target_os = "macos")]
            _credential_lease: None,
            #[cfg(target_os = "windows")]
            _configuration_lease: None,
            persist_count: std::sync::atomic::AtomicUsize::new(0),
            fail_persist_at: std::sync::atomic::AtomicUsize::new(0),
        };
        (
            server,
            backend,
            FixtureGuard {
                _dir: dir,
                _lock: guard,
            },
        )
    }
    pub(super) async fn mount_resource(server: &MockServer, source: &str) {
        mount_resource_with_probe(server, source, false).await;
    }
    async fn mount_zone_owner(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ok(
                json!({"id":"zone1","status":"active","account":{"id":"acct1"}}),
            ))
            .mount(server)
            .await;
    }
    async fn mount_exact_dns(server: &MockServer, records: Value) {
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .and(query_param_is_missing("name"))
            .respond_with(ok(records.clone()))
            .with_priority(100)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .and(query_param("name", "example.com"))
            .respond_with(ok(records))
            .mount(server)
            .await;
    }
    async fn mount_full_dns(server: &MockServer, records: Value) {
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .and(query_param_is_missing("name"))
            .respond_with(ok(records))
            .mount(server)
            .await;
    }
    async fn mount_resource_with_probe(server: &MockServer, source: &str, with_probe: bool) {
        let manifest = json!({"schema":SCHEMA,"accountId":"acct1","script":"edge-one",
            "namespace":"ns1","sourceHash":bundled_source_hash()});
        let mut bindings = vec![
            json!({"type":"kv_namespace","name":"LINKS","namespace_id":"ns1"}),
            json!({"type":"secret_text","name":"SELFTEST_KEY"}),
        ];
        if with_probe {
            bindings.push(json!({"type":"secret_text","name":"PROBE_KEY"}));
        }
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Aconfig",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(manifest.to_string()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/settings",
            ))
            .respond_with(ok(json!({"bindings":bindings})))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/content/v2",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(source.as_bytes().to_vec(), "application/javascript"),
            )
            .mount(server)
            .await;
    }
    async fn mount_selftest_rotation(server: &MockServer, status: u16) {
        let response = if status == 200 {
            ok(json!({}))
        } else {
            ResponseTemplate::new(status)
        };
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/secrets",
            ))
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await;
    }
    pub(super) fn domain() -> Domain {
        Domain {
            id: "domain1".into(),
            account_id: "acct1".into(),
            zone_id: "zone1".into(),
            host: "example.com".into(),
            prefix: "go".into(),
            route_id: "route1".into(),
        }
    }
    pub(super) async fn mount_owned_domain(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(json!([])))
            .with_priority(100)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([{"id":"route1","pattern":"example.com/go/*",
                "script":"edge-one"}])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"prefix":"go"}"#))
            .mount(server)
            .await;
    }

    pub(super) async fn mount_domain_hard_checks(
        server: &MockServer,
        dns_records: Value,
        routes: Value,
    ) {
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ok(json!({"id":"zone1","status":"active",
                "account":{"id":"acct1"}})))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ok(dns_records))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(routes))
            .mount(server)
            .await;
    }

    pub(super) async fn mount_domain_probes(
        server: &MockServer,
        root: ResponseTemplate,
        child: ResponseTemplate,
    ) {
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/"))
            .respond_with(root)
            .mount(server)
            .await;
        Mock::given(method("HEAD"))
            .and(path_regex(r"^/client/v4/probe/example\.com/go/probe-"))
            .respond_with(child)
            .mount(server)
            .await;
    }

    async fn mount_echoing_redirect_probe(
        server: &MockServer,
        query_version: &str,
        fragment: &str,
    ) {
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/"))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;
        let query_version = query_version.to_owned();
        let fragment = fragment.to_owned();
        Mock::given(method("HEAD"))
            .and(path_regex(r"^/client/v4/probe/example\.com/go/probe-"))
            .respond_with(move |request: &wiremock::Request| {
                let probe_segment = request.url.path().rsplit('/').next().unwrap();
                ResponseTemplate::new(302).insert_header(
                    "location",
                    format!(
                        "https://example.org/next?probe={probe_segment}&version={query_version}#{fragment}"
                    ),
                )
            })
            .mount(server)
            .await;
    }

    pub(super) async fn mount_existing_resource_domain_write(server: &MockServer) {
        mount_resource(server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!({"id":"route-new"})))
            .mount(server)
            .await;
    }

    #[test]
    fn host_normalization_preserves_exact_subdomain_and_idn() {
        assert_eq!(
            normalize_host("HTTPS://WWW.Example.COM/some/path").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            normalize_host("例子.测试").unwrap(),
            "xn--fsqu00a.xn--0zwm56d"
        );
        assert!(normalize_host("https://example.com:8443/a").is_err());
        assert!(normalize_host("https://user@example.com/a").is_err());
    }

    #[test]
    fn destination_validation_and_canonicalization() {
        assert!(validate_target("http://example.com").is_err());
        assert!(validate_target("javascript:alert(1)").is_err());
        assert!(validate_target("/relative").is_err());
        assert!(validate_target("https://user@example.com/").is_err());
        assert!(validate_target("https://example.com/#part").is_err());
        assert_eq!(
            canonical_target("https://example.org/路径?q=值").unwrap(),
            "https://example.org/%E8%B7%AF%E5%BE%84?q=%E5%80%BC"
        );
    }

    #[tokio::test]
    async fn invalid_destinations_cannot_prepare_cloud_writes() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let base = "https://example.org/";
        let invalid = [
            format!("{base}{}", "a".repeat(2049 - base.len())),
            format!("{base}{}", "值".repeat(230)),
            "https://example.org:0/".into(),
            "https://example.org/a\nb".into(),
        ];
        for target in invalid {
            for field in ["cnUrl", "defaultUrl"] {
                let mut payload = json!({"kind":"save_link", "domainId":domain().id,
                    "slug":"test", "cnUrl":base, "defaultUrl":base});
                payload[field] = json!(target);
                assert!(backend.prepare_change(&payload).is_err());
                assert!(backend.plans.is_empty());
            }
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(canonical_target(&format!("{base}{}", "a".repeat(2048 - base.len()))).is_ok());
        assert!(canonical_target("https://example.org:8443/").is_ok());
    }

    #[test]
    fn route_overlap_is_conservative_for_wildcards() {
        assert!(route_conflict("example.com/*", "example.com", "go"));
        assert!(route_conflict(
            "*.example.com/go/*",
            "www.example.com",
            "go"
        ));
        assert!(route_conflict("example.com/go/*", "example.com", "go"));
        assert!(!route_conflict("example.org/go/*", "example.com", "go"));
        assert!(!route_conflict("example.com/news/*", "example.com", "go"));
    }

    #[test]
    fn token_template_contains_expected_scopes() {
        let url = url::Url::parse(&Backend::token_template()).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("accountId").map(String::as_str), Some("*"));
        assert_eq!(query.get("zoneId").map(String::as_str), Some("all"));
        let permissions: Value =
            serde_json::from_str(query.get("permissionGroupKeys").unwrap()).unwrap();
        assert_eq!(permissions.as_array().unwrap().len(), 7);
        assert!(permissions
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["key"] == "account_analytics" && p["type"] == "read"));
        assert!(permissions
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["key"] == "workers_routes" && p["type"] == "edit"));
    }

    #[test]
    fn keys_and_slugs_have_bounded_shapes() {
        assert!(validate_prefix("go").is_ok());
        assert!(validate_prefix("GO").is_err());
        assert!(validate_prefix("abcdefghijklm").is_err());
        assert!(validate_slug("Ab_12-").is_ok());
        assert!(validate_slug("bad/path").is_err());
        let name = random_name("edge");
        assert!(name.starts_with("edge-"));
        assert_eq!(name.len(), 17);
    }

    #[test]
    fn journal_identity_survives_multiple_notes_and_completion() {
        let id = "添加域名 example.com (0123456789abcdef)";
        let mut pending = vec![id.to_string()];
        assert!(set_journal_note(&mut pending, id, "已建 KV").is_ok());
        assert!(set_journal_note(&mut pending, id, "已建 Worker").is_ok());
        assert!(pending[0].ends_with("已建 Worker"));
        clear_journal(&mut pending, id).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn journal_uncertain_note_replaces_previous_step_without_losing_other_ops() {
        let id = "保存链接 example.com (one)";
        let other = "保存链接 example.com (two)";
        let mut pending = vec![id.to_string(), other.to_string()];
        set_journal_note(&mut pending, id, "写入中").unwrap();
        set_journal_note(&mut pending, id, "结果不确定").unwrap();
        assert!(pending[0].ends_with("结果不确定"));
        assert_eq!(pending[1], other);
        assert!(clear_journal(&mut pending, "missing").is_err());
    }

    #[tokio::test]
    async fn missing_dns_requires_reviewed_placeholder_plan_and_never_overwrites() {
        let (server, mut backend, _dir) = fixture().await;
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([])).await;
        mount_full_dns(&server, json!([])).await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ok(
                json!({"id":"placeholder","name":"example.com","type":"AAAA",
                "content":"100::","proxied":true,"proxiable":true}),
            ))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(prepared["dnsStatus"], "missing");
        assert_eq!(prepared["actions"][0]["kind"], "createPlaceholder");
        assert_eq!(prepared["canApply"], true);
        assert_eq!(prepared["plan"]["title"], "补齐网站解析");
        let plan_id = prepared["plan"]["id"].as_str().unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap();
        assert!(backend.db.pending_operations.is_empty());
        let requests = server.received_requests().await.unwrap();
        let write = requests
            .iter()
            .find(|request| request.method.as_str() == "POST")
            .unwrap();
        let body: Value = serde_json::from_slice(&write.body).unwrap();
        assert_eq!(
            body,
            json!({"type":"AAAA","name":"example.com","content":"100::","ttl":1,"proxied":true})
        );
    }

    #[tokio::test]
    async fn non_address_dns_records_are_preserved_when_creating_placeholder() {
        let (server, mut backend, _dir) = fixture().await;
        let records = json!([
            {"id":"mx-one","name":"example.com","type":"MX",
                "content":"mail.example.org","proxied":false,"proxiable":false},
            {"id":"txt-one","name":"example.com","type":"TXT",
                "content":"verification=example","proxied":false,"proxiable":false},
            {"id":"caa-one","name":"example.com","type":"CAA",
                "content":"0 issue example.org","proxied":false,"proxiable":false}
        ]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, records.clone()).await;
        mount_full_dns(&server, records).await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ok(
                json!({"id":"placeholder","name":"example.com","type":"AAAA",
                "content":"100::","proxied":true,"proxiable":true}),
            ))
            .mount(&server)
            .await;

        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(prepared["dnsStatus"], "missing");
        assert_eq!(prepared["actions"][0]["kind"], "createPlaceholder");
        assert_eq!(prepared["canApply"], true);
        backend
            .dispatch(
                "apply_plan",
                &json!({"planId":prepared["plan"]["id"].as_str().unwrap()}),
            )
            .await
            .unwrap();

        let writes: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE"))
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].method.as_str(), "POST");
        let body: Value = serde_json::from_slice(&writes[0].body).unwrap();
        assert_eq!(
            body,
            json!({"type":"AAAA","name":"example.com","content":"100::","ttl":1,"proxied":true})
        );
    }

    #[tokio::test]
    async fn non_address_dns_change_blocks_placeholder_write() {
        let (server, mut backend, _dir) = fixture().await;
        let original = json!([
            {"id":"mx-one","name":"example.com","type":"MX",
                "content":"mail.example.org","proxied":false,"proxiable":false},
            {"id":"txt-one","name":"example.com","type":"TXT",
                "content":"verification=first","proxied":false,"proxiable":false}
        ]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, original.clone()).await;
        mount_full_dns(&server, original).await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(prepared["dnsStatus"], "missing");
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();

        server.reset().await;
        mount_zone_owner(&server).await;
        mount_exact_dns(
            &server,
            json!([
                {"id":"mx-one","name":"example.com","type":"MX",
                    "content":"mail.example.org","proxied":false,"proxiable":false},
                {"id":"txt-one","name":"example.com","type":"TXT",
                    "content":"verification=changed","proxied":false,"proxiable":false}
            ]),
        )
        .await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.contains("DNS 记录已变化"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| !matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE")));
    }

    #[tokio::test]
    async fn non_address_dns_priority_change_blocks_placeholder_write() {
        let (server, mut backend, _dir) = fixture().await;
        let original = json!([{"id":"mx-one","name":"example.com","type":"MX",
            "content":"mail.example.org","priority":10,"ttl":300,
            "proxied":false,"proxiable":false}]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, original.clone()).await;
        mount_full_dns(&server, original).await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();

        server.reset().await;
        let changed = json!([{"id":"mx-one","name":"example.com","type":"MX",
            "content":"mail.example.org","priority":50,"ttl":300,
            "proxied":false,"proxiable":false}]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, changed.clone()).await;
        mount_full_dns(&server, changed).await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.contains("DNS 记录已变化"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| !matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE")));
    }

    #[tokio::test]
    async fn full_zone_newer_non_address_content_blocks_placeholder_write() {
        let (server, mut backend, _dir) = fixture().await;
        let original = json!([{"id":"mx-one","name":"example.com","type":"MX",
            "content":"mail.example.org","priority":10,"ttl":300,
            "proxied":false,"proxiable":false}]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, original.clone()).await;
        mount_full_dns(&server, original.clone()).await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();

        server.reset().await;
        let changed = json!([{"id":"mx-one","name":"example.com","type":"MX",
            "content":"changed-mail.example.org","priority":10,"ttl":300,
            "proxied":false,"proxiable":false}]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, original).await;
        mount_full_dns(&server, changed).await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.contains("DNS 记录已变化"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| !matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE")));
    }

    #[tokio::test]
    async fn full_zone_mismatch_blocks_placeholder_plan_during_prepare() {
        let (server, mut backend, _dir) = fixture().await;
        let exact = json!([{"id":"mx-one","name":"example.com","type":"MX",
            "content":"mail.example.org","priority":10,"ttl":300,
            "proxied":false,"proxiable":false}]);
        let full = json!([{"id":"mx-one","name":"example.com","type":"MX",
            "content":"changed-mail.example.org","priority":10,"ttl":300,
            "proxied":false,"proxiable":false}]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, exact).await;
        mount_full_dns(&server, full).await;

        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(prepared["dnsStatus"], "conflict");
        assert_eq!(prepared["canApply"], false);
        assert!(prepared.get("plan").is_none());
        assert!(prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["message"]
                .as_str()
                .is_some_and(|message| message.contains("DNS 记录已变化"))));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| !matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE")));
    }

    #[tokio::test]
    async fn domain_preflight_reports_non_address_records_as_missing_web_address() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([
                {"name":"example.com","type":"MX","proxied":false,"proxiable":false},
                {"name":"example.com","type":"TXT","proxied":false,"proxiable":false},
                {"name":"example.com","type":"CAA","proxied":false,"proxiable":false}
            ]),
            json!([]),
        )
        .await;

        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], false);
        let dns = prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["label"] == "DNS")
            .unwrap();
        assert_eq!(dns["level"], "error");
        assert!(dns["message"]
            .as_str()
            .unwrap()
            .contains("还没有用于打开网址的解析"));
        assert!(!dns["message"].as_str().unwrap().contains("不支持"));
    }

    #[tokio::test]
    async fn new_domain_is_discovered_on_second_page_before_preflight() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].zones.clear();
        let first: Vec<_> = (0..50).map(|i| json!({"id":format!("zone{i}"),"name":format!("site{i}.example.org"),"status":"active"})).collect();
        for (page, result) in [
            ("1", json!(first)),
            (
                "2",
                json!([{"id":"zone1","name":"example.com","status":"active"}]),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path("/client/v4/zones"))
                .and(query_param("account.id", "acct1"))
                .and(query_param("page", page))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"success":true,"result":result,"result_info":{"total_pages":2}}),
                ))
                .expect(1)
                .mount(&server)
                .await;
        }
        mount_domain_hard_checks(
            &server,
            json!([{"type":"A","name":"example.com","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let result = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(result["canApply"], true);
        assert_eq!(result["candidates"][0]["zoneId"], "zone1");
        assert_eq!(
            backend.state()["accounts"][0]["zones"]
                .as_array()
                .unwrap()
                .len(),
            51
        );
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| matches!(request.method.as_str(), "GET" | "HEAD")));
    }

    #[tokio::test]
    async fn pending_domain_refreshes_to_active_before_dns_preparation() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].zones[0].status = "pending".into();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct1"))
            .respond_with(ok(
                json!([{"id":"zone1","name":"example.com","status":"active"}]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        mount_domain_hard_checks(&server, json!([]), json!([])).await;
        let result = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(result["dnsStatus"], "missing");
        assert_eq!(result["canApply"], true);
        assert_eq!(backend.db.accounts[0].zones[0].status, "active");
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn refreshed_but_missing_domain_explains_token_visibility() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].zones.clear();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .respond_with(ok(json!([])))
            .expect(2)
            .mount(&server)
            .await;
        for action in ["prepare_domain", "prepare_domain_dns"] {
            let result = backend
                .dispatch(action, &json!({"input":"example.org","prefix":"go"}))
                .await
                .unwrap();
            assert_eq!(result["canApply"], false);
            let message = result["checks"][0]["message"].as_str().unwrap();
            assert!(message.contains("当前令牌可见") && message.contains("新域名"));
            assert!(!message.contains("均不管理"));
        }
        assert!(backend.plans.is_empty());
    }

    #[tokio::test]
    async fn domain_refresh_failure_does_not_report_missing_or_replace_cached_accounts() {
        let (server, mut backend, _dir) = fixture().await;
        let mut second = backend.db.accounts[0].clone();
        second.id = "acct2".into();
        second.label = "Second account".into();
        backend.db.accounts.push(second);
        keyring_set("acct2", "token", "second-test-token").unwrap();
        let before = serde_json::to_value(&backend.db.accounts).unwrap();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct1"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct2"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let error = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.org","prefix":"go","accountId":"acct2"}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("Second account") && error.contains("无法刷新"));
        assert!(!error.contains("均不管理"));
        assert_eq!(serde_json::to_value(&backend.db.accounts).unwrap(), before);
        assert!(backend.plans.is_empty());
    }

    #[tokio::test]
    async fn selected_account_discovery_does_not_read_other_account() {
        let (server, mut backend, _dir) = fixture().await;
        let mut second = backend.db.accounts[0].clone();
        second.id = "acct2".into();
        backend.db.accounts[0].zones.clear();
        backend.db.accounts.push(second);
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct1"))
            .respond_with(ok(
                json!([{"id":"zone1","name":"example.com","status":"active"}]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let candidates = backend
            .domain_candidates("example.com", Some("acct1"))
            .await
            .unwrap();
        assert!(candidates
            .iter()
            .any(|candidate| candidate.account_id == "acct1"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn duplicate_domain_preparation_stays_local_with_cold_cache_and_other_account() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.accounts[0].zones.clear();
        backend.db.accounts[0].mac_credential_schema = 0;
        let mut other = backend.db.accounts[0].clone();
        other.id = "acct2".into();
        backend.db.accounts.push(other);
        for (prefix, account_id) in [("other", "acct1"), ("go", "acct2")] {
            let result = backend
                .dispatch(
                    "prepare_domain",
                    &json!({"input":"https://EXAMPLE.com/previous/path","prefix":prefix,"accountId":account_id}),
                )
                .await
                .unwrap();
            assert_eq!(result["host"], "example.com");
            assert_eq!(result["canApply"], false);
            assert!(result["plan"].is_null());
            assert_eq!(result["checks"][0]["label"], "本机配置");
        }
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(backend.plans.is_empty());
    }

    #[tokio::test]
    async fn refresh_updates_cloudflare_identity_and_zones_but_preserves_custom_label() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].label = "我的备注".into();
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1"))
            .respond_with(ok(json!({"id":"acct1","name":"Cloud Example"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct1"))
            .respond_with(ok(
                json!([{"id":"zone-new","name":"example.org","status":"active"}]),
            ))
            .mount(&server)
            .await;
        let state = backend
            .dispatch("refresh_accounts", &json!({}))
            .await
            .unwrap();
        assert_eq!(state["accounts"][0]["label"], "我的备注");
        assert_eq!(state["accounts"][0]["cloudflareName"], "Cloud Example");
        assert_eq!(state["accounts"][0]["zones"][0]["id"], "zone-new");
        assert!(state["accounts"][0]["zones"][0].get("accountId").is_none());
    }

    fn add_second_refresh_account(backend: &mut Backend) {
        let mut second = backend.db.accounts[0].clone();
        second.id = "acct2".into();
        second.label = "Second account".into();
        second.zones.clear();
        second.zone_count = 0;
        backend.db.accounts.push(second);
        keyring_set("acct2", "token", "second-test-token").unwrap();
    }

    #[tokio::test]
    async fn refresh_domains_reads_only_selected_token_and_zone_api() {
        let (server, mut backend, _dir) = fixture().await;
        add_second_refresh_account(&mut backend);
        keyring_delete("acct1", "token").unwrap();
        let other = serde_json::to_value(&backend.db.accounts[0]).unwrap();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct2"))
            .and(header_regex("authorization", "Bearer second-test-token"))
            .respond_with(ok(
                json!([{"id":"zone-two","name":"example.org","status":"active"}]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let result = backend
            .dispatch("refresh_domains", &json!({"accountId":"acct2"}))
            .await
            .unwrap();
        assert_eq!(result["accounts"][1]["zones"][0]["name"], "example.org");
        assert_eq!(result["accounts"][1]["label"], "Second account");
        assert_eq!(result["appVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            serde_json::to_value(&backend.db.accounts[0]).unwrap(),
            other
        );
        assert_eq!(*mock_key_reads().lock().unwrap(), vec!["token:acct2"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refresh_domains_and_unknown_host_require_account_without_reading_credentials() {
        let (server, mut backend, _dir) = fixture().await;
        add_second_refresh_account(&mut backend);
        for (action, payload) in [
            ("refresh_domains", json!({})),
            (
                "prepare_domain",
                json!({"input":"example.org","prefix":"go"}),
            ),
            ("prepare_domain_dns", json!({"input":"example.org"})),
            ("refresh_domains", json!({"accountId":"unknown"})),
            ("refresh_domains", json!({"accountId":12})),
        ] {
            assert!(backend.dispatch(action, &payload).await.is_err());
        }
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(backend.plans.is_empty());
    }

    #[tokio::test]
    async fn refresh_domains_uses_single_account_and_preserves_cache_on_failure() {
        let (server, mut backend, _dir) = fixture().await;
        let before = serde_json::to_value(&backend.db.accounts).unwrap();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let error = backend
            .dispatch("refresh_domains", &json!({}))
            .await
            .unwrap_err();
        assert!(error.contains("无法刷新账户"));
        assert_eq!(serde_json::to_value(&backend.db.accounts).unwrap(), before);
        assert_eq!(*mock_key_reads().lock().unwrap(), vec!["token:acct1"]);
    }

    #[tokio::test]
    async fn refresh_domains_rolls_back_when_local_save_fails() {
        let (server, mut backend, _dir) = fixture().await;
        let before = serde_json::to_value(&backend.db.accounts).unwrap();
        backend
            .fail_persist_at
            .store(1, std::sync::atomic::Ordering::SeqCst);
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .respond_with(ok(json!([])))
            .expect(1)
            .mount(&server)
            .await;
        assert!(backend
            .dispatch("refresh_domains", &json!({}))
            .await
            .unwrap_err()
            .contains("保存失败"));
        assert_eq!(serde_json::to_value(&backend.db.accounts).unwrap(), before);
    }

    #[tokio::test]
    async fn refresh_domains_missing_credential_stops_without_cloud_request() {
        let (server, mut backend, _dir) = fixture().await;
        keyring_delete("acct1", "token").unwrap();
        let error = backend
            .dispatch("refresh_domains", &json!({}))
            .await
            .unwrap_err();
        assert!(error.contains("未刷新域名列表"));
        assert_eq!(*mock_key_reads().lock().unwrap(), vec!["token:acct1"]);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn busy_foreground_operations_wait_briefly_then_give_up() {
        let (_server, backend, _dir) = fixture().await;
        let state = AppState(Mutex::new(backend));
        let guard = state.0.lock().await;
        for action in [
            "refresh_domains",
            "refresh_accounts",
            "prepare_domain",
            "prepare_domain_dns",
            "prepare_change",
            "apply_plan",
            "check_pool_health",
            "selftest_link",
            "import_token",
            "remove_account",
            "import_config",
        ] {
            let started = Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(5), lock_backend(&state, action))
                .await
                .unwrap();
            assert!(started.elapsed() >= BUSY_WAIT, "{action} gave up too early");
            let error = result.err().unwrap();
            assert_eq!(error, BUSY_MESSAGE);
        }
        assert!(BUSY_MESSAGE.starts_with("上一个操作还没结束"));
        for word in ["令牌", "凭据", "授权", "权限"] {
            assert!(!BUSY_MESSAGE.contains(word), "{word}");
        }
        assert!(mock_key_reads().lock().unwrap().is_empty());
        drop(guard);
        assert!(lock_backend(&state, "refresh_domains").await.is_ok());
    }

    #[tokio::test]
    async fn busy_foreground_operation_runs_once_the_previous_one_ends() {
        let (_server, backend, _dir) = fixture().await;
        let state = AppState(Mutex::new(backend));
        let guard = state.0.lock().await;
        let (result, _) = tokio::join!(lock_backend(&state, "prepare_domain"), async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(guard);
        });
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn expected_account_token_replace_updates_only_that_account_after_full_validation() {
        let (server, mut backend, _dir) = fixture().await;
        let token = "n".repeat(35);
        Mock::given(method("GET"))
            .and(path("/client/v4/user/tokens/verify"))
            .respond_with(ok(json!({"status":"active"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts"))
            .respond_with(ok(json!([
                {"id":"acct2","name":"Other Account"},
                {"id":"acct1","name":"Updated Cloud Name"}
            ])))
            .mount(&server)
            .await;
        for path_value in [
            "/client/v4/accounts/acct1/workers/scripts",
            "/client/v4/accounts/acct1/storage/kv/namespaces",
        ] {
            Mock::given(method("GET"))
                .and(path(path_value))
                .respond_with(ok(json!([])))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct1"))
            .respond_with(ok(
                json!([{"id":"zone1","name":"example.com","status":"active"}]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;

        let state = backend
            .dispatch(
                "import_token",
                &json!({"token":token,"replace":true,"expectedAccountId":"acct1"}),
            )
            .await
            .unwrap();
        assert_eq!(backend.db.accounts.len(), 1);
        assert_eq!(state["accounts"][0]["label"], "账号 1");
        assert_eq!(state["accounts"][0]["cloudflareName"], "Updated Cloud Name");
        assert_eq!(keyring_get("acct1", "token").unwrap(), token);
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| { request.url.path().contains("/accounts/acct2/") }));
    }

    #[tokio::test]
    async fn expected_account_token_mismatch_changes_neither_keyring_nor_state() {
        let (server, mut backend, _dir) = fixture().await;
        let before_state = backend.database_snapshot();
        let before_token = keyring_get("acct1", "token").unwrap();
        let token = "m".repeat(35);
        Mock::given(method("GET"))
            .and(path("/client/v4/user/tokens/verify"))
            .respond_with(ok(json!({"status":"active"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts"))
            .respond_with(ok(json!([{"id":"acct2","name":"Other Account"}])))
            .mount(&server)
            .await;
        let error = backend
            .dispatch(
                "import_token",
                &json!({"token":token,"replace":true,"expectedAccountId":"acct1"}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("不属于所选账号"));
        assert_eq!(keyring_get("acct1", "token").unwrap(), before_token);
        assert_eq!(backend.database_snapshot(), before_state);
    }

    #[tokio::test]
    async fn dns_only_record_enables_proxy_without_changing_content() {
        let (server, mut backend, _dir) = fixture().await;
        let grey = json!({"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.10","proxied":false,"proxiable":true});
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([grey.clone()])).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-one"))
            .respond_with(ok(grey.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-one"))
            .respond_with(ok(json!({"id":"dns-one","name":"example.com","type":"A",
                "content":"192.0.2.10","proxied":true,"proxiable":true})))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(prepared["dnsStatus"], "dnsOnly");
        let plan_id = prepared["plan"]["id"].as_str().unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let patch = requests
            .iter()
            .find(|request| request.method.as_str() == "PATCH")
            .unwrap();
        let body: Value = serde_json::from_slice(&patch.body).unwrap();
        assert_eq!(body, json!({"proxied":true}));
    }

    #[tokio::test]
    async fn dns_record_change_blocks_write_and_unknown_record_is_not_overwritten() {
        let (server, mut backend, _dir) = fixture().await;
        let original = json!({"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.10","proxied":false,"proxiable":true});
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([original])).await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();
        server.reset().await;
        mount_zone_owner(&server).await;
        mount_exact_dns(
            &server,
            json!([{"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.20","proxied":false,"proxiable":true}]),
        )
        .await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.contains("已变化"));
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| { matches!(request.method.as_str(), "PATCH" | "POST" | "DELETE") }));

        server.reset().await;
        mount_zone_owner(&server).await;
        mount_exact_dns(
            &server,
            json!([{"id":"https-one","name":"example.com","type":"HTTPS",
            "content":"1 . alpn=h3","proxied":false,"proxiable":false}]),
        )
        .await;
        let blocked = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(blocked["dnsStatus"], "unsupported");
        assert_eq!(blocked["canApply"], false);
        assert!(blocked.get("plan").is_none());
    }

    #[tokio::test]
    async fn dns_write_permission_error_is_specific_and_does_not_disable_account() {
        let (server, mut backend, _dir) = fixture().await;
        let grey = json!({"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.10","proxied":false,"proxiable":true});
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([grey.clone()])).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-one"))
            .respond_with(ok(grey))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-one"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let error = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":prepared["plan"]["id"].as_str().unwrap()}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("DNS 编辑权限"));
        assert_eq!(backend.db.accounts.len(), 1);
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn missing_dns_permission_failure_never_retries_or_changes_other_records() {
        let (server, mut backend, _dir) = fixture().await;
        let records = json!([
            {"id":"mail","name":"example.com","type":"MX","content":"mail.example.org",
             "priority":10,"proxied":false,"proxiable":false},
            {"id":"verify","name":"example.com","type":"TXT","content":"verification=example",
             "proxied":false,"proxiable":false}
        ]);
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, records.clone()).await;
        mount_full_dns(&server, records).await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let error = backend
            .dispatch("apply_plan", &json!({"planId":prepared["plan"]["id"]}))
            .await
            .unwrap_err();
        assert!(error.contains("HTTP 403") && error.contains("DNS 编辑权限"));
        assert_eq!(backend.db.accounts.len(), 1);
        assert!(backend.db.pending_operations.is_empty());
        // An explicit refresh may prepare a fresh plan, but never silently reapplies it.
        let refreshed = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(refreshed["dnsStatus"], "missing");
        assert_eq!(refreshed["canApply"], true);
        let writes: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| matches!(request.method.as_str(), "POST" | "PATCH" | "DELETE"))
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].method.as_str(), "POST");
        let value: Value = serde_json::from_slice(&writes[0].body).unwrap();
        assert_eq!(value["type"], "AAAA");
        assert_eq!(value["name"], "example.com");
    }

    #[tokio::test]
    async fn dns_read_failure_is_distinct_and_never_offers_a_plan() {
        let (server, mut backend, _dir) = fixture().await;
        mount_zone_owner(&server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(prepared["dnsStatus"], "readFailed");
        assert_eq!(prepared["canApply"], false);
        assert!(prepared.get("plan").is_none());
        assert!(prepared["checks"][1]["message"]
            .as_str()
            .unwrap()
            .contains("无法读取 DNS"));
    }

    #[tokio::test]
    async fn partial_dns_proxy_failure_is_journaled_and_retry_clears_resolved_history() {
        let (server, mut backend, _dir) = fixture().await;
        let one = json!({"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.10","proxied":false,"proxiable":true});
        let two = json!({"id":"dns-two","name":"example.com","type":"AAAA",
            "content":"2001:db8::10","proxied":false,"proxiable":true});
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([one.clone(), two.clone()])).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-one"))
            .respond_with(ok(one.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-two"))
            .respond_with(ok(two.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-one"))
            .respond_with(ok(json!({"id":"dns-one","name":"example.com","type":"A",
                "content":"192.0.2.10","proxied":true,"proxiable":true})))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-two"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let error = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":prepared["plan"]["id"].as_str().unwrap()}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("500"));
        assert_eq!(backend.db.pending_operations.len(), 1);
        assert!(backend.db.pending_operations[0].contains("已开启 1/2"));

        server.reset().await;
        mount_zone_owner(&server).await;
        let one_done = json!({"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.10","proxied":true,"proxiable":true});
        mount_exact_dns(&server, json!([one_done, two.clone()])).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-two"))
            .respond_with(ok(two))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/client/v4/zones/zone1/dns_records/dns-two"))
            .respond_with(ok(
                json!({"id":"dns-two","name":"example.com","type":"AAAA",
                "content":"2001:db8::10","proxied":true,"proxiable":true}),
            ))
            .mount(&server)
            .await;
        let retry = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        backend
            .dispatch(
                "apply_plan",
                &json!({"planId":retry["plan"]["id"].as_str().unwrap()}),
            )
            .await
            .unwrap();
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn domain_public_dns_mode_is_bound_to_plan_and_invalid_modes_do_not_read_credentials() {
        let (server, mut backend, _dir) = fixture().await;
        for mode in [json!(null), json!(true), json!("other"), json!({})] {
            let error = backend
                .dispatch(
                    "prepare_domain",
                    &json!({"input":"example.com","prefix":"go","dnsMode":mode}),
                )
                .await
                .unwrap_err();
            assert!(error.contains("查询方式"));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(522),
            ResponseTemplate::new(522),
        )
        .await;
        mount_existing_resource_domain_write(&server).await;
        let result = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go","dnsMode":"public"}),
            )
            .await
            .unwrap();
        assert_eq!(result["dnsMode"], "public");
        let id = result["plan"]["id"].as_str().unwrap();
        let plan = backend.plans.iter().find(|p| p.view.id == id).unwrap();
        assert!(matches!(
            plan.kind,
            PlanKind::Domain {
                dns_mode: local_check::DnsMode::Public,
                ..
            }
        ));
        assert!(result["plan"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step.as_str().unwrap().contains("公共 DNS")));
        // The execution payload cannot override the prepared mode or skip the takeover acknowledgment.
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":id,"dnsMode":"system"}))
            .await
            .unwrap_err()
            .contains("接管"));
        let result = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go","dnsMode":"public"}),
            )
            .await
            .unwrap();
        backend.dispatch("apply_plan", &json!({"planId":result["plan"]["id"],"acknowledgeDomainTakeover":true,"dnsMode":"system"})).await.unwrap();
        assert_eq!(backend.db.domains.len(), 1);
        let probes = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_str() == "HEAD")
            .count();
        assert!(probes >= 6); // preparation plus execution both recheck directory and child.
    }

    #[tokio::test]
    async fn domain_404_plan_keeps_original_flow_and_expires_single_use() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], true);
        assert!(prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["level"] == "pass"));
        assert!(prepared["plan"].get("domainTakeoverConfirmation").is_none());
        assert!(prepared["plan"]["steps"][0]
            .as_str()
            .unwrap()
            .contains("所有下级网页"));

        let plan_id = prepared["plan"]["id"].as_str().unwrap();
        let plan = backend
            .plans
            .iter_mut()
            .find(|plan| plan.view.id == plan_id)
            .unwrap();
        plan.expires_at = Instant::now() - Duration::from_secs(1);
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.contains("计划已过期"));
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err()
            .contains("计划不存在或已被使用"));
    }

    #[tokio::test]
    async fn domain_http_200_requires_ack_then_completes_exact_route_write() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(200),
            ResponseTemplate::new(200),
        )
        .await;
        mount_existing_resource_domain_write(&server).await;

        let first = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(first["canApply"], true);
        assert!(first["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["level"] == "warning"
                && check["message"].as_str().unwrap().contains("HTTP 200")));
        let confirmation = first["plan"]["domainTakeoverConfirmation"]
            .as_str()
            .unwrap();
        assert!(confirmation.contains("example.com/go/"));
        assert!(confirmation.contains("未创建的短链接会返回 HTTP 404"));
        let first_id = first["plan"]["id"].as_str().unwrap();
        let error = backend
            .dispatch("apply_plan", &json!({"planId":first_id}))
            .await
            .unwrap_err();
        assert!(error.contains("明确确认接管"));
        let requests = server.received_requests().await.unwrap();
        assert!(!requests
            .iter()
            .any(|request| matches!(request.method.as_str(), "PUT" | "POST" | "DELETE")));

        let second = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let second_id = second["plan"]["id"].as_str().unwrap();
        let state = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":second_id,"acknowledgeDomainTakeover":true}),
            )
            .await
            .unwrap();
        assert_eq!(state["domains"].as_array().unwrap().len(), 1);
        let requests = server.received_requests().await.unwrap();
        let route_write = requests
            .iter()
            .find(|request| {
                request.method.as_str() == "POST"
                    && request.url.path() == "/client/v4/zones/zone1/workers/routes"
            })
            .unwrap();
        let body: Value = serde_json::from_slice(&route_write.body).unwrap();
        assert_eq!(body["pattern"], "example.com/go/*");
        assert!(backend
            .dispatch(
                "apply_plan",
                &json!({"planId":second_id,"acknowledgeDomainTakeover":true}),
            )
            .await
            .unwrap_err()
            .contains("计划不存在或已被使用"));
    }

    #[tokio::test]
    async fn domain_redirect_is_not_followed_and_origin_522_is_a_warning() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"CNAME","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(302).insert_header("location", "https://example.org/elsewhere"),
            ResponseTemplate::new(522),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], true);
        let checks = prepared["checks"].as_array().unwrap();
        assert!(checks.iter().any(|check| {
            check["level"] == "warning"
                && check["message"].as_str().unwrap().contains("HTTP 302")
                && check["message"].as_str().unwrap().contains("Cloudflare")
        }));
        assert!(checks.iter().any(|check| {
            check["level"] == "warning"
                && check["message"].as_str().unwrap().contains("HTTP 522")
                && check["message"].as_str().unwrap().contains("WAF")
        }));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method.as_str() == "HEAD")
                .count(),
            2
        );
        assert_eq!(requests.len(), 5);
        assert!(requests
            .iter()
            .all(|request| request.url.path().starts_with("/client/v4/")));
    }

    #[tokio::test]
    async fn domain_plan_reuses_probe_segment_when_redirect_query_echoes_it() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_echoing_redirect_probe(&server, "one", "stable").await;
        mount_existing_resource_domain_write(&server).await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap();
        let state = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":plan_id,"acknowledgeDomainTakeover":true}),
            )
            .await
            .unwrap();
        assert_eq!(state["domains"].as_array().unwrap().len(), 1);
        let child_paths: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| {
                request.method.as_str() == "HEAD"
                    && request
                        .url
                        .path()
                        .starts_with("/client/v4/probe/example.com/go/probe-")
            })
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(child_paths.len(), 2);
        assert_eq!(child_paths[0], child_paths[1]);
    }

    #[tokio::test]
    async fn domain_redirect_query_and_fragment_changes_still_block_all_writes() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_echoing_redirect_probe(&server, "one", "first").await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap();

        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_echoing_redirect_probe(&server, "two", "second").await;
        let error = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":plan_id,"acknowledgeDomainTakeover":true}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("路径响应状态已变化"));
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| matches!(request.method.as_str(), "PUT" | "POST" | "DELETE")));
    }

    #[tokio::test]
    async fn domain_access_limits_and_timeout_are_hard_errors() {
        let (server, mut backend, _dir) = fixture().await;
        for status in [403, 429] {
            server.reset().await;
            mount_domain_hard_checks(
                &server,
                json!([{"name":"example.com","type":"A","proxied":true}]),
                json!([]),
            )
            .await;
            mount_domain_probes(
                &server,
                ResponseTemplate::new(status),
                ResponseTemplate::new(404),
            )
            .await;
            let prepared = backend
                .dispatch(
                    "prepare_domain",
                    &json!({"input":"example.com","prefix":"go"}),
                )
                .await
                .unwrap();
            assert_eq!(prepared["canApply"], false);
            assert!(prepared["checks"].as_array().unwrap().iter().any(|check| {
                check["level"] == "error"
                    && check["message"]
                        .as_str()
                        .unwrap()
                        .contains(&status.to_string())
            }));
        }
        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404).set_delay(Duration::from_secs(3)),
            ResponseTemplate::new(404).set_delay(Duration::from_secs(3)),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], false);
        assert!(prepared["checks"].as_array().unwrap().iter().any(|check| {
            check["level"] == "error" && check["message"].as_str().unwrap().contains("超时")
        }));
    }

    #[tokio::test]
    async fn domain_head_405_retries_bounded_get_without_following_redirects() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(405),
            ResponseTemplate::new(404),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/probe/example.com/go/"))
            .and(header_regex("range", r"^bytes=0-0$"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ignored body"))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], true);
        assert!(prepared["checks"].as_array().unwrap().iter().any(|check| {
            check["level"] == "warning" && check["message"].as_str().unwrap().contains("HTTP 200")
        }));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| { request.url.path() == "/client/v4/probe/example.com/go/" })
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn domain_hard_gates_block_probes_and_path_risk_changes_block_writes() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":false}]),
            json!([{"id":"other","pattern":"example.com/go/*","script":"another"}]),
        )
        .await;
        let blocked = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(blocked["canApply"], false);
        assert!(blocked["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| { check["label"] == "DNS" && check["level"] == "error" }));
        assert!(blocked["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| { check["label"] == "转发规则" && check["level"] == "error" }));
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method.as_str() == "HEAD"));

        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap();

        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(200),
            ResponseTemplate::new(404),
        )
        .await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.contains("路径响应状态已变化"));
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| matches!(request.method.as_str(), "PUT" | "POST" | "DELETE")));

        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(200),
            ResponseTemplate::new(200),
        )
        .await;
        let warning_plan = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let warning_plan_id = warning_plan["plan"]["id"].as_str().unwrap();
        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(204),
            ResponseTemplate::new(200),
        )
        .await;
        let error = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":warning_plan_id,"acknowledgeDomainTakeover":true}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("路径响应状态已变化"));
        assert!(error.contains("云端没有任何改动"));
    }

    /// A local server that accepts and immediately closes every connection, so
    /// requests fail without any HTTP response.
    async fn closing_listener() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = count.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        (format!("http://{address}/client/v4/"), count)
    }

    fn no_cloud_writes(requests: &[wiremock::Request]) -> bool {
        !requests
            .iter()
            .any(|request| matches!(request.method.as_str(), "PUT" | "POST" | "PATCH" | "DELETE"))
    }

    #[test]
    fn transient_network_reasons_exclude_definitive_dns_results() {
        for reason in [
            "dns_timeout",
            "dns_failed",
            "public_dns_timeout",
            "public_dns_failed",
            "cloud_unreachable",
            "probe_timeout",
            "probe_transport_error",
        ] {
            assert!(is_transient_network_reason(reason), "{reason}");
        }
        for reason in [
            "virtual_dns_address",
            "blocked_non_public_address",
            "invalid_url",
            "public_dns_invalid_response",
            "public_dns_response_too_large",
            "dns_no_answer",
            "client_initialization",
        ] {
            assert!(!is_transient_network_reason(reason), "{reason}");
        }
        let network = |label: &str| {
            let mut check = domain_check::hard_check(label, false, "x");
            check.reason = Some("probe_timeout".into());
            check
        };
        let pass = domain_check::hard_check("DNS", true, "ok");
        let real = domain_check::hard_check("转发规则", false, "现有转发规则与此前缀重叠");
        assert!(!only_transient_errors(std::slice::from_ref(&pass)));
        assert!(only_transient_errors(&[pass, network("短链接目录")]));
        assert!(!only_transient_errors(&[network("短链接目录"), real]));
    }

    #[tokio::test]
    async fn preflight_reads_are_sent_together() {
        let (server, mut backend, _dir) = fixture().await;
        let delay = Duration::from_millis(800);
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(
                ok(json!({"id":"zone1","status":"active","account":{"id":"acct1"}}))
                    .set_delay(delay),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(
                ok(json!([{"name":"example.com","type":"A","proxied":true}])).set_delay(delay),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])).set_delay(delay))
            .mount(&server)
            .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let started = Instant::now();
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        // Sequential reads would need at least 3 x 800 ms.
        assert!(
            started.elapsed() < Duration::from_millis(2000),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(prepared["canApply"], true);
        let labels: Vec<_> = prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| check["label"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            labels,
            [
                "域名归属状态",
                "云端域名归属",
                "DNS",
                "转发规则",
                "短链接目录",
                "随机测试链接"
            ]
        );
    }

    #[tokio::test]
    async fn preflight_marks_unreachable_cloudflare_as_a_network_problem() {
        let (_server, mut backend, _dir) = fixture().await;
        let (base, connections) = closing_listener().await;
        backend.cloud = Cloud::for_test(&base);
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], false);
        let checks = prepared["checks"].as_array().unwrap();
        // The failed ownership read hides the later checks, as before.
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1]["label"], "云端域名归属");
        assert_eq!(checks[1]["level"], "error");
        assert_eq!(checks[1]["reason"], "cloud_unreachable");
        let message = checks[1]["message"].as_str().unwrap();
        assert_eq!(message, "暂时连不上 Cloudflare，这是网络问题");
        assert!(!message.contains("归属此账号"), "{message}");
        // Three reads, each tried three times.
        assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 9);
    }

    #[tokio::test]
    async fn preflight_shows_cloudflare_refusals_and_real_state_separately() {
        let (server, mut backend, _dir) = fixture().await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ok(
                json!([{"name":"example.com","type":"A","proxied":true}]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let zone_check = &prepared["checks"][1];
        assert_eq!(zone_check["label"], "云端域名归属");
        assert!(zone_check["message"].as_str().unwrap().contains("HTTP 403"));
        assert_eq!(zone_check["reason"], CLOUD_REFUSED);

        // A readable zone in the wrong state keeps the ownership wording.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ok(
                json!({"id":"zone1","status":"pending","account":{"id":"acct1"}}),
            ))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert!(prepared["checks"][1]["message"]
            .as_str()
            .unwrap()
            .contains("无法确认域名所属区域已启用且归属此账号"));

        // A DNS read refusal names the read and the real cause; routes still show.
        server.reset().await;
        mount_zone_owner(&server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let checks = prepared["checks"].as_array().unwrap();
        let dns = checks.iter().find(|check| check["label"] == "DNS").unwrap();
        let message = dns["message"].as_str().unwrap();
        assert!(message.starts_with("无法读取 DNS 记录："), "{message}");
        assert!(message.contains("HTTP 403"), "{message}");
        assert_eq!(dns["reason"], CLOUD_REFUSED);
        assert!(checks
            .iter()
            .any(|check| check["label"] == "转发规则" && check["level"] == "pass"));
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.method.as_str() == "HEAD"));
    }

    /// The checks that fail because this computer cannot use the saved
    /// authorization carry `credential`; a 401 or 403 answer carries
    /// `cloud_refused`. Both in domain and DNS preparation.
    #[tokio::test]
    async fn preparation_marks_local_authorization_and_cloud_refusals() {
        let (server, mut backend, _dir) = fixture().await;
        for action in ["prepare_domain", "prepare_domain_dns"] {
            backend.db.accounts[0].token_import_pending = true;
            let prepared = backend
                .dispatch(action, &json!({"input":"example.com","prefix":"go"}))
                .await
                .unwrap();
            let check = prepared["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["label"] == "本机授权")
                .unwrap_or_else(|| panic!("{action}: {prepared}"));
            assert_eq!(check["level"], "error");
            assert_eq!(check["reason"], CREDENTIAL, "{action}");
            backend.db.accounts[0].token_import_pending = false;

            keyring_delete("acct1", "token").unwrap();
            let prepared = backend
                .dispatch(action, &json!({"input":"example.com","prefix":"go"}))
                .await
                .unwrap();
            let check = prepared["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["label"] == "凭据")
                .unwrap_or_else(|| panic!("{action}: {prepared}"));
            assert_eq!(check["reason"], CREDENTIAL, "{action}");
            keyring_set("acct1", "token", "test-token-value").unwrap();
        }
        assert!(server.received_requests().await.unwrap().is_empty());

        // HTTP 401 on the zone read, and on the DNS read of a DNS check.
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        mount_zone_owner(&server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        for action in ["prepare_domain", "prepare_domain_dns"] {
            let prepared = backend
                .dispatch(action, &json!({"input":"example.com","prefix":"go"}))
                .await
                .unwrap();
            let check = prepared["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["label"] == "云端域名归属")
                .unwrap();
            assert!(check["message"].as_str().unwrap().contains("HTTP 401"));
            assert_eq!(check["reason"], CLOUD_REFUSED, "{action}");
        }
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        let dns = prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["label"] == "DNS")
            .unwrap();
        assert!(dns["message"].as_str().unwrap().contains("HTTP 401"));
        assert_eq!(dns["reason"], CLOUD_REFUSED);
        // The DNS check reads the zone's whole record list a second time
        // (the safety check before a fix). A 403 there is a refusal too,
        // both with no address record and with an unproxied one.
        let grey = json!({"id":"dns-one","name":"example.com","type":"A",
            "content":"192.0.2.10","proxied":false,"proxiable":true});
        for exact in [json!([]), json!([grey])] {
            server.reset().await;
            mount_zone_owner(&server).await;
            Mock::given(method("GET"))
                .and(path("/client/v4/zones/zone1/dns_records"))
                .and(query_param("name", "example.com"))
                .respond_with(ok(exact.clone()))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/client/v4/zones/zone1/dns_records"))
                .and(query_param_is_missing("name"))
                .respond_with(ResponseTemplate::new(403))
                .mount(&server)
                .await;
            let prepared = backend
                .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
                .await
                .unwrap();
            assert_eq!(prepared["canApply"], false, "{exact}");
            let dns = prepared["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["label"] == "DNS")
                .unwrap_or_else(|| panic!("{exact}: {prepared}"));
            assert!(
                dns["message"].as_str().unwrap().contains("HTTP 403"),
                "{dns}"
            );
            assert_eq!(dns["reason"], CLOUD_REFUSED, "{exact}");
        }
        // A 500 is neither.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert!(prepared["checks"][1].get("reason").is_none(), "{prepared}");
    }

    #[tokio::test]
    async fn preflight_explains_a_cached_zone_that_is_not_active_yet() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].zones[0].status = "pending".into();
        let (checks, risk) = backend
            .preflight(
                "acct1",
                "zone1",
                "example.com",
                "go",
                None,
                local_check::DnsMode::System,
            )
            .await;
        assert!(risk.is_none());
        assert_eq!(checks.len(), 1);
        assert_eq!(
            checks[0].message,
            "这个域名在 Cloudflare 还没生效（当前状态：pending）。请先到 Cloudflare 按提示把域名服务器改好，生效后再来添加"
        );
        let (checks, _) = backend
            .preflight(
                "acct1",
                "zone-other",
                "example.com",
                "go",
                None,
                local_check::DnsMode::System,
            )
            .await;
        assert_eq!(checks[0].message, "域名所属区域未启用，或不属于此账号");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prepare_domain_names_the_account_that_holds_the_domain() {
        let (server, mut backend, _dir) = fixture().await;
        let mut second = backend.db.accounts[0].clone();
        second.id = "acct2".into();
        second.label = "账号 2".into();
        second.zones.clear();
        backend.db.accounts.push(second);
        keyring_set("acct2", "token", "second-test-token").unwrap();
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct2"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go","accountId":"acct2"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], false);
        let check = &prepared["checks"][0];
        assert_eq!(check["label"], "账号选择");
        assert_eq!(
            check["message"],
            "这个域名在账户「账号 1」下，不在你选的账户里；请把上面的账户改成它再检查"
        );
    }

    #[tokio::test]
    async fn domain_plan_survives_network_only_review_failure_and_applies_with_same_id() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();
        let original = backend.plans.iter().find(|p| p.view.id == plan_id).unwrap();
        let (expires_at, plan_snapshot) = (original.expires_at, original.snapshot.clone());
        let state_before = backend.database_snapshot();
        let persists_before = backend
            .persist_count
            .load(std::sync::atomic::Ordering::SeqCst);

        // Both directory probes time out in the review and in its automatic retry.
        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404).set_delay(Duration::from_secs(3)),
            ResponseTemplate::new(404).set_delay(Duration::from_secs(3)),
        )
        .await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(error.starts_with("网络检查没有完成（"), "{error}");
        assert!(error.contains(PLAN_STILL_VALID), "{error}");
        assert!(
            error.contains("云端没有任何改动，可以直接再点一次确认。"),
            "{error}"
        );
        assert!(error.contains("超时"), "{error}");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method.as_str() == "HEAD")
                .count(),
            4,
            "the review runs twice"
        );
        // Invariant: nothing was written before the marker was returned.
        assert!(no_cloud_writes(&requests));
        assert!(backend.db.pending_operations.is_empty());
        assert_eq!(backend.database_snapshot(), state_before);
        assert_eq!(
            backend
                .persist_count
                .load(std::sync::atomic::Ordering::SeqCst),
            persists_before
        );
        let kept = backend.plans.iter().find(|p| p.view.id == plan_id).unwrap();
        assert_eq!(kept.expires_at, expires_at);
        assert_eq!(kept.snapshot, plan_snapshot);
        assert!(matches!(kept.kind, PlanKind::Domain { .. }));

        // The network recovers: the same plan ID now completes.
        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        mount_existing_resource_domain_write(&server).await;
        let state = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap();
        assert_eq!(state["domains"].as_array().unwrap().len(), 1);
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err()
            .contains("计划不存在或已被使用"));
    }

    #[tokio::test]
    async fn domain_review_retries_once_by_itself_after_a_network_failure() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();
        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        // Only the first review's directory probe times out.
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/"))
            .respond_with(ResponseTemplate::new(404).set_delay(Duration::from_secs(3)))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        mount_existing_resource_domain_write(&server).await;
        let state = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap();
        assert_eq!(state["domains"].as_array().unwrap().len(), 1);
        assert!(backend.plans.iter().all(|p| p.view.id != plan_id));
    }

    #[tokio::test]
    async fn domain_review_real_failure_voids_plan_and_names_the_check() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();
        server.reset().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([{"id":"other","pattern":"example.com/go/*","script":"another"}]),
        )
        .await;
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            "复核没有通过（转发规则：现有转发规则与此前缀重叠）。云端没有任何改动，请重新检查域名。"
        );
        assert!(!error.contains(PLAN_STILL_VALID));
        assert!(no_cloud_writes(&server.received_requests().await.unwrap()));
        assert!(backend.db.pending_operations.is_empty());
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err()
            .contains("计划不存在或已被使用"));
    }

    fn region_snapshot(cloud: Cloud) -> SelftestSnapshot {
        SelftestSnapshot {
            cloud,
            host: "example.com".into(),
            path: "/go/sample".into(),
            url: "https://example.com/go/sample".into(),
            cn_url: "https://example.org/local".into(),
            default_url: "https://example.org/global".into(),
            key: Zeroizing::new(vec![0xa1; 32]),
            pool: None,
        }
    }

    #[tokio::test]
    async fn region_test_retries_network_failures_then_passes() {
        let (server, backend, _guard) = fixture().await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/sample"))
            .respond_with(ResponseTemplate::new(404).set_delay(Duration::from_millis(2500)))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/sample"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://example.org/global"),
            )
            .mount(&server)
            .await;
        let check = run_region_test(
            &region_snapshot(backend.cloud.clone()),
            "US",
            "其他地区",
            Some("https://example.org/global"),
            local_check::DnsMode::Public,
        )
        .await
        .unwrap();
        assert!(check.ok, "{}", check.message);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn region_test_reports_a_persistent_network_failure_with_its_reason() {
        let (base, connections) = closing_listener().await;
        let check = run_region_test(
            &region_snapshot(Cloud::for_test(&base)),
            "US",
            "其他地区",
            Some("https://example.org/global"),
            local_check::DnsMode::Public,
        )
        .await
        .unwrap();
        assert!(!check.ok);
        assert_eq!(check.reason.as_deref(), Some("probe_transport_error"));
        assert!(!check.message.contains("传播"), "{}", check.message);
        // Every attempt ran instead of stopping at the first network error.
        assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn selftest_that_never_got_through_the_network_is_pending_not_failed() {
        let (base, _connections) = closing_listener().await;
        let report = run_selftest_with_mode(
            region_snapshot(Cloud::for_test(&base)),
            local_check::DnsMode::Public,
        )
        .await
        .unwrap();
        // No response at all says nothing about the route or the targets.
        assert_eq!(report["status"], "pending", "{report}");
        assert_eq!(report["message"], SELFTEST_NETWORK_MESSAGE);
        let checks = report["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2);
        for check in checks {
            assert_eq!(check["reason"], "probe_transport_error", "{check}");
            assert!(
                !check["message"].as_str().unwrap().contains("传播"),
                "{check}"
            );
        }
    }

    #[tokio::test]
    async fn selftest_summary_keeps_propagation_and_mismatch_wording() {
        // A 404 on every attempt is still reported as propagation.
        let (server, backend, _guard) = fixture().await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/sample"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let report = run_selftest_with_mode(
            region_snapshot(backend.cloud.clone()),
            local_check::DnsMode::Public,
        )
        .await
        .unwrap();
        assert_eq!(report["status"], "pending", "{report}");
        assert_eq!(report["message"], "边缘配置可能仍在传播");

        // A wrong answer is a real failure.
        server.reset().await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/sample"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://example.org/wrong"),
            )
            .mount(&server)
            .await;
        let report = run_selftest_with_mode(
            region_snapshot(backend.cloud.clone()),
            local_check::DnsMode::Public,
        )
        .await
        .unwrap();
        assert_eq!(report["status"], "failed", "{report}");
        assert_eq!(report["message"], "自检失败，请检查转发规则和目标地址");
    }

    #[tokio::test]
    async fn network_only_review_failure_drops_the_marker_when_the_plan_expired_meanwhile() {
        let (server, mut backend, _dir) = fixture().await;
        mount_domain_hard_checks(
            &server,
            json!([{"name":"example.com","type":"A","proxied":true}]),
            json!([]),
        )
        .await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        let plan_id = prepared["plan"]["id"].as_str().unwrap().to_owned();
        // The plan is still valid when confirmed but runs out while the review
        // (two rounds of reads that get no response) is in progress.
        backend
            .plans
            .iter_mut()
            .find(|p| p.view.id == plan_id)
            .unwrap()
            .expires_at = Instant::now() + Duration::from_millis(500);
        let state_before = backend.database_snapshot();
        let (base, _connections) = closing_listener().await;
        backend.cloud = Cloud::for_test(&base);
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err();
        assert!(
            error.starts_with("网络检查没有完成（云端域名归属："),
            "{error}"
        );
        assert!(!error.contains(PLAN_STILL_VALID), "{error}");
        assert!(!error.contains("再点一次确认"), "{error}");
        assert!(error.ends_with(PLAN_GONE_TAIL), "{error}");
        assert!(backend.plans.iter().all(|p| p.view.id != plan_id));
        assert!(backend.db.pending_operations.is_empty());
        assert_eq!(backend.database_snapshot(), state_before);
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":plan_id}))
            .await
            .unwrap_err()
            .contains("计划不存在或已被使用"));
    }

    #[tokio::test]
    async fn first_domain_checks_cloud_for_existing_app_resources_before_any_write() {
        let manifest = json!({"schema":SCHEMA,"accountId":"acct1","script":"edge-old",
            "namespace":"ns1","sourceHash":bundled_source_hash()})
        .to_string();
        for case in [
            "owned",
            "owned-worker-missing",
            "owned-worker-unreadable",
            "list-fails",
            "read-fails",
            "no-manifest",
            "foreign",
        ] {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.accounts[0].resources = None;
            backend.db.accounts[0].has_resources = false;
            Mock::given(method("GET"))
                .and(path(
                    "/client/v4/accounts/acct1/workers/scripts/edge-old/settings",
                ))
                .respond_with(match case {
                    "owned-worker-missing" => ResponseTemplate::new(404),
                    "owned-worker-unreadable" => ResponseTemplate::new(500),
                    _ => ok(json!({"bindings":[]})),
                })
                .mount(&server)
                .await;
            mount_domain_hard_checks(
                &server,
                json!([{"name":"example.com","type":"A","proxied":true}]),
                json!([]),
            )
            .await;
            Mock::given(method("HEAD"))
                .and(path_regex(r"^/client/v4/probe/example\.com/go/"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
            let namespaces = if case == "list-fails" {
                ResponseTemplate::new(500)
            } else {
                ok(json!([{"id":"ns1","title":"links-old"}]))
            };
            Mock::given(method("GET"))
                .and(path("/client/v4/accounts/acct1/storage/kv/namespaces"))
                .respond_with(namespaces)
                .mount(&server)
                .await;
            let value = match case {
                "read-fails" => ResponseTemplate::new(500),
                "no-manifest" => ResponseTemplate::new(404),
                "foreign" => ResponseTemplate::new(200).set_body_string(
                    json!({"schema":SCHEMA,"accountId":"other","script":"edge-old",
                        "namespace":"ns1"})
                    .to_string(),
                ),
                _ => ResponseTemplate::new(200).set_body_string(manifest.clone()),
            };
            Mock::given(method("GET"))
                .and(path(
                    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Aconfig",
                ))
                .respond_with(value)
                .mount(&server)
                .await;
            // Stops the flow right after the check, before any write.
            Mock::given(method("GET"))
                .and(path("/client/v4/accounts/acct1/workers/scripts"))
                .respond_with(ResponseTemplate::new(503))
                .mount(&server)
                .await;
            let error = backend
                .apply_domain(
                    "acct1",
                    "zone1",
                    "example.com",
                    "go",
                    DomainTakeover {
                        dns_mode: local_check::DnsMode::System,
                        expected_path_risk: &PathRiskSnapshot {
                            root: domain_check::ProbeRisk::Missing,
                            child: domain_check::ProbeRisk::Missing,
                            probe_segment: "probe-fixed".into(),
                        },
                        requires_confirmation: false,
                        acknowledged: false,
                    },
                )
                .await
                .unwrap_err();
            let requests = server.received_requests().await.unwrap();
            let listed_scripts = requests
                .iter()
                .any(|r| r.url.path() == "/client/v4/accounts/acct1/workers/scripts");
            match case {
                "owned" => {
                    assert!(
                        error.contains("已有本工具创建的转发程序"),
                        "{case}: {error}"
                    );
                    assert!(error.contains("从 Cloudflare 找回配置"));
                    assert!(!listed_scripts);
                }
                "owned-worker-missing" => {
                    // Recovery cannot work without the Worker: say what is left.
                    assert!(error.contains("已经不存在，无法自动找回"), "{error}");
                    assert!(error.contains("KV 命名空间 ID 末尾 ns1"));
                    assert!(error.contains("edge-old"));
                    assert!(!error.contains("从 Cloudflare 找回配置"));
                    assert!(!listed_scripts);
                }
                "owned-worker-unreadable" => {
                    assert!(
                        error.contains("无法确认此账号云端是否已有"),
                        "{case}: {error}"
                    );
                    assert!(error.contains("HTTP 500"));
                    assert!(!listed_scripts);
                }
                "list-fails" | "read-fails" => {
                    assert!(
                        error.contains("无法确认此账号云端是否已有"),
                        "{case}: {error}"
                    );
                    assert!(error.contains("HTTP 500"));
                    assert!(!listed_scripts);
                }
                _ => {
                    assert!(!error.contains("本工具创建"), "{case}: {error}");
                    assert!(listed_scripts, "{case}: {error}");
                }
            }
            assert!(!requests
                .iter()
                .any(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE")));
            assert!(backend.db.pending_operations.is_empty(), "{case}");
            assert!(backend.db.domains.is_empty());
        }
    }

    #[tokio::test]
    async fn existing_cloud_config_blocks_domain_write() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ok(json!({"id":"zone1","status":"active",
                "account":{"id":"acct1"}})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ok(json!([{"name":"example.com","type":"A","proxied":true},
                {"name":"example.com","type":"TXT","proxied":false}])))
            .mount(&server)
            .await;
        // A complete earlier setup of this host (config plus this tool's
        // route, under another directory) is not on this computer.
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(
                json!([{"id":"route-old","pattern":"example.com/other/*",
                "script":"edge-one"}]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path_regex(r"^/client/v4/probe/example\.com/go/probe-"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"prefix":"other"}"#))
            .mount(&server)
            .await;
        let error = backend
            .apply_domain(
                "acct1",
                "zone1",
                "example.com",
                "go",
                DomainTakeover {
                    dns_mode: local_check::DnsMode::System,
                    expected_path_risk: &PathRiskSnapshot {
                        root: domain_check::ProbeRisk::Missing,
                        child: domain_check::ProbeRisk::Missing,
                        probe_segment: "probe-fixed".into(),
                    },
                    requires_confirmation: false,
                    acknowledged: false,
                },
            )
            .await
            .unwrap_err();
        assert!(error.contains("已有此主机名"));
        assert!(
            error.contains("“管理账户”，点“从 Cloudflare 找回配置”"),
            "{error}"
        );
        let requests = server.received_requests().await.unwrap();
        assert!(!requests
            .iter()
            .any(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE")));
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn server_error_on_link_write_keeps_uncertain_journal() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(404)).mount(&server).await;
        Mock::given(method("PUT"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(503)).mount(&server).await;
        let error = backend
            .apply_save_link(
                "domain1",
                "short",
                "https://example.org/cn",
                "https://example.org/other",
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.contains("HTTP 503"));
        assert_eq!(backend.db.pending_operations.len(), 1);
        assert!(backend.db.pending_operations[0].contains("不确定"));
        assert!(backend.db.links.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.iter().any(|r| r.method.as_str() == "DELETE"));
    }

    const SHORT_PATH: &str =
        "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort";
    fn unrelated_journals() -> Vec<String> {
        vec![
            "保存链接 example.com / shorter (aaa)：写入结果不确定，需要人工核对".into(),
            "删除链接 www.example.com / short (bbb)：删除结果不确定，需要人工核对".into(),
            "添加域名 example.com/go (ccc)".into(),
        ]
    }

    #[tokio::test]
    async fn later_successful_save_clears_only_that_links_uncertain_record() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.pending_operations = unrelated_journals();
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(SHORT_PATH))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        async fn save(backend: &mut Backend) -> Result<(), String> {
            backend
                .apply_save_link(
                    "domain1",
                    "short",
                    "https://example.org/cn",
                    "https://example.org/other",
                    None,
                    None,
                )
                .await
        }
        assert!(save(&mut backend).await.is_err());
        assert_eq!(backend.db.pending_operations.len(), 4);
        assert!(backend
            .db
            .pending_operations
            .iter()
            .any(|entry| entry.starts_with("保存链接 example.com / short (")));
        save(&mut backend).await.unwrap();
        assert_eq!(backend.db.pending_operations, unrelated_journals());
        let disk: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(disk.pending_operations, unrelated_journals());
        assert_eq!(backend.db.links.len(), 1);
    }

    #[tokio::test]
    async fn later_successful_delete_clears_that_links_uncertain_record() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let local = url_link("short", "https://example.org/cn", "https://example.org/d");
        backend.db.links.push(local.clone());
        backend.db.pending_operations = unrelated_journals();
        backend
            .db
            .pending_operations
            .push("保存链接 example.com / short (ddd)：写入结果不确定，需要人工核对".into());
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_link(&local)))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(SHORT_PATH))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        assert!(backend.apply_delete_link("domain1", "short").await.is_err());
        assert_eq!(backend.db.pending_operations.len(), 5);
        assert_eq!(backend.db.links.len(), 1);
        backend.apply_delete_link("domain1", "short").await.unwrap();
        assert_eq!(backend.db.pending_operations, unrelated_journals());
        let disk: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(disk.pending_operations, unrelated_journals());
        assert!(backend.db.links.is_empty());
    }

    #[tokio::test]
    async fn link_save_persist_failure_keeps_leftover_records() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let leftover = "保存链接 example.com / short (eee)：写入结果不确定，需要人工核对";
        backend.db.pending_operations = vec![leftover.into()];
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(SHORT_PATH))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        // Persist 1 records the journal; persist 2 (link + cleanup) fails.
        backend.fail_persist_at.store(
            backend
                .persist_count
                .load(std::sync::atomic::Ordering::SeqCst)
                + 2,
            std::sync::atomic::Ordering::SeqCst,
        );
        assert!(backend
            .apply_save_link(
                "domain1",
                "short",
                "https://example.org/cn",
                "https://example.org/other",
                None,
                None,
            )
            .await
            .is_err());
        assert!(backend
            .db
            .pending_operations
            .iter()
            .any(|entry| entry == leftover));
        assert_eq!(backend.db.pending_operations.len(), 2);
        let disk: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert!(disk
            .pending_operations
            .iter()
            .any(|entry| entry == leftover));
    }

    #[tokio::test]
    async fn editing_a_link_keeps_its_position_and_drops_duplicates() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let old = url_link("b", "https://example.org/old", "https://example.org/old-d");
        backend.db.links = vec![
            url_link("a", "https://example.org/a", "https://example.org/a-d"),
            old.clone(),
            url_link("c", "https://example.org/c", "https://example.org/c-d"),
            old.clone(),
        ];
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        let b_path =
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ab";
        Mock::given(method("GET"))
            .and(path(b_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_link(&old)))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(b_path))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        backend
            .apply_save_link(
                "domain1",
                "b",
                "https://example.org/new",
                "https://example.org/new-d",
                None,
                None,
            )
            .await
            .unwrap();
        let slugs: Vec<_> = backend.db.links.iter().map(|l| l.slug.as_str()).collect();
        assert_eq!(slugs, ["a", "b", "c"]);
        assert_eq!(backend.db.links[1].cn_url, "https://example.org/new");
    }

    #[tokio::test]
    async fn restored_delete_keeps_the_link_at_its_position() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let local = url_link("short", "https://example.org/cn", "https://example.org/d");
        backend.db.links = vec![
            local.clone(),
            url_link("z", "https://example.org/z", "https://example.org/z-d"),
        ];
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_link(&local)))
            .mount(&server)
            .await;
        for verb in ["DELETE", "PUT"] {
            Mock::given(method(verb))
                .and(path(SHORT_PATH))
                .respond_with(ok(json!({})))
                .mount(&server)
                .await;
        }
        backend.fail_persist_at.store(
            backend
                .persist_count
                .load(std::sync::atomic::Ordering::SeqCst)
                + 2,
            std::sync::atomic::Ordering::SeqCst,
        );
        assert!(backend.apply_delete_link("domain1", "short").await.is_err());
        let slugs: Vec<_> = backend.db.links.iter().map(|l| l.slug.as_str()).collect();
        assert_eq!(slugs, ["short", "z"]);
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn retry_after_possibly_applied_write_points_to_recovery() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(
                json!([{"name":"l:example.com:short"},{"name":"l:example.com:Mixed"}]),
            ))
            .mount(&server)
            .await;
        let error = backend
            .apply_save_link(
                "domain1",
                "short",
                "https://example.org/cn",
                "https://example.org/other",
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(
            error.contains("云端已有同名链接 example.com / short"),
            "{error}"
        );
        assert!(error.contains("从 Cloudflare 找回配置"));
        assert!(!error.contains("大小写相同"));
        let error = backend
            .apply_save_link(
                "domain1",
                "mixed",
                "https://example.org/cn",
                "https://example.org/other",
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.contains("大小写相同"), "{error}");

        backend.db.links.push(url_link(
            "short",
            "https://example.org/cn",
            "https://example.org/d",
        ));
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let error = backend
            .apply_delete_link("domain1", "short")
            .await
            .unwrap_err();
        assert!(error.contains("可能上次删除已生效"), "{error}");
        assert!(error.contains("example.com / short"));
        assert!(!error.contains("请刷新"));
        assert!(backend.db.pending_operations.is_empty());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn changed_worker_source_blocks_cleanup_before_delete() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(
            &server,
            "export default { fetch(){ return new Response('changed') } }",
        )
        .await;
        let error = backend.apply_cleanup("acct1").await.unwrap_err();
        assert!(error.contains("内容已变化"));
        assert!(backend.db.pending_operations.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.iter().any(|r| r.method.as_str() == "DELETE"));
    }

    #[tokio::test]
    async fn route_delete_rejection_restores_only_removed_domain_values() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(Link {
            domain_id: "domain1".into(),
            slug: "short".into(),
            cn_url: "https://example.org/cn".into(),
            default_url: "https://example.org/other".into(),
            updated: now(),
            pool_id: None,
            code: None,
        });
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success":true,"result":[{"name":"l:example.com:short"}],
                "result_info":{"count":1,"cursor":""}
            })))
            .mount(&server)
            .await;
        let link_json = kv_link(&backend.db.links[0]).to_string();
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(200).set_body_string(link_json.clone()))
            .mount(&server).await;
        for key in ["l%3Aexample.com%3Ashort", "c%3Aexample.com"] {
            Mock::given(method("DELETE"))
                .and(path(format!(
                    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/{key}"
                )))
                .respond_with(ok(json!({})))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(path(format!(
                    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/{key}"
                )))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path("/client/v4/zones/zone1/workers/routes/route1"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let error = backend.apply_remove_domain("domain1").await.unwrap_err();
        assert!(error.contains("HTTP 400"));
        assert!(backend.db.pending_operations.is_empty());
        assert_eq!(backend.db.domains.len(), 1);
        assert_eq!(backend.db.links.len(), 1);
        let requests = server.received_requests().await.unwrap();
        let restored_link = requests
            .iter()
            .find(|r| {
                r.method.as_str() == "PUT" && r.url.path().ends_with("l%3Aexample.com%3Ashort")
            })
            .unwrap();
        assert_eq!(restored_link.body, link_json.as_bytes());
        assert!(requests
            .iter()
            .any(|r| r.method.as_str() == "PUT" && r.url.path().ends_with("c%3Aexample.com")));
    }

    #[tokio::test]
    async fn multipart_worker_download_hashes_only_the_main_module() {
        let (server, backend, _dir) = fixture().await;
        let source = include_str!("../../edge/worker.mjs");
        let body = format!(
            "--TeStBoundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{{\"main_module\":\"worker.mjs\"}}\r\n--TeStBoundary\r\nContent-Disposition: form-data; name=\"worker.mjs\"; filename=\"worker.mjs\"\r\nContent-Type: application/javascript+module\r\n\r\n{source}\r\n--TeStBoundary--\r\n"
        );
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/content/v2",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                body.as_bytes().to_vec(),
                "multipart/form-data; boundary=TeStBoundary",
            ))
            .mount(&server)
            .await;
        let module = backend
            .cloud
            .script_content("test-token-value", "acct1", "edge-one")
            .await
            .unwrap();
        assert_eq!(module, source.as_bytes());
        assert_eq!(hex::encode(Sha256::digest(module)), bundled_source_hash());
    }

    pub(super) fn sample_pool() -> Pool {
        Pool {
            id: "pool1".into(),
            name: "测试平台地址".into(),
            official: model::Template {
                prefix: "https://official.example/path/".into(),
                suffix: "".into(),
            },
            candidates: vec![
                model::PoolCandidate {
                    id: "first".into(),
                    prefix: "https://first.example/path/".into(),
                    suffix: "".into(),
                    enabled: true,
                },
                model::PoolCandidate {
                    id: "second".into(),
                    prefix: "https://second.example/path/".into(),
                    suffix: "".into(),
                    enabled: true,
                },
            ],
            updated: now(),
            account_ids: vec!["acct1".into()],
            sync_status: vec![],
        }
    }

    #[tokio::test]
    async fn global_pool_is_saved_locally_without_account_permission_selection() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.account_ids = vec!["unrelated-account".into()];
        let plan = backend
            .prepare_change(&json!({"kind":"save_pool","pool":pool}))
            .unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert!(backend.db.pools[0].account_ids.is_empty());
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(mock_key_reads().lock().unwrap().is_empty());
        backend.db.pools[0].account_ids.push("acct1".into());
        let mut edited = backend.db.pools[0].clone();
        edited.account_ids.clear();
        edited.name = "更新名称".into();
        backend
            .prepare_change(&json!({"kind":"save_pool","pool":edited}))
            .unwrap();
        let PlanKind::SavePool { pool: planned } = &backend.plans.last().unwrap().kind else {
            panic!("wrong plan")
        };
        assert_eq!(planned.account_ids, vec!["acct1"]);
    }

    #[tokio::test]
    async fn global_pool_first_link_syncs_only_its_domain_account_before_link() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let mut pool = sample_pool();
        pool.account_ids.clear();
        backend.db.pools.push(pool);
        let mut other = backend.db.accounts[0].clone();
        other.id = "acct2".into();
        backend.db.accounts.push(other);
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        for name in ["p%3Apool1", "l%3Aexample.com%3Aglobal"] {
            let target =
                format!("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/{name}");
            Mock::given(method("GET"))
                .and(path(target.clone()))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(path(target))
                .respond_with(ok(json!({})))
                .mount(&server)
                .await;
        }
        let plan = backend.prepare_change(&json!({"kind":"save_link","domainId":"domain1","slug":"global","poolId":"pool1","code":"DEMO"})).unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert_eq!(backend.db.links[0].code.as_deref(), Some("DEMO"));
        assert_eq!(backend.db.pools[0].account_ids, vec!["acct1"]);
        assert_eq!(backend.db.pools[0].sync_status[0].status, "synced");
        assert!(backend.db.pending_pool_changes.is_empty());
        let req = server.received_requests().await.unwrap();
        assert!(req.iter().all(|r| !r.url.path().contains("acct2")));
        let writes: Vec<_> = req.iter().filter(|r| r.method.as_str() == "PUT").collect();
        assert_eq!(writes.len(), 2);
        assert!(writes[0].url.path().ends_with("p%3Apool1"));
        assert!(writes[1].url.path().ends_with("l%3Aexample.com%3Aglobal"));
        assert!(!mock_key_reads()
            .lock()
            .unwrap()
            .iter()
            .any(|id| id.contains("acct2")));
    }

    /// A pool recorded as synced whose cloud copy is gone: saving a link says
    /// how to re-create the copy (「编辑地址」→ save) and writes nothing.
    #[tokio::test]
    async fn link_save_on_a_synced_pool_missing_in_the_cloud_names_the_way_out() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let mut pool = sample_pool();
        pool.sync_status = vec![PoolSyncStatus {
            account_id: "acct1".into(),
            status: "synced".into(),
            message: "已同步".into(),
        }];
        backend.db.pools.push(pool);
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path_regex("/values/(p%3Apool1|l%3Aexample.com%3Aglobal)$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let plan = backend.prepare_change(&json!({"kind":"save_link","domainId":"domain1","slug":"global","poolId":"pool1","code":"DEMO"})).unwrap();
        let error = backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap_err();
        assert_eq!(error, POOL_COPY_MISSING_FOR_LINK);
        assert!(
            error.contains("「平台地址」页点这组地址的「编辑地址」"),
            "{error}"
        );
        assert!(error.contains("不用改内容，直接保存一次"), "{error}");
        assert!(backend.db.links.is_empty());
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(!server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE")));
    }

    #[tokio::test]
    async fn global_pool_failed_first_use_keeps_intent_and_does_not_write_link() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        let mut pool = sample_pool();
        pool.account_ids.clear();
        backend.db.pools.push(pool);
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path_regex("/values/(p%3Apool1|l%3Aexample.com%3Aglobal)$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let plan = backend.prepare_change(&json!({"kind":"save_link","domainId":"domain1","slug":"global","poolId":"pool1","code":"DEMO"})).unwrap();
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap_err()
            .contains("503"));
        assert!(backend.db.links.is_empty());
        assert_eq!(backend.db.pending_pool_changes.len(), 1);
        let disk: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(disk.pending_pool_changes.len(), 1);
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() != "PUT" || r.url.path().ends_with("p%3Apool1")));
        assert!(backend.prepare_change(&json!({"kind":"save_link","domainId":"domain1","slug":"global","poolId":"pool1","code":"DEMO"})).is_err());
        server.reset().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        let pending = backend.db.pending_pool_changes[0].pool.clone();
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(pools::cloud_value(&pending).to_string()),
            )
            .mount(&server)
            .await;
        backend.apply_save_pool(pending).await.unwrap();
        assert!(backend.db.pending_pool_changes.is_empty());
        assert_eq!(backend.db.pools[0].sync_status[0].status, "synced");
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    /// The cloud copy of a pool this computer records as synced went missing:
    /// saving it again without changes re-creates the copy, and deleting it
    /// counts that account as already done.
    #[tokio::test]
    async fn pool_whose_synced_cloud_copy_is_missing_can_be_saved_or_deleted() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.sync_status = vec![PoolSyncStatus {
            account_id: "acct1".into(),
            status: "synced".into(),
            message: "已同步".into(),
        }];
        backend.db.pools.push(pool.clone());
        backend.persist().unwrap();
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        // The edit form sends the same content back; preparing accepts it.
        let plan = backend
            .prepare_change(&json!({"kind":"save_pool","pool":pool}))
            .unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(backend.db.pending_operations.is_empty());
        assert_eq!(backend.db.pools[0].sync_status[0].status, "synced");
        let puts: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_str() == "PUT")
            .collect();
        assert_eq!(puts.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&puts[0].body).unwrap(),
            pools::cloud_value(&backend.db.pools[0])
        );
        server.reset().await;

        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .and(query_param("prefix", "l:"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        backend.apply_delete_pool("pool1").await.unwrap();
        assert!(backend.db.pools.is_empty());
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(backend.db.pending_operations.is_empty());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn pool_sync_and_delete_errors_name_the_account() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"different":"configuration"})),
            )
            .mount(&server)
            .await;
        let error = backend.apply_save_pool(sample_pool()).await.unwrap_err();
        assert!(error.starts_with("账户「账号 1」："), "{error}");
        assert!(error.contains("云端已有不同的同名平台地址"));
        assert!(backend.db.pending_operations.is_empty());

        backend.db.pools.push(sample_pool());
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .and(query_param("prefix", "l:"))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
        let error = backend.apply_delete_pool("pool1").await.unwrap_err();
        assert!(error.starts_with("账户「账号 1」："), "{error}");
        assert!(error.contains("停止删除"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn global_pool_refused_first_use_rolls_back_and_unblocks_retry() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.account_ids.clear();
        backend.db.pools.push(pool);
        let pools_before = serde_json::to_value(&backend.db.pools).unwrap();
        let resources = backend.db.accounts[0].resources.clone().unwrap();
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(403))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let error = backend
            .ensure_pool_on_account("pool1", "acct1", "test-token-value", &resources)
            .await
            .unwrap_err();
        assert!(error.contains("HTTP 403"), "{error}");
        assert!(error.contains("短链接未保存"));
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(backend.db.pending_operations.is_empty());
        assert_eq!(
            serde_json::to_value(&backend.db.pools).unwrap(),
            pools_before
        );
        let disk: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert!(disk.pending_pool_changes.is_empty());
        assert!(disk.pending_operations.is_empty());
        // A later attempt is not blocked by a leftover record.
        Mock::given(method("PUT"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        backend
            .ensure_pool_on_account("pool1", "acct1", "test-token-value", &resources)
            .await
            .unwrap();
        assert_eq!(backend.db.pools[0].sync_status[0].status, "synced");
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn global_pool_first_use_updates_current_monitor_and_preserves_other_receipts() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].monitor_enabled = true;
        backend.db.accounts[0].monitor_endpoint = Some("https://probe.example/check".into());
        let mut pool = sample_pool();
        pool.account_ids = vec!["acct2".into()];
        pool.sync_status = vec![PoolSyncStatus {
            account_id: "acct2".into(),
            status: "synced".into(),
            message: "已同步".into(),
        }];
        let revision = pool.updated.clone();
        backend.db.pools.push(pool);
        let resource = backend.db.accounts[0].resources.clone().unwrap();
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/values/m%3Amonitor$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"endpoint":"https://probe.example/check","poolIds":[]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex("/values/(p%3Apool1|m%3Amonitor)$"))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        backend
            .ensure_pool_on_account("pool1", "acct1", "test-token-value", &resource)
            .await
            .unwrap();
        assert_eq!(backend.db.pools[0].account_ids, vec!["acct2", "acct1"]);
        assert_eq!(backend.db.pools[0].updated, revision);
        assert!(backend.db.pools[0]
            .sync_status
            .iter()
            .all(|s| s.status == "synced"));
        let req = server.received_requests().await.unwrap();
        assert!(req.iter().all(|r| r.url.path().contains("acct1")));
        let monitor = req
            .iter()
            .find(|r| r.method.as_str() == "PUT" && r.url.path().ends_with("m%3Amonitor"))
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&monitor.body).unwrap()["poolIds"],
            json!(["pool1"])
        );
    }

    #[tokio::test]
    async fn global_pool_prewrite_persist_failure_and_remote_conflict_never_write() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.account_ids.clear();
        backend.db.pools.push(pool);
        let resources = backend.db.accounts[0].resources.clone().unwrap();
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"different":"configuration"})),
            )
            .mount(&server)
            .await;
        assert!(backend
            .ensure_pool_on_account("pool1", "acct1", "test-token-value", &resources)
            .await
            .unwrap_err()
            .contains("版本不同"));
        assert!(backend.db.pending_pool_changes.is_empty());
        server.reset().await;
        Mock::given(method("GET"))
            .and(path_regex("/values/p%3Apool1$"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        backend.fail_persist_at.store(
            backend
                .persist_count
                .load(std::sync::atomic::Ordering::SeqCst)
                + 1,
            std::sync::atomic::Ordering::SeqCst,
        );
        assert!(backend
            .ensure_pool_on_account("pool1", "acct1", "test-token-value", &resources)
            .await
            .is_err());
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(backend.db.pools[0].account_ids.is_empty());
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn global_pool_edit_updates_every_used_account_without_changing_codes() {
        let (server, mut backend, _dir) = fixture().await;
        let mut other = backend.db.accounts[0].clone();
        other.id = "acct2".into();
        other.resources = Some(Resources {
            script: "edge-two".into(),
            namespace: "ns2".into(),
        });
        backend.db.accounts.push(other);
        keyring_set("acct2", "token", "second-token-value").unwrap();
        let mut old = sample_pool();
        old.account_ids = vec!["acct1".into(), "acct2".into()];
        old.sync_status = old
            .account_ids
            .iter()
            .map(|id| PoolSyncStatus {
                account_id: id.clone(),
                status: "synced".into(),
                message: "已同步".into(),
            })
            .collect();
        backend.db.pools.push(old.clone());
        backend.db.domains.push(domain());
        let mut other_domain = domain();
        other_domain.id = "domain2".into();
        other_domain.account_id = "acct2".into();
        other_domain.host = "example.org".into();
        backend.db.domains.push(other_domain);
        for (domain_id, code) in [("domain1", "DEMO_A"), ("domain2", "DEMO_B")] {
            backend.db.links.push(Link {
                domain_id: domain_id.into(),
                slug: "shared".into(),
                cn_url: String::new(),
                default_url: String::new(),
                updated: now(),
                pool_id: Some("pool1".into()),
                code: Some(code.into()),
            });
        }
        for (account, script, namespace) in
            [("acct1", "edge-one", "ns1"), ("acct2", "edge-two", "ns2")]
        {
            let base = format!("/client/v4/accounts/{account}");
            Mock::given(method("GET")).and(path(format!("{base}/storage/kv/namespaces/{namespace}/values/m%3Aconfig")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"schema":SCHEMA,"accountId":account,"script":script,"namespace":namespace,"sourceHash":bundled_source_hash()}))).mount(&server).await;
            Mock::given(method("GET")).and(path(format!("{base}/workers/scripts/{script}/settings")))
                .respond_with(ok(json!({"bindings":[{"type":"kv_namespace","name":"LINKS","namespace_id":namespace},{"type":"secret_text","name":"SELFTEST_KEY"}]}))).mount(&server).await;
            Mock::given(method("GET"))
                .and(path(format!("{base}/workers/scripts/{script}/content/v2")))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    include_str!("../../edge/worker.mjs").as_bytes(),
                    "application/javascript",
                ))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!(
                    "{base}/storage/kv/namespaces/{namespace}/values/p%3Apool1"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(pools::cloud_value(&old)))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(path(format!(
                    "{base}/storage/kv/namespaces/{namespace}/values/p%3Apool1"
                )))
                .respond_with(ok(json!({})))
                .mount(&server)
                .await;
        }
        let mut edit = old;
        edit.account_ids.clear();
        edit.candidates[0].prefix = "https://new.example/path/".into();
        let plan = backend
            .prepare_change(&json!({"kind":"save_pool","pool":edit}))
            .unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        let req = server.received_requests().await.unwrap();
        let writes: Vec<_> = req.iter().filter(|r| r.method.as_str() == "PUT").collect();
        assert_eq!(writes.len(), 2);
        assert!(
            writes.iter().any(|r| r.url.path().contains("acct1"))
                && writes.iter().any(|r| r.url.path().contains("acct2"))
        );
        assert!(writes
            .iter()
            .all(
                |r| serde_json::from_slice::<Value>(&r.body).unwrap()["candidates"][0]["prefix"]
                    == "https://new.example/path/"
            ));
        assert_eq!(backend.db.links[0].code.as_deref(), Some("DEMO_A"));
        assert_eq!(backend.db.links[1].code.as_deref(), Some("DEMO_B"));
        assert!(backend.db.pending_pool_changes.is_empty());
    }

    #[tokio::test]
    async fn pool_write_503_remains_journaled_and_unsynced() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let error = backend.apply_save_pool(sample_pool()).await.unwrap_err();
        assert!(error.contains("503"));
        assert_eq!(backend.db.pending_operations.len(), 1);
        assert_eq!(backend.db.pools[0].sync_status[0].status, "unknown");
    }

    #[tokio::test]
    async fn remote_template_reference_blocks_pool_delete() {
        let (server, mut backend, _dir) = fixture().await;
        let pool = sample_pool();
        backend.db.pools.push(pool);
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .respond_with(ok(json!([{"name":"l:unknown.example:old"}])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aunknown.example%3Aold"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"poolId":"pool1","code":"abc","updated":"now"}"#))
            .mount(&server).await;
        let error = backend.apply_delete_pool("pool1").await.unwrap_err();
        assert!(error.contains("云端仍有链接引用"));
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.iter().any(|r| r.method.as_str() == "DELETE"));
    }

    #[tokio::test]
    async fn template_backup_keeps_reference_and_state_composes_current_pool() {
        let (_server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.account_ids.clear();
        backend.db.pools.push(pool);
        backend.db.domains.push(domain());
        backend.db.links.push(Link {
            domain_id: "domain1".into(),
            slug: "short".into(),
            cn_url: String::new(),
            default_url: String::new(),
            updated: now(),
            pool_id: Some("pool1".into()),
            code: Some("abc".into()),
        });
        let state = backend.state();
        assert_eq!(
            state["links"][0]["defaultUrl"],
            "https://official.example/path/abc"
        );
        assert!(backend.db.links[0].default_url.is_empty());
        let backup = backend
            .export_config()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert!(backup.contains("\"poolId\": \"pool1\""));
        assert!(!backup.contains("https://first.example/path/abc"));
    }

    #[test]
    fn selftest_selects_next_candidate_only_for_fresh_unhealthy() {
        let pool = sample_pool();
        let now = Utc::now().timestamp();
        let health = json!({"revision":pool.updated,"targets":{
            "first":{"state":"unhealthy","checkedAt":now},
            "second":{"state":"healthy","checkedAt":now}}});
        assert_eq!(
            chosen_cn_target(&pool, "abc", Some(&health), now)
                .unwrap()
                .unwrap(),
            "https://second.example/path/abc"
        );
        assert_eq!(
            chosen_cn_target(&pool, "abc", Some(&health), now + 3601)
                .unwrap()
                .unwrap(),
            "https://first.example/path/abc"
        );
    }

    #[tokio::test]
    async fn monitor_plan_never_exposes_secret() {
        let (_server, mut backend, _dir) = fixture().await;
        let secret = "s".repeat(48);
        let plan = backend
            .dispatch(
                "prepare_monitor",
                &json!({"accountId":"acct1",
            "endpoint":"https://probe.example/check","secret":secret}),
            )
            .await
            .unwrap();
        assert!(!plan.to_string().contains(&secret));
        assert!(!backend.state().to_string().contains(&secret));
        assert!(monitor_endpoint("https://127.0.0.1/check").is_err());
    }

    #[tokio::test]
    async fn pool_retry_accepts_only_previous_or_desired_remote_version() {
        let (server, mut backend, _dir) = fixture().await;
        let mut old = sample_pool();
        old.sync_status.push(PoolSyncStatus {
            account_id: "acct1".into(),
            status: "synced".into(),
            message: "已同步".into(),
        });
        let old_value = pools::cloud_value(&old).to_string();
        let mut desired = old.clone();
        desired.candidates[0].prefix = "https://new.example/path/".into();
        desired.updated = (Utc::now() + chrono::Duration::seconds(1)).to_rfc3339();
        backend.db.pools.push(old);
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(old_value.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert!(backend
            .apply_save_pool(desired)
            .await
            .unwrap_err()
            .contains("503"));
        assert_eq!(backend.db.pending_pool_changes.len(), 1);
        assert_eq!(
            backend.state()["pendingActions"][0]["kind"],
            "resume_pool_sync"
        );
        server.reset().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(old_value))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let pending = backend.db.pending_pool_changes[0].pool.clone();
        backend.apply_save_pool(pending).await.unwrap();
        assert!(backend.db.pending_pool_changes.is_empty());
        assert!(backend.db.pending_operations.is_empty());
        assert_eq!(backend.db.pools[0].sync_status[0].status, "synced");
    }

    #[tokio::test]
    async fn delete_link_persist_failure_restores_cloud_and_local_record() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(Link {
            domain_id: "domain1".into(),
            slug: "short".into(),
            cn_url: "https://example.org/cn".into(),
            default_url: "https://example.org/other".into(),
            updated: now(),
            pool_id: None,
            code: None,
        });
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(200).set_body_string(kv_link(&backend.db.links[0]).to_string()))
            .mount(&server).await;
        Mock::given(method("DELETE"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ok(json!({}))).mount(&server).await;
        Mock::given(method("PUT"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(200)).mount(&server).await;
        backend
            .fail_persist_at
            .store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(backend
            .apply_delete_link("domain1", "short")
            .await
            .unwrap_err()
            .contains("测试注入"));
        assert_eq!(backend.db.links.len(), 1);
        assert!(backend.db.pending_operations.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert!(requests
            .iter()
            .any(|r| r.method.as_str() == "PUT" && r.url.path().ends_with("short")));
    }

    #[tokio::test]
    async fn pool_final_persist_failure_keeps_resumable_intent() {
        let (server, mut backend, _dir) = fixture().await;
        let pool = sample_pool();
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        backend
            .fail_persist_at
            .store(4, std::sync::atomic::Ordering::SeqCst);
        assert!(backend
            .apply_save_pool(pool)
            .await
            .unwrap_err()
            .contains("测试注入"));
        assert_eq!(backend.db.pending_pool_changes.len(), 1);
        assert_eq!(backend.db.pending_operations.len(), 1);
        let disk: Value = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(disk["pendingPoolChanges"].as_array().unwrap().len(), 1);
        server.reset().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        let pending = backend.db.pending_pool_changes[0].pool.clone();
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(pools::cloud_value(&pending).to_string()),
            )
            .mount(&server)
            .await;
        backend.apply_save_pool(pending).await.unwrap();
        assert!(backend.db.pending_pool_changes.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.iter().any(|r| r.method.as_str() == "PUT"));
    }

    #[tokio::test]
    async fn monitor_schedule_failure_resumes_without_secret_in_local_file() {
        let (server, mut backend, _dir) = fixture().await;
        let secret = "q".repeat(48);
        let endpoint = "https://probe.example/check";
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[]})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/secrets",
            ))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        assert!(backend
            .apply_enable_monitor("acct1", endpoint, &secret)
            .await
            .unwrap_err()
            .contains("400"));
        assert_eq!(backend.db.pending_monitor_changes.len(), 1);
        assert!(!backend.db.accounts[0].monitor_enabled);
        assert!(!String::from_utf8(fs::read(&backend.path).unwrap())
            .unwrap()
            .contains(&secret));
        server.reset().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[]})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(json!({"endpoint":endpoint,"poolIds":[]}).to_string()),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/secrets",
            ))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[{"cron":"*/15 * * * *"}]})))
            .mount(&server)
            .await;
        backend
            .apply_enable_monitor("acct1", endpoint, &secret)
            .await
            .unwrap();
        assert!(backend.db.accounts[0].monitor_enabled);
        assert!(backend.db.pending_monitor_changes.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn monitor_disable_partial_delete_resumes_after_cron_is_gone() {
        let (server, mut backend, _dir) = fixture().await;
        let endpoint = "https://probe.example/check";
        backend.db.accounts[0].monitor_enabled = true;
        backend.db.accounts[0].monitor_endpoint = Some(endpoint.into());
        keyring_set("acct1", "probe", &"q".repeat(48)).unwrap();
        mount_resource_with_probe(&server, include_str!("../../edge/worker.mjs"), true).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[{"cron":"*/15 * * * *"}]})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(json!({"endpoint":endpoint,"poolIds":[]}).to_string()),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[]})))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        assert!(backend
            .apply_disable_monitor("acct1")
            .await
            .unwrap_err()
            .contains("400"));
        assert_eq!(backend.db.pending_monitor_changes.len(), 1);
        assert!(backend.db.accounts[0].monitor_enabled);
        server.reset().await;
        mount_resource_with_probe(&server, include_str!("../../edge/worker.mjs"), true).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[]})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(json!({"endpoint":endpoint,"poolIds":[]}).to_string()),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/secrets/PROBE_KEY",
            ))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        backend.apply_disable_monitor("acct1").await.unwrap();
        assert!(!backend.db.accounts[0].monitor_enabled);
        assert!(backend.db.pending_monitor_changes.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn public_dns_selftest_checks_both_regions_without_sending_api_token_or_following_targets(
    ) {
        let (server, backend, _guard) = fixture().await;
        for (country, target) in [
            ("US", "https://example.org/global"),
            ("CN", "https://example.org/local"),
        ] {
            Mock::given(method("HEAD"))
                .and(path("/client/v4/probe/example.com/go/sample"))
                .and(header_regex("x-selftest", &format!(r"\.{country}\.")))
                .respond_with(ResponseTemplate::new(302).insert_header("location", target))
                .expect(1)
                .mount(&server)
                .await;
        }
        let result = run_selftest_with_mode(
            SelftestSnapshot {
                cloud: backend.cloud.clone(),
                host: "example.com".into(),
                path: "/go/sample".into(),
                url: "https://example.com/go/sample".into(),
                cn_url: "https://example.org/local".into(),
                default_url: "https://example.org/global".into(),
                key: Zeroizing::new(vec![0xa1; 32]),
                pool: None,
            },
            local_check::DnsMode::Public,
        )
        .await
        .unwrap();
        assert_eq!(result["status"], "passed");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|r| r.headers.get("authorization").is_none()
                && r.headers.get("x-selftest").is_some()));
    }

    #[tokio::test]
    async fn all_unhealthy_selftest_sends_both_signed_region_probes() {
        let (server, backend, _guard) = fixture().await;
        let pool = sample_pool();
        let at = Utc::now().timestamp();
        let health = json!({"revision":pool.updated,"checkedAt":at,"targets":{
            "first":{"state":"unhealthy","failures":3,"successes":0,"checkedAt":at},
            "second":{"state":"unhealthy","failures":3,"successes":0,"checkedAt":at}}});
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(health.to_string()))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/short"))
            .and(header_regex("x-selftest", r"\.US\."))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://official.example/path/abc"),
            )
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/client/v4/probe/example.com/go/short"))
            .and(header_regex("x-selftest", r"\.CN\."))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let snapshot = SelftestSnapshot {
            cloud: backend.cloud.clone(),
            host: "example.com".into(),
            path: "/go/short".into(),
            url: "https://example.com/go/short".into(),
            cn_url: String::new(),
            default_url: "https://official.example/path/abc".into(),
            key: Zeroizing::new(vec![0xa1; 32]),
            pool: Some((
                pool,
                "abc".into(),
                "acct1".into(),
                "ns1".into(),
                Zeroizing::new("test-token-value".into()),
            )),
        };
        let report = run_selftest(snapshot).await.unwrap();
        assert_eq!(report["status"], "failed");
        assert!(report["checks"][1]["message"]
            .as_str()
            .unwrap()
            .contains("503"));
        let requests = server.received_requests().await.unwrap();
        let signed: Vec<_> = requests
            .iter()
            .filter(|r| r.method.as_str() == "HEAD")
            .map(|r| {
                r.headers
                    .get("x-selftest")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(signed.iter().any(|h| h.contains(".US.")));
        assert!(signed.iter().any(|h| h.contains(".CN.")));
    }

    #[tokio::test]
    async fn selftest_rotation_staging_failure_makes_no_cloud_request() {
        let (server, mut backend, _dir) = fixture().await;
        mock_key_set_failures()
            .lock()
            .unwrap()
            .insert("selftest-pending:acct1".into());
        let error = backend.apply_rotate("acct1").await.unwrap_err();
        assert!(error.contains("系统凭据保存失败"));
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(backend.db.pending_selftest_rotations.is_empty());
        assert_eq!(keyring_get("acct1", "selftest").unwrap(), "a1".repeat(32));
    }

    #[tokio::test]
    async fn selftest_rotation_initial_persist_failure_rolls_back_without_cloud_write() {
        let (server, mut backend, _dir) = fixture().await;
        backend
            .fail_persist_at
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let error = backend.apply_rotate("acct1").await.unwrap_err();
        assert!(error.contains("本机配置保存失败"));
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(backend.db.pending_selftest_rotations.is_empty());
        assert!(keyring_get_optional("acct1", "selftest-pending")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn selftest_rotation_definitive_cloud_failure_stays_pending() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 403).await;
        let error = backend.apply_rotate("acct1").await.unwrap_err();
        assert!(error.contains("403"));
        assert_eq!(backend.db.pending_selftest_rotations.len(), 1);
        assert_eq!(
            backend.db.pending_selftest_rotations[0].status,
            SelftestRotationStatus::DefinitiveFailure
        );
        assert_eq!(keyring_get("acct1", "selftest").unwrap(), "a1".repeat(32));
        let state = State::from(&backend.db);
        assert!(state.accounts[0].needs_selftest_key);
        assert_eq!(state.pending_actions[0].kind, "resume_selftest_rotation");
    }

    #[tokio::test]
    async fn selftest_rotation_uncertain_failure_resumes_with_same_staged_key() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 503).await;
        let error = backend.apply_rotate("acct1").await.unwrap_err();
        assert!(error.contains("503"));
        assert_eq!(
            backend.db.pending_selftest_rotations[0].status,
            SelftestRotationStatus::Uncertain
        );
        let staged = keyring_get("acct1", "selftest-pending").unwrap();
        let disk = String::from_utf8(fs::read(&backend.path).unwrap()).unwrap();
        assert!(!disk.contains(&staged));
        assert_eq!(keyring_get("acct1", "selftest").unwrap(), "a1".repeat(32));

        server.reset().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 200).await;
        backend.resume_selftest_rotation("acct1").await.unwrap();
        assert_eq!(keyring_get("acct1", "selftest").unwrap(), staged);
        assert!(backend.db.pending_selftest_rotations.is_empty());
        assert!(!backend.db.accounts[0].needs_selftest_key);
        let requests = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|request| request.method.as_str() == "PUT")
            .unwrap();
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["text"], staged);
    }

    #[tokio::test]
    async fn selftest_rotation_cloud_applied_recovery_only_promotes_local_key() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 200).await;
        mock_key_set_failures()
            .lock()
            .unwrap()
            .insert("selftest:acct1".into());
        let error = backend.apply_rotate("acct1").await.unwrap_err();
        assert!(error.contains("系统凭据保存失败"));
        assert_eq!(
            backend.db.pending_selftest_rotations[0].status,
            SelftestRotationStatus::CloudApplied
        );
        let staged = keyring_get("acct1", "selftest-pending").unwrap();
        mock_key_set_failures().lock().unwrap().clear();
        server.reset().await;
        backend.resume_selftest_rotation("acct1").await.unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(keyring_get("acct1", "selftest").unwrap(), staged);
        assert!(backend.db.pending_selftest_rotations.is_empty());
    }

    #[tokio::test]
    async fn legacy_selftest_recovery_clears_only_exact_account_journals() {
        let (server, mut backend, _dir) = fixture().await;
        let mut other = backend.db.accounts[0].clone();
        other.id = "acct10".into();
        other.resources = None;
        other.has_resources = false;
        backend.db.accounts.push(other);
        backend.db.pending_operations = vec![
            "重置自检密钥 acct1 (old)：云端已更换密钥，但本机凭据保存失败".into(),
            "重置自检密钥 acct10 (other)：云端已更换密钥，但本机凭据保存失败".into(),
        ];
        let before = State::from(&backend.db);
        assert!(before.accounts[0].needs_selftest_key);
        assert!(before.accounts[1].needs_selftest_key);
        assert_eq!(
            before
                .pending_actions
                .iter()
                .filter(|action| action.kind == "recover_selftest_rotation")
                .count(),
            1
        );
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 200).await;
        backend
            .apply_legacy_selftest_recovery("acct1")
            .await
            .unwrap();
        assert_eq!(
            backend.db.pending_operations,
            vec!["重置自检密钥 acct10 (other)：云端已更换密钥，但本机凭据保存失败"]
        );
        assert!(!backend.db.accounts[0].needs_selftest_key);
        assert!(State::from(&backend.db).accounts[1].needs_selftest_key);
    }

    #[tokio::test]
    async fn pending_selftest_rotation_blocks_destructive_paths_and_resource_mismatch() {
        let (_server, mut backend, _dir) = fixture().await;
        let journal = "重置自检密钥 acct1 (pending)".to_string();
        backend.db.pending_operations.push(journal.clone());
        backend
            .db
            .pending_selftest_rotations
            .push(PendingSelftestRotation {
                account_id: "acct1".into(),
                script: "old-script".into(),
                namespace: "old-namespace".into(),
                journal,
                status: SelftestRotationStatus::Staged,
            });
        keyring_set("acct1", "selftest-pending", &"b2".repeat(32)).unwrap();
        assert!(backend.resume_selftest_rotation("acct1").await.is_err());
        assert!(backend
            .dispatch("remove_account", &json!({"accountId":"acct1"}))
            .await
            .is_err());
        assert!(backend
            .prepare_change(&json!({"kind":"cleanup_account","accountId":"acct1"}))
            .is_err());
        assert!(backend
            .prepare_change(&json!({"kind":"recover_account","accountId":"acct1"}))
            .is_err());
        assert!(backend.import_config("{}").await.is_err());
        assert!(keyring_get_optional("acct1", "selftest-pending")
            .unwrap()
            .is_some());
        assert_eq!(backend.db.pending_selftest_rotations.len(), 1);
    }

    #[tokio::test]
    async fn selftest_rotation_final_persist_failure_keeps_cloud_applied_recoverable() {
        let (server, mut backend, _dir) = fixture().await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 200).await;
        backend
            .fail_persist_at
            .store(3, std::sync::atomic::Ordering::SeqCst);

        let error = backend.apply_rotate("acct1").await.unwrap_err();
        assert!(error.contains("本机配置保存失败"));
        assert_eq!(
            backend.db.pending_selftest_rotations[0].status,
            SelftestRotationStatus::CloudApplied
        );
        let staged = keyring_get("acct1", "selftest-pending").unwrap();
        assert_eq!(keyring_get("acct1", "selftest").unwrap(), staged);
        assert!(State::from(&backend.db).accounts[0].needs_selftest_key);

        server.reset().await;
        backend.resume_selftest_rotation("acct1").await.unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(backend.db.pending_selftest_rotations.is_empty());
        assert!(!backend.db.accounts[0].needs_selftest_key);
    }

    #[tokio::test]
    async fn missing_staged_selftest_key_requires_explicit_replacement_plan() {
        let (server, mut backend, _dir) = fixture().await;
        let journal = "重置自检密钥 acct1 (missing)".to_string();
        backend.db.pending_operations.push(journal.clone());
        backend
            .db
            .pending_selftest_rotations
            .push(PendingSelftestRotation {
                account_id: "acct1".into(),
                script: "edge-one".into(),
                namespace: "ns1".into(),
                journal,
                status: SelftestRotationStatus::CloudApplied,
            });

        let error = backend.resume_selftest_rotation("acct1").await.unwrap_err();
        assert!(error.contains("找不到安全暂存密钥"));
        assert_eq!(
            backend.db.pending_selftest_rotations[0].status,
            SelftestRotationStatus::StagingMissing
        );
        let state = State::from(&backend.db);
        assert_eq!(state.pending_actions[0].kind, "recover_selftest_rotation");
        let plan = backend
            .prepare_change(&json!({
                "kind":"recover_selftest_rotation",
                "accountId":"acct1"
            }))
            .unwrap();
        assert!(plan["steps"][0].as_str().unwrap().contains("生成新密钥"));

        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_selftest_rotation(&server, 200).await;
        backend
            .apply_legacy_selftest_recovery("acct1")
            .await
            .unwrap();
        assert!(backend.db.pending_selftest_rotations.is_empty());
        assert!(keyring_get_optional("acct1", "selftest-pending")
            .unwrap()
            .is_none());
        assert_ne!(keyring_get("acct1", "selftest").unwrap(), "a1".repeat(32));
    }

    #[test]
    fn monitor_payload_matches_worker_count_and_byte_limits() {
        let endpoint = "https://probe.example/check";
        let many: Vec<_> = (0..257).map(|i| format!("p{i}")).collect();
        assert!(validate_monitor_config(&json!({"endpoint":endpoint,"poolIds":many})).is_err());
        let large: Vec<_> = (0..200)
            .map(|i| format!("p{i}_{}", "a".repeat(120)))
            .collect();
        let config = json!({"endpoint":endpoint,"poolIds":large});
        assert!(config.to_string().len() > 16_384);
        assert!(validate_monitor_config(&config).is_err());
        assert!(
            validate_monitor_config(&json!({"endpoint":endpoint,"poolIds":["p1","p2"]})).is_ok()
        );
    }
    #[tokio::test]
    async fn unknown_dns_success_recheck_clears_only_resolved_host_without_writes() {
        let (server, mut backend, _dir) = fixture().await;
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([])).await;
        mount_full_dns(&server, json!([])).await;
        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_string("invalid-json"))
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert!(backend
            .dispatch("apply_plan", &json!({"planId":prepared["plan"]["id"]}))
            .await
            .is_err());
        assert_eq!(backend.db.pending_operations.len(), 1);
        backend
            .db
            .pending_operations
            .push("修复 DNS example.org (other-operation)".into());
        server.reset().await;
        mount_zone_owner(&server).await;
        mount_exact_dns(&server, json!([{"id":"placeholder","name":"example.com","type":"AAAA","content":"100::","proxied":true,"proxiable":true}])).await;
        let checked = backend
            .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
            .await
            .unwrap();
        assert_eq!(checked["dnsStatus"], "ready");
        assert_eq!(checked["canApply"], false);
        assert!(checked.get("plan").is_none());
        assert_eq!(
            backend.db.pending_operations,
            vec!["修复 DNS example.org (other-operation)"]
        );
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }
    #[tokio::test]
    async fn dns_proxy_mail_dependency_blocks_prepare_and_new_dependency_blocks_apply() {
        for present_during_prepare in [true, false] {
            let (server, mut backend, _dir) = fixture().await;
            let grey = json!({"id":"dns-one","name":"example.com","type":"A","content":"192.0.2.10","proxied":false,"proxiable":true});
            let mx = json!({"id":"mail-mx","name":"child.example.com","type":"MX","content":"example.com","priority":10});
            mount_zone_owner(&server).await;
            mount_exact_dns(&server, json!([grey.clone()])).await;
            if present_during_prepare {
                mount_full_dns(&server, json!([grey.clone(), mx.clone()])).await;
            }
            let prepared = backend
                .prepare_domain_dns(&json!({"input":"example.com"}))
                .await
                .unwrap();
            if present_during_prepare {
                assert_eq!(prepared["canApply"], false);
                assert_eq!(prepared["dnsStatus"], "conflict");
            } else {
                assert_eq!(prepared["canApply"], true);
                mount_full_dns(&server, json!([grey, mx])).await;
                let error = backend
                    .dispatch("apply_plan", &json!({"planId":prepared["plan"]["id"]}))
                    .await
                    .unwrap_err();
                assert!(error.contains("MX"), "{error}");
            }
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
            assert!(backend.db.pending_operations.is_empty());
        }
    }

    fn cleanup_health() -> String {
        json!({"revision":"2026-09-30T00:00:00Z","checkedAt":123,
            "targets":{"first":{"state":"unknown","failures":0,"successes":0,"checkedAt":123}}})
        .to_string()
    }

    async fn mount_cleanup_cloud(
        server: &MockServer,
        entries: Vec<(&str, String)>,
    ) -> std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>> {
        let store = std::sync::Arc::new(std::sync::Mutex::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<std::collections::BTreeMap<_, _>>(),
        ));
        mount_resource(server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET")).and(path("/client/v4/zones"))
            .respond_with(ok(json!([{"id":"zone1","name":"example.com","status":"active","account":{"id":"acct1"}}])))
            .with_priority(100)
            .mount(server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])))
            .with_priority(100)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[]})))
            .with_priority(100)
            .mount(server)
            .await;
        let list_store = store.clone();
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut keys = vec![json!({"name":MANIFEST_KEY})];
                keys.extend(
                    list_store
                        .lock()
                        .unwrap()
                        .keys()
                        .map(|key| json!({"name":key})),
                );
                ok(json!(keys))
            })
            .with_priority(100)
            .mount(server)
            .await;
        let read_store = store.clone();
        Mock::given(method("GET"))
            .and(path_regex(r"^/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/(h%3A[^/]+|p%3A[^/]+|m%3Amonitor%3Acursor)$"))
            .respond_with(move |request: &wiremock::Request| {
                let encoded=request.url.path().rsplit('/').next().unwrap();
                let key=url::form_urlencoded::parse(encoded.as_bytes()).next().unwrap().0.into_owned();
                match read_store.lock().unwrap().get(&key) {
                    Some(raw)=>ResponseTemplate::new(200).set_body_string(raw.clone()),
                    None=>ResponseTemplate::new(404)
                }
            }).with_priority(100)
            .mount(server).await;
        let delete_store = store.clone();
        Mock::given(method("DELETE"))
            .and(path_regex(r"^/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/(h%3A[^/]+|p%3A[^/]+|m%3Amonitor%3Acursor)$"))
            .respond_with(move |request: &wiremock::Request| {
                let encoded=request.url.path().rsplit('/').next().unwrap();
                let key=url::form_urlencoded::parse(encoded.as_bytes()).next().unwrap().0.into_owned();
                delete_store.lock().unwrap().remove(&key); ok(json!({}))
            }).with_priority(100)
            .mount(server).await;
        for target in [
            "/client/v4/accounts/acct1/workers/scripts/edge-one",
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1",
        ] {
            Mock::given(method("DELETE"))
                .and(path(target))
                .respond_with(ok(json!({})))
                .with_priority(100)
                .mount(server)
                .await;
        }
        store
    }

    #[tokio::test]
    async fn cleanup_removes_only_valid_orphan_monitor_metadata_and_account_receipts() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.account_ids.push("acct2".into());
        pool.sync_status = vec!["acct1", "acct2"]
            .into_iter()
            .map(|id| PoolSyncStatus {
                account_id: id.into(),
                status: "synced".into(),
                message: "old receipt".into(),
            })
            .collect();
        backend.db.pools.push(pool);
        let store = mount_cleanup_cloud(
            &server,
            vec![
                ("h:pool1", cleanup_health()),
                ("m:monitor:cursor", "2".into()),
            ],
        )
        .await;
        let plan = backend
            .prepare_change(&json!({"kind":"cleanup_account","accountId":"acct1"}))
            .unwrap();
        assert!(plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step.as_str().unwrap().contains("遗留检测")));
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert!(store.lock().unwrap().is_empty());
        assert!(backend.db.accounts[0].resources.is_none());
        assert_eq!(backend.db.pools[0].account_ids, vec!["acct2"]);
        assert_eq!(backend.db.pools[0].sync_status.len(), 1);
        assert_eq!(backend.db.pools[0].sync_status[0].account_id, "acct2");
        assert!(backend.db.pending_operations.is_empty());
        let deletes: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .map(|r| r.url.path().to_owned())
            .collect();
        assert_eq!(deletes.len(), 4);
        assert!(deletes[0].contains("h%3A"));
        assert!(deletes[1].contains("cursor"));
        assert!(deletes[2].ends_with("/edge-one"));
        assert!(deletes[3].ends_with("/ns1"));
    }

    #[tokio::test]
    async fn cleanup_unknown_metadata_and_active_cron_block_all_deletes() {
        for case in 0..5 {
            let (server, mut backend, _dir) = fixture().await;
            let mut health: Value = serde_json::from_str(&cleanup_health()).unwrap();
            health["unexpected"] = json!(true);
            let entries = match case {
                0 => vec![("p:pool1", "{}".into())],
                1 => vec![("h:pool1", health.to_string())],
                2 => vec![("m:monitor:cursor", "-1".into())],
                _ => vec![("h:pool1", cleanup_health())],
            };
            mount_cleanup_cloud(&server, entries).await;
            if case == 3 {
                Mock::given(method("GET"))
                    .and(path(
                        "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
                    ))
                    .respond_with(ok(json!({"schedules":[{"cron":"*/15 * * * *"}]})))
                    .mount(&server)
                    .await;
            }
            if case == 4 {
                Mock::given(method("GET"))
                    .and(path("/client/v4/zones/zone1/workers/routes"))
                    .respond_with(ok(json!([{"id":"route-one","script":"edge-one"}])))
                    .mount(&server)
                    .await;
            }
            assert!(backend.apply_cleanup("acct1").await.is_err());
            assert!(backend.db.accounts[0].resources.is_some());
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
            assert!(backend.db.pending_operations.is_empty());
        }
    }

    #[tokio::test]
    async fn cleanup_removes_pool_copy_that_matches_a_local_pool() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.account_ids.push("acct2".into());
        let copy = pools::cloud_value(&pool).to_string();
        backend.db.pools.push(pool);
        let store = mount_cleanup_cloud(
            &server,
            vec![("p:pool1", copy), ("h:pool1", cleanup_health())],
        )
        .await;
        backend.apply_cleanup("acct1").await.unwrap();
        // The copy is not deleted key by key: it is removed with the namespace,
        // so a failed later step cannot leave a synced pool without its copy.
        assert_eq!(
            store.lock().unwrap().keys().collect::<Vec<_>>(),
            vec!["p:pool1"]
        );
        assert!(backend.db.accounts[0].resources.is_none());
        assert_eq!(backend.db.pools[0].account_ids, vec!["acct2"]);
        assert!(backend.db.pending_operations.is_empty());
        let deletes: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .map(|r| r.url.path().to_owned())
            .collect();
        assert!(deletes.iter().any(|p| p.ends_with("h%3Apool1")));
        assert!(!deletes.iter().any(|p| p.ends_with("p%3Apool1")));
        assert!(deletes.last().unwrap().ends_with("/ns1"));
    }

    #[tokio::test]
    async fn cleanup_rejects_unknown_or_malformed_pool_copies_and_any_link() {
        for case in ["unknown-pool", "bad-json", "not-a-copy", "bad-id", "link"] {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.pools.push(sample_pool());
            let valid = pools::cloud_value(&sample_pool()).to_string();
            let entries = match case {
                "unknown-pool" => vec![("p:other", valid)],
                "bad-json" => vec![("p:pool1", "{not json".to_string())],
                "not-a-copy" => vec![("p:pool1", "[1,2]".to_string())],
                "bad-id" => vec![("p:bad id", valid)],
                _ => vec![
                    ("p:pool1", valid),
                    (
                        "l:example.com:a",
                        r#"{"default":"https://example.org"}"#.to_string(),
                    ),
                ],
            };
            mount_cleanup_cloud(&server, entries).await;
            let error = backend.apply_cleanup("acct1").await.unwrap_err();
            match case {
                "unknown-pool" | "bad-json" | "not-a-copy" => {
                    assert!(error.contains("平台地址副本"), "{case}: {error}")
                }
                _ => assert!(
                    error.contains("KV 仍有业务或未知配置记录"),
                    "{case}: {error}"
                ),
            }
            assert!(backend.db.accounts[0].resources.is_some());
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
            assert!(backend.db.pending_operations.is_empty());
        }
    }

    #[tokio::test]
    async fn cleanup_changed_metadata_blocks_before_first_delete() {
        let (server, mut backend, _dir) = fixture().await;
        mount_cleanup_cloud(&server, vec![("h:pool1", cleanup_health())]).await;
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut value: Value = serde_json::from_str(&cleanup_health()).unwrap();
                if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                    value["checkedAt"] = json!(456);
                }
                ResponseTemplate::new(200).set_body_string(value.to_string())
            })
            .mount(&server)
            .await;
        let error = backend.apply_cleanup("acct1").await.unwrap_err();
        assert!(error.contains("变化"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn cleanup_metadata_failure_reuses_journal_and_skips_already_deleted_keys() {
        let (server, mut backend, _dir) = fixture().await;
        let store = mount_cleanup_cloud(
            &server,
            vec![
                ("h:pool1", cleanup_health()),
                ("m:monitor:cursor", "2".into()),
            ],
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor%3Acursor",
            ))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let error = backend.apply_cleanup("acct1").await.unwrap_err();
        assert!(error.contains("503"), "{error}");
        // A later cleanup finishes it, so the error says so.
        assert!(error.ends_with(CLEANUP_RETRY_HINT), "{error}");
        assert!(backend.db.accounts[0].resources.is_some());
        assert_eq!(backend.db.pending_operations.len(), 1);
        assert!(!store.lock().unwrap().contains_key("h:pool1"));
        backend.db = serde_json::from_slice(&std::fs::read(&backend.path).unwrap()).unwrap();
        backend.apply_cleanup("acct1").await.unwrap();
        assert!(backend.db.pending_operations.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method.as_str() == "DELETE" && r.url.path().ends_with("h%3Apool1"))
                .count(),
            1
        );
    }
    /// A cleanup that started its own record and deleted nothing ends that
    /// record on failure; a record from an earlier run is kept.
    #[tokio::test]
    async fn cleanup_that_deleted_nothing_ends_its_own_record() {
        // The re-read after the record was written fails.
        for resumed in [false, true] {
            let (server, mut backend, _dir) = fixture().await;
            mount_cleanup_cloud(&server, vec![("h:pool1", cleanup_health())]).await;
            let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            Mock::given(method("GET"))
                .and(path(
                    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
                ))
                .respond_with(move |_: &wiremock::Request| {
                    if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 2 {
                        ResponseTemplate::new(500)
                    } else {
                        ResponseTemplate::new(200).set_body_string(cleanup_health())
                    }
                })
                .mount(&server)
                .await;
            let earlier = "清理账号 acct1 (old)：Worker 删除结果不确定，请核对后继续清理";
            if resumed {
                backend.db.pending_operations = vec![earlier.into()];
                backend.persist().unwrap();
            }
            let error = backend.apply_cleanup("acct1").await.unwrap_err();
            assert!(error.contains("遗留检测数据无法再次核实"), "{error}");
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
            let saved: Database =
                serde_json::from_slice(&std::fs::read(&backend.path).unwrap()).unwrap();
            if resumed {
                assert_eq!(backend.db.pending_operations.len(), 1);
                assert!(backend.db.pending_operations[0].starts_with("清理账号 acct1 (old)："));
                assert!(!error.contains(CLEANUP_NOTHING_DELETED), "{error}");
                assert!(error.ends_with(CLEANUP_RETRY_HINT), "{error}");
            } else {
                assert!(error.contains(CLEANUP_NOTHING_DELETED), "{error}");
                assert!(backend.db.pending_operations.is_empty());
            }
            assert_eq!(saved.pending_operations, backend.db.pending_operations);
        }

        // The first delete is the Worker's and it is refused.
        let (server, mut backend, _dir) = fixture().await;
        mount_cleanup_cloud(&server, vec![]).await;
        Mock::given(method("DELETE"))
            .and(path("/client/v4/accounts/acct1/workers/scripts/edge-one"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let error = backend.apply_cleanup("acct1").await.unwrap_err();
        assert!(error.contains("HTTP 403"), "{error}");
        assert!(error.contains(CLEANUP_NOTHING_DELETED), "{error}");
        assert!(backend.db.pending_operations.is_empty());
        assert!(backend.db.accounts[0].resources.is_some());
        drop((server, backend, _dir));

        // A refused first metadata delete deleted nothing either.
        let (server, mut backend, _dir) = fixture().await;
        mount_cleanup_cloud(&server, vec![("h:pool1", cleanup_health())]).await;
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let error = backend.apply_cleanup("acct1").await.unwrap_err();
        assert!(error.contains(CLEANUP_NOTHING_DELETED), "{error}");
        assert!(backend.db.pending_operations.is_empty());
    }

    #[test]
    fn cleanup_worker_delete_that_never_connected_is_not_called_refused() {
        let never_sent = CloudError {
            message: "连不上云端，这一步没有发出去，请检查网络后重试".into(),
            uncertain: false,
            network: true,
        };
        let (note, error) = cleanup_worker_delete_failure(&never_sent, false);
        let note = note.unwrap();
        assert!(!note.contains("被拒绝"), "{note}");
        assert!(note.contains("连不上云端"), "{note}");
        assert!(!error.contains("被拒绝"), "{error}");
        assert!(error.contains("没有发出去"), "{error}");
        assert!(error.ends_with(CLEANUP_RETRY_HINT), "{error}");
        // Nothing deleted yet: the record is ended and the text says so.
        let (note, error) = cleanup_worker_delete_failure(&never_sent, true);
        assert!(note.is_none());
        assert!(error.contains(CLEANUP_NOTHING_DELETED), "{error}");
        assert!(error.ends_with(CLEANUP_RETRY_HINT), "{error}");
        // A real refusal after earlier deletes keeps its wording.
        let refused = CloudError {
            message: "云端请求失败（HTTP 403），请检查令牌权限与资源状态".into(),
            uncertain: false,
            network: false,
        };
        let (note, error) = cleanup_worker_delete_failure(&refused, false);
        assert_eq!(note, Some("Worker 删除被拒绝，账号清理尚未完成"));
        assert_eq!(error, refused.message);
        // An uncertain delete always keeps the record.
        let unclear = CloudError {
            message: "云端写入结果不确定".into(),
            uncertain: true,
            network: true,
        };
        let (note, error) = cleanup_worker_delete_failure(&unclear, true);
        assert_eq!(note, Some("Worker 删除结果不确定，请核对后继续清理"));
        assert!(error.ends_with(CLEANUP_RETRY_HINT), "{error}");
    }

    pub(super) async fn mount_recovery_without_pool(server: &MockServer, with_link: bool) {
        mount_resource(server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(server).await;
        mount_zone_owner(server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("account.id", "acct1"))
            .respond_with(ok(json!([{"id":"zone1","name":"example.com","status":"active","account":{"id":"acct1"}}])))
            .with_priority(100)
            .mount(server).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces"))
            .respond_with(ok(json!([{"id":"ns1"}])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .and(query_param("prefix", "p:"))
            .respond_with(ok(json!([])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(if with_link {
                json!([{"name":"l:example.com:short"}])
            } else {
                json!([])
            }))
            .mount(server)
            .await;
        Mock::given(method("GET")).and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json!({"poolId":"pool1","code":"abc","updated":"2026-09-30T00:00:00Z"}).to_string()))
            .mount(server).await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
            ))
            .respond_with(ok(json!({"schedules":[]})))
            .mount(server)
            .await;
    }

    /// Two routes of this tool for one host: recovery names both patterns and
    /// changes nothing on this computer. Other invalid routes keep the old
    /// sentence.
    #[tokio::test]
    async fn recovery_with_two_own_routes_for_one_host_names_both_and_changes_nothing() {
        for (routes, expected) in [
            (
                json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"},
                    {"id":"route2","pattern":"example.com/other/*","script":"edge-one"}]),
                "域名 example.com 上有两条本工具的转发规则（example.com/go/*、example.com/other/*），没法确定该用哪一条，所以这次没有找回，本机记录没有改动。请联系维护的人处理",
            ),
            (
                json!([{"id":"route1","pattern":"example.org/go/*","script":"edge-one"}]),
                "此 Worker 的路由无效或主机名重复，停止找回以保留现有记录",
            ),
        ] {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.domains.push(domain());
            backend.db.pending_operations = vec!["添加域名 example.com (v)：旧记录".into()];
            backend.persist().unwrap();
            let before = serde_json::to_value(&backend.db).unwrap();
            let before_disk = std::fs::read(&backend.path).unwrap();
            Mock::given(method("GET"))
                .and(path("/client/v4/zones/zone1/workers/routes"))
                .respond_with(ok(routes))
                .with_priority(1)
                .mount(&server)
                .await;
            mount_recovery_without_pool(&server, false).await;
            let error = backend.recover_account("acct1").await.unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(serde_json::to_value(&backend.db).unwrap(), before);
            assert_eq!(std::fs::read(&backend.path).unwrap(), before_disk);
            assert!(!server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE")));
        }
    }

    #[tokio::test]
    async fn recovery_rejects_missing_remote_pool_without_changing_local_data() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.sync_status = vec![PoolSyncStatus {
            account_id: "acct1".into(),
            status: "synced".into(),
            message: "old receipt".into(),
        }];
        backend.db.pools.push(pool);
        backend.db.domains.push(domain());
        backend.persist().unwrap();
        let before = serde_json::to_value(&backend.db).unwrap();
        mount_recovery_without_pool(&server, true).await;
        assert!(backend
            .recover_account("acct1")
            .await
            .unwrap_err()
            .contains("不属于此账号"));
        assert_eq!(serde_json::to_value(&backend.db).unwrap(), before);
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&backend.path).unwrap()).unwrap(),
            before
        );
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn recovery_refreshes_only_current_account_receipts_and_rolls_back_persist_failure() {
        for fail_persist in [false, true] {
            let (server, mut backend, _dir) = fixture().await;
            let mut pool = sample_pool();
            pool.account_ids.push("acct2".into());
            pool.sync_status = vec!["acct1", "acct2"]
                .into_iter()
                .map(|id| PoolSyncStatus {
                    account_id: id.into(),
                    status: "synced".into(),
                    message: "old receipt".into(),
                })
                .collect();
            backend.db.pools.push(pool);
            backend.db.domains.push(domain());
            backend.persist().unwrap();
            let before = serde_json::to_value(&backend.db).unwrap();
            mount_recovery_without_pool(&server, false).await;
            if fail_persist {
                backend
                    .fail_persist_at
                    .store(2, std::sync::atomic::Ordering::SeqCst);
            }
            let result = backend.recover_account("acct1").await;
            if fail_persist {
                assert!(result.is_err());
                assert_eq!(serde_json::to_value(&backend.db).unwrap(), before);
                assert_eq!(
                    serde_json::from_slice::<Value>(&std::fs::read(&backend.path).unwrap())
                        .unwrap(),
                    before
                );
            } else {
                result.unwrap();
                assert_eq!(backend.db.pools[0].account_ids, vec!["acct2"]);
                assert_eq!(backend.db.pools[0].sync_status.len(), 1);
                assert_eq!(backend.db.pools[0].sync_status[0].account_id, "acct2");
            }
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
        }
    }
    #[tokio::test]
    async fn cleanup_new_business_key_during_preflight_blocks_all_deletes() {
        let (server, mut backend, _dir) = fixture().await;
        mount_cleanup_cloud(&server, vec![("h:pool1", cleanup_health())]).await;
        let reads = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let mut keys = vec![json!({"name":MANIFEST_KEY}), json!({"name":"h:pool1"})];
                if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                    keys.push(json!({"name":"p:new-pool"}));
                }
                ok(json!(keys))
            })
            .mount(&server)
            .await;
        assert!(backend
            .apply_cleanup("acct1")
            .await
            .unwrap_err()
            .contains("变化"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
        assert!(backend.db.pending_operations.is_empty());
    }

    #[tokio::test]
    async fn cleanup_uncertain_applied_metadata_delete_resumes_from_remaining_keys() {
        let (server, mut backend, _dir) = fixture().await;
        let store = mount_cleanup_cloud(&server, vec![("h:pool1", cleanup_health())]).await;
        let applied = store.clone();
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
            ))
            .respond_with(move |_: &wiremock::Request| {
                applied.lock().unwrap().remove("h:pool1");
                ResponseTemplate::new(503)
            })
            .up_to_n_times(1)
            .mount(&server)
            .await;
        assert!(backend
            .apply_cleanup("acct1")
            .await
            .unwrap_err()
            .contains("503"));
        assert_eq!(backend.db.pending_operations.len(), 1);
        assert!(store.lock().unwrap().is_empty());
        backend.db = serde_json::from_slice(&std::fs::read(&backend.path).unwrap()).unwrap();
        backend.apply_cleanup("acct1").await.unwrap();
        assert!(backend.db.pending_operations.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method.as_str() == "DELETE" && r.url.path().ends_with("h%3Apool1"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn recovery_refreshes_stale_zone_cache_before_replacing_domain_records() {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts[0].zones.clear();
        backend.db.accounts[0].zone_count = 0;
        backend.db.domains.push(domain());
        mount_recovery_without_pool(&server, true).await;
        Mock::given(method("GET"))
            .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rules":[{"countries":["CN"],"url":"https://example.org/cn"}],
                "default":"https://example.org/other","updated":"2026-09-30T00:00:00Z"
            })))
            .with_priority(1)
            .mount(&server).await;
        backend.recover_account("acct1").await.unwrap();
        assert_eq!(backend.db.domains.len(), 1);
        assert_eq!(backend.db.domains[0].host, "example.com");
        assert_eq!(backend.db.links.len(), 1);
        assert_eq!(backend.db.links[0].domain_id, backend.db.domains[0].id);
        assert_eq!(backend.db.accounts[0].zones.len(), 1);
        assert_eq!(backend.db.accounts[0].zone_count, 1);
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
    }

    #[tokio::test]
    async fn recovery_incomplete_or_failed_zone_read_preserves_local_records() {
        for failed_read in [false, true] {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.domains.push(domain());
            backend.persist().unwrap();
            let before = serde_json::to_value(&backend.db).unwrap();
            mount_recovery_without_pool(&server, false).await;
            Mock::given(method("GET"))
                .and(path("/client/v4/zones"))
                .respond_with(if failed_read {
                    ResponseTemplate::new(403)
                } else {
                    ok(json!([]))
                })
                .mount(&server)
                .await;
            assert!(backend.recover_account("acct1").await.is_err());
            assert_eq!(serde_json::to_value(&backend.db).unwrap(), before);
            assert_eq!(
                serde_json::from_slice::<Value>(&std::fs::read(&backend.path).unwrap()).unwrap(),
                before
            );
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
        }
    }

    #[tokio::test]
    async fn cleanup_journal_persist_failure_cannot_leave_an_undurable_retry_intent() {
        let (server, mut backend, _dir) = fixture().await;
        backend.persist().unwrap();
        mount_cleanup_cloud(&server, vec![("h:pool1", cleanup_health())]).await;
        backend
            .fail_persist_at
            .store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(backend
            .apply_cleanup("acct1")
            .await
            .unwrap_err()
            .contains("本机配置保存失败"));
        assert!(server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method.as_str() == "GET"));
        let state_path = backend.path.clone();
        let durable = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = durable.clone();
        Mock::given(method("DELETE"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
            ))
            .respond_with(move |_: &wiremock::Request| {
                let saved: Value =
                    serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
                observed.store(
                    saved["pendingOperations"]
                        .as_array()
                        .is_some_and(|ops| !ops.is_empty()),
                    std::sync::atomic::Ordering::SeqCst,
                );
                ResponseTemplate::new(503)
            })
            .mount(&server)
            .await;
        assert!(backend.apply_cleanup("acct1").await.is_err());
        assert!(durable.load(std::sync::atomic::Ordering::SeqCst), "every cloud mutation must have a persisted cleanup journal, including retry after local save failure");
    }

    #[tokio::test]
    async fn recovery_rejects_ambiguous_owned_routes_and_changed_zone_ownership() {
        for case in 0..4 {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.domains.push(domain());
            backend.persist().unwrap();
            let before = serde_json::to_value(&backend.db).unwrap();
            mount_recovery_without_pool(&server, false).await;
            if case == 3 {
                Mock::given(method("GET"))
                    .and(path("/client/v4/zones/zone1"))
                    .respond_with(ok(
                        json!({"id":"zone1","status":"active","account":{"id":"acct2"}}),
                    ))
                    .with_priority(1)
                    .mount(&server)
                    .await;
            } else {
                let route = json!({"id":"route1","pattern":"example.com/go/*","script":"edge-one"});
                let routes = match case {
                    0 => json!([{"id":"route1","pattern":"example.com/*","script":"edge-one"}]),
                    1 => json!([{"id":"route1","script":"edge-one"}]),
                    _ => json!([route.clone(), route]),
                };
                Mock::given(method("GET"))
                    .and(path("/client/v4/zones/zone1/workers/routes"))
                    .respond_with(ok(routes))
                    .with_priority(1)
                    .mount(&server)
                    .await;
            }
            assert!(
                backend.recover_account("acct1").await.is_err(),
                "case {case}"
            );
            assert_eq!(serde_json::to_value(&backend.db).unwrap(), before);
            assert_eq!(
                serde_json::from_slice::<Value>(&std::fs::read(&backend.path).unwrap()).unwrap(),
                before
            );
            assert!(server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method.as_str() == "GET"));
        }
    }

    #[tokio::test]
    async fn cleanup_partial_resource_or_final_persist_failure_keeps_explicit_journal() {
        for fail_persist in [false, true] {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.pools.push(sample_pool());
            mount_cleanup_cloud(&server, vec![]).await;
            if fail_persist {
                backend
                    .fail_persist_at
                    .store(3, std::sync::atomic::Ordering::SeqCst);
            } else {
                Mock::given(method("DELETE"))
                    .and(path("/client/v4/accounts/acct1/storage/kv/namespaces/ns1"))
                    .respond_with(ResponseTemplate::new(503))
                    .mount(&server)
                    .await;
            }
            let error = backend.apply_cleanup("acct1").await.unwrap_err();
            assert!(error.contains(if fail_persist {
                "本机配置保存失败"
            } else {
                "Worker 已删除"
            }));
            assert!(backend.db.accounts[0].resources.is_some());
            assert!(backend.db.pools[0]
                .account_ids
                .contains(&"acct1".to_owned()));
            assert_eq!(backend.db.pending_operations.len(), 1);
            let saved: Database =
                serde_json::from_slice(&std::fs::read(&backend.path).unwrap()).unwrap();
            assert!(saved.accounts[0].resources.is_some());
            assert_eq!(saved.pending_operations, backend.db.pending_operations);
            assert_eq!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|r| r.method.as_str() == "DELETE")
                    .count(),
                2
            );
        }
    }

    #[tokio::test]
    async fn pool_health_disabled_accounts_never_read_credentials_or_cloud() {
        for missing_token in [false, true] {
            let (server, mut backend, _dir) = fixture().await;
            backend.db.pools.push(sample_pool());
            if missing_token {
                keyring_delete("acct1", "token").unwrap();
            }
            mock_key_reads().lock().unwrap().clear();
            let snapshot = backend.health_snapshot("pool1");
            let reads = mock_key_reads().lock().unwrap().clone();
            assert!(
                reads.is_empty(),
                "disabled monitoring must not access any credential"
            );
            let result = run_pool_health(snapshot.unwrap()).await.unwrap();
            assert_eq!(result["accounts"][0]["accountId"], "acct1");
            assert_eq!(result["accounts"][0]["source"], "unconfigured");
            assert_eq!(result["accounts"][0]["status"], "unknown");
            assert_eq!(
                result["accounts"][0]["candidates"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            assert!(result["accounts"][0]["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|candidate| candidate["status"] == "unknown"
                    && candidate["message"] == "未启用大陆监测"));
            assert!(server.received_requests().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn pool_health_reads_only_enabled_account_and_preserves_monitor_results() {
        let (server, mut backend, _dir) = fixture().await;
        let mut disabled = backend.db.accounts[0].clone();
        disabled.id = "acct2".into();
        disabled.resources = Some(Resources {
            script: "edge-two".into(),
            namespace: "ns2".into(),
        });
        backend.db.accounts.push(disabled);
        backend.db.accounts[0].monitor_enabled = true;
        let mut pool = sample_pool();
        pool.account_ids.push("acct2".into());
        let checked_at = Utc::now().timestamp();
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pools::cloud_value(&pool)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/h%3Apool1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "revision":pool.updated,"checkedAt":checked_at,
                "targets":{
                    "first":{"state":"healthy","failures":0,"successes":1,"checkedAt":checked_at},
                    "second":{"state":"healthy","failures":0,"successes":1,"checkedAt":checked_at}
                }
            })))
            .mount(&server)
            .await;
        backend.db.pools.push(pool);
        mock_key_reads().lock().unwrap().clear();
        let snapshot = backend.health_snapshot("pool1");
        let reads = mock_key_reads().lock().unwrap().clone();
        assert_eq!(reads, vec!["token:acct1"]);
        let result = run_pool_health(snapshot.unwrap()).await.unwrap();
        assert_eq!(result["accounts"][0]["source"], "mainland_provider");
        assert_eq!(result["accounts"][0]["status"], "healthy");
        assert_eq!(result["accounts"][1]["source"], "unconfigured");
        assert_eq!(result["accounts"][1]["status"], "unknown");
        assert_eq!(
            result["accounts"][1]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.method.as_str() == "GET"
                && request.url.path().contains("/acct1/")));
        keyring_delete("acct1", "token").unwrap();
        mock_key_reads().lock().unwrap().clear();
        assert!(backend.health_snapshot("pool1").is_err());
        let reads = mock_key_reads().lock().unwrap().clone();
        assert_eq!(reads, vec!["token:acct1"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn target_snapshot_labels_enabled_candidates_by_display_order() {
        let (server, mut backend, _dir) = fixture().await;
        let mut pool = sample_pool();
        pool.candidates[0].enabled = false;
        pool.candidates[1].id = "internal-candidate-a".into();
        pool.candidates.push(model::PoolCandidate {
            id: "internal-candidate-b".into(),
            prefix: "https://third.example/path/".into(),
            suffix: "".into(),
            enabled: true,
        });
        backend.db.pools.push(pool);
        backend.db.links.push(Link {
            domain_id: "domain1".into(),
            slug: "short".into(),
            cn_url: String::new(),
            default_url: String::new(),
            updated: now(),
            pool_id: Some("pool1".into()),
            code: Some("DEMO".into()),
        });
        let before = serde_json::to_value(&backend.db).unwrap();
        let targets = backend.target_snapshot("domain1", "short").unwrap();
        assert_eq!(
            targets,
            vec![
                (
                    "官网链接".into(),
                    "https://official.example/path/DEMO".into()
                ),
                (
                    "大陆访问地址 1".into(),
                    "https://second.example/path/DEMO".into()
                ),
                (
                    "大陆访问地址 2".into(),
                    "https://third.example/path/DEMO".into()
                ),
            ]
        );
        assert_eq!(serde_json::to_value(&backend.db).unwrap(), before);
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

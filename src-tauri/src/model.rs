use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub mac_credential_schema: u8,
    #[serde(default)]
    pub token_import_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare_name: Option<String>,
    pub zone_count: usize,
    pub checked_at: Option<String>,
    pub has_resources: bool,
    pub needs_selftest_key: bool,
    #[serde(default)]
    pub monitor_enabled: bool,
    #[serde(default)]
    pub monitor_endpoint: Option<String>,
    #[serde(default)]
    pub needs_monitor_key: bool,
    #[serde(default)]
    pub zones: Vec<Zone>,
    #[serde(default)]
    pub resources: Option<Resources>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub id: String,
    pub label: String,
    pub needs_credential_migration: bool,
    pub needs_token_recovery: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudflare_name: Option<String>,
    pub zone_count: usize,
    pub checked_at: Option<String>,
    pub has_resources: bool,
    pub needs_selftest_key: bool,
    pub monitor_enabled: bool,
    pub monitor_endpoint: Option<String>,
    pub needs_monitor_key: bool,
    pub zones: Vec<ZoneView>,
}

impl From<&Account> for AccountView {
    fn from(a: &Account) -> Self {
        Self {
            id: a.id.clone(),
            label: a.label.clone(),
            needs_credential_migration: cfg!(target_os = "macos") && a.mac_credential_schema != 2,
            needs_token_recovery: a.token_import_pending,
            cloudflare_name: a.cloudflare_name.clone(),
            zone_count: a.zone_count,
            checked_at: a.checked_at.clone(),
            has_resources: a.has_resources,
            needs_selftest_key: a.needs_selftest_key,
            monitor_enabled: a.monitor_enabled,
            monitor_endpoint: a.monitor_endpoint.clone(),
            needs_monitor_key: a.needs_monitor_key,
            zones: a.zones.iter().map(ZoneView::from).collect(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZoneView {
    pub id: String,
    pub name: String,
    pub status: String,
}

impl From<&Zone> for ZoneView {
    fn from(zone: &Zone) -> Self {
        Self {
            id: zone.id.clone(),
            name: zone.name.clone(),
            status: zone.status.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    pub account_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Resources {
    pub script: String,
    pub namespace: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub id: String,
    pub account_id: String,
    pub zone_id: String,
    pub host: String,
    pub prefix: String,
    pub route_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    pub domain_id: String,
    pub slug: String,
    pub cn_url: String,
    pub default_url: String,
    pub updated: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Template {
    pub prefix: String,
    pub suffix: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolCandidate {
    pub id: String,
    pub prefix: String,
    pub suffix: String,
    pub enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolSyncStatus {
    pub account_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pool {
    pub id: String,
    pub name: String,
    pub official: Template,
    pub candidates: Vec<PoolCandidate>,
    pub updated: String,
    #[serde(default)]
    pub account_ids: Vec<String>,
    #[serde(default)]
    pub sync_status: Vec<PoolSyncStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPoolChange {
    pub pool: Pool,
    pub previous: Option<Pool>,
    pub journal: String,
    pub deleting: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingMonitorChange {
    pub account_id: String,
    pub endpoint: String,
    pub enabled: bool,
    pub journal: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelftestRotationStatus {
    Staged,
    DefinitiveFailure,
    Uncertain,
    CloudApplied,
    StagingMissing,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingSelftestRotation {
    pub account_id: String,
    pub script: String,
    pub namespace: String,
    pub journal: String,
    pub status: SelftestRotationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerUpgradePhase {
    Prepared,
    UploadUncertain,
    VerificationFailed,
    ManifestUncertain,
}

/// Only validated, non-secret cloud metadata is stored here. Secret bindings
/// contain their names and types, never their values.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingWorkerUpgrade {
    pub account_id: String,
    pub resources: Resources,
    pub previous_hash: String,
    pub target_hash: String,
    pub manifest: serde_json::Value,
    pub settings: serde_json::Value,
    /// Missing on journals from older app versions, whose settings never changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_settings: Option<serde_json::Value>,
    pub schedules: serde_json::Value,
    pub journal: String,
    pub phase: WorkerUpgradePhase,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Database {
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub domains: Vec<Domain>,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default)]
    pub pools: Vec<Pool>,
    #[serde(default)]
    pub pending_pool_changes: Vec<PendingPoolChange>,
    #[serde(default)]
    pub pending_monitor_changes: Vec<PendingMonitorChange>,
    #[serde(default)]
    pub pending_selftest_rotations: Vec<PendingSelftestRotation>,
    #[serde(default)]
    pub pending_worker_upgrades: Vec<PendingWorkerUpgrade>,
    #[serde(default)]
    pub pending_operations: Vec<String>,
}

impl Database {
    pub(crate) fn has_legacy_selftest_rotation(&self, account_id: &str) -> bool {
        !self
            .pending_selftest_rotations
            .iter()
            .any(|p| p.account_id == account_id)
            && self
                .pending_operations
                .iter()
                .any(|entry| entry.starts_with(&format!("重置自检密钥 {account_id} (")))
    }

    /// This exception only repairs missing local resource identity. Unknown or
    /// overlapping unfinished work must remain blocked, never silently cleared.
    pub(crate) fn can_recover_selftest_resources(&self, account_id: &str) -> bool {
        let pool_mentions = |p: &PendingPoolChange| {
            p.pool.account_ids.iter().any(|id| id == account_id)
                || p.previous
                    .as_ref()
                    .is_some_and(|old| old.account_ids.iter().any(|id| id == account_id))
        };
        if !self
            .accounts
            .iter()
            .any(|a| a.id == account_id && a.resources.is_none())
            || !self.has_legacy_selftest_rotation(account_id)
            || self
                .pending_monitor_changes
                .iter()
                .any(|p| p.account_id == account_id)
            || self.pending_pool_changes.iter().any(pool_mentions)
            || self
                .pending_worker_upgrades
                .iter()
                .any(|p| p.account_id == account_id)
        {
            return false;
        }
        let matches_journal = |entry: &str, journal: &str| {
            !journal.is_empty()
                && (entry == journal
                    || entry
                        .strip_prefix(journal)
                        .is_some_and(|rest| rest.starts_with('：')))
        };
        self.pending_operations.iter().all(|entry| {
            entry.starts_with(&format!("重置自检密钥 {account_id} ("))
                || self.accounts.iter().any(|a| {
                    a.id != account_id
                        && self.has_legacy_selftest_rotation(&a.id)
                        && entry.starts_with(&format!("重置自检密钥 {} (", a.id))
                })
                || self
                    .pending_selftest_rotations
                    .iter()
                    .any(|p| p.account_id != account_id && matches_journal(entry, &p.journal))
                || self
                    .pending_monitor_changes
                    .iter()
                    .any(|p| p.account_id != account_id && matches_journal(entry, &p.journal))
                || self
                    .pending_pool_changes
                    .iter()
                    .any(|p| !pool_mentions(p) && matches_journal(entry, &p.journal))
                || self
                    .pending_worker_upgrades
                    .iter()
                    .any(|p| p.account_id != account_id && matches_journal(entry, &p.journal))
        })
    }
}

impl Database {
    /// When a pending record still has its own recovery entry (the buttons
    /// built from `pending_actions`, or the account's cleanup), says where to
    /// handle it. Such records must not be dismissed as plain notes.
    pub(crate) fn dedicated_recovery_hint(&self, entry: &str) -> Option<String> {
        self.dedicated_recovery_entry(entry)
            .map(|place| format!("这条记录有专门的处理入口，不能直接清除。{place}"))
    }

    /// The sentence naming a pending record's own recovery entry, if it has
    /// one (see `dedicated_recovery_hint`).
    pub(crate) fn dedicated_recovery_entry(&self, entry: &str) -> Option<String> {
        let matches_journal = |journal: &str| {
            !journal.is_empty()
                && (entry == journal
                    || entry
                        .strip_prefix(journal)
                        .is_some_and(|rest| rest.starts_with('：')))
        };
        // The resume bar sits above the page content on every page and is
        // titled 「有 N 项变更可继续处理」.
        let button = |label: &str| {
            Some(format!(
                "请用页面上方“……项变更可继续处理”那一栏里的「{label}」按钮处理"
            ))
        };
        if let Some(p) = self
            .pending_pool_changes
            .iter()
            .find(|p| matches_journal(&p.journal))
        {
            return button(if p.deleting {
                "继续删除"
            } else {
                "继续同步"
            });
        }
        if self
            .pending_monitor_changes
            .iter()
            .any(|p| matches_journal(&p.journal))
        {
            return button("继续处理监测");
        }
        if self
            .pending_worker_upgrades
            .iter()
            .any(|p| matches_journal(&p.journal))
        {
            return button("继续核对升级");
        }
        for account in &self.accounts {
            let rotation = self
                .pending_selftest_rotations
                .iter()
                .find(|p| p.account_id == account.id);
            if rotation.is_some_and(|p| matches_journal(&p.journal))
                || entry.starts_with(&format!("重置自检密钥 {} (", account.id))
            {
                return button(match rotation {
                    Some(p) if p.status == SelftestRotationStatus::StagingMissing => "查看修复计划",
                    Some(_) => "继续修复",
                    None if self.can_recover_selftest_resources(&account.id) => "找回本机检测配置",
                    None => "查看修复计划",
                });
            }
            // A cleanup refuses to run while the account has a local domain
            // or no recorded resources (an account removed from this computer
            // and imported again), so its record would have no way out: it
            // may be dismissed then.
            if entry.starts_with(&format!("清理账号 {} (", account.id))
                && account.resources.is_some()
                && !self.domains.iter().any(|d| d.account_id == account.id)
            {
                // The record itself shows only the account ID.
                return Some(format!(
                    "请到「Cloudflare 账户」页打开账户「{}」的「管理账户」，再点一次「删除云端短链接服务」继续处理",
                    account.label
                ));
            }
        }
        None
    }

    /// For a record that may be cleared by hand but that one more click
    /// usually finishes: where that click is. Advice only; it never blocks
    /// clearing the record.
    pub(crate) fn resume_hint(&self, entry: &str) -> Option<String> {
        let (kind, rest) = entry.split_once(' ')?;
        let host = &rest[..rest.find([' ', '（']).unwrap_or(rest.len())];
        let domain = self.domains.iter().find(|d| d.host == host)?;
        match kind {
            "移除域名" => Some(format!(
                "到「域名管理」对域名 {host} 再点一次「移除域名」把它做完"
            )),
            // The note `revived_links_note` leaves on an add-domain record.
            "添加域名" if entry.contains(REVIVED_LINKS_MARK) => {
                let label = self
                    .accounts
                    .iter()
                    .find(|a| a.id == domain.account_id)
                    .map_or("这个域名所属账户", |a| a.label.as_str());
                Some(format!(
                    "到「Cloudflare 账户」页打开账户「{label}」的「管理账户」，点「从 Cloudflare 找回配置」把那些短链接找回来"
                ))
            }
            _ => None,
        }
    }
}

/// Part of the note kept on an add-domain record whose reused setup brought
/// back links this computer does not list (see `resume_hint`).
pub(crate) const REVIVED_LINKS_MARK: &str = "条短链接，现在重新生效了";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub accounts: Vec<AccountView>,
    pub domains: Vec<Domain>,
    pub links: Vec<Link>,
    pub pools: Vec<Pool>,
    pub pending_operations: Vec<String>,
    pub pending_actions: Vec<PendingAction>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAction {
    pub kind: String,
    pub pool_id: Option<String>,
    pub account_id: Option<String>,
    pub label: String,
}

impl From<&Database> for State {
    fn from(db: &Database) -> Self {
        let has_legacy_rotation = |account_id: &str| db.has_legacy_selftest_rotation(account_id);
        Self {
            accounts: db
                .accounts
                .iter()
                .map(|account| {
                    let mut view = AccountView::from(account);
                    if db
                        .pending_selftest_rotations
                        .iter()
                        .any(|pending| pending.account_id == account.id)
                        || has_legacy_rotation(&account.id)
                    {
                        view.needs_selftest_key = true;
                    }
                    view
                })
                .collect(),
            domains: db.domains.clone(),
            links: db
                .links
                .iter()
                .cloned()
                .map(|mut link| {
                    if let (Some(pool_id), Some(code)) = (&link.pool_id, &link.code) {
                        if let Some(pool) = db.pools.iter().find(|p| &p.id == pool_id) {
                            link.default_url =
                                crate::pools::compose(&pool.official, code).unwrap_or_default();
                            link.cn_url = pool
                                .candidates
                                .iter()
                                .find(|c| c.enabled)
                                .and_then(|c| crate::pools::compose(&Template::from(c), code).ok())
                                .unwrap_or_default();
                        }
                    }
                    link
                })
                .collect(),
            pools: db.pools.clone(),
            pending_operations: db.pending_operations.clone(),
            pending_actions: db
                .pending_pool_changes
                .iter()
                .map(|p| PendingAction {
                    kind: if p.deleting {
                        "delete_pool"
                    } else {
                        "resume_pool_sync"
                    }
                    .into(),
                    pool_id: Some(p.pool.id.clone()),
                    account_id: None,
                    label: if p.deleting {
                        format!("继续删除平台地址 {}", p.pool.name)
                    } else {
                        format!("继续同步平台地址 {}", p.pool.name)
                    },
                })
                .chain(db.pending_monitor_changes.iter().map(|p| PendingAction {
                    kind: "resume_monitor".into(),
                    pool_id: None,
                    account_id: Some(p.account_id.clone()),
                    label: if p.enabled {
                        "继续启用监测".into()
                    } else {
                        "继续关闭监测".into()
                    },
                }))
                .chain(db.pending_selftest_rotations.iter().map(|p| {
                    PendingAction {
                        kind: if p.status == SelftestRotationStatus::StagingMissing {
                            "recover_selftest_rotation"
                        } else {
                            "resume_selftest_rotation"
                        }
                        .into(),
                        pool_id: None,
                        account_id: Some(p.account_id.clone()),
                        label: if p.status == SelftestRotationStatus::StagingMissing {
                            "重新建立自检密钥".into()
                        } else {
                            "继续恢复自检密钥".into()
                        },
                    }
                }))
                .chain(db.pending_worker_upgrades.iter().map(|p| PendingAction {
                    kind: "resume_worker_upgrade".into(),
                    pool_id: None,
                    account_id: Some(p.account_id.clone()),
                    label: "继续核对 Worker 变更".into(),
                }))
                .chain(
                    db.accounts
                        .iter()
                        .filter(|account| has_legacy_rotation(&account.id))
                        .map(|account| PendingAction {
                            kind: if db.can_recover_selftest_resources(&account.id) {
                                "recover_selftest_resources"
                            } else {
                                "recover_selftest_rotation"
                            }
                            .into(),
                            pool_id: None,
                            account_id: Some(account.id.clone()),
                            label: if db.can_recover_selftest_resources(&account.id) {
                                "找回检测服务配置"
                            } else {
                                "恢复旧版自检密钥操作"
                            }
                            .into(),
                        }),
                )
                .collect(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanView {
    pub id: String,
    pub title: String,
    pub steps: Vec<String>,
    pub warnings: Vec<String>,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_takeover_confirmation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_migration_confirmation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainCheckLevel {
    Pass,
    Warning,
    Error,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainCheck {
    pub label: String,
    pub ok: bool,
    pub message: String,
    pub level: DomainCheckLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone)]
pub enum PlanKind {
    SetClickProtection {
        account_id: String,
        target_hash: String,
        enabled: bool,
    },
    SetClickStats {
        account_id: String,
        target_hash: String,
        enabled: bool,
    },
    UpgradeWorker {
        account_id: String,
        target_hash: String,
    },
    ResumeWorkerUpgrade {
        account_id: String,
    },
    DismissWorkerUpgrade {
        account_id: String,
    },
    MigrateCredentials {
        account_id: String,
    },
    Domain {
        account_id: String,
        zone_id: String,
        host: String,
        prefix: String,
        path_risk: crate::domain_check::PathRiskSnapshot,
        dns_mode: crate::local_check::DnsMode,
        requires_takeover_confirmation: bool,
    },
    DomainDns {
        account_id: String,
        zone_id: String,
        host: String,
        snapshot: crate::domain_check::DnsSnapshot,
    },
    SaveLink {
        domain_id: String,
        slug: String,
        create_only: bool,
        exact_edit: bool,
        cn_url: String,
        default_url: String,
        pool_id: Option<String>,
        code: Option<String>,
    },
    SavePool {
        pool: Pool,
    },
    DeletePool {
        pool_id: String,
    },
    EnableMonitor {
        account_id: String,
        endpoint: String,
        secret: zeroize::Zeroizing<String>,
    },
    DisableMonitor {
        account_id: String,
    },
    DeleteLink {
        domain_id: String,
        slug: String,
    },
    RemoveDomain {
        domain_id: String,
    },
    CleanupAccount {
        account_id: String,
    },
    RecoverAccount {
        account_id: String,
    },
    RotateSelftest {
        account_id: String,
    },
    ResumeSelftestRotation {
        account_id: String,
    },
    RecoverSelftestRotation {
        account_id: String,
    },
    RecoverSelftestResources {
        account_id: String,
    },
    /// Removes one exact pending record from local state; no cloud access.
    DismissPendingOperation {
        entry: String,
    },
}

pub struct Plan {
    pub view: PlanView,
    pub kind: PlanKind,
    pub expires_at: std::time::Instant,
    pub snapshot: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub account_id: String,
    pub label: String,
    pub zone_id: String,
    pub status: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainPreparation {
    pub host: String,
    pub prefix: String,
    pub dns_mode: String,
    pub candidates: Vec<Candidate>,
    pub checks: Vec<DomainCheck>,
    pub can_apply: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsActionView {
    pub kind: String,
    pub record_type: String,
    pub name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainDnsPreparation {
    pub host: String,
    pub candidates: Vec<Candidate>,
    pub checks: Vec<DomainCheck>,
    pub dns_status: String,
    pub actions: Vec<DnsActionView>,
    pub can_apply: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_account_loads_and_state_exposes_only_safe_zone_fields() {
        let account: Account = serde_json::from_value(serde_json::json!({
            "id":"acct-example",
            "label":"自定义备注",
            "zoneCount":1,
            "checkedAt":null,
            "hasResources":false,
            "needsSelftestKey":false,
            "zones":[{"id":"zone-example","name":"example.com","status":"active","account_id":"acct-example"}]
        }))
        .unwrap();
        assert_eq!(account.cloudflare_name, None);
        assert_eq!(account.mac_credential_schema, 0);
        assert_eq!(account.label, "自定义备注");
        let value = serde_json::to_value(AccountView::from(&account)).unwrap();
        assert!(value.get("cloudflareName").is_none());
        assert_eq!(value["needsCredentialMigration"], cfg!(target_os = "macos"));
        assert!(value.get("macCredentialSchema").is_none());
        assert_eq!(value["zones"][0]["id"], "zone-example");
        assert_eq!(value["zones"][0]["name"], "example.com");
        assert_eq!(value["zones"][0]["status"], "active");
        assert!(value["zones"][0].get("accountId").is_none());
    }
}

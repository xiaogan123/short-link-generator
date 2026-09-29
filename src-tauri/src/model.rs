use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub label: String,
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
    pub pending_operations: Vec<String>,
}

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
        Self {
            accounts: db.accounts.iter().map(AccountView::from).collect(),
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
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub label: String,
    pub ok: bool,
    pub message: String,
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
}

#[derive(Clone)]
pub enum PlanKind {
    Domain {
        account_id: String,
        zone_id: String,
        host: String,
        prefix: String,
        path_risk: crate::domain_check::PathRiskSnapshot,
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
}

pub struct Plan {
    pub view: PlanView,
    pub kind: PlanKind,
    pub expires_at: std::time::Instant,
    pub snapshot: String,
}

#[derive(Serialize)]
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
        assert_eq!(account.label, "自定义备注");
        let value = serde_json::to_value(AccountView::from(&account)).unwrap();
        assert!(value.get("cloudflareName").is_none());
        assert_eq!(value["zones"][0]["id"], "zone-example");
        assert_eq!(value["zones"][0]["name"], "example.com");
        assert_eq!(value["zones"][0]["status"], "active");
        assert!(value["zones"][0].get("accountId").is_none());
    }
}

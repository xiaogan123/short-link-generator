mod cloud;
mod local_check;
mod model;
mod pools;

use chrono::Utc;
use cloud::{Cloud, CloudError};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use model::{
    Account, Candidate, Check, Database, Domain, DomainPreparation, Link, PendingMonitorChange,
    PendingPoolChange, Plan, PlanKind, PlanView, Pool, PoolSyncStatus, Resources, State, Zone,
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
use tauri_plugin_updater::UpdaterExt;
use tokio::sync::Mutex;

#[cfg(not(test))]
const KEYRING_SERVICE: &str = "org.shortlink.generator";
const MANIFEST_KEY: &str = "m:config";
const SCHEMA: u32 = 1;
fn bundled_source_hash() -> String {
    hex::encode(Sha256::digest(
        include_str!("../../edge/worker.mjs").as_bytes(),
    ))
}

pub struct AppState(Mutex<Backend>);

struct Backend {
    db: Database,
    path: PathBuf,
    plans: Vec<Plan>,
    cloud: Cloud,
    app: Option<tauri::AppHandle>,
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
    key: Vec<u8>,
    pool: Option<(Pool, String, String, String, String)>,
}

struct HealthSnapshot {
    pool: Pool,
    accounts: Vec<(String, String, String, bool)>,
    cloud: Cloud,
}

fn problem(error: CloudError) -> String {
    error.message
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
        return mock_keys()
            .lock()
            .expect("test key store")
            .get(&format!("{kind}:{id}"))
            .cloned()
            .ok_or_else(|| "系统凭据库中找不到所需密钥".into());
    }
    #[cfg(not(test))]
    {
        keyring::Entry::new(KEYRING_SERVICE, &format!("{kind}:{id}"))
            .map_err(|_| "系统凭据库不可用".to_string())?
            .get_password()
            .map_err(|_| "系统凭据库中找不到所需密钥".to_string())
    }
}
fn keyring_set(id: &str, kind: &str, value: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        mock_keys()
            .lock()
            .expect("test key store")
            .insert(format!("{kind}:{id}"), value.to_string());
        Ok(())
    }
    #[cfg(not(test))]
    {
        keyring::Entry::new(KEYRING_SERVICE, &format!("{kind}:{id}"))
            .map_err(|_| "系统凭据库不可用".to_string())?
            .set_password(value)
            .map_err(|_| "无法写入系统凭据库".to_string())
    }
}
fn keyring_delete(id: &str, kind: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        mock_keys()
            .lock()
            .expect("test key store")
            .remove(&format!("{kind}:{id}"));
        Ok(())
    }
    #[cfg(not(test))]
    {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{kind}:{id}"))
            .map_err(|_| "系统凭据库不可用".to_string())?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("无法从系统凭据库删除凭据".to_string()),
        }
    }
}
#[cfg(test)]
fn mock_keys() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static KEYS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
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
    let parsed = url::Url::parse(value).map_err(|_| "目标网址无效".to_string())?;
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
    let ids = value["poolIds"].as_array().ok_or("监测资源池清单无效")?;
    if ids.len() > 256 || value.to_string().len() > 16_384 {
        return Err("监测资源池清单超过 Worker 上限".into());
    }
    let mut unique = HashSet::new();
    for id in ids {
        let id = id.as_str().ok_or("监测资源池清单无效")?;
        if !pools::valid_id(id) || !unique.insert(id) {
            return Err("监测资源池清单无效".into());
        }
    }
    Ok(())
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
        let code = remote["code"].as_str().ok_or("模板链接缺少代码")?;
        if !pools::valid_code(code) {
            return Err("模板代码无效".into());
        }
        let pool = pools
            .iter()
            .find(|p| p.id == pool_id)
            .ok_or("找不到链接引用的资源池")?;
        let candidate = pool
            .candidates
            .iter()
            .find(|c| c.enabled)
            .ok_or("资源池没有启用的候选")?;
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
        .ok_or_else(|| "操作记录不存在".to_string())?;
    *item = note.clone();
    Ok(note)
}
fn clear_journal(pending: &mut Vec<String>, id: &str) -> Result<(), String> {
    let before = pending.len();
    pending.retain(|entry| !journal_matches(entry, id));
    if pending.len() == before {
        return Err("操作记录不存在".into());
    }
    Ok(())
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
    fn load(path: PathBuf, app: tauri::AppHandle) -> Result<Self, String> {
        let db = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| "无法读取本机配置".to_string())?;
            serde_json::from_slice(&bytes).map_err(|_| "本机配置格式无效".to_string())?
        } else {
            Database::default()
        };
        Ok(Self {
            db,
            path,
            plans: Vec::new(),
            cloud: Cloud::new()?,
            app: Some(app),
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
        fs::write(&tmp, bytes).map_err(|_| "无法保存配置".to_string())?;
        fs::rename(&tmp, &self.path).map_err(|_| "无法提交配置".to_string())
    }
    fn state(&self) -> Value {
        serde_json::to_value(State::from(&self.db)).unwrap_or(Value::Null)
    }
    fn account(&self, id: &str) -> Result<&Account, String> {
        self.db
            .accounts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| "找不到此账号".into())
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
        let view = PlanView {
            id: random_id(),
            title: title.into(),
            steps,
            warnings,
            expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
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

    async fn import_token(&mut self, token: &str, replace: bool) -> Result<Value, String> {
        if !(35..=100).contains(&token.len())
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err("令牌格式不像 Cloudflare API 令牌".into());
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
        let mut imported = Vec::new();
        for remote in accounts {
            let id = value_str(&remote, "id")?.to_owned();
            if !valid_id(&id) {
                return Err("云端账号标识无效".into());
            }
            if self.db.accounts.iter().any(|a| a.id == id) && !replace {
                return Err("这个账号已经导入过；若要换令牌，请确认替换".into());
            }
            self.cloud
                .get(token, &format!("accounts/{id}/workers/scripts"))
                .await
                .map_err(|_| "令牌缺少 Workers 脚本读取权限".to_string())?;
            self.cloud
                .get(token, &format!("accounts/{id}/storage/kv/namespaces"))
                .await
                .map_err(|_| "令牌缺少 Workers KV 存储权限".to_string())?;
            let zones = self.fetch_zones(token, &id).await?;
            if let Some(zone) = zones.first() {
                self.cloud
                    .get(token, &format!("zones/{}/workers/routes", zone.id))
                    .await
                    .map_err(|_| "令牌缺少 Workers 路由读取权限".to_string())?;
            }
            imported.push((id, zones));
        }
        // Validate every account before changing credentials or local state.
        for (id, zones) in imported {
            keyring_set(&id, "token", token)?;
            if let Some(account) = self.db.accounts.iter_mut().find(|a| a.id == id) {
                account.zone_count = zones.len();
                account.zones = zones;
                account.checked_at = Some(now());
            } else {
                let count = self.db.accounts.len() + 1;
                self.db.accounts.push(Account {
                    id,
                    label: format!("账号 {count}"),
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
        self.persist()?;
        Ok(self.state())
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

    async fn refresh_accounts(&mut self) -> Result<Value, String> {
        for i in 0..self.db.accounts.len() {
            let id = self.db.accounts[i].id.clone();
            let token = keyring_get(&id, "token")?;
            let zones = self.fetch_zones(&token, &id).await?;
            self.db.accounts[i].zone_count = zones.len();
            self.db.accounts[i].zones = zones;
            self.db.accounts[i].checked_at = Some(now());
        }
        self.persist()?;
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

    async fn preflight(
        &self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        prefix: &str,
    ) -> Vec<Check> {
        let mut checks = Vec::new();
        let account = match self.account(account_id) {
            Ok(v) => v,
            Err(e) => {
                checks.push(Check {
                    label: "账号".into(),
                    ok: false,
                    message: e,
                });
                return checks;
            }
        };
        let zone = account.zones.iter().find(|z| {
            z.id == zone_id && (host == z.name || host.ends_with(&format!(".{}", z.name)))
        });
        let active = zone.is_some_and(|z| z.status == "active");
        checks.push(Check {
            label: "区域状态".into(),
            ok: active,
            message: if active {
                "区域已启用".into()
            } else {
                "区域未启用或归属不匹配".into()
            },
        });
        if !active {
            return checks;
        }
        let token = match keyring_get(account_id, "token") {
            Ok(t) => t,
            Err(e) => {
                checks.push(Check {
                    label: "凭据".into(),
                    ok: false,
                    message: e,
                });
                return checks;
            }
        };
        let remote_zone = self.cloud.get(&token, &format!("zones/{zone_id}")).await;
        let remote_active = remote_zone.is_ok_and(|v| {
            v["result"]["status"] == "active"
                && v["result"]["id"].as_str() == Some(zone_id)
                && v["result"]["account"]["id"].as_str() == Some(account_id)
        });
        checks.push(Check {
            label: "实时区域状态".into(),
            ok: remote_active,
            message: if remote_active {
                "云端确认区域已启用".into()
            } else {
                "无法确认云端区域已启用且归属一致".into()
            },
        });
        if !remote_active {
            return checks;
        }
        let dns_path = format!("zones/{zone_id}/dns_records?name={}", cloud::encode(host));
        let dns = self.cloud.list_pages(&token, &dns_path).await;
        let (ok, message) = match dns {
            Ok(items) => {
                let exact: Vec<_> = items
                    .iter()
                    .filter(|r| {
                        r["name"].as_str() == Some(host)
                            && matches!(r["type"].as_str(), Some("A" | "AAAA" | "CNAME"))
                    })
                    .collect();
                let ok = !exact.is_empty() && exact.iter().all(|r| r["proxied"] == true);
                (
                    ok,
                    if ok {
                        "DNS 已代理"
                    } else {
                        "该主机名没有 DNS 记录，或存在未代理记录"
                    },
                )
            }
            Err(_) => (false, "无法读取 DNS 记录"),
        };
        checks.push(Check {
            label: "DNS".into(),
            ok,
            message: message.into(),
        });
        let routes = self
            .cloud
            .get(&token, &format!("zones/{zone_id}/workers/routes"))
            .await;
        let (ok, message) = match routes {
            Ok(v) => {
                let Some(arr) = v["result"].as_array() else {
                    checks.push(Check {
                        label: "路由".into(),
                        ok: false,
                        message: "云端路由列表格式无效".into(),
                    });
                    return checks;
                };
                let found = arr.iter().any(|r| {
                    r["pattern"]
                        .as_str()
                        .is_some_and(|p| route_conflict(p, host, prefix))
                });
                (
                    !found,
                    if found {
                        "现有 Worker 路由与此前缀重叠"
                    } else {
                        "没有发现重叠路由"
                    },
                )
            }
            Err(_) => (false, "无法读取 Worker 路由"),
        };
        checks.push(Check {
            label: "路由".into(),
            ok,
            message: message.into(),
        });
        for (label, path) in [
            ("前缀根路径", format!("/{prefix}/")),
            ("随机子路径", format!("/{prefix}/{}", random_name("probe"))),
        ] {
            let url = format!("https://{host}{path}");
            let result = self.cloud_probe(&url, None).await;
            let ok = matches!(result, Ok((404, _)));
            checks.push(Check {
                label: label.into(),
                ok,
                message: if ok {
                    "返回 404，可使用此前缀".into()
                } else {
                    "路径已有内容或无法确定，请换前缀或检查网络".into()
                },
            });
        }
        checks
    }

    async fn cloud_probe(
        &self,
        url: &str,
        header: Option<String>,
    ) -> Result<(u16, Option<String>), String> {
        self.cloud.probe(url, header).await.map_err(problem)
    }

    async fn prepare_domain(&mut self, payload: &Value) -> Result<Value, String> {
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
        let candidates = self.candidates(&host);
        let choice = payload["accountId"].as_str();
        let selected = if candidates.len() == 1 && choice.is_none() {
            candidates.first()
        } else {
            choice.and_then(|id| candidates.iter().find(|c| c.account_id == id))
        };
        let mut checks = Vec::new();
        let mut plan = None;
        if self.db.domains.iter().any(|d| d.host == host) {
            checks.push(Check {
                label: "本机配置".into(),
                ok: false,
                message: "这个主机名已经添加".into(),
            });
        } else if candidates.is_empty() {
            checks.push(Check {
                label: "区域归属".into(),
                ok: false,
                message: "域名不在已导入账号的区域里".into(),
            });
        } else if selected.is_none() {
            checks.push(Check {
                label: "账号选择".into(),
                ok: false,
                message: "请选择此域名所属的账号".into(),
            });
        } else if let Some(c) = selected {
            checks = self
                .preflight(&c.account_id, &c.zone_id, &host, &prefix)
                .await;
            if checks.iter().all(|c| c.ok) {
                let has_resources = self.account(&c.account_id)?.resources.is_some();
                let mut steps = Vec::new();
                if !has_resources {
                    steps.push("创建此账号专用的 KV 与 Worker，并设置自检密钥".into());
                }
                steps.push(format!("写入 {host} 的前缀配置"));
                steps.push(format!("创建路由 {}", route_pattern(&host, &prefix)));
                plan = Some(self.make_plan(
                    "添加域名",
                    steps,
                    vec!["边缘配置传播可能需要一段时间".into()],
                    PlanKind::Domain {
                        account_id: c.account_id.clone(),
                        zone_id: c.zone_id.clone(),
                        host: host.clone(),
                        prefix: prefix.clone(),
                    },
                ));
            }
        }
        Ok(serde_json::to_value(DomainPreparation {
            host,
            prefix,
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
            {"key":"dns","type":"read"},
            {"key":"account_settings","type":"read"}
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
            "save_link" => {
                let domain_id = field(payload, "domainId")?.to_owned();
                let domain = self.domain(&domain_id)?;
                let slug = field(payload, "slug")?.to_owned();
                let (cn_url, default_url, pool_id, code) =
                    if let Some(pool_id) = payload["poolId"].as_str().filter(|s| !s.is_empty()) {
                        let code = field(payload, "code")?;
                        if !pools::valid_code(code) {
                            return Err("模板代码无效".into());
                        }
                        let pool = self
                            .db
                            .pools
                            .iter()
                            .find(|p| p.id == pool_id)
                            .ok_or("找不到此资源池")?;
                        if !pool.account_ids.contains(&domain.account_id) {
                            return Err("此资源池未授权给域名所属账号".into());
                        }
                        let candidate = pool
                            .candidates
                            .iter()
                            .find(|c| c.enabled)
                            .ok_or("资源池没有已启用候选目标")?;
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
                validate_slug(&slug)?;
                let existing = self
                    .db
                    .links
                    .iter()
                    .any(|l| l.domain_id == domain_id && l.slug == slug);
                (
                    "保存链接",
                    vec![format!("{}：{} 配置地区目标", domain.host, slug)],
                    if existing {
                        vec!["这会覆盖现有链接目标".into()]
                    } else {
                        vec![]
                    },
                    PlanKind::SaveLink {
                        domain_id,
                        slug,
                        cn_url,
                        default_url,
                        pool_id,
                        code,
                    },
                )
            }
            "save_pool" => {
                let mut pool: Pool = serde_json::from_value(payload["pool"].clone())
                    .map_err(|_| "资源池数据格式无效".to_string())?;
                if pool.id.is_empty() {
                    pool.id = random_id();
                }
                if self
                    .db
                    .pending_pool_changes
                    .iter()
                    .any(|p| p.pool.id == pool.id)
                {
                    return Err("此资源池有未完成同步，请先恢复该操作".into());
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
                    "保存资源池",
                    vec![format!(
                        "同步至 {accounts} 个账号；现有 {refs} 条引用随资源池生效"
                    )],
                    if refs > 0 {
                        vec!["变更将影响全部引用此资源池的链接".into()]
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
                    .ok_or("此资源池没有未完成同步")?;
                (
                    "恢复资源池同步",
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
                    .ok_or("找不到此资源池")?;
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
                    return Err("资源池同步尚未完成，不能删除".into());
                }
                if self
                    .db
                    .links
                    .iter()
                    .any(|l| l.pool_id.as_deref() == Some(&pool_id))
                {
                    return Err("仍有链接引用此资源池".into());
                }
                (
                    "删除资源池",
                    vec![format!(
                        "从 {} 个账号删除资源池配置",
                        pool.account_ids.len()
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
                        format!("删除 {} 的 Worker 路由", domain.host),
                        format!("删除此前缀配置和 {count} 条链接记录"),
                    ],
                    vec!["边缘节点可能暂时保留已缓存的配置".into()],
                    PlanKind::RemoveDomain { domain_id: id },
                )
            }
            "cleanup_account" => {
                let id = field(payload, "accountId")?.to_owned();
                let account = self.account(&id)?;
                let resources = account.resources.as_ref().ok_or("此账号没有已登记资源")?;
                if self.db.domains.iter().any(|d| d.account_id == id) {
                    return Err("此账号还有域名，请先移除域名".into());
                }
                (
                    "清理账号资源",
                    vec![
                        format!("删除 Worker {}", resources.script),
                        format!("删除 KV 命名空间 {}", resources.namespace),
                    ],
                    vec!["此操作会永久删除账号专用云端资源".into()],
                    PlanKind::CleanupAccount { account_id: id },
                )
            }
            "recover_account" => {
                let id = field(payload, "accountId")?.to_owned();
                self.account(&id)?;
                (
                    "从账号找回",
                    vec![
                        "只读扫描账号里的 Worker、KV 与路由，并验证归属".into(),
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
                    return Err("账号尚无 Worker".into());
                }
                (
                    "重置自检密钥",
                    vec![
                        "生成新密钥并更新云端 Worker 绑定".into(),
                        "把新密钥存入系统凭据库".into(),
                    ],
                    vec!["其他设备保存的旧自检密钥将失效".into()],
                    PlanKind::RotateSelftest { account_id: id },
                )
            }
            _ => return Err("不支持此变更类型".into()),
        };
        let view = self.make_plan(title, steps, warnings, plan_kind);
        serde_json::to_value(view).map_err(|_| "无法建立操作计划".into())
    }

    async fn dispatch(&mut self, action: &str, payload: &Value) -> Result<Value, String> {
        match action {
            "get_state" => Ok(self.state()),
            "token_template" => Ok(Value::String(Self::token_template())),
            "import_token" => {
                self.import_token(
                    field(payload, "token")?,
                    payload["replace"].as_bool().unwrap_or(false),
                )
                .await
            }
            "rename_account" => {
                let id = field(payload, "accountId")?;
                let label = field(payload, "label")?.trim();
                if label.is_empty() || label.chars().count() > 64 {
                    return Err("备注名需为 1–64 个字符".into());
                }
                self.db
                    .accounts
                    .iter_mut()
                    .find(|a| a.id == id)
                    .ok_or("找不到此账号")?
                    .label = label.to_owned();
                self.persist()?;
                Ok(self.state())
            }
            "remove_account" => {
                let id = field(payload, "accountId")?;
                self.account(id)?;
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
                {
                    return Err("此账号有未完成的云端操作，请先在待处理操作中恢复".into());
                }
                keyring_delete(id, "token")?;
                keyring_delete(id, "selftest")?;
                let _ = keyring_delete(id, "probe");
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
                self.persist()?;
                Ok(self.state())
            }
            "refresh_accounts" => self.refresh_accounts().await,
            "prepare_domain" => self.prepare_domain(payload).await,
            "prepare_change" => self.prepare_change(payload),
            "prepare_monitor" => {
                let account_id = field(payload, "accountId")?.to_owned();
                if self.db.pending_pool_changes.iter().any(|p| {
                    p.pool.account_ids.contains(&account_id)
                        || p.previous
                            .as_ref()
                            .is_some_and(|old| old.account_ids.contains(&account_id))
                }) {
                    return Err("此账号的资源池操作尚未完成，请先恢复".into());
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
                    return Err("此账号尚无 Worker/KV 资源".into());
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
                    "此账号有 {enabled_targets} 个候选目标；每轮最多检查 20 个，轮转间隔可能使结果超出一小时有效期"
                ));
                }
                let view = self.make_plan(
                    "启用可选监测",
                    vec![
                        format!("配置监测服务 {endpoint}"),
                        format!(
                            "配置 Worker 密钥、{pool_count} 个资源池的清单与每 15 分钟计划任务"
                        ),
                    ],
                    warnings,
                    PlanKind::EnableMonitor {
                        account_id,
                        endpoint,
                        secret,
                    },
                );
                serde_json::to_value(view).map_err(|_| "无法建立监测计划".into())
            }
            "disable_monitor" => {
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
                        "移除 Worker 计划任务、监测配置与专用密钥".into(),
                        "保留现有链接和资源池".into(),
                    ],
                    vec![],
                    PlanKind::DisableMonitor { account_id },
                );
                serde_json::to_value(view).map_err(|_| "无法建立监测计划".into())
            }
            "resume_monitor" => {
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
                        secret: keyring_get(account_id, "probe")?,
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
                self.apply(plan.kind).await?;
                Ok(self.state())
            }
            "selftest_link" => Err("自检调用路径无效".into()),
            "export_config" => self.export_config(),
            "import_config" => self.import_config(field(payload, "json")?).await,
            "check_update" => self.check_update(false).await,
            "install_update" => self.check_update(true).await,
            _ => Err("不支持此操作".into()),
        }
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

    async fn check_update(&self, install: bool) -> Result<Value, String> {
        let (Some(pubkey), Some(endpoint)) = (
            option_env!("SLG_UPDATER_PUBLIC_KEY"),
            option_env!("SLG_UPDATER_ENDPOINT"),
        ) else {
            return Ok(json!({"status":"unavailable","message":"此版本未配置更新通道"}));
        };
        if pubkey.is_empty() {
            return Ok(json!({"status":"unavailable","message":"此版本未配置更新通道"}));
        }
        let url = url::Url::parse(endpoint).map_err(|_| "更新地址配置无效".to_string())?;
        if url.scheme() != "https" {
            return Err("更新地址必须使用 HTTPS".into());
        }
        let updater = self
            .app
            .as_ref()
            .ok_or("更新服务不可用")?
            .updater_builder()
            .endpoints(vec![url])
            .map_err(|_| "更新通道配置无效".to_string())?
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| "更新服务不可用".to_string())?;
        let available = updater
            .check()
            .await
            .map_err(|_| "无法检查更新，请稍后再试".to_string())?;
        let Some(update) = available else {
            return Ok(json!({"status":"up_to_date","message":"当前已是最新版本"}));
        };
        if !install {
            return Ok(json!({"status":"available","version":update.version,
                "notes":update.body,"message":"发现新版本"}));
        }
        update
            .download_and_install(|_, _| {}, || {})
            .await
            .map_err(|_| "更新下载或安装失败".to_string())?;
        Ok(json!({"status":"installed","version":update.version,
            "message":"更新已安装，请重新启动应用"}))
    }

    async fn import_config(&mut self, json_text: &str) -> Result<Value, String> {
        if !self.db.pending_monitor_changes.is_empty() || !self.db.pending_pool_changes.is_empty() {
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
            self.account(id)?;
            labels.push((id.to_owned(), label.to_owned()));
        }
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
                    if d.account_id == account_id {
                        Ok(d.id.clone())
                    } else {
                        Err("同一主机名已有另一账号的本机配置".to_string())
                    }
                })
                .transpose()?
                .unwrap_or_else(random_id);
            recovered_domains.push(Domain {
                id: domain_id,
                account_id: account_id.into(),
                zone_id: zone.id.clone(),
                host,
                prefix: prefix.into(),
                route_id,
            });
        }
        let mut recovered_links = Vec::new();
        let mut recovered_pools = Vec::new();
        for item in pool_entries {
            let mut pool: Pool =
                serde_json::from_value(item.clone()).map_err(|_| "备份资源池格式无效")?;
            pool.sync_status.clear();
            pools::validate_pool(&pool)?;
            for id in &pool.account_ids {
                let account = self.account(id)?;
                let resources = account
                    .resources
                    .as_ref()
                    .ok_or("备份资源池账号缺少云端资源")?;
                let token = keyring_get(id, "token")?;
                let raw = self
                    .cloud
                    .read_value(&token, id, &resources.namespace, &format!("p:{}", pool.id))
                    .await
                    .map_err(problem)?
                    .ok_or("云端缺少备份资源池")?;
                let remote: Value = serde_json::from_str(&raw).map_err(|_| "云端资源池格式无效")?;
                if !pools::matching_cloud_value(&pool, &remote) {
                    return Err("云端资源池与备份不同".into());
                }
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
                .ok_or("链接没有对应域名")?;
            let slug = field(item, "slug")?;
            validate_slug(slug)?;
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
                if value["poolId"].as_str() != Some(pool_id) || value["code"].as_str() != Some(code)
                {
                    return Err("云端模板链接与备份不同".into());
                }
                if !recovered_pools
                    .iter()
                    .any(|p| p.id == pool_id && p.account_ids.contains(&domain.account_id))
                {
                    return Err("备份资源池未包含链接所属账号".into());
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
            recovered_links.push(link);
        }
        for pool in &recovered_pools {
            if let Some(existing) = self.db.pools.iter().find(|p| p.id == pool.id) {
                if pools::cloud_value(existing) != pools::cloud_value(pool) {
                    return Err("本机已有不同版本的同名资源池".into());
                }
            }
        }
        for pool in recovered_pools {
            if let Some(existing) = self.db.pools.iter_mut().find(|p| p.id == pool.id) {
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
                self.db.pools.push(pool);
            }
        }
        for domain in recovered_domains {
            if !self.db.domains.iter().any(|d| d.host == domain.host) {
                self.db.domains.push(domain);
            }
        }
        for link in recovered_links {
            if let Some(domain) = self.db.domains.iter().find(|d| d.id == link.domain_id) {
                if !self
                    .db
                    .links
                    .iter()
                    .any(|l| l.domain_id == domain.id && l.slug == link.slug)
                {
                    self.db.links.push(link);
                }
            }
        }
        for (id, label) in labels {
            if let Some(account) = self.db.accounts.iter_mut().find(|a| a.id == id) {
                account.label = label;
            }
        }
        self.persist()?;
        Ok(self.state())
    }

    async fn ensure_domain_owned(&self, domain: &Domain, token: &str) -> Result<Resources, String> {
        let account = self.account(&domain.account_id)?;
        let resources = account.resources.clone().ok_or("账号资源未登记")?;
        self.verify_resource_source(token, &account.id, &resources)
            .await?;
        if !account.zones.iter().any(|z| {
            z.id == domain.zone_id
                && z.status == "active"
                && (domain.host == z.name || domain.host.ends_with(&format!(".{}", z.name)))
        }) {
            return Err("区域状态或域名归属已变化".into());
        }
        let manifest = self
            .cloud
            .read_value(token, &account.id, &resources.namespace, MANIFEST_KEY)
            .await
            .map_err(problem)?
            .ok_or("云端缺少资源清单")?;
        let manifest: Value =
            serde_json::from_str(&manifest).map_err(|_| "云端资源清单损坏".to_string())?;
        if manifest["schema"] != SCHEMA
            || manifest["script"] != resources.script
            || manifest["namespace"] != resources.namespace
            || manifest["accountId"] != account.id
        {
            return Err("云端资源清单与本机不一致".into());
        }
        let settings = self
            .cloud
            .script_settings(token, &account.id, &resources.script)
            .await
            .map_err(problem)?;
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
            return Err("Worker 路由已变化，请刷新或找回".into());
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
            .ok_or("云端域名配置已丢失")?;
        let config: Value =
            serde_json::from_str(&config).map_err(|_| "云端域名配置损坏".to_string())?;
        if config["prefix"].as_str() != Some(domain.prefix.as_str()) {
            return Err("云端前缀与本机不一致".into());
        }
        Ok(resources)
    }

    async fn verify_resource_source(
        &self,
        token: &str,
        account_id: &str,
        resources: &Resources,
    ) -> Result<(), String> {
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
        let expected = (bindings.len() == 2 || bindings.len() == 3)
            && bindings.iter().any(|b| {
                b["type"] == "kv_namespace"
                    && b["name"] == "LINKS"
                    && b["namespace_id"] == resources.namespace
            })
            && bindings
                .iter()
                .any(|b| b["type"] == "secret_text" && b["name"] == "SELFTEST_KEY")
            && (bindings.len() == 2
                || bindings
                    .iter()
                    .any(|b| b["type"] == "secret_text" && b["name"] == "PROBE_KEY"))
            && bindings.iter().all(|b| {
                matches!(
                    b["name"].as_str(),
                    Some("LINKS" | "SELFTEST_KEY" | "PROBE_KEY")
                )
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
        Ok(())
    }

    async fn apply(&mut self, kind: PlanKind) -> Result<(), String> {
        match kind {
            PlanKind::Domain {
                account_id,
                zone_id,
                host,
                prefix,
            } => {
                self.apply_domain(&account_id, &zone_id, &host, &prefix)
                    .await
            }
            PlanKind::SaveLink {
                domain_id,
                slug,
                cn_url,
                default_url,
                pool_id,
                code,
            } => {
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
        }
    }

    async fn apply_domain(
        &mut self,
        account_id: &str,
        zone_id: &str,
        host: &str,
        prefix: &str,
    ) -> Result<(), String> {
        if self.db.domains.iter().any(|d| d.host == host) {
            return Err("这个主机名已经添加".into());
        }
        let checks = self.preflight(account_id, zone_id, host, prefix).await;
        if checks.iter().any(|c| !c.ok) {
            return Err("预检状态已变化，请重新检查域名".into());
        }
        let token = keyring_get(account_id, "token")?;
        let existing = self.account(account_id)?.resources.clone();
        if let Some(r) = &existing {
            self.verify_resource_source(&token, account_id, r).await?;
            let manifest = self
                .cloud
                .read_value(&token, account_id, &r.namespace, MANIFEST_KEY)
                .await
                .map_err(problem)?
                .ok_or("云端资源清单缺失")?;
            let manifest: Value =
                serde_json::from_str(&manifest).map_err(|_| "云端资源清单损坏".to_string())?;
            if manifest["schema"] != SCHEMA
                || manifest["accountId"] != account_id
                || manifest["script"] != r.script
                || manifest["namespace"] != r.namespace
            {
                return Err("云端资源归属与本机不一致".into());
            }
            let settings = self
                .cloud
                .script_settings(&token, account_id, &r.script)
                .await
                .map_err(problem)?;
            if !settings["result"]["bindings"].as_array().is_some_and(|bs| {
                bs.iter().any(|b| {
                    b["type"] == "kv_namespace"
                        && b["name"] == "LINKS"
                        && b["namespace_id"] == r.namespace
                })
            }) {
                return Err("Worker 的 KV 绑定已变化".into());
            }
            if self
                .cloud
                .read_value(&token, account_id, &r.namespace, &format!("c:{host}"))
                .await
                .map_err(problem)?
                .is_some()
            {
                return Err("云端已有此主机名的配置，请先从账号找回，不能覆盖".into());
            }
        }
        let names = if existing.is_none() {
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
        let mut resources = existing.clone();
        let operation: Result<(), CloudError> = async {
            if resources.is_none() {
                let (namespace_name, script) = names.clone().expect("new account resource names");
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
                    })?
                    .to_owned();
                created_namespace = Some(namespace.clone());
                self.journal_note(&journal, "已建 KV，正在上传 Worker")
                    .map_err(|m| CloudError {
                        message: m,
                        uncertain: true,
                    })?;
                let mut key = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                let key_hex = hex::encode(key);
                keyring_set(account_id, "selftest", &key_hex).map_err(|m| CloudError {
                    message: m,
                    uncertain: false,
                })?;
                self.cloud
                    .upload_script(&token, account_id, &script, &namespace, &key_hex)
                    .await?;
                created_script = Some(script.clone());
                self.journal_note(&journal, "已建 Worker，正在写资源清单")
                    .map_err(|m| CloudError {
                        message: m,
                        uncertain: true,
                    })?;
                let manifest = json!({"schema":SCHEMA,"accountId":account_id,
                    "script":script,"namespace":namespace,"sourceHash":bundled_source_hash()});
                self.cloud
                    .write_value(
                        &token,
                        account_id,
                        &namespace,
                        MANIFEST_KEY,
                        &manifest.to_string(),
                    )
                    .await?;
                resources = Some(Resources { script, namespace });
            }
            let r = resources.as_ref().expect("created or existing");
            self.cloud
                .write_value(
                    &token,
                    account_id,
                    &r.namespace,
                    &format!("c:{host}"),
                    &json!({"prefix":prefix}).to_string(),
                )
                .await?;
            wrote_config = true;
            self.journal_note(&journal, "已写前缀配置，正在创建路由")
                .map_err(|m| CloudError {
                    message: m,
                    uncertain: true,
                })?;
            let route = self
                .cloud
                .post(
                    &token,
                    &format!("zones/{zone_id}/workers/routes"),
                    json!({"pattern":route_pattern(host,prefix),"script":r.script}),
                )
                .await?;
            route_id = Some(
                route["result"]["id"]
                    .as_str()
                    .ok_or_else(|| CloudError {
                        message: "路由响应缺少标识".into(),
                        uncertain: true,
                    })?
                    .to_owned(),
            );
            Ok(())
        }
        .await;
        if let Err(error) = operation {
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
            self.journal_note(&journal, "失败且回滚未完全成功，需要人工核对")?;
            return Err(format!("{}；回滚未完成，请检查操作记录", error.message));
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
        self.persist()?;
        self.journal_end(&journal)
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
        validate_slug(slug)?;
        validate_target(cn)?;
        validate_target(default)?;
        let domain = self.domain(domain_id)?.clone();
        let token = keyring_get(&domain.account_id, "token")?;
        let resources = self.ensure_domain_owned(&domain, &token).await?;
        if let (Some(pool_id), Some(code)) = (pool_id, code) {
            if !pools::valid_code(code) {
                return Err("模板代码无效".into());
            }
            self.ensure_pool_on_account(pool_id, &domain.account_id, &token, &resources)
                .await?;
        }
        let key = format!("l:{}:{slug}", domain.host);
        let previous = self
            .cloud
            .read_value(&token, &domain.account_id, &resources.namespace, &key)
            .await
            .map_err(problem)?;
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
        let link = Link {
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
            if e.uncertain {
                self.journal_note(&journal, "写入结果不确定，需要人工核对")?;
            } else {
                self.journal_end(&journal)?;
            }
            return Err(e.message);
        }
        self.db
            .links
            .retain(|l| l.domain_id != domain_id || l.slug != slug);
        self.db.links.push(link);
        self.persist()?;
        self.journal_end(&journal)
    }

    async fn ensure_pool_on_account(
        &mut self,
        pool_id: &str,
        account_id: &str,
        token: &str,
        resources: &Resources,
    ) -> Result<(), String> {
        let pool = self
            .db
            .pools
            .iter()
            .find(|p| p.id == pool_id)
            .cloned()
            .ok_or("找不到资源池")?;
        if !pool.account_ids.iter().any(|id| id == account_id) {
            return Err("资源池未授权给此账号".into());
        }
        let key = format!("p:{pool_id}");
        let remote = self
            .cloud
            .read_value(token, account_id, &resources.namespace, &key)
            .await
            .map_err(problem)?;
        if let Some(raw) = remote {
            let value: Value = serde_json::from_str(&raw).map_err(|_| "云端资源池格式无效")?;
            if !pools::matching_cloud_value(&pool, &value) {
                return Err("云端资源池与本机版本不同，请先修复同步状态".into());
            }
        } else {
            let journal = format!(
                "首次同步资源池 {} / {} ({})",
                pool_id,
                account_id,
                random_id()
            );
            self.journal_start(&journal)?;
            if let Err(e) = self
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
                self.journal_note(&journal, "资源池首次写入未完成")?;
                return Err(e.message);
            }
            if let Some(status) = self
                .db
                .pools
                .iter_mut()
                .find(|p| p.id == pool_id)
                .and_then(|p| {
                    p.sync_status
                        .iter_mut()
                        .find(|s| s.account_id == account_id)
                })
            {
                status.status = "synced".into();
                status.message = "首次使用时已同步".into();
            }
            self.persist()?;
            self.journal_end(&journal)?;
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
            .ok_or("监测资源池清单无效")?
            .iter()
            .map(|v| v.as_str().ok_or("监测资源池清单无效"))
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
            return Err("存在不同的未完成资源池操作".into());
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
                return Err("不能从已有资源池直接移除账号，请先删除引用".into());
            }
        }
        struct Target {
            account: String,
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
            let token = keyring_get(id, "token")?;
            self.verify_resource_source(&token, id, resources).await?;
            let monitor = self
                .monitor_config_for(id, &token, &resources.namespace, &pool.id)
                .await?;
            if let Some(mut projected) = monitor.clone() {
                let ids = projected["poolIds"]
                    .as_array_mut()
                    .ok_or("监测资源池清单无效")?;
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
                let value: Value = serde_json::from_str(&raw).map_err(|_| "云端资源池格式无效")?;
                let already_desired =
                    pending.is_some() && pools::matching_cloud_value(&pool, &value);
                let owned = already_desired
                    || old.as_ref().is_some_and(|prior| {
                        prior.account_ids.contains(id) && pools::matching_cloud_value(prior, &value)
                    });
                if !owned {
                    return Err("云端已有不同的同名资源池，停止覆盖".into());
                }
                targets.push(Target {
                    account: id.clone(),
                    token,
                    namespace: resources.namespace.clone(),
                    monitor,
                    already_desired,
                });
            } else if old.as_ref().is_some_and(|prior| {
                prior
                    .sync_status
                    .iter()
                    .any(|s| s.account_id == *id && s.status == "synced")
            }) {
                return Err("已同步资源池在云端缺失，请先核对".into());
            } else {
                targets.push(Target {
                    account: id.clone(),
                    token,
                    namespace: resources.namespace.clone(),
                    monitor,
                    already_desired: false,
                });
            }
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
            .unwrap_or_else(|| format!("同步资源池 {} ({})", pool.id, random_id()));
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
                .ok_or("资源池同步状态丢失")?;
            match result {
                Ok(()) => {}
                Err(e) => {
                    status.status = if e.uncertain { "unknown" } else { "failed" }.into();
                    status.message = e.message.clone();
                    self.persist()?;
                    self.journal_note(&journal, "账号同步未完成，需要核对云端状态")?;
                    return Err(e.message);
                }
            }
            if let Some(mut monitor) = target.monitor {
                let ids = monitor["poolIds"]
                    .as_array_mut()
                    .ok_or("监测资源池清单无效")?;
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
                        status.message = "资源池已写入，监测清单未确认".into();
                        self.persist()?;
                        self.journal_note(&journal, "资源池已写入，但监测清单未同步")?;
                        return Err(e.message);
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
        let pending = self
            .db
            .pending_pool_changes
            .iter()
            .find(|p| p.pool.id == pool_id)
            .cloned();
        if pending.as_ref().is_some_and(|p| !p.deleting) {
            return Err("资源池同步尚未完成，不能删除".into());
        }
        let pool = self
            .db
            .pools
            .iter()
            .find(|p| p.id == pool_id)
            .cloned()
            .ok_or("找不到资源池")?;
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
            return Err("仍有本机链接引用此资源池".into());
        }
        struct Target {
            account: String,
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
                let value: Value = serde_json::from_str(&raw).map_err(|_| "云端链接格式无效")?;
                if value["poolId"].as_str() == Some(pool_id) {
                    return Err("云端仍有链接引用此资源池".into());
                }
            }
            let raw = self
                .cloud
                .read_value(&token, id, &resources.namespace, &format!("p:{pool_id}"))
                .await
                .map_err(problem)?;
            if let Some(raw) = raw {
                if !pool.account_ids.contains(id) {
                    return Err("另一账号存在同名资源池，停止删除".into());
                }
                let value: Value = serde_json::from_str(&raw).map_err(|_| "云端资源池格式无效")?;
                if !pools::matching_cloud_value(&pool, &value) {
                    return Err("云端资源池已变化，停止删除".into());
                }
                targets.push(Target {
                    account: id.clone(),
                    token,
                    namespace: resources.namespace.clone(),
                    monitor,
                    already_deleted: false,
                });
            } else if pending.is_some() && pool.account_ids.contains(id) {
                targets.push(Target {
                    account: id.clone(),
                    token,
                    namespace: resources.namespace.clone(),
                    monitor,
                    already_deleted: true,
                });
            } else if pool
                .sync_status
                .iter()
                .any(|s| s.account_id == *id && s.status == "synced")
            {
                return Err("已同步资源池在云端缺失，请先核对".into());
            }
        }
        let journal = pending
            .as_ref()
            .map(|p| p.journal.clone())
            .unwrap_or_else(|| format!("删除资源池 {} ({})", pool_id, random_id()));
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
                    return Err(e.message);
                }
            }
            if let Some(mut monitor) = target.monitor {
                let ids = monitor["poolIds"]
                    .as_array_mut()
                    .ok_or("监测资源池清单无效")?;
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
                    self.journal_note(&journal, "资源池已删除，但监测清单未同步")?;
                    return Err(e.message);
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
        if !has_probe && pending.is_none() {
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
            .ok_or("云端链接不存在，请刷新或找回")?;
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
        self.db
            .links
            .retain(|l| l.domain_id != domain_id || l.slug != slug);
        if let Err(e) = self.persist() {
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
                self.db.links.push(local);
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
        let resources = self.ensure_domain_owned(&domain, &token).await?;
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
        if keys.iter().any(|k| !expected.contains(k)) || keys.len() != expected.len() {
            return Err("云端链接清单与本机不同，请先找回再移除".into());
        }
        let mut saved = Vec::new();
        for key in &keys {
            let value = self
                .cloud
                .read_value(&token, &domain.account_id, &resources.namespace, key)
                .await
                .map_err(problem)?
                .ok_or("云端链接在预检后消失")?;
            saved.push((key.clone(), value));
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
                        self.journal_note(&journal, "链接删除结果不确定")?;
                        return Err(e.message);
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
                return Err(e.message);
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
                return Err(e.message);
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
        self.db.links.retain(|l| l.domain_id != domain_id);
        self.db.domains.retain(|d| d.id != domain_id);
        self.persist()?;
        self.journal_end(&journal)
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
        if self.db.domains.iter().any(|d| d.account_id == account_id) {
            return Err("此账号仍有域名".into());
        }
        let resources = self
            .account(account_id)?
            .resources
            .clone()
            .ok_or("没有可清理资源")?;
        let token = keyring_get(account_id, "token")?;
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
        if keys.iter().any(|k| k != MANIFEST_KEY) {
            return Err("KV 仍有配置记录，停止清理".into());
        }
        let fresh_zones = self.fetch_zones(&token, account_id).await?;
        for zone in &fresh_zones {
            let routes = self
                .cloud
                .get(&token, &format!("zones/{}/workers/routes", zone.id))
                .await
                .map_err(problem)?;
            let items = routes["result"].as_array().ok_or("云端路由列表格式无效")?;
            if items
                .iter()
                .any(|r| r["script"].as_str() == Some(resources.script.as_str()))
            {
                return Err("仍有路由指向此 Worker，停止清理".into());
            }
        }
        let journal = format!("清理账号 {} ({})", account_id, random_id());
        self.journal_start(&journal)?;
        if let Err(e) = self
            .cloud
            .delete(
                &token,
                &format!("accounts/{account_id}/workers/scripts/{}", resources.script),
            )
            .await
        {
            if e.uncertain {
                self.journal_note(&journal, "Worker 删除结果不确定")?;
            } else {
                self.journal_end(&journal)?;
            }
            return Err(e.message);
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
                "{}；Worker 已删除，请按操作记录核对剩余 KV",
                e.message
            ));
        }
        keyring_delete(account_id, "selftest")?;
        if let Some(a) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            a.resources = None;
            a.has_resources = false;
            a.needs_selftest_key = false;
        }
        self.persist()?;
        self.journal_end(&journal)
    }

    async fn apply_rotate(&mut self, account_id: &str) -> Result<(), String> {
        let resources = self
            .account(account_id)?
            .resources
            .clone()
            .ok_or("账号没有 Worker")?;
        let token = keyring_get(account_id, "token")?;
        self.verify_resource_source(&token, account_id, &resources)
            .await?;
        // A successful manifest and binding read are required before a secret write.
        let manifest = self
            .cloud
            .read_value(&token, account_id, &resources.namespace, MANIFEST_KEY)
            .await
            .map_err(problem)?
            .ok_or("云端资源清单缺失")?;
        let parsed: Value =
            serde_json::from_str(&manifest).map_err(|_| "云端资源清单损坏".to_string())?;
        if parsed["accountId"] != account_id
            || parsed["script"] != resources.script
            || parsed["namespace"] != resources.namespace
        {
            return Err("云端资源归属不匹配".into());
        }
        self.cloud
            .script_settings(&token, account_id, &resources.script)
            .await
            .map_err(problem)?;
        let mut key = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let new_hex = hex::encode(key);
        let journal = format!("重置自检密钥 {} ({})", account_id, random_id());
        self.journal_start(&journal)?;
        if let Err(e) = self
            .cloud
            .rotate_secret(&token, account_id, &resources.script, &new_hex)
            .await
        {
            if e.uncertain {
                self.journal_note(&journal, "密钥更新结果不确定")?;
            } else {
                self.journal_end(&journal)?;
            }
            return Err(e.message);
        }
        if let Err(e) = keyring_set(account_id, "selftest", &new_hex) {
            self.journal_note(&journal, "云端已更换密钥，但本机凭据保存失败")?;
            return Err(e);
        }
        if let Some(a) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            a.needs_selftest_key = false;
        }
        self.persist()?;
        self.journal_end(&journal)
    }

    async fn recover_account(&mut self, account_id: &str) -> Result<(), String> {
        if !self.db.pending_monitor_changes.is_empty() || !self.db.pending_pool_changes.is_empty() {
            return Err("请先恢复未完成的云端操作再找回账号".into());
        }
        let token = keyring_get(account_id, "token")?;
        let account = self.account(account_id)?.clone();
        let namespaces = self
            .cloud
            .list_pages(
                &token,
                &format!("accounts/{account_id}/storage/kv/namespaces"),
            )
            .await
            .map_err(problem)?;
        let mut matches = Vec::new();
        for ns in namespaces {
            let Some(id) = ns["id"].as_str() else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let Some(raw) = self
                .cloud
                .read_value(&token, account_id, id, MANIFEST_KEY)
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
            let settings = self
                .cloud
                .script_settings(&token, account_id, script)
                .await
                .map_err(problem)?;
            let verified = settings["result"]["bindings"].as_array().is_some_and(|bs| {
                bs.iter().any(|b| {
                    b["type"] == "kv_namespace" && b["name"] == "LINKS" && b["namespace_id"] == id
                })
            });
            if verified {
                let resources = Resources {
                    script: script.into(),
                    namespace: id.into(),
                };
                if self
                    .verify_resource_source(&token, account_id, &resources)
                    .await
                    .is_ok()
                {
                    matches.push(resources);
                }
            }
        }
        if matches.len() != 1 {
            return Err("未找到唯一且已验证的 Worker/KV 资源组合".into());
        }
        let resources = matches.remove(0);
        let mut recovered_domains = Vec::new();
        for zone in &account.zones {
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
                let Some(pattern) = route["pattern"].as_str() else {
                    continue;
                };
                let Some((host, path)) = pattern.split_once('/') else {
                    continue;
                };
                let Some(prefix) = path.strip_suffix("/*") else {
                    continue;
                };
                if normalize_host(host).as_deref() != Ok(host)
                    || validate_prefix(prefix).is_err()
                    || !(host == zone.name || host.ends_with(&format!(".{}", zone.name)))
                {
                    continue;
                }
                let raw = self
                    .cloud
                    .read_value(
                        &token,
                        account_id,
                        &resources.namespace,
                        &format!("c:{host}"),
                    )
                    .await
                    .map_err(problem)?
                    .ok_or("路由对应的前缀记录缺失")?;
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
                    route_id: value_str(route, "id")?.into(),
                });
            }
        }
        let mut recovered_pools = self.db.pools.clone();
        let pool_keys = self
            .cloud
            .list_keys(&token, account_id, &resources.namespace, "p:")
            .await
            .map_err(problem)?;
        for key in pool_keys {
            let id = key.strip_prefix("p:").ok_or("资源池键无效")?;
            if !pools::valid_id(id) {
                return Err("资源池键无效".into());
            }
            let raw = self
                .cloud
                .read_value(&token, account_id, &resources.namespace, &key)
                .await
                .map_err(problem)?
                .ok_or("资源池键在扫描中消失")?;
            let value: Value = serde_json::from_str(&raw).map_err(|_| "资源池记录格式无效")?;
            if value["version"] != 1 {
                return Err("资源池版本不受支持".into());
            }
            let official: model::Template = serde_json::from_value(value["official"].clone())
                .map_err(|_| "资源池默认模板无效")?;
            let candidates: Vec<model::PoolCandidate> =
                serde_json::from_value(value["candidates"].clone())
                    .map_err(|_| "资源池候选模板无效")?;
            let updated = value["revision"].as_str().ok_or("资源池修订号无效")?;
            let mut pool = Pool {
                id: id.into(),
                name: format!("资源池 {id}"),
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
                    return Err("多个账号的同名资源池配置不一致".into());
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
                    if !recovered_pools
                        .iter()
                        .any(|p| p.id == pool_id && p.account_ids.contains(&account_id.to_string()))
                    {
                        return Err("云端模板链接引用的资源池未归属此账号".into());
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
            let ids = config["poolIds"].as_array().ok_or("监测资源池清单无效")?;
            let actual: std::collections::HashSet<&str> = ids
                .iter()
                .map(|v| v.as_str().ok_or("监测资源池清单无效"))
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
        let key_missing = keyring_get(account_id, "selftest").is_err();
        if let Some(a) = self.db.accounts.iter_mut().find(|a| a.id == account_id) {
            a.resources = Some(resources);
            a.has_resources = true;
            a.needs_selftest_key = key_missing;
            a.monitor_enabled = monitor_enabled;
            a.monitor_endpoint = monitor_endpoint;
            a.needs_monitor_key = monitor_enabled && keyring_get(account_id, "probe").is_err();
        }
        self.persist()
    }

    fn selftest_snapshot(
        &self,
        domain_id: &str,
        slug: &str,
    ) -> Result<Option<SelftestSnapshot>, String> {
        validate_slug(slug)?;
        let domain = self.domain(domain_id)?;
        let link = self
            .db
            .links
            .iter()
            .find(|l| l.domain_id == domain_id && l.slug == slug)
            .ok_or("找不到此链接")?;
        let key_hex = match keyring_get(&domain.account_id, "selftest") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let bytes = hex::decode(key_hex).map_err(|_| "自检密钥格式无效".to_string())?;
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
                .ok_or("找不到资源池")?;
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
                keyring_get(&domain.account_id, "token")?,
            ))
        } else {
            None
        };
        let (cn_url, default_url) = if let Some((pool, code, _, _, _)) = &pool {
            let candidate = pool
                .candidates
                .iter()
                .find(|c| c.enabled)
                .ok_or("资源池无启用候选")?;
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
            key: bytes,
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
            .ok_or("找不到资源池")?;
        let mut accounts = Vec::new();
        for id in &pool.account_ids {
            let account = self.account(id)?;
            if let Some(resources) = &account.resources {
                accounts.push((
                    id.clone(),
                    keyring_get(id, "token")?,
                    resources.namespace.clone(),
                    account.monitor_enabled,
                ));
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
                .ok_or("找不到资源池")?;
            let mut targets = vec![(
                "其他地区官方目标".into(),
                pools::compose(&pool.official, code)?,
            )];
            for c in pool.candidates.iter().filter(|c| c.enabled) {
                targets.push((
                    format!("中国大陆候选 {}", c.id),
                    pools::compose(&model::Template::from(c), code)?,
                ));
            }
            Ok(targets)
        } else {
            Ok(vec![
                ("中国大陆目标".into(), link.cn_url.clone()),
                ("其他地区目标".into(), link.default_url.clone()),
            ])
        }
    }
}

async fn run_pool_health(snapshot: HealthSnapshot) -> Result<Value, String> {
    let mut accounts = Vec::new();
    for id in &snapshot.pool.account_ids {
        let Some((_, token, namespace, monitor_enabled)) = snapshot
            .accounts
            .iter()
            .find(|(account, _, _, _)| account == id)
        else {
            accounts.push(
                json!({"accountId":id,"source":"unconfigured","checkedAt":null,
                "status":"unknown","candidates":[]}),
            );
            continue;
        };
        if !monitor_enabled {
            accounts.push(json!({"accountId":id,"source":"unconfigured","checkedAt":null,
                "status":"unknown","candidates":snapshot.pool.candidates.iter().map(|c|
                    json!({"id":c.id,"status":"unknown","checkedAt":null,"message":"未启用大陆监测"}))
                    .collect::<Vec<_>>() }));
            continue;
        }
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
                    json!({"id":c.id,"status":"unknown","checkedAt":null,"message":"资源池云端版本未确认"}))
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

async fn run_region_test(
    snapshot: &SelftestSnapshot,
    country: &str,
    label: &str,
    expected: Option<&str>,
) -> Result<Check, String> {
    let mut pending = false;
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
        let result = tokio::time::timeout(
            Duration::from_secs(6),
            snapshot.cloud.probe(&snapshot.url, Some(header)),
        )
        .await;
        match result {
            Ok(Ok((302, Some(location)))) if expected == Some(location.as_str()) => {
                return Ok(Check {
                    label: label.into(),
                    ok: true,
                    message: "302 与 Location 均正确".into(),
                })
            }
            Ok(Ok((503, None))) if expected.is_none() => {
                return Ok(Check {
                    label: label.into(),
                    ok: false,
                    message: "边缘确认所有大陆候选暂时不可用（HTTP 503）".into(),
                });
            }
            Ok(Ok((404, _))) | Ok(Err(_)) | Err(_) => pending = true,
            _ => pending = false,
        }
        if attempt < 4 {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
    Ok(Check {
        label: label.into(),
        ok: false,
        message: if pending {
            "边缘配置可能仍在传播或网络暂时不可用".into()
        } else {
            "响应状态或 Location 与预期不符".into()
        },
    })
}

async fn run_selftest(snapshot: SelftestSnapshot) -> Result<Value, String> {
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
                run_region_test(&snapshot, "US", "其他地区", Some(&snapshot.default_url)),
                run_region_test(&snapshot, "CN", "中国大陆", None)
            )
        })
        .await
        .map_err(|_| "自检超时")??;
        return Ok(
            json!({"status":"failed","message":"所有已启用大陆候选目标暂时不可用",
            "checks":[other,cn]}),
        );
    };
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::try_join!(
            run_region_test(&snapshot, "US", "其他地区", Some(&snapshot.default_url)),
            run_region_test(&snapshot, "CN", "中国大陆", Some(&expected_cn))
        )
    })
    .await;
    let checks = match result {
        Ok(Ok((other, cn))) => vec![other, cn],
        Ok(Err(e)) => return Err(e),
        Err(_) => vec![
            Check {
                label: "其他地区".into(),
                ok: false,
                message: "自检超时，请稍后重试".into(),
            },
            Check {
                label: "中国大陆".into(),
                ok: false,
                message: "自检超时，请稍后重试".into(),
            },
        ],
    };
    let status = if checks.iter().all(|c| c.ok) {
        "passed"
    } else if checks
        .iter()
        .any(|c| c.message.contains("传播") || c.message.contains("超时"))
    {
        "pending"
    } else {
        "failed"
    };
    Ok(json!({"status":status,
            "message":match status {"passed"=>"两个地区的跳转均通过自检",
                "pending"=>"边缘配置可能仍在传播","failed"=>"自检失败，请检查路由和目标",
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

#[tauri::command]
async fn dispatch(request: Value, state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let action = field(&request, "action")?.to_string();
    let payload = request.get("payload").cloned().unwrap_or_else(|| json!({}));
    if action == "check_pool_health" {
        let snapshot = {
            let backend = state.0.lock().await;
            backend.health_snapshot(field(&payload, "poolId")?)?
        };
        return run_pool_health(snapshot).await;
    }
    if action == "check_link_targets" {
        let targets = {
            let backend = state.0.lock().await;
            backend.target_snapshot(field(&payload, "domainId")?, field(&payload, "slug")?)?
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut stream = futures_util::stream::iter(targets.iter().cloned().enumerate().map(
            |(index, (label, url))| async move {
                let result =
                    tokio::time::timeout(Duration::from_secs(15), local_check::check(&label, &url))
                        .await
                        .unwrap_or_else(|_| local_check::timeout_result(&label, &url));
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
                entry.unwrap_or_else(|| local_check::timeout_result(&targets[i].0, &targets[i].1))
            })
            .collect();
        return Ok(json!({"checkedAt":now(),"checks":checks}));
    }
    if action == "selftest_link" {
        let snapshot = {
            let backend = state.0.lock().await;
            backend.selftest_snapshot(field(&payload, "domainId")?, field(&payload, "slug")?)?
        };
        return match snapshot {
            Some(snapshot) => run_selftest(snapshot).await,
            None => Ok(json!({"status":"key_missing",
                "message":"本机没有自检密钥，请先单独确认重置密钥","checks":[] })),
        };
    }
    let mut backend = state.0.lock().await;
    backend.dispatch(&action, &payload).await
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
            let backend = Backend::load(dir.join("state.json"), app.handle().clone())
                .map_err(std::io::Error::other)?;
            app.manage(AppState(Mutex::new(backend)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![dispatch])
        .run(tauri::generate_context!())
        .expect("application failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{header_regex, method, path, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    fn ok(result: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({"success":true,"result":result}))
    }
    struct FixtureGuard {
        _dir: tempfile::TempDir,
        _lock: tokio::sync::OwnedMutexGuard<()>,
    }
    async fn fixture() -> (MockServer, Backend, FixtureGuard) {
        static LOCK: std::sync::OnceLock<std::sync::Arc<tokio::sync::Mutex<()>>> =
            std::sync::OnceLock::new();
        let guard = LOCK
            .get_or_init(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        keyring_set("acct1", "token", "test-token-value").unwrap();
        keyring_set("acct1", "selftest", &"a1".repeat(32)).unwrap();
        let account = Account {
            id: "acct1".into(),
            label: "账号 1".into(),
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
                pending_operations: vec![],
            },
            path: dir.path().join("state.json"),
            plans: vec![],
            cloud: Cloud::for_test(&format!("{}/client/v4/", server.uri())),
            app: None,
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
    async fn mount_resource(server: &MockServer, source: &str) {
        mount_resource_with_probe(server, source, false).await;
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
    fn domain() -> Domain {
        Domain {
            id: "domain1".into(),
            account_id: "acct1".into(),
            zone_id: "zone1".into(),
            host: "example.com".into(),
            prefix: "go".into(),
            route_id: "route1".into(),
        }
    }
    async fn mount_owned_domain(server: &MockServer) {
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
        assert_eq!(permissions.as_array().unwrap().len(), 6);
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
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/workers/routes"))
            .respond_with(ok(json!([])))
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
            .apply_domain("acct1", "zone1", "example.com", "go")
            .await
            .unwrap_err();
        assert!(error.contains("已有此主机名"));
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
                "result_info":{"count":1}
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

    fn sample_pool() -> Pool {
        Pool {
            id: "pool1".into(),
            name: "测试资源池".into(),
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
            key: vec![0xa1; 32],
            pool: Some((
                pool,
                "abc".into(),
                "acct1".into(),
                "ns1".into(),
                "test-token-value".into(),
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
}

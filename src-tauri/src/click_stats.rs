use super::*;
use cloud::AnalyticsError;
use serde::Serialize;

const MAX_GROUPS: usize = 11;
const STATS_CENTER_PAGE_SIZE: usize = 25;
const MAX_STATS_QUERY_BYTES: usize = 32 * 1024;
const MAX_SAFE_COUNT: u64 = 9_007_199_254_740_991;

pub(super) fn dataset_name(namespace: &str) -> Result<String, String> {
    if namespace.len() != 32
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("账户统计资源标识无效，尚未启用统计".into());
    }
    Ok(format!("slg_clicks_{namespace}"))
}

pub(super) fn binding(namespace: &str) -> Result<Value, String> {
    Ok(json!({"name":"CLICK_EVENTS","type":"analytics_engine","dataset":dataset_name(namespace)?}))
}

pub(super) fn valid_binding(value: &Value, namespace: &str) -> bool {
    binding(namespace).is_ok_and(|expected| value == &expected)
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Totals {
    total: u64,
    likely_human: u64,
    likely_bot: u64,
    unknown: u64,
    previews: u64,
    prefetches: u64,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Ready,
    Disabled,
    NoData,
    PermissionDenied,
    Unavailable,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsResponse<'a> {
    status: Status,
    message: &'a str,
    domain_id: &'a str,
    slug: &'a str,
    days: u64,
    queried_at: String,
    estimated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    totals: Option<Totals>,
}

#[derive(Clone)]
struct ScopeDomain {
    id: String,
    host: String,
    prefix: String,
}

#[derive(Clone)]
struct PageLink {
    domain_id: String,
    host: String,
    prefix: String,
    slug: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsCenterRow {
    domain_id: String,
    slug: String,
    totals: Totals,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsCenterResponse<'a> {
    status: Status,
    message: &'a str,
    account_id: &'a str,
    domain_id: Option<&'a str>,
    days: u64,
    page: u64,
    page_size: usize,
    total_links: usize,
    queried_at: String,
    estimated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    totals: Option<Totals>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<Vec<StatsCenterRow>>,
}

fn response(
    status: Status,
    message: &str,
    domain_id: &str,
    slug: &str,
    days: u64,
    totals: Option<Totals>,
) -> Result<Value, String> {
    serde_json::to_value(StatsResponse {
        status,
        message,
        domain_id,
        slug,
        days,
        queried_at: now(),
        estimated: true,
        totals,
    })
    .map_err(|_| "无法读取点击统计".into())
}

#[allow(clippy::too_many_arguments)]
fn center_response(
    status: Status,
    message: &str,
    account_id: &str,
    domain_id: Option<&str>,
    days: u64,
    page: u64,
    total_links: usize,
    totals: Option<Totals>,
    rows: Option<Vec<StatsCenterRow>>,
) -> Result<Value, String> {
    serde_json::to_value(StatsCenterResponse {
        status,
        message,
        account_id,
        domain_id,
        days,
        page,
        page_size: STATS_CENTER_PAGE_SIZE,
        total_links,
        queried_at: now(),
        estimated: true,
        totals,
        rows,
    })
    .map_err(|_| "无法读取统计中心".into())
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

fn sql(dataset: &str, domain: &Domain, slug: &str, days: u64) -> String {
    // Values originate in validated owned local records, not SQL supplied by a
    // caller. Escaping remains explicit even though their alphabets exclude '.
    format!("SELECT blob5 AS classification, blob6 AS traffic_kind, blob7 AS reason, SUM(_sample_interval) AS count \
        FROM {dataset} WHERE blob1 = 'v1' AND blob2 = {} AND blob3 = {} AND blob4 = {} \
        AND timestamp > NOW() - INTERVAL '{days}' DAY AND timestamp <= NOW() \
        GROUP BY blob5, blob6, blob7 LIMIT {} FORMAT JSON",
        literal(&domain.host), literal(&domain.prefix), literal(slug), MAX_GROUPS + 1)
}

fn bounded_sql(query: String) -> Result<String, String> {
    if query.len() > MAX_STATS_QUERY_BYTES {
        Err("统计范围过大，无法安全建立查询；请改为选择单个域名".into())
    } else {
        Ok(query)
    }
}

fn summary_sql(dataset: &str, domains: &[ScopeDomain], days: u64) -> Result<String, String> {
    let allowlist = domains
        .iter()
        .map(|domain| {
            format!(
                "(blob2 = {} AND blob3 = {})",
                literal(&domain.host),
                literal(&domain.prefix)
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    bounded_sql(format!(
        "SELECT blob5 AS classification, blob6 AS traffic_kind, blob7 AS reason, SUM(_sample_interval) AS count \
        FROM {dataset} WHERE blob1 = 'v1' AND ({allowlist}) \
        AND timestamp > NOW() - INTERVAL '{days}' DAY AND timestamp <= NOW() \
        GROUP BY blob5, blob6, blob7 LIMIT {} FORMAT JSON",
        MAX_GROUPS + 1
    ))
}

fn page_sql(dataset: &str, links: &[PageLink], days: u64) -> Result<String, String> {
    let allowlist = links
        .iter()
        .map(|link| {
            format!(
                "(blob2 = {} AND blob3 = {} AND blob4 = {})",
                literal(&link.host),
                literal(&link.prefix),
                literal(&link.slug)
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    bounded_sql(format!(
        "SELECT blob2 AS host, blob3 AS prefix, blob4 AS canonical_slug, \
        blob5 AS classification, blob6 AS traffic_kind, blob7 AS reason, \
        SUM(_sample_interval) AS count FROM {dataset} \
        WHERE blob1 = 'v1' AND ({allowlist}) \
        AND timestamp > NOW() - INTERVAL '{days}' DAY AND timestamp <= NOW() \
        GROUP BY blob2, blob3, blob4, blob5, blob6, blob7 LIMIT {} FORMAT JSON",
        links.len() * MAX_GROUPS + 1
    ))
}

fn valid_group(classification: &str, kind: &str, reason: &str) -> bool {
    matches!(
        (classification, kind, reason),
        ("likely_bot", "preview", "ua_preview")
            | ("unknown", "prefetch", "prefetch_header")
            | (
                "likely_bot",
                "click",
                "cf_verified_bot"
                    | "cf_verified_bot_category"
                    | "cf_score_low"
                    | "ua_automation"
                    | "ua_bot"
            )
            | (
                "likely_human",
                "click",
                "cf_score_high" | "browser_navigation"
            )
            | (
                "unknown",
                "click",
                "missing_user_agent" | "insufficient_signals"
            )
    )
}

fn weighted_count(value: &Value) -> Result<u64, AnalyticsError> {
    let count = value
        .as_u64()
        .or_else(|| {
            value.as_str().and_then(|s| {
                if s.is_empty() || s.len() > 16 || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                s.parse().ok()
            })
        })
        .ok_or(AnalyticsError::Unavailable)?;
    if count > MAX_SAFE_COUNT {
        return Err(AnalyticsError::Unavailable);
    }
    Ok(count)
}

fn add_count(total: &mut u64, count: u64) -> Result<(), AnalyticsError> {
    *total = total
        .checked_add(count)
        .filter(|n| *n <= MAX_SAFE_COUNT)
        .ok_or(AnalyticsError::Unavailable)?;
    Ok(())
}

fn aggregate(value: &Value) -> Result<Option<Totals>, AnalyticsError> {
    let rows = value["data"]
        .as_array()
        .ok_or(AnalyticsError::Unavailable)?;
    // Cloudflare reports pre-aggregation input events in
    // `rows_before_limit_at_least`, so it can legitimately exceed the number
    // of grouped result rows. The LIMIT + 1 sentinel and the exact `rows`
    // count below bound the returned groups instead.
    if rows.len() > MAX_GROUPS || value["rows"].as_u64() != Some(rows.len() as u64) {
        return Err(AnalyticsError::Unavailable);
    }
    if rows.is_empty() {
        return Ok(None);
    }
    let mut totals = Totals::default();
    let mut groups = HashSet::new();
    let mut all_events = 0;
    for row in rows {
        let object = row.as_object().ok_or(AnalyticsError::Unavailable)?;
        if object.len() != 4
            || object.keys().any(|k| {
                !["classification", "traffic_kind", "reason", "count"].contains(&k.as_str())
            })
        {
            return Err(AnalyticsError::Unavailable);
        }
        let class = row["classification"]
            .as_str()
            .ok_or(AnalyticsError::Unavailable)?;
        let kind = row["traffic_kind"]
            .as_str()
            .ok_or(AnalyticsError::Unavailable)?;
        let reason = row["reason"].as_str().ok_or(AnalyticsError::Unavailable)?;
        if !valid_group(class, kind, reason) || !groups.insert((class, kind, reason)) {
            return Err(AnalyticsError::Unavailable);
        }
        let count = weighted_count(&row["count"])?;
        add_count(&mut all_events, count)?;
        match kind {
            "preview" => add_count(&mut totals.previews, count)?,
            "prefetch" => add_count(&mut totals.prefetches, count)?,
            _ => {
                add_count(&mut totals.total, count)?;
                match class {
                    "likely_human" => add_count(&mut totals.likely_human, count)?,
                    "likely_bot" => add_count(&mut totals.likely_bot, count)?,
                    _ => add_count(&mut totals.unknown, count)?,
                }
            }
        }
    }
    Ok(Some(totals))
}

fn aggregate_page(
    value: &Value,
    links: &[PageLink],
) -> Result<Vec<StatsCenterRow>, AnalyticsError> {
    if links.is_empty() || links.len() > STATS_CENTER_PAGE_SIZE {
        return Err(AnalyticsError::Unavailable);
    }
    let rows = value["data"]
        .as_array()
        .ok_or(AnalyticsError::Unavailable)?;
    let max_groups = links
        .len()
        .checked_mul(MAX_GROUPS)
        .ok_or(AnalyticsError::Unavailable)?;
    // `rows_before_limit_at_least` counts input events before aggregation, not
    // returned identity/group rows. Keep the result bounded with LIMIT + 1,
    // the local group ceiling and the exact `rows` count.
    if rows.len() > max_groups || value["rows"].as_u64() != Some(rows.len() as u64) {
        return Err(AnalyticsError::Unavailable);
    }

    let mut totals = vec![Totals::default(); links.len()];
    let mut all_events = vec![0_u64; links.len()];
    let mut groups = HashSet::new();
    for row in rows {
        let object = row.as_object().ok_or(AnalyticsError::Unavailable)?;
        if object.len() != 7
            || object.keys().any(|key| {
                ![
                    "host",
                    "prefix",
                    "canonical_slug",
                    "classification",
                    "traffic_kind",
                    "reason",
                    "count",
                ]
                .contains(&key.as_str())
            })
        {
            return Err(AnalyticsError::Unavailable);
        }
        let host = row["host"].as_str().ok_or(AnalyticsError::Unavailable)?;
        let prefix = row["prefix"].as_str().ok_or(AnalyticsError::Unavailable)?;
        let slug = row["canonical_slug"]
            .as_str()
            .ok_or(AnalyticsError::Unavailable)?;
        let classification = row["classification"]
            .as_str()
            .ok_or(AnalyticsError::Unavailable)?;
        let kind = row["traffic_kind"]
            .as_str()
            .ok_or(AnalyticsError::Unavailable)?;
        let reason = row["reason"].as_str().ok_or(AnalyticsError::Unavailable)?;
        let index = links
            .iter()
            .position(|link| link.host == host && link.prefix == prefix && link.slug == slug)
            .ok_or(AnalyticsError::Unavailable)?;
        if !valid_group(classification, kind, reason)
            || !groups.insert((index, classification, kind, reason))
        {
            return Err(AnalyticsError::Unavailable);
        }
        let count = weighted_count(&row["count"])?;
        add_count(&mut all_events[index], count)?;
        match kind {
            "preview" => add_count(&mut totals[index].previews, count)?,
            "prefetch" => add_count(&mut totals[index].prefetches, count)?,
            _ => {
                add_count(&mut totals[index].total, count)?;
                match classification {
                    "likely_human" => add_count(&mut totals[index].likely_human, count)?,
                    "likely_bot" => add_count(&mut totals[index].likely_bot, count)?,
                    _ => add_count(&mut totals[index].unknown, count)?,
                }
            }
        }
    }

    Ok(links
        .iter()
        .zip(totals)
        .map(|(link, totals)| StatsCenterRow {
            domain_id: link.domain_id.clone(),
            slug: link.slug.clone(),
            totals,
        })
        .collect())
}

fn zero_rows(links: &[PageLink]) -> Vec<StatsCenterRow> {
    links
        .iter()
        .map(|link| StatsCenterRow {
            domain_id: link.domain_id.clone(),
            slug: link.slug.clone(),
            totals: Totals::default(),
        })
        .collect()
}

impl Backend {
    pub(super) async fn get_stats_center(&self, payload: &Value) -> Result<Value, String> {
        let account_id = field(payload, "accountId")?;
        if !valid_id(account_id) {
            return Err("账号标识无效".into());
        }
        let accounts: Vec<_> = self
            .db
            .accounts
            .iter()
            .filter(|account| account.id == account_id)
            .collect();
        let [account] = accounts.as_slice() else {
            return Err(if accounts.is_empty() {
                "找不到此账号".into()
            } else {
                "本机账号记录重复，无法安全查询统计".into()
            });
        };
        let domain_id = match payload.get("domainId") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if valid_id(value) => Some(value.as_str()),
            _ => return Err("指定域名标识无效".into()),
        };
        let days = payload["days"]
            .as_u64()
            .filter(|days| [1, 7, 30].contains(days))
            .ok_or("统计范围仅支持 1、7 或 30 天")?;
        let page = payload["page"]
            .as_u64()
            .filter(|page| *page >= 1)
            .ok_or("页码必须是从 1 开始的整数")?;
        if payload["pageSize"].as_u64() != Some(STATS_CENTER_PAGE_SIZE as u64) {
            return Err("统计中心每页固定显示 25 条链接".into());
        }
        let offset = page
            .checked_sub(1)
            .and_then(|page| page.checked_mul(STATS_CENTER_PAGE_SIZE as u64))
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or("页码超出可查询范围")?;

        let selected_domains: Vec<&Domain> = if let Some(id) = domain_id {
            let matches: Vec<_> = self
                .db
                .domains
                .iter()
                .filter(|domain| domain.id == id)
                .collect();
            let [domain] = matches.as_slice() else {
                return Err(if matches.is_empty() {
                    "找不到此域名".into()
                } else {
                    "本机域名记录重复，无法安全查询统计".into()
                });
            };
            if domain.account_id != account_id {
                return Err("此域名不属于所选账号".into());
            }
            vec![*domain]
        } else {
            self.db
                .domains
                .iter()
                .filter(|domain| domain.account_id == account_id)
                .collect()
        };

        let mut scope = Vec::with_capacity(selected_domains.len());
        let mut domain_ids = HashSet::new();
        let mut remote_identities = HashSet::new();
        for domain in selected_domains {
            if !valid_id(&domain.id)
                || self
                    .db
                    .domains
                    .iter()
                    .filter(|candidate| candidate.id == domain.id)
                    .count()
                    != 1
            {
                return Err("本机域名记录无效".into());
            }
            validate_prefix(&domain.prefix)?;
            if normalize_host(&domain.host).as_deref() != Ok(domain.host.as_str())
                || !remote_identities.insert((domain.host.clone(), domain.prefix.clone()))
                || !domain_ids.insert(domain.id.clone())
            {
                return Err("本机域名记录无效或重复".into());
            }
            scope.push(ScopeDomain {
                id: domain.id.clone(),
                host: domain.host.clone(),
                prefix: domain.prefix.clone(),
            });
        }
        scope.sort_by(|left, right| left.id.cmp(&right.id));

        if scope.is_empty() {
            return center_response(
                Status::NoData,
                "当前账户尚无本机已导入域名，未读取云端统计",
                account_id,
                domain_id,
                days,
                page,
                0,
                None,
                Some(Vec::new()),
            );
        }

        let mut links = Vec::new();
        let mut link_identities = HashSet::new();
        for link in self
            .db
            .links
            .iter()
            .filter(|link| domain_ids.contains(&link.domain_id))
        {
            validate_slug(&link.slug)?;
            if !link_identities.insert((link.domain_id.clone(), link.slug.clone())) {
                return Err("本机短链接记录重复，无法安全查询统计".into());
            }
            let domain = scope
                .iter()
                .find(|domain| domain.id == link.domain_id)
                .ok_or("本机短链接归属无效")?;
            links.push(PageLink {
                domain_id: link.domain_id.clone(),
                host: domain.host.clone(),
                prefix: domain.prefix.clone(),
                slug: link.slug.clone(),
            });
        }
        links.sort_by(|left, right| {
            (&left.domain_id, &left.slug).cmp(&(&right.domain_id, &right.slug))
        });
        let total_links = links.len();
        if total_links == 0 {
            return center_response(
                Status::NoData,
                "当前账户在所选范围尚无本机短链接，未读取云端历史统计",
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                Some(Vec::new()),
            );
        }
        let page_links = links
            .get(
                offset
                    ..offset
                        .saturating_add(STATS_CENTER_PAGE_SIZE)
                        .min(total_links),
            )
            .unwrap_or(&[])
            .to_vec();

        let Some(resources) = account.resources.as_ref() else {
            return center_response(
                Status::Disabled,
                "此账户尚未启用点击统计",
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                None,
            );
        };
        let dataset = dataset_name(&resources.namespace)?;
        let summary_query = summary_sql(&dataset, &scope, days)?;
        let page_query = if page_links.is_empty() {
            None
        } else {
            Some(page_sql(&dataset, &page_links, days)?)
        };
        if self.require_no_worker_upgrade(account_id).is_err() {
            return center_response(
                Status::Unavailable,
                "请先核对该账户待处理的 Worker 变更，再查询统计",
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                None,
            );
        }

        // Enumeration, canonical identity, ownership, pagination and both SQL
        // bounds are resolved before the selected account credential is read.
        self.require_credentials(account_id)?;
        let token = Zeroizing::new(keyring_get(account_id, "token")?);
        if self
            .verify_resource_source(&token, account_id, resources)
            .await
            .is_err()
        {
            return center_response(
                Status::Unavailable,
                "尚未确认此账户的转发程序归属与配置，暂时不能查询统计",
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                None,
            );
        }
        let settings = match self
            .cloud
            .script_settings(&token, account_id, &resources.script)
            .await
        {
            Ok(value) => value,
            Err(_) => {
                return center_response(
                    Status::Unavailable,
                    AnalyticsError::Unavailable.message(),
                    account_id,
                    domain_id,
                    days,
                    page,
                    total_links,
                    None,
                    None,
                )
            }
        };
        let Some(bindings) = settings["result"]["bindings"].as_array() else {
            return center_response(
                Status::Unavailable,
                AnalyticsError::Unavailable.message(),
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                None,
            );
        };
        let analytics: Vec<_> = bindings
            .iter()
            .filter(|binding| binding["name"] == "CLICK_EVENTS")
            .collect();
        if analytics.is_empty() {
            return center_response(
                Status::Disabled,
                "此账户尚未启用点击统计；启用后才会开始采集",
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                None,
            );
        }
        if analytics.len() != 1 || !valid_binding(analytics[0], &resources.namespace) {
            return center_response(
                Status::Unavailable,
                "统计绑定与此账户的资源不一致，请核对配置",
                account_id,
                domain_id,
                days,
                page,
                total_links,
                None,
                None,
            );
        }

        let summary = self
            .cloud
            .analytics_sql(&token, account_id, &summary_query)
            .await
            .and_then(|value| aggregate(&value));
        let totals = match summary {
            Ok(Some(totals)) => totals,
            Ok(None) => {
                return center_response(
                    Status::NoData,
                    "所选域名范围在该时段未返回任何事件；本页按零展示，但不能据此确认没有访问",
                    account_id,
                    domain_id,
                    days,
                    page,
                    total_links,
                    None,
                    Some(zero_rows(&page_links)),
                )
            }
            Err(error) => {
                return center_response(
                    if error == AnalyticsError::PermissionDenied {
                        Status::PermissionDenied
                    } else {
                        Status::Unavailable
                    },
                    error.message(),
                    account_id,
                    domain_id,
                    days,
                    page,
                    total_links,
                    None,
                    None,
                )
            }
        };

        let rows = if let Some(query) = page_query {
            match self
                .cloud
                .analytics_sql_center_page(&token, account_id, &query)
                .await
                .and_then(|value| aggregate_page(&value, &page_links))
            {
                Ok(rows) => rows,
                Err(error) => {
                    return center_response(
                        if error == AnalyticsError::PermissionDenied {
                            Status::PermissionDenied
                        } else {
                            Status::Unavailable
                        },
                        error.message(),
                        account_id,
                        domain_id,
                        days,
                        page,
                        total_links,
                        None,
                        None,
                    )
                }
            }
        } else {
            Vec::new()
        };
        center_response(
            Status::Ready,
            "汇总覆盖所选域名范围内的全部统计事件，包括已删除链接的历史事件；列表仅显示本页当前本机链接。次数按采样权重估计，可能延迟",
            account_id,
            domain_id,
            days,
            page,
            total_links,
            Some(totals),
            Some(rows),
        )
    }

    pub(super) async fn get_link_stats(&self, payload: &Value) -> Result<Value, String> {
        let domain_id = field(payload, "domainId")?;
        let slug = field(payload, "slug")?;
        let days = payload["days"]
            .as_u64()
            .filter(|d| [1, 7, 30].contains(d))
            .ok_or("统计范围仅支持 1、7 或 30 天")?;
        validate_slug(slug)?;
        let domain = self.domain(domain_id)?;
        validate_prefix(&domain.prefix)?;
        if normalize_host(&domain.host).as_deref() != Ok(domain.host.as_str()) {
            return Err("本机域名记录无效".into());
        }
        if !self
            .db
            .links
            .iter()
            .any(|l| l.domain_id == domain_id && l.slug == slug)
        {
            return Err("找不到此链接".into());
        }
        let account = self.account(&domain.account_id)?;
        let reply =
            |status, message, totals| response(status, message, domain_id, slug, days, totals);
        let Some(resources) = account.resources.as_ref() else {
            return reply(Status::Disabled, "此账户尚未启用点击统计", None);
        };
        let dataset = dataset_name(&resources.namespace)?;
        if self.require_no_worker_upgrade(&account.id).is_err() {
            return reply(
                Status::Unavailable,
                "请先核对该账户待处理的 Worker 变更，再查询统计",
                None,
            );
        }
        // All input/local ownership checks precede access to the selected token.
        self.require_credentials(&account.id)?;
        let token = Zeroizing::new(keyring_get(&account.id, "token")?);
        if self
            .verify_resource_source(&token, &account.id, resources)
            .await
            .is_err()
        {
            return reply(
                Status::Unavailable,
                "尚未确认此账户的转发程序归属与配置，暂时不能查询统计",
                None,
            );
        }
        let settings = match self
            .cloud
            .script_settings(&token, &account.id, &resources.script)
            .await
        {
            Ok(v) => v,
            Err(_) => {
                return reply(
                    Status::Unavailable,
                    AnalyticsError::Unavailable.message(),
                    None,
                )
            }
        };
        let Some(bindings) = settings["result"]["bindings"].as_array() else {
            return reply(
                Status::Unavailable,
                AnalyticsError::Unavailable.message(),
                None,
            );
        };
        let analytics: Vec<_> = bindings
            .iter()
            .filter(|v| v["name"] == "CLICK_EVENTS")
            .collect();
        if analytics.is_empty() {
            return reply(
                Status::Disabled,
                "此账户尚未启用点击统计；启用后才会开始采集",
                None,
            );
        }
        if analytics.len() != 1 || !valid_binding(analytics[0], &resources.namespace) {
            return reply(
                Status::Unavailable,
                "统计绑定与此账户的资源不一致，请核对配置",
                None,
            );
        }
        let query = sql(&dataset, domain, slug, days);
        let result = self
            .cloud
            .analytics_sql(&token, &account.id, &query)
            .await
            .and_then(|value| aggregate(&value));
        match result {
            Ok(Some(totals)) => reply(
                Status::Ready,
                "按采样权重估计的请求次数，可能延迟；疑似人工不等于确认真人，也不是独立访客数",
                Some(totals),
            ),
            Ok(None) => reply(
                Status::NoData,
                "所选时间范围暂无可用事件；可能尚未产生或尚未完成处理，不能据此确认零次访问",
                None,
            ),
            Err(error) => reply(
                if error == AnalyticsError::PermissionDenied {
                    Status::PermissionDenied
                } else {
                    Status::Unavailable
                },
                error.message(),
                None,
            ),
        }
    }
}

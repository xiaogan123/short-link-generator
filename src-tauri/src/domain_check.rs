use crate::model::{DomainCheck, DomainCheckLevel};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecordFingerprint {
    pub id: String,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub ttl: Option<Value>,
    pub priority: Option<Value>,
    pub data: Option<Value>,
    pub settings: Option<Value>,
    pub proxied: bool,
    pub proxiable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsSnapshot {
    // Missing means that the host has no web address record. Keep any safe
    // non-address records in the snapshot so observed mail or validation
    // changes block the reviewed write.
    Missing(Vec<DnsRecordFingerprint>),
    EnableProxy(Vec<DnsRecordFingerprint>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsAssessment {
    Ready,
    Missing,
    DnsOnly(Vec<DnsRecordFingerprint>),
    Unsupported(String),
    Conflict(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsClassification {
    Ready,
    Missing,
    NeedsProxy,
    Unsupported(String),
    Conflict(String),
}

#[derive(Clone, Copy)]
struct DnsRecordState<'a> {
    record_type: &'a str,
    proxied: bool,
    proxiable: bool,
}

pub fn dns_fingerprint(items: &[Value], host: &str) -> Result<Vec<DnsRecordFingerprint>, String> {
    let mut records = Vec::new();
    for item in items
        .iter()
        .filter(|item| item["name"].as_str() == Some(host))
    {
        let id = item["id"].as_str().ok_or("DNS 记录缺少标识")?;
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("DNS 记录标识无效".into());
        }
        let record_type = item["type"].as_str().ok_or("DNS 记录缺少类型")?;
        let content = item["content"].as_str().ok_or("DNS 记录缺少内容")?;
        let proxied = item["proxied"].as_bool().unwrap_or(false);
        let proxiable = item["proxiable"]
            .as_bool()
            .unwrap_or(matches!(record_type, "A" | "AAAA" | "CNAME"));
        records.push(DnsRecordFingerprint {
            id: id.to_owned(),
            name: host.to_owned(),
            record_type: record_type.to_owned(),
            content: content.to_owned(),
            // Snapshot only fields that configure the DNS answer. Provider
            // timestamps and other response metadata are intentionally excluded.
            ttl: optional_config(item, "ttl"),
            priority: optional_config(item, "priority"),
            data: optional_config(item, "data"),
            settings: optional_config(item, "settings"),
            proxied,
            proxiable,
        });
    }
    records.sort_by(|a, b| {
        (&a.record_type, &a.id, &a.content).cmp(&(&b.record_type, &b.id, &b.content))
    });
    Ok(records)
}

fn optional_config(item: &Value, key: &str) -> Option<Value> {
    item.get(key).filter(|value| !value.is_null()).cloned()
}

pub fn classify_dns_records(items: &[Value], host: &str) -> Result<DnsClassification, String> {
    let records = items
        .iter()
        .filter(|item| item["name"].as_str() == Some(host))
        .map(|item| {
            let record_type = item["type"].as_str().ok_or("DNS 记录缺少类型")?;
            Ok(DnsRecordState {
                record_type,
                proxied: item["proxied"].as_bool().unwrap_or(false),
                proxiable: item["proxiable"]
                    .as_bool()
                    .unwrap_or(matches!(record_type, "A" | "AAAA" | "CNAME")),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(classify_dns_states(&records))
}

fn classify_dns_states(records: &[DnsRecordState<'_>]) -> DnsClassification {
    if records.is_empty() {
        return DnsClassification::Missing;
    }
    if records.iter().any(|record| record.record_type == "NS") {
        return DnsClassification::Conflict("该主机名存在 NS 委派，不能由应用接管 DNS".into());
    }
    if records.iter().any(|record| {
        !matches!(
            record.record_type,
            "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "CAA"
        )
    }) {
        return DnsClassification::Unsupported(
            "这个域名还有其他类型的 DNS 设置，应用无法确认能否安全共存；请先人工检查".into(),
        );
    }
    let address_records: Vec<_> = records
        .iter()
        .filter(|record| matches!(record.record_type, "A" | "AAAA" | "CNAME"))
        .collect();
    if address_records.is_empty() {
        return DnsClassification::Missing;
    }
    let has_cname = address_records
        .iter()
        .any(|record| record.record_type == "CNAME");
    if has_cname && address_records.len() != 1 {
        return DnsClassification::Conflict("同一主机名的 CNAME 与其他地址记录冲突".into());
    }
    if address_records.iter().any(|record| !record.proxiable) {
        return DnsClassification::Unsupported(
            "云端标记至少一条地址记录不支持代理，应用不会强行修改".into(),
        );
    }
    if address_records.iter().all(|record| record.proxied) {
        DnsClassification::Ready
    } else {
        DnsClassification::NeedsProxy
    }
}

pub fn assess_dns(records: &[DnsRecordFingerprint]) -> DnsAssessment {
    let states: Vec<_> = records
        .iter()
        .map(|record| DnsRecordState {
            record_type: &record.record_type,
            proxied: record.proxied,
            proxiable: record.proxiable,
        })
        .collect();
    match classify_dns_states(&states) {
        DnsClassification::Ready => DnsAssessment::Ready,
        DnsClassification::Missing => DnsAssessment::Missing,
        DnsClassification::NeedsProxy => DnsAssessment::DnsOnly(
            records
                .iter()
                .filter(|record| {
                    matches!(record.record_type.as_str(), "A" | "AAAA" | "CNAME") && !record.proxied
                })
                .cloned()
                .collect(),
        ),
        DnsClassification::Unsupported(message) => DnsAssessment::Unsupported(message),
        DnsClassification::Conflict(message) => DnsAssessment::Conflict(message),
    }
}

pub fn placeholder_conflict(all_records: &[Value], host: &str, zone_name: &str) -> Option<String> {
    let host = host.trim_end_matches('.');
    let zone_name = zone_name.trim_end_matches('.');
    for item in all_records {
        let Some(name) = item["name"].as_str().map(|name| name.trim_end_matches('.')) else {
            return Some("DNS 区域记录格式无效，无法安全创建占位记录".into());
        };
        let Some(record_type) = item["type"].as_str() else {
            return Some("DNS 区域记录格式无效，无法安全创建占位记录".into());
        };
        if record_type == "NS"
            && (name == host || (name != zone_name && host.ends_with(&format!(".{name}"))))
        {
            return Some(format!("{name} 存在 NS 子域委派，应用不会在其下创建记录"));
        }
        if name == host {
            if matches!(record_type, "MX" | "TXT" | "CAA") {
                continue;
            }
            return Some(format!(
                "完整区域清单显示该主机名已有 {record_type} 记录，不能创建占位记录"
            ));
        }
        if let Some(suffix) = name.strip_prefix("*.") {
            if host.ends_with(&format!(".{suffix}")) {
                return Some(format!(
                    "{name} 是覆盖该主机名的通配符记录，需先人工确认现有业务"
                ));
            }
        }
    }
    None
}

// Enabling the HTTP proxy also changes address answers used by non-HTTP
// services. Inspect reverse CNAME dependencies across the entire zone before
// allowing an MX/SRV target to become proxied.
pub fn proxy_conflict(all_records: &[Value], host: &str, zone_name: &str) -> Option<String> {
    let normalize = |name: &str| name.trim_end_matches('.').to_ascii_lowercase();
    let host = normalize(host);
    let zone_name = normalize(zone_name);
    let mut aliases = std::collections::HashSet::from([host.clone()]);
    let mut cnames = Vec::new();
    let mut services = Vec::new();
    for item in all_records {
        let Some(name) = item["name"].as_str().map(normalize) else {
            return Some("DNS 区域记录格式无效，无法安全开启代理".into());
        };
        let Some(kind) = item["type"].as_str() else {
            return Some("DNS 区域记录格式无效，无法安全开启代理".into());
        };
        if kind == "NS"
            && (name == host || (name != zone_name && host.ends_with(&format!(".{name}"))))
        {
            return Some(format!("{name} 存在 NS 子域委派，不能安全开启代理"));
        }
        if matches!(kind, "CNAME" | "MX" | "SRV") {
            let target = if kind == "SRV" {
                item["data"]["target"].as_str().or_else(|| {
                    item["content"]
                        .as_str()
                        .and_then(|value| value.split_whitespace().last())
                })
            } else {
                item["content"].as_str()
            };
            let Some(target) = target.filter(|target| !target.is_empty()) else {
                return Some(format!("{name} 的 {kind} 目标无法核实，停止开启代理"));
            };
            let target = normalize(target);
            if kind == "CNAME" {
                cnames.push((name, target));
            } else {
                services.push((name, kind, target));
            }
        }
    }
    loop {
        let before = aliases.len();
        for (name, target) in &cnames {
            if aliases.contains(target) {
                aliases.insert(name.clone());
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    services.into_iter().find_map(|(name, kind, target)| {
        aliases.contains(&target).then(|| format!(
            "{name} 的 {kind} 记录直接或通过 CNAME 使用 {host}；开启代理可能中断邮件或其他服务，请使用独立短链接主机名"
        ))
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRiskSnapshot {
    pub root: ProbeRisk,
    pub child: ProbeRisk,
    pub probe_segment: String,
}

impl PathRiskSnapshot {
    pub fn requires_takeover_confirmation(&self) -> bool {
        self.root.is_warning() || self.child.is_warning()
    }

    pub fn can_replace(&self, previous: &Self) -> bool {
        self.probe_segment == previous.probe_segment
            && self.root.can_replace(&previous.root)
            && self.child.can_replace(&previous.child)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeRisk {
    Missing,
    Content { status: u16 },
    Redirect { status: u16, target: RedirectTarget },
    OriginFailure { status: u16 },
    Blocked { status: u16 },
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedirectTarget {
    Missing,
    Valid(String),
    Invalid(String),
}

impl ProbeRisk {
    fn is_warning(&self) -> bool {
        matches!(
            self,
            Self::Content { .. } | Self::Redirect { .. } | Self::OriginFailure { .. }
        )
    }

    fn can_replace(&self, previous: &Self) -> bool {
        match (self, previous) {
            (Self::Missing, Self::Missing) => true,
            // A warning disappearing into a 404 reduces risk and does not invalidate consent.
            (Self::Missing, previous) if previous.is_warning() => true,
            _ => self == previous,
        }
    }
}

pub fn hard_check(label: impl Into<String>, ok: bool, message: impl Into<String>) -> DomainCheck {
    DomainCheck {
        label: label.into(),
        ok,
        message: message.into(),
        level: if ok {
            DomainCheckLevel::Pass
        } else {
            DomainCheckLevel::Error
        },
    }
}

pub fn classify_probe(
    label: &str,
    request_url: &str,
    random_segment: Option<&str>,
    result: Result<(u16, Option<String>), String>,
) -> (DomainCheck, ProbeRisk) {
    let (status, location) = match result {
        Ok(value) => value,
        Err(message) => {
            return (
                DomainCheck {
                    label: label.into(),
                    ok: false,
                    message: format!("暂时无法检查此路径：{message}"),
                    level: DomainCheckLevel::Error,
                },
                ProbeRisk::Unreachable,
            )
        }
    };
    if status == 404 {
        return (
            DomainCheck {
                label: label.into(),
                ok: true,
                message: "没有发现内容（HTTP 404），可使用这个短链接目录".into(),
                level: DomainCheckLevel::Pass,
            },
            ProbeRisk::Missing,
        );
    }
    if (200..300).contains(&status) {
        return (
            warning(
                label,
                format!("此路径返回 HTTP {status}；确认后该短链接目录及其下级网页将由短链接处理"),
            ),
            ProbeRisk::Content { status },
        );
    }
    if (300..400).contains(&status) {
        let target = normalize_redirect(request_url, location.as_deref(), random_segment);
        let detail = location
            .as_deref()
            .map(|value| format!("，Location 为 {value}"))
            .unwrap_or_else(|| "，响应未提供 Location".into());
        return (
            warning(
                label,
                format!(
                    "此路径返回 HTTP {status} 跳转{detail}；该跳转也可能来自先于 Worker 执行的 Cloudflare 重定向或访问策略，接入只创建指定目录的 Worker 路由，不保证绕过这些策略"
                ),
            ),
            ProbeRisk::Redirect { status, target },
        );
    }
    if (500..600).contains(&status) {
        return (
            warning(
                label,
                format!(
                    "此路径返回 HTTP {status}；接管后该短链接目录由 Worker 直接处理，不依赖源站，但此结果不代表 Cloudflare 或 WAF 故障会自动解决"
                ),
            ),
            ProbeRisk::OriginFailure { status },
        );
    }
    let explanation = match status {
        401 => "需要身份验证",
        403 => "访问被拒绝",
        407 => "代理要求身份验证",
        429 => "访问频率受限",
        _ => "响应状态无法确认路径可安全接管",
    };
    (
        DomainCheck {
            label: label.into(),
            ok: false,
            message: format!("此路径返回 HTTP {status}（{explanation}），请处理后重新检查"),
            level: DomainCheckLevel::Error,
        },
        ProbeRisk::Blocked { status },
    )
}

fn warning(label: &str, message: String) -> DomainCheck {
    DomainCheck {
        label: label.into(),
        ok: true,
        message,
        level: DomainCheckLevel::Warning,
    }
}

fn normalize_redirect(
    request_url: &str,
    location: Option<&str>,
    random_segment: Option<&str>,
) -> RedirectTarget {
    let Some(location) = location else {
        return RedirectTarget::Missing;
    };
    let Some(mut target) = url::Url::parse(request_url)
        .ok()
        .and_then(|base| base.join(location).ok())
    else {
        return RedirectTarget::Invalid(location.to_owned());
    };
    if let Some(segment) = random_segment {
        let normalized_path = target
            .path()
            .split('/')
            .map(|part| if part == segment { "{probe}" } else { part })
            .collect::<Vec<_>>()
            .join("/");
        if normalized_path != target.path() {
            target.set_path(&normalized_path);
        }
    }
    RedirectTarget::Valid(target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_record(
        id: &str,
        record_type: &str,
        content: &str,
        proxied: bool,
        proxiable: bool,
    ) -> Value {
        serde_json::json!({
            "id":id,
            "name":"example.com",
            "type":record_type,
            "content":content,
            "proxied":proxied,
            "proxiable":proxiable
        })
    }

    #[test]
    fn dns_assessment_distinguishes_missing_grey_unsupported_and_conflict() {
        assert_eq!(assess_dns(&[]), DnsAssessment::Missing);
        let grey = dns_fingerprint(
            &[dns_record("one", "A", "192.0.2.10", false, true)],
            "example.com",
        )
        .unwrap();
        assert!(matches!(assess_dns(&grey), DnsAssessment::DnsOnly(_)));
        let unsupported = dns_fingerprint(
            &[dns_record("one", "A", "192.0.2.10", false, false)],
            "example.com",
        )
        .unwrap();
        assert!(matches!(
            assess_dns(&unsupported),
            DnsAssessment::Unsupported(_)
        ));
        let conflict = dns_fingerprint(
            &[
                dns_record("one", "CNAME", "example.org", false, true),
                dns_record("two", "A", "192.0.2.10", false, true),
            ],
            "example.com",
        )
        .unwrap();
        assert!(matches!(assess_dns(&conflict), DnsAssessment::Conflict(_)));
    }

    #[test]
    fn dns_assessment_treats_mail_and_validation_records_as_missing_web_address() {
        let records = dns_fingerprint(
            &[
                dns_record("mx-one", "MX", "mail.example.org", false, false),
                dns_record("txt-one", "TXT", "verification=example", false, false),
                dns_record("caa-one", "CAA", "0 issue example.org", false, false),
            ],
            "example.com",
        )
        .unwrap();
        assert_eq!(assess_dns(&records), DnsAssessment::Missing);

        let unknown = dns_fingerprint(
            &[dns_record(
                "https-one",
                "HTTPS",
                "1 . alpn=h3",
                false,
                false,
            )],
            "example.com",
        )
        .unwrap();
        assert!(matches!(
            assess_dns(&unknown),
            DnsAssessment::Unsupported(_)
        ));
        let mixed_unknown = dns_fingerprint(
            &[
                dns_record("a-one", "A", "192.0.2.10", true, true),
                dns_record("https-one", "HTTPS", "1 . alpn=h3", false, false),
            ],
            "example.com",
        )
        .unwrap();
        assert!(matches!(
            assess_dns(&mixed_unknown),
            DnsAssessment::Unsupported(_)
        ));

        let delegated = dns_fingerprint(
            &[dns_record("ns-one", "NS", "ns1.example.org", false, false)],
            "example.com",
        )
        .unwrap();
        assert!(matches!(assess_dns(&delegated), DnsAssessment::Conflict(_)));
    }

    #[test]
    fn cname_can_coexist_with_mail_records_but_not_other_addresses() {
        let ready = dns_fingerprint(
            &[
                dns_record("cname-one", "CNAME", "origin.example.org", true, true),
                dns_record("mx-one", "MX", "mail.example.org", false, false),
                dns_record("txt-one", "TXT", "verification=example", false, false),
            ],
            "example.com",
        )
        .unwrap();
        assert_eq!(assess_dns(&ready), DnsAssessment::Ready);

        let grey = dns_fingerprint(
            &[dns_record(
                "cname-one",
                "CNAME",
                "origin.example.org",
                false,
                true,
            )],
            "example.com",
        )
        .unwrap();
        assert!(matches!(assess_dns(&grey), DnsAssessment::DnsOnly(_)));
    }

    #[test]
    fn dns_fingerprint_tracks_config_fields_but_ignores_provider_timestamps() {
        let original = serde_json::json!([{
            "id":"mx-one",
            "name":"example.com",
            "type":"MX",
            "content":"mail.example.org",
            "ttl":300,
            "priority":10,
            "data":{"priority":10,"target":"mail.example.org"},
            "settings":{"ipv4_only":false},
            "proxied":false,
            "proxiable":false,
            "modified_on":"2026-09-30T00:00:00Z"
        }]);
        let expected = dns_fingerprint(original.as_array().unwrap(), "example.com").unwrap();

        let mut timestamp_only = original.clone();
        timestamp_only[0]["modified_on"] = serde_json::json!("2026-09-30T00:01:00Z");
        assert_eq!(
            dns_fingerprint(timestamp_only.as_array().unwrap(), "example.com").unwrap(),
            expected
        );

        for (field, value) in [
            ("ttl", serde_json::json!(600)),
            ("priority", serde_json::json!(50)),
            (
                "data",
                serde_json::json!({"priority":50,"target":"mail.example.org"}),
            ),
            ("settings", serde_json::json!({"ipv4_only":true})),
        ] {
            let mut changed = original.clone();
            changed[0][field] = value;
            assert_ne!(
                dns_fingerprint(changed.as_array().unwrap(), "example.com").unwrap(),
                expected,
                "{field} must be part of the reviewed DNS snapshot"
            );
        }
    }

    #[test]
    fn placeholder_guard_allows_exact_mail_and_validation_records() {
        let records = vec![
            dns_record("mx-one", "MX", "mail.example.org", false, false),
            dns_record("txt-one", "TXT", "verification=example", false, false),
            dns_record("caa-one", "CAA", "0 issue example.org", false, false),
        ];
        assert_eq!(
            placeholder_conflict(&records, "example.com", "example.com"),
            None
        );
    }

    #[test]
    fn placeholder_guard_rejects_parent_delegation_and_wildcard() {
        let delegated = vec![serde_json::json!({
            "id":"ns-one","name":"child.example.com","type":"NS","content":"ns1.example.org"
        })];
        assert!(
            placeholder_conflict(&delegated, "go.child.example.com", "example.com")
                .unwrap()
                .contains("NS")
        );
        let wildcard = vec![serde_json::json!({
            "id":"wild-one","name":"*.example.com","type":"A","content":"192.0.2.20"
        })];
        assert!(
            placeholder_conflict(&wildcard, "go.example.com", "example.com")
                .unwrap()
                .contains("通配符")
        );
        let exact_delegation = vec![serde_json::json!({
            "id":"ns-two","name":"go.example.com","type":"NS","content":"ns1.example.org"
        })];
        assert!(
            placeholder_conflict(&exact_delegation, "go.example.com", "example.com")
                .unwrap()
                .contains("NS")
        );
    }

    #[test]
    fn only_404_is_a_path_pass() {
        let (check, risk) = classify_probe(
            "短链接目录",
            "https://example.com/go/",
            None,
            Ok((404, None)),
        );
        assert_eq!(check.level, DomainCheckLevel::Pass);
        assert_eq!(risk, ProbeRisk::Missing);
        for status in [401, 403, 407, 410, 429] {
            let (check, _) = classify_probe(
                "短链接目录",
                "https://example.com/go/",
                None,
                Ok((status, None)),
            );
            assert_eq!(check.level, DomainCheckLevel::Error);
            assert!(check.message.contains(&status.to_string()));
        }
    }

    #[test]
    fn redirects_normalize_only_the_generated_probe_segment() {
        let (_, first) = classify_probe(
            "随机测试链接",
            "https://example.com/go/probe-first",
            Some("probe-first"),
            Ok((302, Some("/login/probe-first?from=fixed#kept".into()))),
        );
        let (_, second) = classify_probe(
            "随机测试链接",
            "https://example.com/go/probe-second",
            Some("probe-second"),
            Ok((302, Some("/login/probe-second?from=fixed#kept".into()))),
        );
        assert_eq!(first, second);
        assert_eq!(
            first,
            ProbeRisk::Redirect {
                status: 302,
                target: RedirectTarget::Valid(
                    "https://example.com/login/%7Bprobe%7D?from=fixed#kept".into()
                )
            }
        );
    }

    #[test]
    fn redirect_fragment_changes_are_preserved_in_the_snapshot() {
        let (_, first) = classify_probe(
            "短链接目录",
            "https://example.com/go/",
            None,
            Ok((302, Some("/login#first".into()))),
        );
        let (_, second) = classify_probe(
            "短链接目录",
            "https://example.com/go/",
            None,
            Ok((302, Some("/login#second".into()))),
        );
        assert_ne!(first, second);
        assert!(!second.can_replace(&first));
    }

    #[test]
    fn malformed_redirect_locations_remain_distinct_from_each_other_and_missing() {
        let (_, first) = classify_probe(
            "短链接目录",
            "https://example.com/go/",
            None,
            Ok((302, Some("http://[first".into()))),
        );
        let (_, second) = classify_probe(
            "短链接目录",
            "https://example.com/go/",
            None,
            Ok((302, Some("http://[second".into()))),
        );
        let (_, missing) = classify_probe(
            "短链接目录",
            "https://example.com/go/",
            None,
            Ok((302, None)),
        );
        assert_ne!(first, second);
        assert_ne!(first, missing);
        assert_ne!(second, missing);
        assert!(!second.can_replace(&first));
        assert!(!missing.can_replace(&first));
    }

    #[test]
    fn risk_may_only_stay_equal_or_drop_to_404() {
        let warning = PathRiskSnapshot {
            root: ProbeRisk::Content { status: 200 },
            child: ProbeRisk::Redirect {
                status: 302,
                target: RedirectTarget::Valid("https://example.org/next".into()),
            },
            probe_segment: "probe-fixed".into(),
        };
        let same = warning.clone();
        assert!(same.can_replace(&warning));
        let safer = PathRiskSnapshot {
            root: ProbeRisk::Missing,
            child: ProbeRisk::Missing,
            probe_segment: "probe-fixed".into(),
        };
        assert!(safer.can_replace(&warning));
        let changed = PathRiskSnapshot {
            root: ProbeRisk::Content { status: 204 },
            child: warning.child.clone(),
            probe_segment: "probe-fixed".into(),
        };
        assert!(!changed.can_replace(&warning));
        assert!(!warning.can_replace(&safer));
    }
    #[test]
    fn proxy_blocks_mail_and_srv_targets_through_aliases_and_delegation() {
        let aliases = vec![
            serde_json::json!({"name":"alias.example.com","type":"CNAME","content":"MAIL.EXAMPLE.COM."}),
            serde_json::json!({"name":"other.example.com","type":"CNAME","content":"alias.example.com"}),
        ];
        for service in [
            serde_json::json!({"name":"example.com","type":"MX","content":"mail.example.com"}),
            serde_json::json!({"name":"example.com","type":"MX","content":"other.example.com"}),
            serde_json::json!({"name":"_sip._tcp.example.com","type":"SRV","content":"0 5 5060 other.example.com"}),
            serde_json::json!({"name":"_sip._tcp.example.com","type":"SRV","data":{"target":"other.example.com."}}),
            serde_json::json!({"name":"mail.example.com","type":"NS","content":"ns.example.org"}),
        ] {
            let mut all = aliases.clone();
            all.push(service);
            assert!(proxy_conflict(&all, "mail.example.com", "example.com").is_some());
        }
        let mut unrelated = aliases;
        unrelated.push(
            serde_json::json!({"name":"example.com","type":"MX","content":"unrelated.example.org"}),
        );
        assert!(proxy_conflict(&unrelated, "mail.example.com", "example.com").is_none());
        assert!(proxy_conflict(
            &[serde_json::json!({"name":"_sip._tcp.example.com","type":"SRV"})],
            "mail.example.com",
            "example.com"
        )
        .is_some());
    }
}

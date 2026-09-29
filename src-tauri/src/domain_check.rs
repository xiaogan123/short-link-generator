use crate::model::{DomainCheck, DomainCheckLevel};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecordFingerprint {
    pub id: String,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    pub proxiable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsSnapshot {
    Missing,
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
            proxied,
            proxiable,
        });
    }
    records.sort_by(|a, b| {
        (&a.record_type, &a.id, &a.content).cmp(&(&b.record_type, &b.id, &b.content))
    });
    Ok(records)
}

pub fn assess_dns(records: &[DnsRecordFingerprint]) -> DnsAssessment {
    if records.is_empty() {
        return DnsAssessment::Missing;
    }
    if records.iter().any(|record| record.record_type == "NS") {
        return DnsAssessment::Conflict("该主机名存在 NS 委派，不能由应用接管 DNS".into());
    }
    let address_records: Vec<_> = records
        .iter()
        .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA" | "CNAME"))
        .collect();
    if address_records.is_empty() {
        return DnsAssessment::Unsupported(
            "该主机名已有不可代理的 DNS 记录，应用不会添加或覆盖地址记录".into(),
        );
    }
    let has_cname = address_records
        .iter()
        .any(|record| record.record_type == "CNAME");
    if has_cname && address_records.len() != 1 {
        return DnsAssessment::Conflict("同一主机名的 CNAME 与其他地址记录冲突".into());
    }
    if address_records.iter().any(|record| !record.proxiable) {
        return DnsAssessment::Unsupported(
            "云端标记至少一条地址记录不支持代理，应用不会强行修改".into(),
        );
    }
    let pending: Vec<_> = address_records
        .into_iter()
        .filter(|record| !record.proxied)
        .cloned()
        .collect();
    if pending.is_empty() {
        DnsAssessment::Ready
    } else {
        DnsAssessment::DnsOnly(pending)
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
        if name == host {
            return Some("完整区域清单显示该主机名已有 DNS 记录，不能创建占位记录".into());
        }
        if record_type == "NS"
            && name != zone_name
            && (host == name || host.ends_with(&format!(".{name}")))
        {
            return Some(format!("{name} 存在 NS 子域委派，应用不会在其下创建记录"));
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
                    message: format!("无法连接此路径（DNS、TLS、超时或网络失败）：{message}"),
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
}

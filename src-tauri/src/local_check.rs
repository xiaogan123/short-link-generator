use chrono::Utc;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(mapped));
            }
            let s = v.segments();
            !((s[0] & 0xe000) != 0x2000
                || v == Ipv6Addr::LOCALHOST
                || v == Ipv6Addr::UNSPECIFIED
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xff00) == 0xff00
                || (s[0] == 0x2001 && s[1] == 0xdb8)
                || (s[0] == 0x2001 && s[1] == 0x10))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CheckIssue {
    InvalidUrl,
    DnsTimeout,
    DnsFailed,
    DnsEmpty,
    VirtualAddress,
    NonPublicAddress,
    ClientInitialization,
}

impl CheckIssue {
    fn details(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::InvalidUrl => ("invalid_url", "address", "地址格式不支持，只能检查公开的 HTTPS 网站"),
            Self::DnsTimeout => ("dns_timeout", "dns", "查询网站地址超时，请稍后重试"),
            Self::DnsFailed => ("dns_failed", "dns", "当前电脑无法解析网站域名，请检查网络后重试"),
            Self::DnsEmpty => ("dns_no_answer", "dns", "没有查询到网站的 IP 地址，尚未连接网站"),
            Self::VirtualAddress => ("virtual_dns_address", "dns", "本机网络设置影响了检测：域名返回虚拟地址范围，可能与代理或 VPN 有关。尚未连接网站，不能据此判断网站是否可用"),
            Self::NonPublicAddress => ("blocked_non_public_address", "dns", "域名指向非公开地址，已停止检测。尚未连接网站，请检查域名和本机网络设置"),
            Self::ClientInitialization => ("client_initialization", "connection", "无法启动网站检查，请稍后重试"),
        }
    }
}

fn virtual_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            a == 198 && (b == 18 || b == 19)
        }
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .is_some_and(|v| virtual_address(IpAddr::V4(v))),
    }
}

// Keep mixed public/private answers blocked. A more useful diagnosis must not
// weaken the address check or allow a virtual DNS response to reach transport.
fn validate_addresses(addrs: &[SocketAddr]) -> Result<(), CheckIssue> {
    if addrs.is_empty() {
        return Err(CheckIssue::DnsEmpty);
    }
    if addrs
        .iter()
        .any(|a| !public_ip(a.ip()) && !virtual_address(a.ip()))
    {
        return Err(CheckIssue::NonPublicAddress);
    }
    if addrs.iter().any(|a| virtual_address(a.ip())) {
        return Err(CheckIssue::VirtualAddress);
    }
    Ok(())
}

async fn client_for(url: &url::Url) -> Result<Client, CheckIssue> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(CheckIssue::InvalidUrl);
    }
    let host = url
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port_or_known_default().ok_or(CheckIssue::InvalidUrl)?;
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| CheckIssue::DnsTimeout)?
        .map_err(|_| CheckIssue::DnsFailed)?
        .collect()
    };
    validate_addresses(&addrs)?;
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(true)
        .timeout(Duration::from_secs(6))
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|_| CheckIssue::ClientInitialization)
}

pub async fn check(label: &str, initial: &str) -> Value {
    let checked_at = Utc::now().to_rfc3339();
    let mut url = match url::Url::parse(initial) {
        Ok(v) => v,
        Err(_) => return issue_result(label, &CheckIssue::InvalidUrl, &checked_at, initial),
    };
    for hop in 0..=3 {
        let client = match client_for(&url).await {
            Ok(c) => c,
            Err(e) => return issue_result(label, &e, &checked_at, url.as_str()),
        };
        let mut response = client.request(Method::HEAD, url.clone()).send().await;
        if response
            .as_ref()
            .is_ok_and(|r| r.status() == StatusCode::METHOD_NOT_ALLOWED)
        {
            response = client.request(Method::GET, url.clone()).send().await;
        }
        let response = match response {
            Ok(r) => r,
            Err(e) => {
                let (reason, message) = if e.is_timeout() {
                    ("request_timeout", "连接网站超时，尚不能确认是否可用")
                } else {
                    (
                        "transport_error",
                        "当前电脑未能连接网站，可能与网络、证书或连接限制有关",
                    )
                };
                return result(
                    label,
                    "unknown",
                    reason,
                    "connection",
                    message,
                    &checked_at,
                    url.as_str(),
                );
            }
        };
        if response
            .headers()
            .get("cf-mitigated")
            .and_then(|v| v.to_str().ok())
            == Some("challenge")
        {
            return result(
                label,
                "unknown",
                "http_challenge",
                "response",
                "网站要求验证码，自动检查无法确认，请在浏览器中查看",
                &checked_at,
                url.as_str(),
            );
        }
        let status = response.status();
        if status.is_redirection() {
            if hop == 3 {
                return result(
                    label,
                    "unknown",
                    "redirect_limit",
                    "redirect",
                    "网站连续跳转次数过多，尚不能确认最终页面",
                    &checked_at,
                    url.as_str(),
                );
            }
            let location = match response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            {
                Some(v) => v,
                None => {
                    return result(
                        label,
                        "unknown",
                        "redirect_missing",
                        "redirect",
                        "网站要求跳转，但没有提供新地址",
                        &checked_at,
                        url.as_str(),
                    )
                }
            };
            url = match url.join(location) {
                Ok(v) => v,
                Err(_) => {
                    return result(
                        label,
                        "unknown",
                        "redirect_invalid",
                        "redirect",
                        "网站提供的跳转地址无效",
                        &checked_at,
                        url.as_str(),
                    )
                }
            };
            continue;
        }
        let (state, reason, message) = if status.is_success() {
            ("passed", "http_success", "当前电脑已收到网站的正常响应")
        } else if status == StatusCode::FORBIDDEN
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::UNAUTHORIZED
        {
            (
                "unknown",
                "http_restricted",
                "网站限制了自动检查，请在浏览器中确认",
            )
        } else if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
            ("failed", "http_missing", "页面不存在或已移除（404/410）")
        } else if status.is_server_error() {
            ("failed", "http_server_error", "网站服务器报错")
        } else {
            (
                "unknown",
                "http_inconclusive",
                "已收到网站响应，但尚不能确认页面可用",
            )
        };
        return result(
            label,
            state,
            reason,
            "response",
            message,
            &checked_at,
            url.as_str(),
        );
    }
    result(
        label,
        "unknown",
        "incomplete",
        "connection",
        "检查未完成",
        &checked_at,
        initial,
    )
}

fn issue_result(label: &str, issue: &CheckIssue, checked_at: &str, url: &str) -> Value {
    let (reason, stage, message) = issue.details();
    result(label, "unknown", reason, stage, message, checked_at, url)
}

fn result(
    label: &str,
    status: &str,
    reason: &str,
    stage: &str,
    message: &str,
    checked_at: &str,
    url: &str,
) -> Value {
    json!({"label":label,"status":status,"reason":reason,"stage":stage,"message":message,
        "checkedAt":checked_at,"source":"local","url":url})
}

pub fn timeout_result(label: &str, url: &str) -> Value {
    result(
        label,
        "unknown",
        "request_timeout",
        "connection",
        "本机检查超时，请稍后重试",
        &Utc::now().to_rfc3339(),
        url,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_local_and_special_ips() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "198.18.0.1",
            "198.19.255.254",
            "::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "::ffff:198.18.0.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn diagnosis_distinguishes_empty_virtual_and_mixed_dns_without_allowing_any() {
        let addr = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 443);
        assert_eq!(validate_addresses(&[]), Err(CheckIssue::DnsEmpty));
        assert_eq!(
            validate_addresses(&[addr("198.18.0.1")]),
            Err(CheckIssue::VirtualAddress)
        );
        assert_eq!(
            validate_addresses(&[addr("1.1.1.1"), addr("198.18.0.1")]),
            Err(CheckIssue::VirtualAddress)
        );
        assert_eq!(
            validate_addresses(&[addr("1.1.1.1"), addr("127.0.0.1")]),
            Err(CheckIssue::NonPublicAddress)
        );
        assert_eq!(
            validate_addresses(&[addr("198.18.0.1"), addr("10.0.0.1")]),
            Err(CheckIssue::NonPublicAddress)
        );
        assert_eq!(validate_addresses(&[addr("1.1.1.1")]), Ok(()));
    }

    #[tokio::test]
    async fn blocked_destinations_return_specific_unknown_before_transport() {
        for (url, reason) in [
            ("https://198.18.0.1/", "virtual_dns_address"),
            ("https://127.0.0.1/", "blocked_non_public_address"),
            ("https://[::1]/", "blocked_non_public_address"),
            ("https://[::ffff:198.18.0.1]/", "virtual_dns_address"),
            ("http://127.0.0.1/", "invalid_url"),
            ("https://user:password@example.com/", "invalid_url"),
        ] {
            let value = check("目标网站", url).await;
            assert_eq!(value["status"], "unknown", "{url}");
            assert_eq!(value["reason"], reason, "{url}");
            assert_eq!(value["source"], "local");
            assert!(!value["message"]
                .as_str()
                .unwrap()
                .contains("不经过系统代理"));
        }
    }
}

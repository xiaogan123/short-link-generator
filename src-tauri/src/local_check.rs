use chrono::Utc;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

mod public_dns;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsMode {
    System,
    Public,
}

impl DnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Public => "public",
        }
    }
}

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
            // Keep the existing global-unicast-only policy. In particular,
            // NAT64, IPv4-compatible, ULA, link-local and multicast addresses
            // must not bypass the IPv4/private-address checks through IPv6.
            if (s[0] & 0xe000) != 0x2000 {
                return false;
            }
            // IANA special-purpose registry, including its more-specific
            // globally reachable exceptions within 2001::/23:
            // https://www.iana.org/assignments/iana-ipv6-special-registry/
            if s[0] == 0x2001 && s[1] < 0x0200 {
                return (s[1] == 1
                    && s[2..7].iter().all(|segment| *segment == 0)
                    && (1..=3).contains(&s[7]))
                    || s[1] == 3
                    || (s[1] == 4 && s[2] == 0x112)
                    || (s[1] & 0xfff0) == 0x20
                    || (s[1] & 0xfff0) == 0x30;
            }
            // Documentation prefixes and 6to4 are not accepted as ordinary
            // public website destinations. Teredo is excluded above.
            !(s[0] == 0x2002
                || (s[0] == 0x2001 && s[1] == 0xdb8)
                || (s[0] == 0x3fff && (s[1] & 0xf000) == 0))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CheckIssue {
    InvalidUrl,
    DnsTimeout,
    DnsFailed,
    DnsEmpty,
    PublicDnsTimeout,
    PublicDnsFailed,
    PublicDnsInvalidResponse,
    PublicDnsResponseTooLarge,
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
            Self::PublicDnsTimeout => ("public_dns_timeout", "dns", "公共 DNS 查询超时，尚未连接网站，请稍后重试"),
            Self::PublicDnsFailed => ("public_dns_failed", "dns", "未能从公共 DNS 查询网站地址，尚未连接网站，请稍后重试"),
            Self::PublicDnsInvalidResponse => ("public_dns_invalid_response", "dns", "公共 DNS 返回的信息不完整或不匹配，已停止检测，尚未连接网站"),
            Self::PublicDnsResponseTooLarge => ("public_dns_response_too_large", "dns", "公共 DNS 返回的信息超出检查范围，已停止检测，尚未连接网站"),
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

async fn client_for(url: &url::Url, mode: DnsMode) -> Result<Client, CheckIssue> {
    client_for_with_timeout(url, mode, Duration::from_secs(6)).await
}

pub(crate) async fn client_for_probe(
    url: &url::Url,
    mode: DnsMode,
    timeout: Duration,
) -> Result<Client, String> {
    client_for_with_timeout(url, mode, timeout)
        .await
        .map_err(|issue| issue.details().2.to_owned())
}

async fn client_for_with_timeout(
    url: &url::Url,
    mode: DnsMode,
    timeout: Duration,
) -> Result<Client, CheckIssue> {
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
    } else if mode == DnsMode::Public {
        public_dns::resolve(host, port).await?
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
        .timeout(timeout)
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|_| CheckIssue::ClientInitialization)
}

pub async fn check(label: &str, initial: &str) -> Value {
    check_with_mode(label, initial, DnsMode::System).await
}

pub async fn check_with_mode(label: &str, initial: &str, mode: DnsMode) -> Value {
    let mut value = check_inner(label, initial, mode).await;
    value["dnsMode"] = json!(mode.as_str());
    value
}

async fn check_inner(label: &str, initial: &str, mode: DnsMode) -> Value {
    let checked_at = Utc::now().to_rfc3339();
    let mut url = match url::Url::parse(initial) {
        Ok(v) => v,
        Err(_) => return issue_result(label, &CheckIssue::InvalidUrl, &checked_at, initial),
    };
    for hop in 0..=3 {
        let client = match client_for(&url, mode).await {
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
    let mut value = result(
        label,
        "unknown",
        "request_timeout",
        "connection",
        "本机检查超时，请稍后重试",
        &Utc::now().to_rfc3339(),
        url,
    );
    value["dnsMode"] = json!(DnsMode::System.as_str());
    value
}

pub fn timeout_result_with_mode(label: &str, url: &str, mode: DnsMode) -> Value {
    let mut value = timeout_result(label, url);
    value["dnsMode"] = json!(mode.as_str());
    value
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

    #[test]
    fn ipv6_special_prefixes_and_translation_cannot_bypass_address_guards() {
        for ip in [
            "2001::1",                           // Teredo
            "2001:2::1",                         // Benchmarking
            "2001:2:0:ffff:ffff:ffff:ffff:ffff", // End of benchmarking /48
            "2001:10::1",                        // Deprecated ORCHID /28
            "2001:1f:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:1::4",     // Outside globally reachable anycast exceptions
            "2001:4:113::1", // Outside AS112 exception
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", // End of IETF /23
            "2001:db8::1",
            "2002::1",
            "2002:7f00:1::1", // 6to4 embedding loopback
            "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff::1",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", // End of documentation /20
            "64:ff9b::7f00:1",                        // Well-known NAT64 embedding loopback
            "64:ff9b::101:101",                       // NAT64 remains conservatively blocked
            "64:ff9b:1::a00:1",                       // Local-use NAT64
            "::127.0.0.1",                            // Deprecated IPv4-compatible
            "::ffff:10.0.0.1",
            "::ffff:198.18.0.1",
            "100::1",
            "100:0:0:1::1",
            "5f00::1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!public_ip(ip), "{ip}");
            assert!(
                validate_addresses(&[
                    SocketAddr::new("1.1.1.1".parse().unwrap(), 443),
                    SocketAddr::new(ip, 443),
                ])
                .is_err(),
                "mixed answer containing {ip}"
            );
        }
        // Preserve ordinary public IPv6 and IANA's globally reachable
        // exceptions rather than rejecting their containing block wholesale.
        for ip in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:30::1",
            "2001:3f:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:200::1", // Just beyond IETF /23
            "2620:4f:8000::1",
            "3fff:1000::1", // Just beyond documentation /20
            "::ffff:1.1.1.1",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
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

    #[tokio::test]
    async fn public_mode_does_not_resolve_or_connect_to_literal_or_local_destinations() {
        for (url, reason) in [
            ("https://198.18.0.1/", "virtual_dns_address"),
            ("https://[::ffff:198.18.0.1]/", "virtual_dns_address"),
            ("https://127.0.0.1/", "blocked_non_public_address"),
            ("https://[::1]/", "blocked_non_public_address"),
            ("https://localhost/", "blocked_non_public_address"),
            ("https://test.localhost/", "blocked_non_public_address"),
            ("https://router.local/", "blocked_non_public_address"),
            ("https://router.home.arpa/", "blocked_non_public_address"),
            ("http://example.org/", "invalid_url"),
            ("https://user:password@example.org/", "invalid_url"),
        ] {
            let result = check_with_mode("目标网站", url, DnsMode::Public).await;
            assert_eq!(result["status"], "unknown", "{url}");
            assert_eq!(result["reason"], reason, "{url}");
            assert_eq!(result["dnsMode"], "public");
            assert_eq!(result["source"], "local");
        }
        assert_eq!(
            timeout_result_with_mode("目标网站", "https://example.org/", DnsMode::Public)
                ["dnsMode"],
            "public"
        );
        assert_eq!(
            timeout_result("目标网站", "https://example.org/")["dnsMode"],
            "system"
        );
    }

    #[tokio::test]
    async fn probe_client_reuses_the_same_address_and_https_guards() {
        for mode in [DnsMode::System, DnsMode::Public] {
            for (address, expected) in [
                ("https://198.18.0.1/", "虚拟地址"),
                ("https://127.0.0.1/", "非公开地址"),
                ("https://[::1]/", "非公开地址"),
                ("https://[2002:7f00:1::1]/", "非公开地址"),
                ("https://[2001:2::1]/", "非公开地址"),
                ("https://[3fff::1]/", "非公开地址"),
                ("https://[64:ff9b::7f00:1]/", "非公开地址"),
                ("http://example.org/", "HTTPS"),
                ("https://user:password@example.org/", "HTTPS"),
            ] {
                let url = url::Url::parse(address).unwrap();
                let error = client_for_probe(&url, mode, Duration::from_secs(30))
                    .await
                    .unwrap_err();
                assert!(error.contains(expected), "{address}: {error}");
            }
        }
    }
}

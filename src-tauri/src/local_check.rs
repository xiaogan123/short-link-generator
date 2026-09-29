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

async fn client_for(url: &url::Url) -> Result<Client, String> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("只检测公开的 HTTPS 网站".into());
    }
    let host = url.host_str().unwrap();
    let port = url.port_or_known_default().ok_or("网站端口无效")?;
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| "DNS 查询超时")?
        .map_err(|_| "DNS 查询失败")?
        .collect()
    };
    if addrs.is_empty() || addrs.iter().any(|a| !public_ip(a.ip())) {
        return Err("网站域名解析到非公开地址，停止检测".into());
    }
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(true)
        .timeout(Duration::from_secs(6))
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|_| "网络检查初始化失败".into())
}

pub async fn check(label: &str, initial: &str) -> Value {
    let checked_at = Utc::now().to_rfc3339();
    let mut url = match url::Url::parse(initial) {
        Ok(v) => v,
        Err(_) => return result(label, "unknown", "保存的网站地址无效", &checked_at, initial),
    };
    for hop in 0..=3 {
        let client = match client_for(&url).await {
            Ok(c) => c,
            Err(e) => return result(label, "unknown", &e, &checked_at, url.as_str()),
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
            Err(_) => {
                return result(
                    label,
                    "unknown",
                    "本机请求超时或网络失败",
                    &checked_at,
                    url.as_str(),
                )
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
                "网站要求完成验证码等验证，暂时无法确认",
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
                    "网站跳转次数过多，暂时无法确认",
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
                        "网站跳转时没有提供新地址，暂时无法确认",
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
                        "网站跳转地址无效，暂时无法确认",
                        &checked_at,
                        url.as_str(),
                    )
                }
            };
            continue;
        }
        let (state, message) = if status.is_success() {
            ("passed", "当前电脑已收到网站的正常响应")
        } else if status == StatusCode::FORBIDDEN
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::UNAUTHORIZED
        {
            ("unknown", "网站拒绝或限制自动检测，暂时无法确认")
        } else if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
            ("failed", "页面不存在或已移除（404/410）")
        } else if status.is_server_error() {
            ("failed", "网站服务器报错")
        } else {
            ("unknown", "网站响应无法确认")
        };
        return result(label, state, message, &checked_at, url.as_str());
    }
    result(label, "unknown", "检查未完成", &checked_at, initial)
}

fn result(label: &str, status: &str, message: &str, checked_at: &str, url: &str) -> Value {
    let message = if message.starts_with("本机直连") {
        message.to_string()
    } else {
        format!("本机直连（不经过系统代理）：{message}")
    };
    json!({"label":label,"status":status,"message":message,"checkedAt":checked_at,
        "source":"local","url":url})
}

pub fn timeout_result(label: &str, url: &str) -> Value {
    result(
        label,
        "unknown",
        "本机直连（不经过系统代理）检查超时",
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
            "::1",
            "fc00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()));
        }
        assert!(public_ip(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))));
    }
}

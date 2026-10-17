//! Anonymous, single-hop verification of a locally imported short link.
//! This deliberately has no Cloud or credential-store dependency.
use super::*;
use reqwest::{
    header::{HeaderMap, LOCATION},
    StatusCode,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{future::Future, sync::OnceLock};
use tokio::sync::Semaphore;

const PROBE_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct RedirectSnapshot {
    source: url::Url,
    expected: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResultStatus {
    Passed,
    Failed,
    Unknown,
}

impl ResultStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

type Outcome = (ResultStatus, &'static str, &'static str);

fn result(
    status: ResultStatus,
    reason: &'static str,
    message: &'static str,
    mode: local_check::DnsMode,
) -> Value {
    json!({
        "status": status.as_str(),
        "message": message,
        "checkedAt": now(),
        "reason": reason,
        "dnsMode": mode.as_str(),
    })
}

fn outcome(value: Outcome, mode: local_check::DnsMode) -> Value {
    result(value.0, value.1, value.2, mode)
}

fn exactly_one<'a, T>(items: impl Iterator<Item = &'a T>) -> Option<&'a T> {
    let mut items = items;
    let value = items.next()?;
    items.next().is_none().then_some(value)
}

fn snapshot(backend: &Backend, domain_id: &str, slug: &str) -> Result<RedirectSnapshot, String> {
    validate_slug(slug)?;
    let domain = exactly_one(backend.db.domains.iter().filter(|d| d.id == domain_id))
        .ok_or("找不到唯一的本地域名，无法检查跳转")?;
    let link = exactly_one(
        backend
            .db
            .links
            .iter()
            .filter(|l| l.domain_id == domain_id && l.slug == slug),
    )
    .ok_or("找不到唯一的本地短链接，无法检查跳转")?;

    // Imported or corrupted local records must not turn this feature into an
    // arbitrary URL probe. DNS validation below additionally blocks private IPs.
    if normalize_host(&domain.host).as_deref() != Ok(domain.host.as_str()) {
        return Err("本地域名无效，无法检查跳转".into());
    }
    validate_prefix(&domain.prefix)?;
    let source = format!("https://{}/{}/{}", domain.host, domain.prefix, slug);
    let source = url::Url::parse(&source).map_err(|_| "本地短链接地址无效".to_string())?;
    if source.scheme() != "https" || source.host_str() != Some(domain.host.as_str()) {
        return Err("本地短链接地址无效".into());
    }

    let expected = match (&link.pool_id, &link.code) {
        (None, None) => vec![
            canonical_target(&link.cn_url)?,
            canonical_target(&link.default_url)?,
        ],
        (Some(pool_id), Some(code)) => {
            if !pools::valid_code(code) {
                return Err("邀请码无效，无法检查跳转".into());
            }
            let pool = exactly_one(backend.db.pools.iter().filter(|p| &p.id == pool_id))
                .ok_or("找不到唯一的平台地址，无法检查跳转")?;
            let mut urls = vec![pools::compose(&pool.official, code)?];
            for candidate in pool.candidates.iter().filter(|c| c.enabled) {
                urls.push(pools::compose(&model::Template::from(candidate), code)?);
            }
            if urls.len() == 1 {
                return Err("平台地址没有已启用的大陆备用地址，无法检查跳转".into());
            }
            urls
        }
        _ => return Err("短链接的平台地址配置不完整，无法检查跳转".into()),
    };
    Ok(RedirectSnapshot { source, expected })
}

fn classify(status: StatusCode, location: Option<&str>, expected: &[String]) -> Outcome {
    if status == StatusCode::FOUND {
        return match location {
            None => (
                ResultStatus::Failed,
                "missing_location",
                "短链接返回跳转，但缺少目标地址",
            ),
            Some(actual) if expected.iter().any(|target| target == actual) => (
                ResultStatus::Passed,
                "location_match",
                "首跳地址与本地配置一致",
            ),
            Some(_) => (
                ResultStatus::Failed,
                "location_mismatch",
                "首跳地址与本地配置不一致",
            ),
        };
    }
    if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
        return (
            ResultStatus::Failed,
            "link_missing",
            "短链接返回不存在或已删除",
        );
    }
    if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
        return (
            ResultStatus::Unknown,
            "access_limited",
            "网站限制了本次检查，暂不能判断跳转",
        );
    }
    if status == StatusCode::UNAUTHORIZED {
        return (
            ResultStatus::Unknown,
            "authentication_required",
            "网站要求身份验证，暂不能判断跳转",
        );
    }
    if status == StatusCode::METHOD_NOT_ALLOWED {
        return (
            ResultStatus::Unknown,
            "method_unsupported",
            "网站不支持本次安全检查方式，暂不能判断跳转",
        );
    }
    if status.is_server_error() {
        return (
            ResultStatus::Unknown,
            "server_unavailable",
            "网站暂时无法完成检查，请稍后重试",
        );
    }
    (
        ResultStatus::Unknown,
        "unexpected_status",
        "网站返回了未明确的响应，暂不能判断跳转",
    )
}

fn classify_response(status: StatusCode, headers: &HeaderMap, expected: &[String]) -> Outcome {
    if status != StatusCode::FOUND {
        return classify(status, None, expected);
    }
    let mut locations = headers.get_all(LOCATION).iter();
    match (locations.next(), locations.next()) {
        (None, _) => classify(status, None, expected),
        (Some(_), Some(_)) => (
            ResultStatus::Unknown,
            "ambiguous_location",
            "网站返回多个跳转目标，暂不能判断跳转",
        ),
        (Some(location), None) => match location.to_str() {
            Ok(location) => classify(status, Some(location), expected),
            Err(_) => (
                ResultStatus::Failed,
                "invalid_location",
                "网站返回的跳转目标格式无效",
            ),
        },
    }
}

fn issue_outcome(issue: &local_check::CheckIssue) -> Outcome {
    let (reason, _, _) = issue.details();
    (
        ResultStatus::Unknown,
        reason,
        "当前网络未能完成安全检查，暂不能判断跳转",
    )
}

fn probe_semaphore() -> &'static Semaphore {
    static PROBE: OnceLock<Semaphore> = OnceLock::new();
    PROBE.get_or_init(|| Semaphore::new(1))
}

fn build_head_request(
    client: &reqwest::Client,
    source: &url::Url,
) -> Result<reqwest::Request, reqwest::Error> {
    client.head(source.clone()).build()
}

async fn run_probe(
    snapshot: &RedirectSnapshot,
    used_public: &AtomicBool,
) -> (Outcome, local_check::DnsMode) {
    let mut mode = local_check::DnsMode::System;
    let client = match local_check::client_for_probe(&snapshot.source, mode, PROBE_BUDGET).await {
        Ok(client) => client,
        Err(local_check::CheckIssue::VirtualAddress) => {
            mode = local_check::DnsMode::Public;
            used_public.store(true, Ordering::Relaxed);
            match local_check::client_for_probe(&snapshot.source, mode, PROBE_BUDGET).await {
                Ok(client) => client,
                Err(issue) => return (issue_outcome(&issue), mode),
            }
        }
        Err(issue) => return (issue_outcome(&issue), mode),
    };
    // HEAD is intentional: the Worker excludes it from click statistics.
    // The client has redirects disabled and this code makes exactly one request.
    let request = match build_head_request(&client, &snapshot.source) {
        Ok(request) => request,
        Err(_) => {
            return (
                (
                    ResultStatus::Unknown,
                    "transport_error",
                    "网络连接未完成，暂不能判断跳转",
                ),
                mode,
            )
        }
    };
    let response = match client.execute(request).await {
        Ok(response) => response,
        Err(error) => {
            let reason = if error.is_timeout() {
                "timeout"
            } else {
                "transport_error"
            };
            return (
                (
                    ResultStatus::Unknown,
                    reason,
                    "网络连接未完成，暂不能判断跳转",
                ),
                mode,
            );
        }
    };
    (
        classify_response(response.status(), response.headers(), &snapshot.expected),
        mode,
    )
}

async fn bounded_result(
    budget: Duration,
    used_public: &AtomicBool,
    probe: impl Future<Output = (Outcome, local_check::DnsMode)>,
) -> Value {
    match tokio::time::timeout(budget, probe).await {
        Ok((probe_result, mode)) => outcome(probe_result, mode),
        Err(_) => result(
            ResultStatus::Unknown,
            "timeout",
            "跳转检查超时，请稍后重试",
            if used_public.load(Ordering::Relaxed) {
                local_check::DnsMode::Public
            } else {
                local_check::DnsMode::System
            },
        ),
    }
}

pub(super) async fn check_link_redirect(
    state: &AppState,
    domain_id: &str,
    slug: &str,
) -> Result<Value, String> {
    let permit = probe_semaphore().try_acquire();
    let _permit = match permit {
        Ok(permit) => permit,
        Err(_) => {
            return Ok(result(
                ResultStatus::Unknown,
                "busy",
                "已有跳转检查正在进行，请稍后重试",
                local_check::DnsMode::System,
            ))
        }
    };
    let snapshot = match state.0.try_lock() {
        Ok(backend) => snapshot(&backend, domain_id, slug)?,
        Err(_) => {
            return Ok(result(
                ResultStatus::Unknown,
                "busy",
                "本地操作正在进行，请稍后重试",
                local_check::DnsMode::System,
            ))
        }
    };
    // The backend mutex is dropped before DNS or transport work begins.
    let used_public = AtomicBool::new(false);
    Ok(bounded_result(
        PROBE_BUDGET,
        &used_public,
        run_probe(&snapshot, &used_public),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{domain, fixture};

    fn manual_link() -> Link {
        Link {
            domain_id: "domain1".into(),
            slug: "Ab_1".into(),
            cn_url: "https://EXAMPLE.org/Aa?Code=xY".into(),
            default_url: "https://example.org/Bb?code=xy".into(),
            updated: now(),
            pool_id: None,
            code: None,
        }
    }

    #[tokio::test]
    async fn snapshot_uses_only_local_records_and_preserves_target_path_and_query() {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(manual_link());
        let snapshot = snapshot(&backend, "domain1", "Ab_1").unwrap();
        assert_eq!(snapshot.source.as_str(), "https://example.com/go/Ab_1");
        assert_eq!(
            snapshot.expected,
            [
                "https://example.org/Aa?Code=xY",
                "https://example.org/Bb?code=xy"
            ]
        );
        assert_eq!(
            classify(
                StatusCode::FOUND,
                Some(&snapshot.expected[0]),
                &snapshot.expected
            )
            .0,
            ResultStatus::Passed
        );
        assert_eq!(
            classify(
                StatusCode::FOUND,
                Some("https://example.org/aa?Code=xY"),
                &snapshot.expected
            )
            .1,
            "location_mismatch"
        );
        assert_eq!(
            classify(
                StatusCode::FOUND,
                Some("https://example.org/Aa?Code=xy"),
                &snapshot.expected
            )
            .1,
            "location_mismatch"
        );
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn pool_snapshot_excludes_disabled_candidates_and_rejects_ambiguous_records() {
        let (_server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        let mut link = manual_link();
        link.pool_id = Some("pool1".into());
        link.code = Some("Code1".into());
        backend.db.links.push(link);
        backend.db.pools.push(Pool {
            id: "pool1".into(),
            name: "Example".into(),
            official: model::Template {
                prefix: "https://example.org/official?code=".into(),
                suffix: "".into(),
            },
            candidates: vec![
                model::PoolCandidate {
                    id: "on".into(),
                    prefix: "https://example.org/on?code=".into(),
                    suffix: "".into(),
                    enabled: true,
                },
                model::PoolCandidate {
                    id: "off".into(),
                    prefix: "https://example.org/off?code=".into(),
                    suffix: "".into(),
                    enabled: false,
                },
            ],
            updated: now(),
            account_ids: vec![],
            sync_status: vec![],
        });
        let found = snapshot(&backend, "domain1", "Ab_1").unwrap();
        assert_eq!(
            found.expected,
            [
                "https://example.org/official?code=Code1",
                "https://example.org/on?code=Code1"
            ]
        );
        backend.db.pools.push(backend.db.pools[0].clone());
        assert!(snapshot(&backend, "domain1", "Ab_1").is_err());
        backend.db.pools.pop();
        backend.db.links.push(backend.db.links[0].clone());
        assert!(snapshot(&backend, "domain1", "Ab_1").is_err());
        backend.db.links.pop();
        backend.db.domains.push(backend.db.domains[0].clone());
        assert!(snapshot(&backend, "domain1", "Ab_1").is_err());
        assert!(mock_key_reads().lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_source_and_partial_pool_reference_stop_before_transport() {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(manual_link());
        for host in [
            "127.0.0.1",
            "example.com:443",
            "example.com/path",
            "localhost",
        ] {
            backend.db.domains[0].host = host.into();
            assert!(snapshot(&backend, "domain1", "Ab_1").is_err());
        }
        backend.db.domains[0] = domain();
        backend.db.domains[0].prefix = "../admin".into();
        assert!(snapshot(&backend, "domain1", "Ab_1").is_err());
        backend.db.domains[0] = domain();
        backend.db.links[0].pool_id = Some("pool1".into());
        assert!(snapshot(&backend, "domain1", "Ab_1").is_err());
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn head_request_has_no_auth_and_never_requests_a_destination() {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let source = url::Url::parse("https://example.com/go/Ab_1").unwrap();
        let request = build_head_request(&client, &source).unwrap();
        assert_eq!(request.method(), reqwest::Method::HEAD);
        assert_eq!(request.url(), &source);
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
        assert!(request.headers().get(reqwest::header::COOKIE).is_none());
        assert!(request.headers().get("X-Selftest-Signature").is_none());
        assert!(include_str!("../../edge/worker.mjs")
            .contains("if (!head && selftest === null) recordClick"));
    }

    #[test]
    fn fixed_outcomes_hide_location_and_classify_uncertainty() {
        let expected = vec!["https://example.org/Aa?Code=xY".into()];
        for code in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::OK,
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(classify(code, None, &expected).0, ResultStatus::Unknown);
        }
        for code in [StatusCode::NOT_FOUND, StatusCode::GONE] {
            assert_eq!(classify(code, None, &expected).0, ResultStatus::Failed);
        }
        assert_eq!(
            classify(StatusCode::FOUND, None, &expected).1,
            "missing_location"
        );
        let value = outcome(
            classify(
                StatusCode::FOUND,
                Some("https://example.org/private?token=secret"),
                &expected,
            ),
            local_check::DnsMode::System,
        );
        assert_eq!(value["reason"], "location_mismatch");
        assert!(!value.to_string().contains("secret"));
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(
            classify(StatusCode::METHOD_NOT_ALLOWED, None, &expected).1,
            "method_unsupported"
        );
        assert_eq!(
            classify(StatusCode::UNAUTHORIZED, None, &expected).1,
            "authentication_required"
        );
    }

    #[test]
    fn duplicate_or_invalid_location_cannot_pass_and_unicode_target_uses_url_serialization() {
        let expected = vec![canonical_target("https://EXAMPLE.org/邀请?Code=甲").unwrap()];
        assert!(expected[0].contains("%E9%82%80"));
        let mut headers = HeaderMap::new();
        headers.append(LOCATION, expected[0].parse().unwrap());
        assert_eq!(
            classify_response(StatusCode::FOUND, &headers, &expected).0,
            ResultStatus::Passed
        );
        headers.append(LOCATION, expected[0].parse().unwrap());
        assert_eq!(
            classify_response(StatusCode::FOUND, &headers, &expected).1,
            "ambiguous_location"
        );
        let mut invalid = HeaderMap::new();
        invalid.append(
            LOCATION,
            reqwest::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_ne!(
            classify_response(StatusCode::FOUND, &invalid, &expected).0,
            ResultStatus::Passed
        );
    }

    #[tokio::test]
    async fn busy_probe_and_backend_lock_fail_without_waiting_or_reading_credentials() {
        let (_server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(manual_link());
        let state = AppState(Mutex::new(backend));
        let permit = probe_semaphore().try_acquire().unwrap();
        let busy = check_link_redirect(&state, "domain1", "Ab_1")
            .await
            .unwrap();
        assert_eq!(busy["status"], "unknown");
        assert_eq!(busy["reason"], "busy");
        drop(permit);
        let lock = state.0.lock().await;
        let busy = check_link_redirect(&state, "domain1", "Ab_1")
            .await
            .unwrap();
        assert_eq!(busy["reason"], "busy");
        drop(lock);
        assert!(mock_key_reads().lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn timeout_is_unknown_and_reports_the_dns_mode_reached() {
        let used_public = AtomicBool::new(true);
        let never = std::future::pending::<(Outcome, local_check::DnsMode)>();
        let value = bounded_result(Duration::from_millis(1), &used_public, never).await;
        assert_eq!(value["status"], "unknown");
        assert_eq!(value["reason"], "timeout");
        assert_eq!(value["dnsMode"], "public");
    }
}

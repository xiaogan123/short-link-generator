use super::*;
use tests::{domain, fixture};
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

const NAMESPACE: &str = "0123456789abcdef0123456789abcdef";
const SQL_PATH: &str = "/client/v4/accounts/acct1/analytics_engine/sql";

fn arrange(backend: &mut Backend) {
    backend.db.accounts[0].resources.as_mut().unwrap().namespace = NAMESPACE.into();
    backend.db.domains.push(domain());
    backend.db.links.push(Link {
        domain_id: "domain1".into(),
        slug: "OK".into(),
        cn_url: "https://example.org/private-target?code=private-referral".into(),
        default_url: "https://example.org/default".into(),
        updated: now(),
        pool_id: None,
        code: Some("private-referral".into()),
    });
}
async fn resource(server: &MockServer, enabled: bool) {
    let mut bindings = vec![
        json!({"type":"kv_namespace","name":"LINKS","namespace_id":NAMESPACE}),
        json!({"type":"secret_text","name":"SELFTEST_KEY"}),
    ];
    if enabled {
        bindings.push(click_stats::binding(NAMESPACE).unwrap());
    }
    let manifest = json!({"schema":SCHEMA,"accountId":"acct1","script":"edge-one","namespace":NAMESPACE,"sourceHash":bundled_source_hash()});
    Mock::given(method("GET"))
        .and(path(format!(
            "/client/v4/accounts/acct1/storage/kv/namespaces/{NAMESPACE}/values/m%3Aconfig"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(manifest.to_string()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/workers/scripts/edge-one/settings",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result":{"bindings":bindings}})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/workers/scripts/edge-one/content/v2",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("../../edge/worker.mjs"),
            "application/javascript",
        ))
        .mount(server)
        .await;
}
fn row(class: &str, kind: &str, reason: &str, count: Value) -> Value {
    json!({"classification":class,"traffic_kind":kind,"reason":reason,"count":count})
}
fn envelope(rows: Vec<Value>) -> Value {
    json!({"meta":[],"rows":rows.len(),"data":rows})
}
fn valid_groups() -> [(&'static str, &'static str, &'static str); 11] {
    [
        ("likely_bot", "preview", "ua_preview"),
        ("unknown", "prefetch", "prefetch_header"),
        ("likely_bot", "click", "cf_verified_bot"),
        ("likely_bot", "click", "cf_verified_bot_category"),
        ("likely_bot", "click", "cf_score_low"),
        ("likely_bot", "click", "ua_automation"),
        ("likely_bot", "click", "ua_bot"),
        ("likely_human", "click", "cf_score_high"),
        ("likely_human", "click", "browser_navigation"),
        ("unknown", "click", "missing_user_agent"),
        ("unknown", "click", "insufficient_signals"),
    ]
}
fn observed_aggregated_rows() -> Vec<Value> {
    vec![
        row("unknown", "click", "missing_user_agent", json!("1")),
        row("unknown", "click", "insufficient_signals", json!("1")),
        row("likely_bot", "click", "ua_bot", json!("2")),
        row("likely_bot", "preview", "ua_preview", json!("1")),
        row("likely_bot", "click", "ua_automation", json!("5")),
        row("unknown", "prefetch", "prefetch_header", json!("1")),
    ]
}
fn page_row(
    host: &str,
    prefix: &str,
    slug: &str,
    class: &str,
    kind: &str,
    reason: &str,
    count: Value,
) -> Value {
    json!({"host":host,"prefix":prefix,"canonical_slug":slug,
        "classification":class,"traffic_kind":kind,"reason":reason,"count":count})
}
async fn query(backend: &mut Backend, days: u64) -> Value {
    backend
        .dispatch(
            "get_link_stats",
            &json!({"domainId":"domain1","slug":"OK","days":days}),
        )
        .await
        .unwrap()
}
async fn center_query(backend: &mut Backend, domain_id: Option<&str>, page: u64) -> Value {
    let mut payload = json!({
        "accountId":"acct1",
        "days":7,
        "page":page,
        "pageSize":25
    });
    if let Some(domain_id) = domain_id {
        payload["domainId"] = json!(domain_id);
    }
    backend
        .dispatch("get_stats_center", &payload)
        .await
        .unwrap()
}

#[tokio::test]
async fn stats_validate_inputs_and_local_ownership_before_credentials() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    for payload in [
        json!({"domainId":"domain1","slug":"OK","days":0}),
        json!({"domainId":"domain1","slug":"OK","days":365}),
        json!({"domainId":"domain1","slug":"OK","days":"7"}),
        json!({"domainId":"domain1","slug":"OK","days":7.5}),
        json!({"domainId":"domain1","slug":"' OR 1=1","days":7}),
        json!({"domainId":"domain1","slug":"ok","days":7}),
        json!({"domainId":"foreign-domain","slug":"OK","days":7}),
    ] {
        assert!(backend.dispatch("get_link_stats", &payload).await.is_err());
    }
    backend.db.accounts[0].resources.as_mut().unwrap().namespace = "unsafe;dataset".into();
    assert!(backend
        .dispatch(
            "get_link_stats",
            &json!({"domainId":"domain1","slug":"OK","days":7})
        )
        .await
        .is_err());
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn stats_weighted_counts_query_only_owned_scope_and_keep_preview_prefetch_separate() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    resource(&server, true).await;
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![
            row("likely_human", "click", "browser_navigation", json!(3)),
            row("likely_bot", "click", "cf_verified_bot", json!("5")),
            row("unknown", "click", "missing_user_agent", json!(7)),
            row("likely_bot", "preview", "ua_preview", json!(11)),
            row("unknown", "prefetch", "prefetch_header", json!(13)),
        ])))
        .mount(&server)
        .await;
    let value = backend.dispatch("get_link_stats", &json!({"domainId":"domain1","slug":"OK","days":7,"accountId":"foreign","sql":"SELECT * FROM private","url":"http://example.org"})).await.unwrap();
    assert_eq!(value["status"], "ready");
    assert_eq!(
        value["totals"],
        json!({"total":15,"likelyHuman":3,"likelyBot":5,"unknown":7,"previews":11,"prefetches":13})
    );
    assert_eq!(value["estimated"], true);
    assert_eq!(value["domainId"], "domain1");
    assert_eq!(value["slug"], "OK");
    assert_eq!(*mock_key_reads().lock().unwrap(), vec!["token:acct1"]);
    let requests = server.received_requests().await.unwrap();
    let request = requests.iter().find(|r| r.method == "POST").unwrap();
    let sql = std::str::from_utf8(&request.body).unwrap();
    assert!(sql.contains(&format!("FROM slg_clicks_{NAMESPACE}")));
    for clause in [
        "SUM(_sample_interval)",
        "blob1 = 'v1'",
        "blob2 = 'example.com'",
        "blob3 = 'go'",
        "blob4 = 'OK'",
        "INTERVAL '7' DAY",
        "GROUP BY blob5, blob6, blob7 LIMIT 12 FORMAT JSON",
    ] {
        assert!(sql.contains(clause), "{clause}");
    }
    for private in [
        "private-target",
        "private-referral",
        "default",
        "foreign",
        "SELECT *",
        "http://",
    ] {
        assert!(!sql.contains(private));
    }
    assert!(requests
        .iter()
        .all(|r| r.method == "GET" || r.url.path() == SQL_PATH));
}

#[tokio::test]
async fn stats_accepts_pre_aggregation_event_metadata() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    resource(&server, true).await;
    let mut body = envelope(observed_aggregated_rows());
    body["rows_before_limit_at_least"] = json!(11);
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let value = query(&mut backend, 7).await;
    assert_eq!(value["status"], "ready");
    assert_eq!(
        value["totals"],
        json!({"total":9,"likelyHuman":0,"likelyBot":7,"unknown":2,"previews":1,"prefetches":1})
    );
}

#[tokio::test]
async fn stats_disabled_has_no_analytics_query_and_no_fake_totals() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    resource(&server, false).await;
    let value = query(&mut backend, 1).await;
    assert_eq!(value["status"], "disabled");
    assert!(value.get("totals").is_none());
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| r.method == "GET"));
}

#[tokio::test]
async fn stats_empty_is_no_data_but_zero_weight_group_is_ready() {
    for (rows, expected) in [
        (vec![], "no_data"),
        (
            vec![row("unknown", "click", "insufficient_signals", json!(0))],
            "ready",
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        arrange(&mut backend);
        resource(&server, true).await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope(rows)))
            .mount(&server)
            .await;
        let value = query(&mut backend, 30).await;
        assert_eq!(value["status"], expected);
        assert_eq!(value.get("totals").is_some(), expected == "ready");
    }
}

#[tokio::test]
async fn stats_provider_failures_are_sanitized_and_never_counts() {
    for status in [401, 403, 400, 404, 429, 500, 503, 302] {
        let (server, mut backend, _guard) = fixture().await;
        arrange(&mut backend);
        resource(&server, true).await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", "http://example.org/private")
                    .set_body_string("private-token-or-query-provider-error"),
            )
            .mount(&server)
            .await;
        let value = query(&mut backend, 7).await;
        assert_eq!(
            value["status"],
            if [401, 403].contains(&status) {
                "permission_denied"
            } else {
                "unavailable"
            }
        );
        assert!(value.get("totals").is_none());
        assert!(!value.to_string().contains("private-token"));
        if [401, 403].contains(&status) {
            let message = value["message"].as_str().unwrap();
            assert!(message.contains("Cloudflare 拒绝统计读取"));
            assert!(message.contains("账户分析 · 读取"));
            assert!(message.contains("启用 Analytics Engine"));
            assert!(!message.contains("增加"));
        }
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn stats_reject_malformed_unknown_duplicate_or_overflow_data() {
    let valid = row("likely_human", "click", "browser_navigation", json!(1));
    let mut wrong_rows = envelope(vec![valid.clone()]);
    wrong_rows["rows"] = json!(2);
    let mut extra = valid.clone();
    extra["raw_ua"] = json!("private-ua");
    let mut error = envelope(vec![]);
    error["exception"] = json!("private-query");
    let mut cases = vec![
        json!({}),
        json!({"data":[],"rows":"0"}),
        wrong_rows,
        error,
        envelope(vec![valid.clone(), valid]),
        envelope(vec![extra]),
        envelope(vec![row("human", "click", "browser_navigation", json!(1))]),
        envelope(vec![row("likely_human", "preview", "ua_preview", json!(1))]),
        envelope(vec![row(
            "likely_human",
            "click",
            "unknown_reason",
            json!(1),
        )]),
        envelope(vec![
            row(
                "likely_human",
                "click",
                "browser_navigation",
                json!(9_007_199_254_740_991_u64),
            ),
            row("unknown", "click", "missing_user_agent", json!(1)),
        ]),
        envelope(
            (0..12)
                .map(|_| row("likely_human", "click", "browser_navigation", json!(1)))
                .collect(),
        ),
    ];
    for count in [
        json!(-1),
        json!(0.5),
        json!("NaN"),
        json!("Infinity"),
        json!(true),
        Value::Null,
        json!("-1"),
        json!(9_007_199_254_740_992_u64),
        json!("18446744073709551616"),
    ] {
        cases.push(envelope(vec![row(
            "likely_human",
            "click",
            "browser_navigation",
            count,
        )]));
    }
    for body in cases {
        let (server, mut backend, _guard) = fixture().await;
        arrange(&mut backend);
        resource(&server, true).await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let value = query(&mut backend, 7).await;
        assert_eq!(value["status"], "unavailable", "{body}");
        assert!(value.get("totals").is_none());
        assert!(!value.to_string().contains("private-"));
    }
}

#[tokio::test]
async fn stats_bounds_response_body_and_rejects_invalid_json() {
    for body in ["not JSON".to_owned(), " ".repeat(65537)] {
        let (server, mut backend, _guard) = fixture().await;
        arrange(&mut backend);
        resource(&server, true).await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let value = query(&mut backend, 7).await;
        assert_eq!(value["status"], "unavailable");
        assert!(value.get("totals").is_none());
    }
}

#[tokio::test]
async fn stats_center_validates_range_scope_and_pagination_before_credentials() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    let mut other = backend.db.accounts[0].clone();
    other.id = "acct2".into();
    backend.db.accounts.push(other);
    backend.db.domains.push(Domain {
        id: "domain2".into(),
        account_id: "acct2".into(),
        zone_id: "zone2".into(),
        host: "other.example.com".into(),
        prefix: "go".into(),
        route_id: "route2".into(),
    });

    for payload in [
        json!({"accountId":"missing","days":7,"page":1,"pageSize":25}),
        json!({"accountId":"acct1","domainId":"domain2","days":7,"page":1,"pageSize":25}),
        json!({"accountId":"acct1","domainId":"","days":7,"page":1,"pageSize":25}),
        json!({"accountId":"acct1","days":2,"page":1,"pageSize":25}),
        json!({"accountId":"acct1","days":7,"page":0,"pageSize":25}),
        json!({"accountId":"acct1","days":7,"page":"1","pageSize":25}),
        json!({"accountId":"acct1","days":7,"page":1,"pageSize":24}),
        json!({"accountId":"acct1","days":7,"page":u64::MAX,"pageSize":25}),
    ] {
        assert!(
            backend
                .dispatch("get_stats_center", &payload)
                .await
                .is_err(),
            "{payload}"
        );
    }
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn stats_center_empty_local_scope_does_not_read_credentials_or_claim_history_empty() {
    let (server, mut backend, _guard) = fixture().await;
    let value = center_query(&mut backend, None, 1).await;
    assert_eq!(value["status"], "no_data");
    assert_eq!(value["accountId"], "acct1");
    assert!(value["domainId"].is_null());
    assert_eq!(value["totalLinks"], 0);
    assert_eq!(value["rows"], json!([]));
    assert!(value.get("totals").is_none());
    assert!(value["message"].as_str().unwrap().contains("本机"));
    assert!(!value["message"].as_str().unwrap().contains("历史为空"));
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn stats_center_summary_covers_scope_while_rows_only_cover_stable_current_page() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    backend.db.domains.push(Domain {
        id: "domain2".into(),
        account_id: "acct1".into(),
        zone_id: "zone1".into(),
        host: "second.example.com".into(),
        prefix: "out".into(),
        route_id: "route2".into(),
    });
    for index in 0..25 {
        backend.db.links.push(Link {
            domain_id: "domain2".into(),
            slug: format!("S{index:02}"),
            cn_url: "https://example.org/cn".into(),
            default_url: "https://example.org/default".into(),
            updated: now(),
            pool_id: None,
            code: None,
        });
    }
    resource(&server, true).await;
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob5 AS classification"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![
            row("likely_human", "click", "browser_navigation", json!(30)),
            row("likely_bot", "click", "cf_score_low", json!(20)),
            row("unknown", "click", "insufficient_signals", json!(10)),
            row("likely_bot", "preview", "ua_preview", json!(4)),
            row("unknown", "prefetch", "prefetch_header", json!(2)),
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob2 AS host"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![
            page_row(
                "second.example.com",
                "out",
                "S24",
                "likely_human",
                "click",
                "browser_navigation",
                json!("3"),
            ),
            page_row(
                "second.example.com",
                "out",
                "S24",
                "likely_bot",
                "preview",
                "ua_preview",
                json!(1),
            ),
        ])))
        .mount(&server)
        .await;

    let value = center_query(&mut backend, None, 2).await;
    assert_eq!(value["status"], "ready");
    assert_eq!(value["totalLinks"], 26);
    assert_eq!(value["page"], 2);
    assert_eq!(value["pageSize"], 25);
    assert_eq!(
        value["totals"],
        json!({"total":60,"likelyHuman":30,"likelyBot":20,"unknown":10,"previews":4,"prefetches":2})
    );
    assert_eq!(
        value["rows"],
        json!([{"domainId":"domain2","slug":"S24","totals":{
            "total":3,"likelyHuman":3,"likelyBot":0,"unknown":0,"previews":1,"prefetches":0
        }}])
    );
    assert!(value["message"].as_str().unwrap().contains("已删除链接"));
    assert_eq!(*mock_key_reads().lock().unwrap(), vec!["token:acct1"]);

    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .map(|request| std::str::from_utf8(&request.body).unwrap())
        .collect();
    assert_eq!(posts.len(), 2);
    let summary = posts
        .iter()
        .find(|query| query.starts_with("SELECT blob5"))
        .unwrap();
    for clause in [
        "blob2 = 'example.com' AND blob3 = 'go'",
        "blob2 = 'second.example.com' AND blob3 = 'out'",
        "GROUP BY blob5, blob6, blob7 LIMIT 12",
    ] {
        assert!(summary.contains(clause), "{clause}");
    }
    assert!(!summary.contains("blob4 ="));
    let detail = posts
        .iter()
        .find(|query| query.starts_with("SELECT blob2"))
        .unwrap();
    assert!(detail.contains("blob4 = 'S24'"));
    assert!(!detail.contains("blob4 = 'S23'"));
    assert!(!detail.contains("blob4 = 'OK'"));
    assert!(detail.contains("LIMIT 12 FORMAT JSON"));
}

#[tokio::test]
async fn stats_center_accepts_pre_aggregation_event_metadata_for_summary_and_page() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    resource(&server, true).await;

    let mut summary = envelope(observed_aggregated_rows());
    summary["rows_before_limit_at_least"] = json!(11);
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob5 AS classification"))
        .respond_with(ResponseTemplate::new(200).set_body_json(summary))
        .mount(&server)
        .await;

    let mut detail = envelope(
        observed_aggregated_rows()
            .into_iter()
            .map(|group| {
                page_row(
                    "example.com",
                    "go",
                    "OK",
                    group["classification"].as_str().unwrap(),
                    group["traffic_kind"].as_str().unwrap(),
                    group["reason"].as_str().unwrap(),
                    group["count"].clone(),
                )
            })
            .collect(),
    );
    detail["rows_before_limit_at_least"] = json!(11);
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob2 AS host"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .mount(&server)
        .await;

    let value = center_query(&mut backend, Some("domain1"), 1).await;
    let expected =
        json!({"total":9,"likelyHuman":0,"likelyBot":7,"unknown":2,"previews":1,"prefetches":1});
    assert_eq!(value["status"], "ready");
    assert_eq!(value["totals"], expected);
    assert_eq!(value["rows"][0]["totals"], expected);
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        2
    );
}

#[tokio::test]
async fn stats_center_no_data_keeps_summary_status_and_zero_fills_current_rows() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    resource(&server, true).await;
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob5 AS classification"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![])))
        .mount(&server)
        .await;

    let value = center_query(&mut backend, Some("domain1"), 1).await;
    assert_eq!(value["status"], "no_data");
    assert_eq!(value["domainId"], "domain1");
    assert!(value.get("totals").is_none());
    assert_eq!(
        value["rows"],
        json!([{"domainId":"domain1","slug":"OK","totals":{
            "total":0,"likelyHuman":0,"likelyBot":0,"unknown":0,"previews":0,"prefetches":0
        }}])
    );
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1
    );
}

#[tokio::test]
async fn stats_center_empty_page_skips_detail_query_but_keeps_scope_totals() {
    let (server, mut backend, _guard) = fixture().await;
    arrange(&mut backend);
    resource(&server, true).await;
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob5 AS classification"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![row(
            "likely_human",
            "click",
            "browser_navigation",
            json!(8),
        )])))
        .mount(&server)
        .await;

    let value = center_query(&mut backend, None, 2).await;
    assert_eq!(value["status"], "ready");
    assert_eq!(value["totalLinks"], 1);
    assert_eq!(value["rows"], json!([]));
    assert_eq!(value["totals"]["total"], 8);
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1
    );
}

#[tokio::test]
async fn stats_center_rejects_corrupt_summary_or_detail_without_partial_success() {
    for corrupt_summary in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        arrange(&mut backend);
        resource(&server, true).await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .and(body_string_contains("SELECT blob5 AS classification"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(if corrupt_summary {
                    json!({"rows":1,"data":"private-corrupt"})
                } else {
                    envelope(vec![row(
                        "likely_human",
                        "click",
                        "browser_navigation",
                        json!(9),
                    )])
                }),
            )
            .mount(&server)
            .await;
        if !corrupt_summary {
            Mock::given(method("POST"))
                .and(path(SQL_PATH))
                .and(body_string_contains("SELECT blob2 AS host"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows":1,
                    "data":"private-corrupt"
                })))
                .mount(&server)
                .await;
        }

        let value = center_query(&mut backend, None, 1).await;
        assert_eq!(value["status"], "unavailable");
        assert!(value.get("totals").is_none());
        assert!(value.get("rows").is_none());
        assert!(!value.to_string().contains("private-corrupt"));
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            if corrupt_summary { 1 } else { 2 }
        );
    }
}

#[tokio::test]
async fn stats_center_accepts_a_full_legal_page_larger_than_single_link_budget() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.accounts[0].resources.as_mut().unwrap().namespace = NAMESPACE.into();
    let host = format!(
        "{}.{}.{}.example.com",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60)
    );
    backend.db.domains.push(Domain {
        id: "domain-long".into(),
        account_id: "acct1".into(),
        zone_id: "zone1".into(),
        host: host.clone(),
        prefix: "campaign".into(),
        route_id: "route-long".into(),
    });
    let slugs: Vec<_> = (0..25)
        .map(|index| format!("S{index:02}{}", "x".repeat(29)))
        .collect();
    for slug in &slugs {
        backend.db.links.push(Link {
            domain_id: "domain-long".into(),
            slug: slug.clone(),
            cn_url: "https://example.org/cn".into(),
            default_url: "https://example.org/default".into(),
            updated: now(),
            pool_id: None,
            code: None,
        });
    }
    resource(&server, true).await;
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob5 AS classification"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![row(
            "likely_human",
            "click",
            "browser_navigation",
            json!(25),
        )])))
        .mount(&server)
        .await;
    let detail = envelope(
        slugs
            .iter()
            .flat_map(|slug| {
                valid_groups().map(|(class, kind, reason)| {
                    page_row(&host, "campaign", slug, class, kind, reason, json!(1))
                })
            })
            .collect(),
    );
    let detail_bytes = serde_json::to_vec(&detail).unwrap().len();
    assert!(detail_bytes > 64 * 1024, "{detail_bytes}");
    assert!(detail_bytes < 256 * 1024, "{detail_bytes}");
    Mock::given(method("POST"))
        .and(path(SQL_PATH))
        .and(body_string_contains("SELECT blob2 AS host"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .mount(&server)
        .await;

    let value = center_query(&mut backend, None, 1).await;
    assert_eq!(value["status"], "ready");
    assert_eq!(value["rows"].as_array().unwrap().len(), 25);
    for row in value["rows"].as_array().unwrap() {
        assert_eq!(
            row["totals"],
            json!({"total":9,"likelyHuman":2,"likelyBot":5,"unknown":2,"previews":1,"prefetches":1})
        );
    }
}

#[tokio::test]
async fn stats_center_bounds_large_provider_fields_and_detail_group_count() {
    let oversized_valid_json = json!({
        "meta":"x".repeat(256 * 1024),
        "rows":1,
        "data":[page_row(
            "example.com",
            "go",
            "OK",
            "likely_human",
            "click",
            "browser_navigation",
            json!(1),
        )]
    });
    assert!(serde_json::to_vec(&oversized_valid_json).unwrap().len() > 256 * 1024);
    for body in [
        oversized_valid_json,
        envelope(
            (0..12)
                .map(|_| {
                    page_row(
                        "example.com",
                        "go",
                        "OK",
                        "likely_human",
                        "click",
                        "browser_navigation",
                        json!(1),
                    )
                })
                .collect(),
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        arrange(&mut backend);
        resource(&server, true).await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .and(body_string_contains("SELECT blob5 AS classification"))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope(vec![row(
                "likely_human",
                "click",
                "browser_navigation",
                json!(1),
            )])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(SQL_PATH))
            .and(body_string_contains("SELECT blob2 AS host"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let value = center_query(&mut backend, None, 1).await;
        assert_eq!(value["status"], "unavailable");
        assert!(value.get("totals").is_none());
        assert!(value.get("rows").is_none());
    }
}

#[tokio::test]
async fn stats_center_bounds_generated_sql_before_credentials() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.accounts[0].resources.as_mut().unwrap().namespace = NAMESPACE.into();
    for index in 0..180 {
        let domain_id = format!("d{index:03}");
        backend.db.domains.push(Domain {
            id: domain_id.clone(),
            account_id: "acct1".into(),
            zone_id: "zone1".into(),
            host: format!(
                "{index:03}.{}.{}.{}.example.com",
                "a".repeat(55),
                "b".repeat(55),
                "c".repeat(55)
            ),
            prefix: "go".into(),
            route_id: format!("r{index:03}"),
        });
        backend.db.links.push(Link {
            domain_id,
            slug: format!("S{index:03}"),
            cn_url: "https://example.org/cn".into(),
            default_url: "https://example.org/default".into(),
            updated: now(),
            pool_id: None,
            code: None,
        });
    }

    let error = backend
        .dispatch(
            "get_stats_center",
            &json!({"accountId":"acct1","days":30,"page":1,"pageSize":25}),
        )
        .await
        .unwrap_err();
    assert!(error.contains("统计范围过大"));
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

//! Ways out after a write whose answer was lost: dismissing a plain pending
//! record, clearing settled records automatically, recognising leftovers of an
//! unfinished domain setup, and checking the cloud before calling a write
//! uncertain.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tests::{
    domain, fixture, mount_domain_hard_checks, mount_domain_probes, mount_owned_domain,
    mount_recovery_without_pool, mount_resource, ok, url_link,
};
use wiremock::{
    matchers::{method, path, path_regex, query_param},
    Mock, MockServer, Request, ResponseTemplate,
};

const CONFIG_PATH: &str =
    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com";
const ROUTES_PATH: &str = "/client/v4/zones/zone1/workers/routes";
const SHORT_PATH: &str =
    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort";
const KEYS_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys";

/// Link keys of example.com left in the cloud.
async fn mount_host_links(server: &MockServer, links: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(KEYS_PATH))
        .and(query_param("prefix", "l:example.com:"))
        .respond_with(links)
        .mount(server)
        .await;
}

fn writes(requests: &[Request]) -> Vec<&Request> {
    requests
        .iter()
        .filter(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE"))
        .collect()
}

async fn requests(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap()
}

fn saved(backend: &Backend) -> Database {
    serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap()
}

/// Mounts zone, DNS, the given route list and 404 probes for example.com/go.
async fn mount_domain_checks(server: &MockServer, routes: Value) {
    mount_domain_hard_checks(
        server,
        json!([{"name":"example.com","type":"A","proxied":true}]),
        routes,
    )
    .await;
    mount_domain_probes(
        server,
        ResponseTemplate::new(404),
        ResponseTemplate::new(404),
    )
    .await;
}

async fn add_example_domain(backend: &mut Backend) -> Result<(), String> {
    let risk = PathRiskSnapshot {
        root: domain_check::ProbeRisk::Missing,
        child: domain_check::ProbeRisk::Missing,
        probe_segment: "probe-fixed".into(),
    };
    backend
        .apply_domain(
            "acct1",
            "zone1",
            "example.com",
            "go",
            DomainTakeover {
                dns_mode: local_check::DnsMode::System,
                expected_path_risk: &risk,
                requires_confirmation: false,
                acknowledged: false,
            },
        )
        .await
}

// ---- A1: dismissing a plain record -------------------------------------

#[tokio::test]
async fn dismiss_removes_only_the_first_exact_record_and_touches_no_cloud() {
    let (server, mut backend, _guard) = fixture().await;
    let entry = "添加域名 example.com (old)：云端结果不确定，需要人工核对";
    backend.db.pending_operations = vec![
        "保存链接 example.com / short (a)".into(),
        entry.into(),
        format!("{entry}（另一条）"),
        entry.into(),
    ];
    backend.persist().unwrap();
    let plan = backend
        .prepare_change(&json!({"kind":"dismiss_pending_operation","entry":entry}))
        .unwrap();
    assert_eq!(plan["title"], "清除待处理记录");
    assert_eq!(plan["steps"][0], "只从本机删除这条记录，不改动云端");
    assert_eq!(
        plan["warnings"][0],
        "请先确认这条记录对应的云端状态已经核对过"
    );
    let state = backend
        .dispatch("apply_plan", &json!({"planId": plan["id"]}))
        .await
        .unwrap();
    let expected = vec![
        "保存链接 example.com / short (a)".to_string(),
        format!("{entry}（另一条）"),
        entry.to_string(),
    ];
    assert_eq!(backend.db.pending_operations, expected);
    assert_eq!(saved(&backend).pending_operations, expected);
    assert_eq!(state["pendingOperations"], json!(expected));
    assert!(requests(&server).await.is_empty());
    assert!(mock_key_reads().lock().unwrap().is_empty());
}

#[tokio::test]
async fn dismiss_rejects_missing_records_and_records_with_their_own_entry() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.pending_operations = vec![
        "重置自检密钥 acct1 (r)：云端结果不确定".into(),
        "清理账号 acct1 (c)：删除结果不确定".into(),
        "清理账号 gone-account (c)：删除结果不确定".into(),
        "添加域名 example.com (a)".into(),
    ];
    let prepare = |backend: &mut Backend, entry: &str| {
        backend.prepare_change(&json!({"kind":"dismiss_pending_operation","entry":entry}))
    };
    assert_eq!(
        prepare(&mut backend, "添加域名 example.com (a").unwrap_err(),
        RECORD_GONE
    );
    assert!(prepare(&mut backend, "添加域名 example.com (a)：")
        .unwrap_err()
        .contains("已经不在了"));
    let error = prepare(&mut backend, "重置自检密钥 acct1 (r)：云端结果不确定").unwrap_err();
    assert!(error.contains("不能直接清除"), "{error}");
    assert!(
        error.contains("页面上方“……项变更可继续处理”那一栏里的「"),
        "{error}"
    );
    assert!(!error.contains("首页"), "{error}");
    let error = prepare(&mut backend, "清理账号 acct1 (c)：删除结果不确定").unwrap_err();
    assert!(error.contains("「删除云端短链接服务」"), "{error}");
    // The record shows only the account ID, so the text names the account.
    assert!(
        error.contains("打开账户「账号 1」的「管理账户」"),
        "{error}"
    );
    assert!(backend
        .prepare_change(&json!({"kind":"dismiss_pending_operation"}))
        .unwrap_err()
        .contains("缺少参数：entry"));
    assert!(backend.plans.is_empty());
    // A cleanup record of an account that is no longer here has no button.
    prepare(&mut backend, "清理账号 gone-account (c)：删除结果不确定").unwrap();
    // Apply checks again: a record that went away in between is reported.
    backend
        .db
        .pending_operations
        .retain(|e| e != "添加域名 example.com (a)");
    assert_eq!(
        backend
            .dismiss_pending_operation("添加域名 example.com (a)")
            .unwrap_err(),
        RECORD_GONE
    );
    // Once the account has a local domain again, the cleanup refuses to run
    // ("此账号仍有域名"), so its record may be dismissed by hand.
    backend.db.domains.push(domain());
    backend
        .dismiss_pending_operation("清理账号 acct1 (c)：删除结果不确定")
        .unwrap();
    assert!(!backend
        .db
        .pending_operations
        .iter()
        .any(|e| e.starts_with("清理账号 acct1 (")));
    // An account removed from this computer and imported again has no
    // recorded resources: the cleanup refuses ("此账号没有已登记资源"), so the
    // record may be dismissed by hand as well.
    backend.db.domains.clear();
    backend.db.pending_operations = vec!["清理账号 acct1 (c)：删除结果不确定".into()];
    assert!(prepare(&mut backend, "清理账号 acct1 (c)：删除结果不确定").is_err());
    backend.db.accounts[0].resources = None;
    assert!(backend
        .db
        .dedicated_recovery_entry("清理账号 acct1 (c)：删除结果不确定")
        .is_none());
    backend
        .dismiss_pending_operation("清理账号 acct1 (c)：删除结果不确定")
        .unwrap();
    assert!(backend.db.pending_operations.is_empty());
    assert!(requests(&server).await.is_empty());
}

/// Records that may be cleared by hand but that one more click finishes get
/// advice naming that click, and only while the click exists.
#[tokio::test]
async fn resume_hint_names_the_click_only_while_it_exists() {
    let (_server, mut backend, _guard) = fixture().await;
    let removal = "移除域名 example.com (old)：链接删除结果不确定";
    let revived = format!("添加域名 example.com (new)：{}", revived_links_note(2));
    assert!(revived.contains(model::REVIVED_LINKS_MARK));
    // The domain is not on this computer: there is nothing to click.
    assert_eq!(backend.db.resume_hint(removal), None);
    assert_eq!(backend.db.resume_hint(&revived), None);
    backend.db.domains.push(domain());
    assert_eq!(
        backend.db.resume_hint(removal).as_deref(),
        Some("到「域名管理」对域名 example.com 再点一次「移除域名」把它做完")
    );
    assert_eq!(
        backend.db.resume_hint(&revived).as_deref(),
        Some("到「Cloudflare 账户」页打开账户「账号 1」的「管理账户」，点「从 Cloudflare 找回配置」把那些短链接找回来")
    );
    // Other records of the host, and records of other hosts, get none.
    for entry in [
        "添加域名 example.com (a)：云端结果不确定，需要人工核对",
        "移除域名 www.example.com (old)：链接删除结果不确定",
        "保存链接 example.com / short (abc)",
        "",
    ] {
        assert_eq!(backend.db.resume_hint(entry), None, "{entry}");
    }
    // Advice only: both stay dismissable by hand.
    assert!(backend.db.dedicated_recovery_entry(removal).is_none());
    assert!(backend.db.dedicated_recovery_entry(&revived).is_none());
}

#[tokio::test]
async fn dismiss_refuses_structured_recovery_records_and_keeps_record_on_save_failure() {
    let (_server, mut backend, _guard) = fixture().await;
    backend
        .db
        .pending_monitor_changes
        .push(PendingMonitorChange {
            account_id: "acct1".into(),
            endpoint: "https://probe.example/check".into(),
            enabled: true,
            journal: "启用监测 acct1 (m)".into(),
        });
    backend.db.pending_operations = vec![
        "启用监测 acct1 (m)：写入结果不确定".into(),
        "移除域名 example.com (x)：路由删除结果不确定".into(),
    ];
    let error = backend
        .prepare_change(&json!({"kind":"dismiss_pending_operation",
            "entry":"启用监测 acct1 (m)：写入结果不确定"}))
        .unwrap_err();
    assert!(error.contains("「继续处理监测」"), "{error}");
    let before = backend.db.pending_operations.clone();
    backend.fail_persist_at.store(
        backend.persist_count.load(Ordering::SeqCst) + 1,
        Ordering::SeqCst,
    );
    assert!(backend
        .dismiss_pending_operation("移除域名 example.com (x)：路由删除结果不确定")
        .is_err());
    assert_eq!(backend.db.pending_operations, before);
}

/// A note naming cloud leftovers is never cleared automatically, so the manual
/// way out must accept it; otherwise it would block Worker upgrades for good.
#[tokio::test]
async fn note_naming_cloud_leftovers_can_be_dismissed_by_hand() {
    let (server, mut backend, _guard) = fixture().await;
    let note = format!(
        "添加域名 example.com（计划 KV links-a，Worker edge-a，f）：云端结果不确定，需要人工核对；{UNDO_INCOMPLETE}，可能还留着 KV links-a（ID ns-a），请到 Cloudflare 后台核对后删除"
    );
    backend.db.pending_operations = vec![note.clone()];
    backend.persist().unwrap();
    let plan = backend
        .prepare_change(&json!({"kind":"dismiss_pending_operation","entry":note}))
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId": plan["id"]}))
        .await
        .unwrap();
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
    assert!(requests(&server).await.is_empty());
}

// ---- A1: records settled automatically ---------------------------------

#[tokio::test]
async fn adding_a_domain_clears_earlier_add_records_of_the_same_host() {
    let (server, mut backend, _guard) = fixture().await;
    let undo_note = format!(
        "添加域名 example.com（计划 KV links-b，Worker edge-b，old3）：云端结果不确定，需要人工核对；{UNDO_INCOMPLETE}，可能还留着 KV links-b"
    );
    // The new-account form names resources and is kept (see below).
    let kept = vec![
        "添加域名 example.com（计划 KV links-a，Worker edge-a，old2）：云端结果不确定，需要人工核对"
            .to_string(),
        "添加域名 www.example.com (x)".to_string(),
        "添加域名 example.com.example (y)".to_string(),
        "移除域名 example.com (z)：路由删除结果不确定".to_string(),
        undo_note,
    ];
    backend.db.pending_operations =
        vec!["添加域名 example.com (old1)：云端结果不确定，需要人工核对".into()];
    backend.db.pending_operations.extend(kept.clone());
    mount_domain_checks(&server, json!([])).await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!({"id":"route-new"})))
        .mount(&server)
        .await;
    add_example_domain(&mut backend).await.unwrap();
    assert_eq!(backend.db.domains.len(), 1);
    assert_eq!(backend.db.pending_operations, kept);
    assert_eq!(saved(&backend).pending_operations, kept);
}

#[tokio::test]
async fn removing_a_domain_clears_earlier_remove_records_of_the_same_host() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let kept = vec![
        "移除域名 www.example.com (w)：路由删除结果不确定".to_string(),
        "添加域名 example.com (a)".to_string(),
    ];
    backend.db.pending_operations = vec!["移除域名 example.com (old)：路由删除结果不确定".into()];
    backend.db.pending_operations.extend(kept.clone());
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_owned_domain(&server).await;
    Mock::given(method("DELETE"))
        .and(path(CONFIG_PATH))
        .respond_with(ok(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/client/v4/zones/zone1/workers/routes/route1"))
        .respond_with(ok(json!({})))
        .mount(&server)
        .await;
    backend.apply_remove_domain("domain1").await.unwrap();
    assert!(backend.db.domains.is_empty());
    assert_eq!(backend.db.pending_operations, kept);
    assert_eq!(saved(&backend).pending_operations, kept);
}

#[tokio::test]
async fn recovery_clears_domain_and_link_records_for_the_accounts_hosts() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let undo_note = format!(
        "添加域名 example.com（计划 KV links-a，Worker edge-a，f）：云端结果不确定，需要人工核对；{UNDO_INCOMPLETE}，可能还留着 KV links-a"
    );
    let kept = vec![
        "添加域名 example.org (e)".to_string(),
        undo_note,
        "修复 DNS example.com (g)".to_string(),
    ];
    backend.db.pending_operations = vec![
        "添加域名 example.com (a)：云端结果不确定，需要人工核对".into(),
        "移除域名 example.com (b)：路由删除结果不确定".into(),
        "保存链接 example.com / short (c)：写入结果不确定，需要人工核对".into(),
        "删除链接 sub.example.com / x (d)：删除结果不确定，需要人工核对".into(),
    ];
    backend.db.pending_operations.extend(kept.clone());
    mount_recovery_without_pool(&server, false).await;
    backend.recover_account("acct1").await.unwrap();
    assert_eq!(backend.db.domains.len(), 1);
    assert_eq!(backend.db.pending_operations, kept);
    assert_eq!(saved(&backend).pending_operations, kept);
    assert!(writes(&requests(&server).await).is_empty());
}

/// The new-account record of a first setup whose rollback did not finish:
/// the only place naming the KV and Worker that may be left in the cloud.
fn rollback_record_with_names() -> String {
    format!("添加域名 example.com（计划 KV links-a，Worker edge-a，r1）：{ROLLBACK_INCOMPLETE}")
}

/// The existing-account form names no resources.
fn rollback_record_without_names() -> String {
    format!("添加域名 example.com (r2)：{ROLLBACK_INCOMPLETE}")
}

#[test]
fn only_records_naming_resources_count_as_leftover_names() {
    assert!(names_leftover_resources(&rollback_record_with_names()));
    assert!(names_leftover_resources(&format!(
        "添加域名 example.com（计划 KV links-a，Worker edge-a，f）：云端结果不确定，需要人工核对；{UNDO_INCOMPLETE}，可能还留着 KV links-a"
    )));
    assert!(!names_leftover_resources(&rollback_record_without_names()));
    assert!(!names_leftover_resources(
        "添加域名 example.com (r2)：云端结果不确定，需要人工核对"
    ));
    // Every new-account record may name resources that exist, whatever its
    // note: the KV create in flight, the progress notes, an unclear answer.
    for note in [
        "",
        "：已建 KV，正在上传 Worker",
        "：已建 Worker，正在写资源清单",
        "：云端结果不确定，需要人工核对",
        "：已写前缀配置，正在创建路由",
    ] {
        let entry = format!("添加域名 example.com（计划 KV links-a，Worker edge-a，r1）{note}");
        assert!(names_leftover_resources(&entry), "{entry}");
    }
    // The planned names must sit in the record ID, not only in the note.
    assert!(!names_leftover_resources(
        "添加域名 example.com (r3)：见（计划 KV links-a）"
    ));
}

#[tokio::test]
async fn adding_a_domain_keeps_new_account_records_whatever_their_note() {
    let (server, mut backend, _guard) = fixture().await;
    let kept = vec![
        "添加域名 example.com（计划 KV links-a，Worker edge-a，p1）：已建 KV，正在上传 Worker"
            .to_string(),
        "添加域名 example.com（计划 KV links-b，Worker edge-b，p2）：已建 Worker，正在写资源清单"
            .to_string(),
        "添加域名 example.com（计划 KV links-c，Worker edge-c，p3）".to_string(),
    ];
    backend.db.pending_operations = kept.clone();
    mount_domain_checks(&server, json!([])).await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!({"id":"route-new"})))
        .mount(&server)
        .await;
    add_example_domain(&mut backend).await.unwrap();
    assert_eq!(backend.db.pending_operations, kept);
    assert_eq!(saved(&backend).pending_operations, kept);
    // They stay dismissable by hand.
    for entry in &kept {
        backend
            .prepare_change(&json!({"kind":"dismiss_pending_operation","entry":entry}))
            .unwrap();
    }
}

#[tokio::test]
async fn adding_a_domain_keeps_a_rollback_record_that_names_resources() {
    let (server, mut backend, _guard) = fixture().await;
    let kept = vec![rollback_record_with_names()];
    backend.db.pending_operations = vec![rollback_record_without_names()];
    backend.db.pending_operations.extend(kept.clone());
    mount_domain_checks(&server, json!([])).await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!({"id":"route-new"})))
        .mount(&server)
        .await;
    add_example_domain(&mut backend).await.unwrap();
    assert_eq!(backend.db.domains.len(), 1);
    assert_eq!(backend.db.pending_operations, kept);
    assert_eq!(saved(&backend).pending_operations, kept);
}

#[tokio::test]
async fn recovery_keeps_a_rollback_record_that_names_resources() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let kept = vec![rollback_record_with_names()];
    backend.db.pending_operations = vec![rollback_record_without_names()];
    backend.db.pending_operations.extend(kept.clone());
    mount_recovery_without_pool(&server, false).await;
    backend.recover_account("acct1").await.unwrap();
    assert_eq!(backend.db.pending_operations, kept);
    assert_eq!(saved(&backend).pending_operations, kept);
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn rollback_record_that_names_resources_can_be_dismissed_by_hand() {
    let (server, mut backend, _guard) = fixture().await;
    let record = rollback_record_with_names();
    backend.db.pending_operations = vec![record.clone()];
    backend.persist().unwrap();
    let plan = backend
        .prepare_change(&json!({"kind":"dismiss_pending_operation","entry":record}))
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId": plan["id"]}))
        .await
        .unwrap();
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
    assert!(requests(&server).await.is_empty());
}

// ---- A2: leftovers of an unfinished domain setup -----------------------

#[tokio::test]
async fn leftover_prefix_config_with_same_prefix_is_kept_and_route_created() {
    for (stored, rewritten) in [
        (r#"{"prefix":"go"}"#, false),
        (r#"{"prefix":"other"}"#, true),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_checks(&server, json!([])).await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_host_links(&server, ok(json!([]))).await;
        Mock::given(method("GET"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(stored))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(ROUTES_PATH))
            .respond_with(ok(json!({"id":"route-new"})))
            .expect(1)
            .mount(&server)
            .await;
        add_example_domain(&mut backend).await.unwrap();
        assert_eq!(backend.db.domains[0].route_id, "route-new");
        let all = requests(&server).await;
        let config_writes: Vec<_> = writes(&all)
            .into_iter()
            .filter(|r| r.method.as_str() == "PUT")
            .collect();
        assert_eq!(config_writes.len(), usize::from(rewritten), "{stored}");
        if rewritten {
            assert_eq!(config_writes[0].body, br#"{"prefix":"go"}"#);
        }
        assert!(backend.db.pending_operations.is_empty());
    }
}

/// A prefix config without a route whose old links are still in the cloud:
/// the same directory revives them (the record says so and points to
/// recovery), another directory is refused, a failed read writes nothing.
#[tokio::test]
async fn leftover_prefix_config_with_old_links_is_checked_before_reuse() {
    for (stored, links, outcome) in [
        (
            r#"{"prefix":"go"}"#,
            ok(json!([{"name":"l:example.com:a"},{"name":"l:example.com:b"}])),
            "revived",
        ),
        (
            r#"{"prefix":"old"}"#,
            ok(json!([{"name":"l:example.com:a"}])),
            "other",
        ),
        (
            "not json",
            ok(json!([{"name":"l:example.com:a"}])),
            "unreadable",
        ),
        (
            r#"{"prefix":"go"}"#,
            ResponseTemplate::new(403),
            "read_failed",
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_checks(&server, json!([])).await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_host_links(&server, links).await;
        Mock::given(method("GET"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(stored))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(ROUTES_PATH))
            .respond_with(ok(json!({"id":"route-new"})))
            .mount(&server)
            .await;
        let result = add_example_domain(&mut backend).await;
        let all = requests(&server).await;
        match outcome {
            "revived" => {
                result.unwrap();
                assert_eq!(backend.db.domains.len(), 1);
                assert_eq!(writes(&all).len(), 1, "only the route is created");
                assert_eq!(backend.db.pending_operations.len(), 1);
                let record = &backend.db.pending_operations[0];
                assert!(record.starts_with("添加域名 example.com ("), "{record}");
                assert!(
                    record.ends_with(&format!("：{}", revived_links_note(2))),
                    "{record}"
                );
                assert!(record.contains("「管理账户」点「从 Cloudflare 找回配置」"));
                assert_eq!(
                    saved(&backend).pending_operations,
                    backend.db.pending_operations
                );
                // Recovery settles it: it is a plain add record of this host.
                assert!(!names_leftover_resources(record));
                assert_eq!(journal_host(record), Some("example.com"));
                assert!(backend.db.dedicated_recovery_hint(record).is_none());
            }
            _ => {
                let error = result.unwrap_err();
                match outcome {
                    "other" => assert_eq!(
                        error,
                        "云端还留着这个主机名以前的 1 条短链接，它们用的链接目录是「old」。请把链接目录改成「old」再添加；本次没有做任何改动"
                    ),
                    "unreadable" => {
                        assert!(error.contains("1 条短链接"), "{error}");
                        assert!(error.contains("请联系维护的人"), "{error}");
                    }
                    _ => assert!(error.contains("HTTP 403"), "{error}"),
                }
                assert!(writes(&all).is_empty(), "{outcome}");
                assert!(backend.db.domains.is_empty());
                assert!(backend.db.pending_operations.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn recovery_settles_the_record_about_revived_links() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.db.pending_operations = vec![format!(
        "添加域名 example.com (v)：{}",
        revived_links_note(1)
    )];
    mount_recovery_without_pool(&server, false).await;
    backend.recover_account("acct1").await.unwrap();
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
}

/// This tool's route for the host under another directory, without a prefix
/// config: what an interrupted removal leaves. Adding with a new directory
/// would create a second route for the host and break recovery.
#[tokio::test]
async fn leftover_route_under_another_directory_blocks_until_the_old_one_is_used() {
    let message = "这个域名上还留着本工具以前建的转发规则 example.com/old/*（上次移除没做完）。请把链接目录改成「old」再检查，添加时会直接沿用它";
    for (config, expected) in [
        (ResponseTemplate::new(404), message),
        (
            ResponseTemplate::new(200).set_body_string(r#"{"prefix":"old"}"#),
            NEEDS_RECOVERY_MESSAGE,
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_checks(
            &server,
            json!([{"id":"route-old","pattern":"example.com/old/*","script":"edge-one"}]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path(CONFIG_PATH))
            .respond_with(config)
            .mount(&server)
            .await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], false);
        let check = prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["label"] == "转发规则")
            .unwrap();
        assert_eq!(check["level"], "error");
        assert_eq!(check["message"], expected);
        assert!(writes(&requests(&server).await).is_empty());
    }

    // A failed read of the prefix config is reported like the neighbouring
    // reads, not as a missing config.
    let (server, mut backend, _guard) = fixture().await;
    mount_domain_checks(
        &server,
        json!([{"id":"route-old","pattern":"example.com/old/*","script":"edge-one"}]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let prepared = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    let check = prepared["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "转发规则")
        .unwrap();
    assert_eq!(check["level"], "error");
    assert!(check["message"]
        .as_str()
        .unwrap()
        .starts_with("无法读取云端前缀配置："));
}

/// The same guard at confirm time: the leftover route showed up after the
/// review read the routes. Nothing is written.
#[tokio::test]
async fn confirm_refuses_a_leftover_route_under_another_directory() {
    let (server, mut backend, _guard) = fixture().await;
    Mock::given(method("GET"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!([])))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    mount_domain_checks(
        &server,
        json!([{"id":"route-old","pattern":"example.com/old/*","script":"edge-one"}]),
    )
    .await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let error = add_example_domain(&mut backend).await.unwrap_err();
    assert_eq!(
        error,
        "这个域名上还留着本工具以前建的转发规则 example.com/old/*（上次移除没做完）。请把链接目录改成「old」再检查，添加时会直接沿用它"
    );
    assert!(writes(&requests(&server).await).is_empty());
    assert!(backend.db.domains.is_empty());
    assert!(backend.db.pending_operations.is_empty());
}

#[test]
fn stray_route_message_names_the_directory_only_for_this_tools_pattern() {
    assert!(stray_route_message("example.com", "example.com/old/*").contains("「old」"));
    let odd = stray_route_message("example.com", "example.com/old");
    assert!(!odd.contains("「"), "{odd}");
    assert!(odd.contains("请联系维护的人"), "{odd}");
}

#[tokio::test]
async fn leftover_route_of_this_tool_passes_preflight_and_is_adopted() {
    let (server, mut backend, _guard) = fixture().await;
    mount_domain_checks(
        &server,
        json!([{"id":"route-old","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_host_links(&server, ok(json!([]))).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let prepared = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(prepared["canApply"], true, "{prepared}");
    let route_check = prepared["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "转发规则")
        .unwrap();
    assert_eq!(route_check["level"], "pass");
    assert_eq!(
        route_check["message"],
        "发现本工具上次没做完留下的转发规则，接入时会直接沿用"
    );
    backend
        .dispatch("apply_plan", &json!({"planId": prepared["plan"]["id"]}))
        .await
        .unwrap();
    assert_eq!(backend.db.domains[0].route_id, "route-old");
    let all = requests(&server).await;
    assert!(!all.iter().any(|r| r.method.as_str() == "POST"));
    assert_eq!(writes(&all).len(), 1);
}

/// The adopted route was not created by this run, so a failed prefix write
/// must leave it alone: rollback only undoes what this run did.
#[tokio::test]
async fn failed_config_write_does_not_delete_the_adopted_leftover_route() {
    let (server, mut backend, _guard) = fixture().await;
    mount_domain_checks(
        &server,
        json!([{"id":"route-old","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_host_links(&server, ok(json!([]))).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let error = add_example_domain(&mut backend).await.unwrap_err();
    assert!(error.contains("HTTP 403"), "{error}");
    assert!(backend.db.domains.is_empty());
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
    let all = requests(&server).await;
    assert!(!all
        .iter()
        .any(|r| matches!(r.method.as_str(), "DELETE" | "POST")));
}

/// This tool's exact route without a prefix config whose links are still in
/// the cloud: an interrupted removal whose config rollback failed. Adopting
/// the route revives them, so the record stays and points to recovery;
/// without links it ends as before; a failed key listing writes nothing.
#[tokio::test]
async fn adopted_leftover_route_with_old_links_keeps_the_record() {
    for (links, outcome) in [
        (
            ok(json!([{"name":"l:example.com:a"},{"name":"l:example.com:b"}])),
            "revived",
        ),
        (ok(json!([])), "no_links"),
        (ResponseTemplate::new(403), "read_failed"),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_checks(
            &server,
            json!([{"id":"route-old","pattern":"example.com/go/*","script":"edge-one"}]),
        )
        .await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_host_links(&server, links).await;
        Mock::given(method("GET"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let result = add_example_domain(&mut backend).await;
        let all = requests(&server).await;
        assert_eq!(
            all.iter()
                .filter(|r| r.method.as_str() == "GET" && r.url.path() == KEYS_PATH)
                .count(),
            1,
            "{outcome}"
        );
        match outcome {
            "read_failed" => {
                let error = result.unwrap_err();
                assert!(error.contains("HTTP 403"), "{error}");
                assert!(writes(&all).is_empty());
                assert!(backend.db.domains.is_empty());
                assert!(backend.db.pending_operations.is_empty());
            }
            _ => {
                result.unwrap();
                assert_eq!(backend.db.domains[0].route_id, "route-old");
                // Only the prefix config is written; the route is adopted.
                assert_eq!(writes(&all).len(), 1, "{outcome}");
                assert!(!all.iter().any(|r| r.method.as_str() == "POST"));
                if outcome == "revived" {
                    assert_eq!(backend.db.pending_operations.len(), 1);
                    let record = &backend.db.pending_operations[0];
                    assert!(record.starts_with("添加域名 example.com ("), "{record}");
                    assert!(
                        record.ends_with(&format!("：{}", revived_links_note(2))),
                        "{record}"
                    );
                } else {
                    assert!(backend.db.pending_operations.is_empty());
                }
                assert_eq!(
                    saved(&backend).pending_operations,
                    backend.db.pending_operations
                );
            }
        }
    }
}

/// The plain first add of a host (no prefix config, no route of this tool)
/// does not list link keys: its request count stays as it was.
#[tokio::test]
async fn fresh_domain_add_does_not_list_link_keys() {
    let (server, mut backend, _guard) = fixture().await;
    mount_domain_checks(&server, json!([])).await;
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!({"id":"route-new"})))
        .mount(&server)
        .await;
    add_example_domain(&mut backend).await.unwrap();
    assert_eq!(backend.db.domains[0].route_id, "route-new");
    assert!(!requests(&server)
        .await
        .iter()
        .any(|r| r.url.path() == KEYS_PATH));
    assert!(backend.db.pending_operations.is_empty());
}

#[tokio::test]
async fn complete_setup_or_foreign_route_still_blocks_at_preflight() {
    // This tool's exact route plus its config: recovery, with its entry.
    let (server, mut backend, _guard) = fixture().await;
    mount_domain_checks(
        &server,
        json!([{"id":"route-old","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"prefix":"go"}"#))
        .mount(&server)
        .await;
    let prepared = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(prepared["canApply"], false);
    let check = prepared["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "转发规则")
        .unwrap();
    assert_eq!(check["level"], "error");
    assert_eq!(check["message"], NEEDS_RECOVERY_MESSAGE);
    assert!(NEEDS_RECOVERY_MESSAGE.contains("“管理账户”，点“从 Cloudflare 找回配置”"));
    // Release the shared fixture lock before the next cases take it.
    drop((server, backend, _guard));

    // Same pattern but another Worker, or this Worker with a wider pattern,
    // is someone else's route: unchanged conflict.
    for routes in [
        json!([{"id":"r","pattern":"example.com/go/*","script":"another"}]),
        json!([{"id":"r","pattern":"example.com/*","script":"edge-one"}]),
        json!([{"id":"r","pattern":"example.com/go/*","script":"edge-one"},
            {"id":"s","pattern":"*example.com/*","script":"another"}]),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_checks(&server, routes.clone()).await;
        let prepared = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(prepared["canApply"], false, "{routes}");
        assert!(prepared["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["label"] == "转发规则" && c["message"] == "现有转发规则与此前缀重叠"));
    }
}

// ---- A3: an uncertain domain write is checked before giving up ---------

/// KV value for c:example.com whose PUT answers 503; `lands` decides whether
/// the value was in fact stored, `readable` whether reading it back works.
async fn mount_uncertain_config(server: &MockServer, lands: bool, readable: bool) {
    let stored = Arc::new(Mutex::new(None::<Vec<u8>>));
    let put_store = stored.clone();
    Mock::given(method("PUT"))
        .and(path(CONFIG_PATH))
        .respond_with(move |request: &Request| {
            if lands {
                *put_store.lock().unwrap() = Some(request.body.clone());
            }
            ResponseTemplate::new(503)
        })
        .mount(server)
        .await;
    // The first read is the check before writing; later ones read back.
    let read_before = AtomicBool::new(false);
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(move |_: &Request| {
            let read_back = read_before.swap(true, Ordering::SeqCst);
            if let Some(body) = stored.lock().unwrap().clone() {
                return ResponseTemplate::new(200).set_body_raw(body, "application/json");
            }
            if read_back && !readable {
                return ResponseTemplate::new(500);
            }
            ResponseTemplate::new(404)
        })
        .mount(server)
        .await;
}

#[tokio::test]
async fn uncertain_config_write_is_read_back_before_deciding() {
    for case in ["landed", "missing", "unreadable"] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_checks(&server, json!([])).await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_uncertain_config(&server, case == "landed", case != "unreadable").await;
        Mock::given(method("POST"))
            .and(path(ROUTES_PATH))
            .respond_with(ok(json!({"id":"route-new"})))
            .mount(&server)
            .await;
        let result = add_example_domain(&mut backend).await;
        let all = requests(&server).await;
        let posted = all.iter().any(|r| r.method.as_str() == "POST");
        match case {
            "landed" => {
                result.unwrap();
                assert!(posted);
                assert_eq!(backend.db.domains.len(), 1);
                assert!(backend.db.pending_operations.is_empty());
            }
            "missing" => {
                assert_eq!(
                    result.unwrap_err(),
                    "这一步没有收到明确的答复，查看后发现前缀配置没有写进云端，请再试一次"
                );
                assert!(!posted);
                assert!(backend.db.domains.is_empty());
                assert!(backend.db.pending_operations.is_empty(), "{case}");
            }
            _ => {
                let error = result.unwrap_err();
                assert!(error.contains("写入结果不确定"), "{error}");
                assert!(!posted);
                assert_eq!(backend.db.pending_operations.len(), 1);
                assert!(backend.db.pending_operations[0].contains("云端结果不确定"));
            }
        }
        assert!(!all.iter().any(|r| r.method.as_str() == "DELETE"), "{case}");
    }
}

#[tokio::test]
async fn uncertain_route_create_looks_for_the_route_before_deciding() {
    for case in ["created", "missing", "unreadable"] {
        let (server, mut backend, _guard) = fixture().await;
        mount_domain_probes(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(404),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1"))
            .respond_with(ok(
                json!({"id":"zone1","status":"active","account":{"id":"acct1"}}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ok(
                json!([{"name":"example.com","type":"A","proxied":true}]),
            ))
            .mount(&server)
            .await;
        let posted = Arc::new(AtomicBool::new(false));
        let seen = posted.clone();
        Mock::given(method("GET"))
            .and(path(ROUTES_PATH))
            .respond_with(move |_: &Request| {
                if !seen.load(Ordering::SeqCst) {
                    return ok(json!([]));
                }
                match case {
                    "created" => ok(json!([{"id":"route-late","pattern":"example.com/go/*",
                        "script":"edge-one"}])),
                    "missing" => ok(json!([])),
                    _ => ResponseTemplate::new(500),
                }
            })
            .mount(&server)
            .await;
        let flag = posted.clone();
        Mock::given(method("POST"))
            .and(path(ROUTES_PATH))
            .respond_with(move |_: &Request| {
                flag.store(true, Ordering::SeqCst);
                ResponseTemplate::new(503)
            })
            .expect(1)
            .mount(&server)
            .await;
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        Mock::given(method("GET"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(CONFIG_PATH))
            .respond_with(ok(json!({})))
            .mount(&server)
            .await;
        let result = add_example_domain(&mut backend).await;
        let all = requests(&server).await;
        let deleted_config = all
            .iter()
            .any(|r| r.method.as_str() == "DELETE" && r.url.path() == CONFIG_PATH);
        match case {
            "created" => {
                result.unwrap();
                assert_eq!(backend.db.domains[0].route_id, "route-late");
                assert!(backend.db.pending_operations.is_empty());
                assert!(!deleted_config);
            }
            "missing" => {
                assert_eq!(
                    result.unwrap_err(),
                    "这一步没有收到明确的答复，查看后发现转发规则没有建成，请再试一次"
                );
                assert!(backend.db.domains.is_empty());
                assert!(backend.db.pending_operations.is_empty());
                assert!(deleted_config, "definite failure rolls back the config");
            }
            _ => {
                assert!(result.unwrap_err().contains("写入结果不确定"));
                assert_eq!(backend.db.pending_operations.len(), 1);
                assert!(!deleted_config);
            }
        }
    }
}

/// A new account (no local resources) whose KV create or Worker upload
/// answers 503. Returns the server; deletes answer `delete_status`.
async fn new_account_fixture(
    kv_uncertain: bool,
    delete_status: u16,
) -> (MockServer, Backend, tests::FixtureGuard) {
    let (server, mut backend, guard) = fixture().await;
    backend.db.accounts[0].resources = None;
    backend.db.accounts[0].has_resources = false;
    mount_domain_checks(&server, json!([])).await;
    Mock::given(method("GET"))
        .and(path("/client/v4/accounts/acct1/workers/scripts"))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;
    // The namespace list shows what the create request really made.
    let created = Arc::new(Mutex::new(None::<String>));
    let listed = created.clone();
    Mock::given(method("GET"))
        .and(path("/client/v4/accounts/acct1/storage/kv/namespaces"))
        .respond_with(move |_: &Request| match listed.lock().unwrap().clone() {
            Some(title) => ok(json!([{"id":"ns-new","title":title}])),
            None => ok(json!([])),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns-new/values/m%3Aconfig",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let store = created.clone();
    Mock::given(method("POST"))
        .and(path("/client/v4/accounts/acct1/storage/kv/namespaces"))
        .respond_with(move |request: &Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            *store.lock().unwrap() = body["title"].as_str().map(str::to_owned);
            if kv_uncertain {
                ResponseTemplate::new(503)
            } else {
                ok(json!({"id":"ns-new"}))
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(
            r"^/client/v4/accounts/acct1/workers/scripts/edge-",
        ))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(
            r"^/client/v4/accounts/acct1/workers/scripts/edge-",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns-new",
        ))
        .respond_with(if delete_status == 200 {
            ok(json!({}))
        } else {
            ResponseTemplate::new(delete_status)
        })
        .mount(&server)
        .await;
    (server, backend, guard)
}

#[tokio::test]
async fn uncertain_first_setup_is_undone_so_retries_do_not_pile_up() {
    for kv_uncertain in [false, true] {
        let (server, mut backend, _guard) = new_account_fixture(kv_uncertain, 200).await;
        let error = add_example_domain(&mut backend).await.unwrap_err();
        assert_eq!(error, UNDONE_FIRST_SETUP);
        assert!(!error.contains("网络中断"), "{error}");
        assert!(backend.db.pending_operations.is_empty());
        assert!(saved(&backend).pending_operations.is_empty());
        assert!(backend.db.accounts[0].resources.is_none());
        assert!(backend.db.domains.is_empty());
        let all = requests(&server).await;
        assert!(all.iter().any(|r| r.method.as_str() == "DELETE"
            && r.url.path() == "/client/v4/accounts/acct1/storage/kv/namespaces/ns-new"));
        // The Worker is only deleted once its upload was sent.
        let script_deleted = all.iter().any(|r| {
            r.method.as_str() == "DELETE" && r.url.path().contains("/workers/scripts/edge-")
        });
        assert_eq!(script_deleted, !kv_uncertain);
        if !kv_uncertain {
            assert_eq!(keyring_get_optional("acct1", "selftest").unwrap(), None);
        }
    }
}

#[tokio::test]
async fn first_setup_that_cannot_be_undone_names_what_is_left() {
    let (_server, mut backend, _guard) = new_account_fixture(false, 500).await;
    let error = add_example_domain(&mut backend).await.unwrap_err();
    assert!(error.contains("写入结果不确定"), "{error}");
    assert!(error.contains("没能全部撤销"), "{error}");
    assert_eq!(backend.db.pending_operations.len(), 1);
    let note = &backend.db.pending_operations[0];
    assert!(note.contains(UNDO_INCOMPLETE), "{note}");
    assert!(note.contains("KV links-"), "{note}");
    assert!(note.contains("ID ns-new"), "{note}");
    // The Worker was confirmed gone; only the KV is named as left over.
    let tail = note.split(UNDO_INCOMPLETE).nth(1).unwrap();
    assert!(!tail.contains("Worker"), "{note}");
    assert_eq!(
        saved(&backend).pending_operations,
        backend.db.pending_operations
    );
}

/// The KV and the Worker were created; only the ownership manifest write got
/// no clear answer. Without a manifest the next attempt would not notice this
/// set and would build a second one, so it has to be undone as well.
#[tokio::test]
async fn uncertain_manifest_write_of_a_first_setup_is_undone_too() {
    let (server, mut backend, _guard) = new_account_fixture(false, 200).await;
    Mock::given(method("PUT"))
        .and(path_regex(
            r"^/client/v4/accounts/acct1/workers/scripts/edge-",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true})))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(
            r"^/client/v4/accounts/acct1/workers/scripts/edge-",
        ))
        .respond_with(ok(json!({})))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns-new/values/m%3Aconfig",
        ))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let error = add_example_domain(&mut backend).await.unwrap_err();
    assert_eq!(error, UNDONE_FIRST_SETUP);
    assert!(!error.contains("网络中断"), "{error}");
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
    assert!(backend.db.accounts[0].resources.is_none());
    assert!(backend.db.domains.is_empty());
    assert_eq!(keyring_get_optional("acct1", "selftest").unwrap(), None);
    let all = requests(&server).await;
    let deleted = |needle: &str| {
        all.iter()
            .any(|r| r.method.as_str() == "DELETE" && r.url.path().contains(needle))
    };
    assert!(deleted("/workers/scripts/edge-"));
    assert!(deleted("/storage/kv/namespaces/ns-new"));
}

// ---- A4: a link save that in fact went through -------------------------

#[tokio::test]
async fn uncertain_link_write_that_landed_counts_as_saved() {
    for lands in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        let old = "保存链接 example.com / short (old)：写入结果不确定，需要人工核对";
        backend.db.pending_operations = vec![old.into()];
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        let stored = Arc::new(Mutex::new(None::<Vec<u8>>));
        let put_store = stored.clone();
        Mock::given(method("PUT"))
            .and(path(SHORT_PATH))
            .respond_with(move |request: &Request| {
                if lands {
                    *put_store.lock().unwrap() = Some(request.body.clone());
                }
                ResponseTemplate::new(503)
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(move |_: &Request| match stored.lock().unwrap().clone() {
                Some(body) => ResponseTemplate::new(200).set_body_raw(body, "application/json"),
                None => ResponseTemplate::new(404),
            })
            .mount(&server)
            .await;
        let result = backend
            .apply_save_link(
                "domain1",
                "short",
                "https://example.org/cn",
                "https://example.org/other",
                None,
                None,
            )
            .await;
        if lands {
            result.unwrap();
            assert_eq!(backend.db.links.len(), 1);
            assert!(backend.db.pending_operations.is_empty());
            assert!(saved(&backend).pending_operations.is_empty());
        } else {
            assert!(result.unwrap_err().contains("写入结果不确定"));
            assert!(backend.db.links.is_empty());
            assert_eq!(backend.db.pending_operations.len(), 2);
            assert!(backend.db.pending_operations.iter().any(|e| e == old));
        }
    }
}

#[tokio::test]
async fn retry_of_a_save_that_already_landed_succeeds_without_writing() {
    // New link: the cloud already lists and holds exactly this content.
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let old = "保存链接 example.com / short (old)：写入结果不确定，需要人工核对";
    backend.db.pending_operations = vec![old.into(), "添加域名 example.org (x)".into()];
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_owned_domain(&server).await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
        ))
        .and(query_param("prefix", "l:example.com:"))
        .respond_with(ok(json!([{"name":"l:example.com:short"}])))
        .with_priority(1)
        .mount(&server)
        .await;
    let mut landed = url_link(
        "short",
        "https://example.org/cn",
        "https://example.org/other",
    );
    landed.updated = "2026-11-01T00:00:00Z".into();
    Mock::given(method("GET"))
        .and(path(SHORT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv_link(&landed)))
        .mount(&server)
        .await;
    backend
        .apply_save_link(
            "domain1",
            "short",
            "https://example.org/cn",
            "https://example.org/other",
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.db.links.len(), 1);
    assert_eq!(backend.db.links[0].updated, "2026-11-01T00:00:00Z");
    assert_eq!(
        backend.db.pending_operations,
        vec!["添加域名 example.org (x)".to_string()]
    );
    assert_eq!(saved(&backend).links.len(), 1);
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn same_name_with_different_cloud_content_still_points_to_recovery() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_owned_domain(&server).await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys",
        ))
        .and(query_param("prefix", "l:example.com:"))
        .respond_with(ok(json!([{"name":"l:example.com:short"}])))
        .with_priority(1)
        .mount(&server)
        .await;
    let other = url_link(
        "short",
        "https://example.org/cn",
        "https://example.org/elsewhere",
    );
    Mock::given(method("GET"))
        .and(path(SHORT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv_link(&other)))
        .mount(&server)
        .await;
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
    assert!(
        error.contains("云端已有同名链接 example.com / short"),
        "{error}"
    );
    assert!(error.contains("从 Cloudflare 找回配置"));
    assert!(backend.db.links.is_empty());
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn edit_whose_new_target_already_landed_succeeds_without_writing() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.db.links.push(url_link(
        "short",
        "https://example.org/cn",
        "https://example.org/old",
    ));
    backend.db.pending_operations =
        vec!["保存链接 example.com / short (old)：写入结果不确定，需要人工核对".into()];
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_owned_domain(&server).await;
    let landed = url_link("short", "https://example.org/cn", "https://example.org/new");
    Mock::given(method("GET"))
        .and(path(SHORT_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(kv_link(&landed)))
        .mount(&server)
        .await;
    backend
        .apply_save_link(
            "domain1",
            "short",
            "https://example.org/cn",
            "https://example.org/new",
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.db.links.len(), 1);
    assert_eq!(backend.db.links[0].default_url, "https://example.org/new");
    assert!(backend.db.pending_operations.is_empty());
    assert!(writes(&requests(&server).await).is_empty());
}

#[test]
fn journal_host_reads_both_domain_forms_and_link_records() {
    assert_eq!(
        journal_host("添加域名 example.com (a)"),
        Some("example.com")
    );
    assert_eq!(
        journal_host("添加域名 example.com（计划 KV links-a，Worker edge-a，b）"),
        Some("example.com")
    );
    assert_eq!(
        journal_host("移除域名 example.com (c)"),
        Some("example.com")
    );
    assert_eq!(
        journal_host("保存链接 www.example.com / short (d)"),
        Some("www.example.com")
    );
    assert_eq!(
        journal_host("删除链接 example.com / x (e)"),
        Some("example.com")
    );
    assert_eq!(journal_host("修复 DNS example.com (f)"), None);
    assert_eq!(journal_host("清理账号 acct1 (g)"), None);
}

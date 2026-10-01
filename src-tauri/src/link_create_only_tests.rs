use super::*;
use tests::{domain, fixture, mount_owned_domain, mount_resource};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn original_link() -> Link {
    Link {
        domain_id: "domain1".into(),
        slug: "original".into(),
        cn_url: "https://example.org/original-cn".into(),
        default_url: "https://example.org/original-default".into(),
        updated: "2026-09-30T00:00:00Z".into(),
        pool_id: None,
        code: None,
    }
}

fn save_payload(slug: &str) -> Value {
    json!({
        "kind": "save_link", "domainId": "domain1", "slug": slug,
        "cnUrl": "https://example.org/new-cn",
        "defaultUrl": "https://example.org/new-default",
        "createOnly": true
    })
}

fn link_path(slug: &str) -> String {
    format!("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3A{slug}")
}

async fn mount_owned_resources(server: &MockServer) {
    mount_resource(server, include_str!("../../edge/worker.mjs")).await;
    mount_owned_domain(server).await;
}

async fn assert_no_cloud_writes(server: &MockServer) {
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| !matches!(request.method.as_str(), "PUT" | "POST" | "DELETE")));
}

#[tokio::test]
async fn create_only_rejects_invalid_boolean_without_credentials_or_requests() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    for invalid in [Value::Null, json!("true"), json!(1), json!([]), json!({})] {
        let mut payload = save_payload("copy");
        payload["createOnly"] = invalid;
        assert!(backend
            .prepare_change(&payload)
            .unwrap_err()
            .contains("必须为布尔值"));
    }
    assert!(backend.plans.is_empty());
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn create_only_prepare_rejects_local_duplicate_without_changing_original() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.db.links.push(original_link());
    let before = backend.database_snapshot();
    assert!(backend
        .prepare_change(&save_payload("original"))
        .unwrap_err()
        .contains("已存在同名链接"));
    assert_eq!(backend.database_snapshot(), before);
    assert!(backend.plans.is_empty());
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn create_only_apply_rechecks_local_duplicate_before_credentials_or_requests() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.prepare_change(&save_payload("original")).unwrap();
    let kind = backend.plans.pop().unwrap().kind;
    backend.db.links.push(original_link());
    let before = backend.database_snapshot();
    assert!(backend
        .apply(kind, false)
        .await
        .unwrap_err()
        .contains("已存在同名链接"));
    assert_eq!(backend.database_snapshot(), before);
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn create_only_stale_or_expired_plan_cannot_write() {
    for expired in [false, true] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        let plan = backend.prepare_change(&save_payload("original")).unwrap();
        if expired {
            backend.plans[0].expires_at = Instant::now() - Duration::from_secs(1);
        } else {
            backend.db.links.push(original_link());
        }
        let before = backend.database_snapshot();
        let error = backend
            .dispatch("apply_plan", &json!({"planId": plan["id"]}))
            .await
            .unwrap_err();
        assert!(error.contains(if expired {
            "计划已过期"
        } else {
            "本机配置已变化"
        }));
        assert_eq!(backend.database_snapshot(), before);
        assert!(backend.plans.is_empty());
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn create_only_remote_target_discovered_after_prepare_is_never_overwritten() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.db.links.push(original_link());
    let plan = backend.prepare_change(&save_payload("copy")).unwrap();
    mount_owned_resources(&server).await;
    let mut remote_link = original_link();
    remote_link.slug = "copy".into();
    Mock::given(method("GET"))
        .and(path(link_path("copy")))
        .respond_with(ResponseTemplate::new(200).set_body_string(kv_link(&remote_link).to_string()))
        .expect(1)
        .mount(&server)
        .await;
    let before = backend.database_snapshot();
    assert!(backend
        .dispatch("apply_plan", &json!({"planId": plan["id"]}))
        .await
        .unwrap_err()
        .contains("云端链接与本机记录不一致"));
    assert_eq!(backend.database_snapshot(), before);
    assert_no_cloud_writes(&server).await;
}

#[tokio::test]
async fn create_only_new_name_persists_both_links_and_writes_only_the_new_key() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let original = original_link();
    let before_original = serde_json::to_value(&original).unwrap();
    backend.db.links.push(original);
    mount_owned_resources(&server).await;
    Mock::given(method("GET"))
        .and(path(link_path("copy")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(link_path("copy")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let plan = backend.prepare_change(&save_payload("copy")).unwrap();
    assert_eq!(plan["title"], "另存为新链接");
    assert!(plan["warnings"][0]
        .as_str()
        .unwrap()
        .contains("已有链接保持不变"));
    backend
        .dispatch("apply_plan", &json!({"planId": plan["id"]}))
        .await
        .unwrap();
    let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
    for database in [&backend.db, &saved] {
        assert_eq!(database.links.len(), 2);
        assert_eq!(
            serde_json::to_value(
                database
                    .links
                    .iter()
                    .find(|link| link.slug == "original")
                    .unwrap()
            )
            .unwrap(),
            before_original
        );
        let new_link = database
            .links
            .iter()
            .find(|link| link.slug == "copy")
            .unwrap();
        assert_eq!(new_link.cn_url, "https://example.org/new-cn");
        assert_eq!(new_link.default_url, "https://example.org/new-default");
        assert!(database.pending_operations.is_empty());
    }
    let requests = server.received_requests().await.unwrap();
    let writes: Vec<_> = requests
        .iter()
        .filter(|request| matches!(request.method.as_str(), "PUT" | "POST" | "DELETE"))
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].method.as_str(), "PUT");
    assert_eq!(writes[0].url.path(), link_path("copy"));
    let body: Value = serde_json::from_slice(&writes[0].body).unwrap();
    assert_eq!(body["default"], "https://example.org/new-default");
}

#[tokio::test]
async fn create_only_omitted_or_false_preserves_existing_edit_behavior() {
    for explicit_false in [false, true] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(original_link());
        mount_owned_resources(&server).await;
        Mock::given(method("GET"))
            .and(path(link_path("original")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(kv_link(&backend.db.links[0]).to_string()),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(link_path("original")))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let mut payload = save_payload("original");
        if explicit_false {
            payload["createOnly"] = json!(false);
        } else {
            payload.as_object_mut().unwrap().remove("createOnly");
        }
        let plan = backend.prepare_change(&payload).unwrap();
        assert_eq!(plan["title"], "保存链接");
        assert_eq!(plan["warnings"][0], "这会覆盖现有链接目标");
        backend
            .dispatch("apply_plan", &json!({"planId": plan["id"]}))
            .await
            .unwrap();
        assert_eq!(backend.db.links.len(), 1);
        assert_eq!(backend.db.links[0].slug, "original");
        assert_eq!(backend.db.links[0].cn_url, "https://example.org/new-cn");
        assert_eq!(
            backend.db.links[0].default_url,
            "https://example.org/new-default"
        );
        assert!(backend.db.pending_operations.is_empty());
    }
}

#[tokio::test]
async fn create_only_uncertain_write_preserves_original_and_recovery_journal() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.db.links.push(original_link());
    let before_links = serde_json::to_value(&backend.db.links).unwrap();
    mount_owned_resources(&server).await;
    Mock::given(method("GET"))
        .and(path(link_path("copy")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(link_path("copy")))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let plan = backend.prepare_change(&save_payload("copy")).unwrap();
    assert!(backend
        .dispatch("apply_plan", &json!({"planId": plan["id"]}))
        .await
        .unwrap_err()
        .contains("HTTP 503"));
    assert_eq!(
        serde_json::to_value(&backend.db.links).unwrap(),
        before_links
    );
    assert_eq!(backend.db.pending_operations.len(), 1);
    assert!(backend.db.pending_operations[0].contains("不确定"));
    let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
    assert_eq!(saved.pending_operations, backend.db.pending_operations);
    assert_eq!(serde_json::to_value(&saved.links).unwrap(), before_links);
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method.as_str() != "DELETE"));
}

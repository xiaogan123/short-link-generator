use super::*;
use std::sync::{Arc, Mutex as StdMutex};
use tests::{domain, fixture, mount_owned_domain, mount_resource};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const SCRIPT_PATH: &str = "/client/v4/accounts/acct1/workers/scripts/edge-one";
const MANIFEST_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Aconfig";
const KEYS_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys";
const OLD_SOURCE: &str = "export default {fetch(){return new Response('old')}}";
fn ok(result: Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({"success":true,"result":result,"result_info":{"cursor":""}}))
}
fn settings() -> Value {
    json!({"main_module":"worker.mjs","compatibility_date":"2025-01-01","compatibility_flags":["nodejs_compat","streams_enable_constructors"],
        "usage_model":"standard","logpush":false,"placement":{"mode":"off"},"observability":{"enabled":false},
        "bindings":[{"type":"kv_namespace","name":"LINKS","namespace_id":"ns1"},
            {"type":"secret_text","name":"SELFTEST_KEY"},{"type":"secret_text","name":"PROBE_KEY"}]})
}
struct Remote {
    source: String,
    manifest: Value,
    settings: Value,
    schedules: Value,
    upload_status: u16,
    fail_manifest: bool,
    change_schedules: bool,
    missing_secrets: bool,
    delay_content_visibility: bool,
    annotations_after_upload: Option<Value>,
}
async fn mount_upgrade(server: &MockServer, state_path: &std::path::Path) -> Arc<StdMutex<Remote>> {
    let remote = Arc::new(StdMutex::new(Remote {
        source: OLD_SOURCE.into(),
        manifest: json!({"schema":SCHEMA,"accountId":"acct1","script":"edge-one","namespace":"ns1","sourceHash":hex::encode(Sha256::digest(OLD_SOURCE))}),
        settings: settings(),
        schedules: json!({"schedules":[{"cron":"*/15 * * * *"}]}),
        upload_status: 200,
        fail_manifest: false,
        change_schedules: false,
        missing_secrets: false,
        delay_content_visibility: false,
        annotations_after_upload: None,
    }));
    for suffix in ["/content/v2", "/settings", "/schedules"] {
        let remote = remote.clone();
        Mock::given(method("GET"))
            .and(path(format!("{SCRIPT_PATH}{suffix}")))
            .respond_with(move |_: &wiremock::Request| {
                let state = remote.lock().unwrap();
                match suffix {
                    "/content/v2" => ResponseTemplate::new(200)
                        .set_body_raw(state.source.clone(), "application/javascript"),
                    "/settings" => ok(state.settings.clone()),
                    _ => ok(state.schedules.clone()),
                }
            })
            .mount(server)
            .await;
    }
    let state = remote.clone();
    Mock::given(method("GET"))
        .and(path(MANIFEST_PATH))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_string(state.lock().unwrap().manifest.to_string())
        })
        .mount(server)
        .await;
    let state = remote.clone();
    let state_path = state_path.to_owned();
    Mock::given(method("PUT"))
        .and(path(SCRIPT_PATH))
        .respond_with(move |_: &wiremock::Request| {
            let db: Database = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
            assert_eq!(
                db.pending_worker_upgrades.len(),
                1,
                "intent must be durable before upload"
            );
            assert_eq!(
                db.pending_worker_upgrades[0].phase,
                WorkerUpgradePhase::Prepared
            );
            assert!(db.pending_worker_upgrades[0]
                .settings
                .get("annotations")
                .is_none());
            let mut state = state.lock().unwrap();
            if !state.delay_content_visibility {
                state.source = include_str!("../../edge/worker.mjs").into();
            }
            state.settings["bindings"].as_array_mut().unwrap().reverse();
            state.settings["compatibility_flags"]
                .as_array_mut()
                .unwrap()
                .reverse();
            if let Some(annotations) = state.annotations_after_upload.clone() {
                state.settings["annotations"] = annotations;
            }
            if state.change_schedules {
                state.schedules = json!({"schedules":[]});
            }
            if state.missing_secrets {
                state.settings["bindings"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|b| b["type"] != "secret_text");
            }
            if state.upload_status == 200 {
                ok(json!({}))
            } else {
                ResponseTemplate::new(state.upload_status)
            }
        })
        .mount(server)
        .await;
    let state = remote.clone();
    Mock::given(method("PUT"))
        .and(path(MANIFEST_PATH))
        .respond_with(move |request: &wiremock::Request| {
            let mut state = state.lock().unwrap();
            if state.fail_manifest {
                return ResponseTemplate::new(503);
            }
            state.manifest = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200)
        })
        .mount(server)
        .await;
    remote
}
async fn apply_upgrade(backend: &mut Backend) -> Result<Value, String> {
    let plan = backend.prepare_change(&json!({"kind":"upgrade_worker","accountId":"acct1"}))?;
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
}
async fn resume_upgrade(backend: &mut Backend) -> Result<Value, String> {
    let plan =
        backend.prepare_change(&json!({"kind":"resume_worker_upgrade","accountId":"acct1"}))?;
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
}
async fn writes(server: &MockServer) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE"))
        .collect()
}
async fn upload_metadata(request: &wiremock::Request) -> Value {
    let content_type = request
        .headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    let boundary = multer::parse_boundary(content_type).unwrap();
    let body = request.body.clone();
    let stream = futures_util::stream::once(async move { Ok::<_, std::io::Error>(body) });
    let mut parts = multer::Multipart::new(stream, boundary);
    while let Some(part) = parts.next_field().await.unwrap() {
        if part.name() == Some("metadata") {
            return serde_json::from_slice(&part.bytes().await.unwrap()).unwrap();
        }
    }
    panic!("missing metadata");
}
#[tokio::test]
async fn upgrade_preserves_secrets_settings_schedules_and_has_single_use_preview() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let mut second = domain();
    second.id = "domain2".into();
    second.host = "www.example.com".into();
    backend.db.domains.push(second);
    let remote = mount_upgrade(&server, &backend.path).await;
    let plan = backend
        .prepare_change(&json!({"kind":"upgrade_worker","accountId":"acct1"}))
        .unwrap();
    assert!(plan["steps"][0]
        .as_str()
        .unwrap()
        .contains("www.example.com"));
    assert!(server.received_requests().await.unwrap().is_empty());
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert!(backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .is_err());
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend.db.pending_operations.is_empty());
    assert_eq!(
        remote.lock().unwrap().manifest["sourceHash"],
        bundled_source_hash()
    );
    let mutations = writes(&server).await;
    assert_eq!(mutations.len(), 2);
    assert_eq!(mutations[0].url.path(), SCRIPT_PATH);
    let metadata = upload_metadata(&mutations[0]).await;
    assert_eq!(metadata["keep_bindings"], json!(["secret_text"]));
    assert_eq!(
        metadata["bindings"],
        json!([{"type":"kv_namespace","name":"LINKS","namespace_id":"ns1"}])
    );
    assert_eq!(metadata["compatibility_date"], "2025-01-01");
    assert_eq!(
        metadata["compatibility_flags"],
        json!(["nodejs_compat", "streams_enable_constructors"])
    );
    assert!(!metadata.to_string().contains("\"text\":"));
    assert!(mock_key_reads()
        .lock()
        .unwrap()
        .iter()
        .all(|kind| kind == "token:acct1"));
    let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
    assert!(saved.pending_worker_upgrades.is_empty());
}
#[tokio::test]
async fn upgrade_interruptions_resume_only_manifest_and_keep_durable_intent() {
    for interruption in ["upload", "verification", "manifest"] {
        let (server, mut backend, _guard) = fixture().await;
        let remote = mount_upgrade(&server, &backend.path).await;
        {
            let mut r = remote.lock().unwrap();
            match interruption {
                "upload" => r.upload_status = 503,
                "verification" => r.change_schedules = true,
                _ => r.fail_manifest = true,
            }
        }
        assert!(apply_upgrade(&mut backend).await.is_err());
        assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
        let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
        assert_eq!(saved.pending_worker_upgrades.len(), 1);
        assert_eq!(
            serde_json::to_value(&saved.pending_worker_upgrades[0]).unwrap(),
            serde_json::to_value(&backend.db.pending_worker_upgrades[0]).unwrap()
        );
        backend.db = saved;
        {
            let mut r = remote.lock().unwrap();
            r.fail_manifest = false;
            r.schedules = json!({"schedules":[{"cron":"*/15 * * * *"}]});
        }
        let before = writes(&server).await.len();
        resume_upgrade(&mut backend).await.unwrap();
        let mutations = writes(&server).await;
        assert!(mutations[before..]
            .iter()
            .all(|r| r.url.path() == MANIFEST_PATH));
        assert_eq!(
            mutations
                .iter()
                .filter(|r| r.url.path() == SCRIPT_PATH)
                .count(),
            1
        );
        assert!(backend.db.pending_worker_upgrades.is_empty());
    }
}
#[tokio::test]
async fn upgrade_unknown_source_does_not_write_and_explicit_dismiss_is_local() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().upload_status = 503;
    assert!(apply_upgrade(&mut backend).await.is_err());
    remote.lock().unwrap().source =
        "export default {fetch(){return new Response('external')}}".into();
    let before = writes(&server).await.len();
    assert!(resume_upgrade(&mut backend)
        .await
        .unwrap_err()
        .contains("未知外部版本"));
    assert_eq!(writes(&server).await.len(), before);
    let plan = backend
        .prepare_change(&json!({"kind":"dismiss_worker_upgrade","accountId":"acct1"}))
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert_eq!(writes(&server).await.len(), before);
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend
        .verify_resource_source(
            "test",
            "acct1",
            backend.db.accounts[0].resources.as_ref().unwrap()
        )
        .await
        .is_err());
}
#[tokio::test]
async fn upgrade_previous_source_requires_separate_local_dismiss_without_reupload() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().upload_status = 503;
    assert!(apply_upgrade(&mut backend).await.is_err());
    let p = backend.db.pending_worker_upgrades[0].clone();
    {
        let mut r = remote.lock().unwrap();
        r.source = OLD_SOURCE.into();
        r.manifest = p.manifest;
    }
    // Prepared may also be the durable state after a crash following upload.
    backend.db.pending_worker_upgrades[0].phase = WorkerUpgradePhase::Prepared;
    backend.persist().unwrap();
    let before = writes(&server).await.len();
    assert!(resume_upgrade(&mut backend)
        .await
        .unwrap_err()
        .contains("可能尚未同步"));
    assert_eq!(writes(&server).await.len(), before);
    assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
    let plan = backend
        .prepare_change(&json!({"kind":"dismiss_worker_upgrade","accountId":"acct1"}))
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert_eq!(writes(&server).await.len(), before);
    assert!(backend.db.pending_worker_upgrades.is_empty());
}
#[tokio::test]
async fn upgrade_missing_secrets_finishes_with_existing_repair_flags() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().missing_secrets = true;
    backend.db.accounts[0].monitor_enabled = true;
    apply_upgrade(&mut backend).await.unwrap();
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend.db.accounts[0].needs_selftest_key);
    assert!(backend.db.accounts[0].needs_monitor_key);
    backend
        .verify_resource_source(
            "test",
            "acct1",
            backend.db.accounts[0].resources.as_ref().unwrap(),
        )
        .await
        .unwrap();
    assert!(backend
        .prepare_change(&json!({"kind":"rotate_selftest","accountId":"acct1"}))
        .is_ok());
}
#[tokio::test]
async fn upgrade_unsupported_settings_stale_manifest_and_persist_failure_write_nothing() {
    for reason in ["settings", "manifest", "persist"] {
        let (server, mut backend, _guard) = fixture().await;
        let remote = mount_upgrade(&server, &backend.path).await;
        match reason {
            "settings" => remote.lock().unwrap().settings["logpush"] = json!(true),
            "manifest" => remote.lock().unwrap().manifest["unexpected"] = json!("unknown"),
            _ => backend
                .fail_persist_at
                .store(1, std::sync::atomic::Ordering::SeqCst),
        }
        assert!(apply_upgrade(&mut backend).await.is_err());
        assert!(writes(&server).await.is_empty());
        assert!(backend.db.pending_worker_upgrades.is_empty());
    }
}
#[tokio::test]
async fn pending_upgrade_blocks_affected_account_and_preserves_other_accounts() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().upload_status = 503;
    assert!(apply_upgrade(&mut backend).await.is_err());
    for kind in [
        "save_link",
        "recover_account",
        "cleanup_account",
        "rotate_selftest",
    ] {
        assert!(backend.prepare_change(&json!({"kind":kind,"accountId":"acct1","domainId":"domain1","slug":"new","cnUrl":"https://example.org/cn","defaultUrl":"https://example.org/default"})).is_err());
    }
    assert!(backend
        .dispatch("remove_account", &json!({"accountId":"acct1"}))
        .await
        .is_err());
    let mut other = backend.db.accounts[0].clone();
    other.id = "acct2".into();
    backend.db.accounts.push(other);
    assert!(backend
        .prepare_change(&json!({"kind":"rotate_selftest","accountId":"acct2"}))
        .is_ok());
    assert!(backend
        .prepare_change(&json!({"kind":"upgrade_worker","accountId":"acct2"}))
        .is_err());
    assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
}
fn payload(slug: &str, create_only: bool) -> Value {
    json!({"kind":"save_link","domainId":"domain1","slug":slug,"createOnly":create_only,"cnUrl":"https://example.org/Cn?Code=XyZ","defaultUrl":"https://example.org/Default?Code=XyZ"})
}
fn link(slug: &str) -> Link {
    Link {
        domain_id: "domain1".into(),
        slug: slug.into(),
        cn_url: "https://example.org/old-cn".into(),
        default_url: "https://example.org/old-default".into(),
        updated: now(),
        pool_id: None,
        code: None,
    }
}
#[tokio::test]
async fn names_prepare_normalizes_new_even_without_create_only_and_preserves_legacy_exact() {
    let (_server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    for create_only in [true, false] {
        backend
            .prepare_change(&payload("NeW_123", create_only))
            .unwrap();
        match backend.plans.pop().unwrap().kind {
            PlanKind::SaveLink {
                slug, exact_edit, ..
            } => {
                assert_eq!(slug, "new_123");
                assert!(!exact_edit);
            }
            _ => panic!(),
        }
    }
    backend.db.links.extend([link("OK"), link("ok")]);
    for slug in ["OK", "ok"] {
        backend.prepare_change(&payload(slug, false)).unwrap();
        match backend.plans.pop().unwrap().kind {
            PlanKind::SaveLink {
                slug: actual,
                exact_edit,
                ..
            } => {
                assert_eq!(actual, slug);
                assert!(exact_edit);
            }
            _ => panic!(),
        }
    }
    assert!(backend.prepare_change(&payload("oK", false)).is_err());
    assert!(backend.prepare_change(&payload("OK", true)).is_err());
}
#[tokio::test]
async fn names_apply_rejects_local_fold_race_before_requests() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.prepare_change(&payload("NEW", false)).unwrap();
    let kind = backend.plans.pop().unwrap().kind;
    backend.db.links.push(link("New"));
    assert!(backend.apply(kind, false).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn names_cloud_preflight_failure_or_collision_is_zero_write() {
    for scenario in [
        "collision",
        "network",
        "cursor_cycle",
        "malformed_info",
        "null_info",
        "malformed_cursor",
        "null_cursor",
        "malformed_count",
        "missing_result",
        "rejected_envelope",
        "wrong_prefix",
    ] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        let response = match scenario {
            "network" => ResponseTemplate::new(503),
            "collision" => ok(json!([{"name":"l:example.com:NeW"}])),
            "malformed_info" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result":[],"result_info":[]})),
            "null_info" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result":[],"result_info":null})),
            "malformed_cursor" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result":[],"result_info":{"cursor":42}})),
            "null_cursor" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result":[],"result_info":{"cursor":null}})),
            "malformed_count" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result":[],"result_info":{"count":-1}})),
            "missing_result" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":true,"result_info":{"cursor":""}})),
            "rejected_envelope" => ResponseTemplate::new(200)
                .set_body_json(json!({"success":false,"result":[],"result_info":{"cursor":""}})),
            "wrong_prefix" => ok(json!([{"name":"l:example.org:new"}])),
            _ => ResponseTemplate::new(200).set_body_json(
                json!({"success":true,"result":[],"result_info":{"cursor":"repeat"}}),
            ),
        };
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(response)
            .mount(&server)
            .await;
        backend.prepare_change(&payload("NeW", false)).unwrap();
        let kind = backend.plans.pop().unwrap().kind;
        assert!(backend.apply(kind, false).await.is_err());
        assert!(writes(&server).await.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }
}
#[tokio::test]
async fn names_new_write_is_lowercase_and_exact_legacy_edits_do_not_list() {
    for slug in ["NeW", "OK", "ok"] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        let new = slug == "NeW";
        if !new {
            backend.db.links.extend([link("OK"), link("ok")]);
        }
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        let canonical = if new { "new" } else { slug };
        let value_path=format!("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3A{canonical}");
        Mock::given(method("GET"))
            .and(path(&value_path))
            .respond_with(if new {
                ResponseTemplate::new(404)
            } else {
                ResponseTemplate::new(200).set_body_string(kv_link(&link(slug)).to_string())
            })
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(&value_path))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let plan = backend.prepare_change(&payload(slug, false)).unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert!(backend
            .db
            .links
            .iter()
            .any(|l| l.slug == canonical && l.default_url.contains("Code=XyZ")));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path() == KEYS_PATH)
                .count(),
            usize::from(new)
        );
        assert_eq!(writes(&server).await.len(), 1);
    }
}

#[tokio::test]
async fn upgrade_final_persist_failure_resumes_without_any_additional_cloud_write() {
    let (server, mut backend, _guard) = fixture().await;
    mount_upgrade(&server, &backend.path).await;
    backend
        .fail_persist_at
        .store(3, std::sync::atomic::Ordering::SeqCst);
    assert!(apply_upgrade(&mut backend).await.is_err());
    assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
    let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
    backend.db = saved;
    let before = writes(&server).await.len();
    resume_upgrade(&mut backend).await.unwrap();
    assert_eq!(writes(&server).await.len(), before);
    assert!(backend.db.pending_worker_upgrades.is_empty());
}

#[tokio::test]
async fn upgrade_dismiss_does_not_require_migration_or_read_any_credential() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().upload_status = 503;
    assert!(apply_upgrade(&mut backend).await.is_err());
    backend.db.accounts[0].mac_credential_schema = 0;
    mock_key_reads().lock().unwrap().clear();
    let before = writes(&server).await.len();
    let plan = backend
        .prepare_change(&json!({"kind":"dismiss_worker_upgrade","accountId":"acct1"}))
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert_eq!(writes(&server).await.len(), before);
    assert!(backend.db.pending_worker_upgrades.is_empty());
}

#[tokio::test]
async fn upgrade_legacy_journal_blocks_prepare_and_stale_target_blocks_apply() {
    let (server, mut backend, _guard) = fixture().await;
    backend
        .db
        .pending_operations
        .push("重置自检密钥 acct1 (legacy)".into());
    assert!(backend
        .prepare_change(&json!({"kind":"upgrade_worker","accountId":"acct1"}))
        .is_err());
    backend.db.pending_operations.clear();
    assert!(backend
        .apply(
            PlanKind::UpgradeWorker {
                account_id: "acct1".into(),
                target_hash: "0".repeat(64)
            },
            false
        )
        .await
        .is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(mock_key_reads().lock().unwrap().is_empty());
}

#[tokio::test]
async fn names_paginated_collision_and_nonadjacent_cursor_cycle_never_write() {
    for collision in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .respond_with(move |request: &wiremock::Request| {
                let cursor = request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "cursor")
                    .map(|(_, v)| v.into_owned());
                let (names, next) = match cursor.as_deref() {
                    None => (json!([]), "first"),
                    Some("first") if collision => (json!([{"name":"l:example.com:NEW"}]), ""),
                    Some("first") => (json!([]), "second"),
                    _ => (json!([]), "first"),
                };
                ResponseTemplate::new(200).set_body_json(
                    json!({"success":true,"result":names,"result_info":{"cursor":next}}),
                )
            })
            .mount(&server)
            .await;
        backend.prepare_change(&payload("NeW", false)).unwrap();
        let kind = backend.plans.pop().unwrap().kind;
        assert!(backend.apply(kind, false).await.is_err());
        assert!(writes(&server).await.is_empty());
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == KEYS_PATH)
                .count(),
            if collision { 2 } else { 3 }
        );
    }
}

#[tokio::test]
async fn import_and_recovery_keep_both_legacy_exact_names() {
    for recover in [false, true] {
        let (server, mut backend, _guard) = fixture().await;
        tests::mount_recovery_without_pool(&server, false).await;
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(
                json!([{"name":"l:example.com:OK"},{"name":"l:example.com:ok"}]),
            ))
            .with_priority(1)
            .mount(&server)
            .await;
        for slug in ["OK", "ok"] {
            Mock::given(method("GET")).and(path(format!("/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3A{slug}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(kv_link(&link(slug)).to_string())).mount(&server).await;
        }
        if recover {
            backend.recover_account("acct1").await.unwrap();
        } else {
            let backup = json!({"schema":SCHEMA,"accounts":[{"id":"acct1","label":"Example"}],"domains":[{"accountId":"acct1","host":"example.com","prefix":"go"}],
                "links":[{"host":"example.com","slug":"OK","cnUrl":"https://example.org/old-cn","defaultUrl":"https://example.org/old-default"},
                    {"host":"example.com","slug":"ok","cnUrl":"https://example.org/old-cn","defaultUrl":"https://example.org/old-default"}]});
            backend.import_config(&backup.to_string()).await.unwrap();
        }
        assert_eq!(backend.db.links.len(), 2, "recover={recover}");
        assert!(backend.db.links.iter().any(|l| l.slug == "OK"));
        assert!(backend.db.links.iter().any(|l| l.slug == "ok"));
        assert!(writes(&server).await.is_empty());
    }
}

#[tokio::test]
async fn upgrade_missing_secrets_can_use_confirmed_selftest_and_monitor_repairs() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().missing_secrets = true;
    backend.db.accounts[0].monitor_enabled = true;
    backend.db.accounts[0].monitor_endpoint = Some("https://example.org/probe".into());
    apply_upgrade(&mut backend).await.unwrap();
    let state = remote.clone();
    Mock::given(method("PUT"))
        .and(path(format!("{SCRIPT_PATH}/secrets")))
        .respond_with(move |request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["name"], "SELFTEST_KEY");
            state.lock().unwrap().settings["bindings"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"SELFTEST_KEY","type":"secret_text"}));
            ok(json!({}))
        })
        .mount(&server)
        .await;
    let plan = backend
        .prepare_change(&json!({"kind":"rotate_selftest","accountId":"acct1"}))
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert!(!backend.db.accounts[0].needs_selftest_key);
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(json!({"endpoint":"https://example.org/probe"}).to_string()),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
        ))
        .respond_with(ok(json!({})))
        .mount(&server)
        .await;
    let state = remote.clone();
    Mock::given(method("PUT"))
        .and(path(format!("{SCRIPT_PATH}/schedules")))
        .respond_with(move |_: &wiremock::Request| {
            state.lock().unwrap().schedules = json!({"schedules":[]});
            ok(json!({}))
        })
        .mount(&server)
        .await;
    let plan = backend
        .dispatch("disable_monitor", &json!({"accountId":"acct1"}))
        .await
        .unwrap();
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert!(!backend.db.accounts[0].monitor_enabled);
    assert!(!backend.db.accounts[0].needs_monitor_key);
    assert!(backend.db.pending_operations.is_empty());
    assert_eq!(
        writes(&server)
            .await
            .iter()
            .filter(|r| r.url.path() == SCRIPT_PATH)
            .count(),
        1
    );
}

#[tokio::test]
async fn accepted_upload_with_old_content_read_keeps_pending_until_target_is_visible() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().delay_content_visibility = true;
    assert!(apply_upgrade(&mut backend)
        .await
        .unwrap_err()
        .contains("可能尚未同步"));
    assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
    assert_eq!(backend.db.pending_operations.len(), 1);
    let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
    assert_eq!(saved.pending_worker_upgrades.len(), 1);
    assert_eq!(writes(&server).await.len(), 1);
    assert_eq!(writes(&server).await[0].url.path(), SCRIPT_PATH);
    assert_eq!(
        remote.lock().unwrap().manifest["sourceHash"],
        hex::encode(Sha256::digest(OLD_SOURCE))
    );
    assert!(resume_upgrade(&mut backend)
        .await
        .unwrap_err()
        .contains("可能尚未同步"));
    assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
    assert_eq!(writes(&server).await.len(), 1);
    remote.lock().unwrap().source = include_str!("../../edge/worker.mjs").into();
    resume_upgrade(&mut backend).await.unwrap();
    let mutations = writes(&server).await;
    assert_eq!(mutations.len(), 2);
    assert_eq!(mutations[1].url.path(), MANIFEST_PATH);
    assert_eq!(
        mutations
            .iter()
            .filter(|r| r.url.path() == SCRIPT_PATH)
            .count(),
        1
    );
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend.db.pending_operations.is_empty());
}

#[tokio::test]
async fn names_terminal_pages_without_cursor_allow_new_link_creation() {
    for info in [None, Some(json!({})), Some(json!({"count":0}))] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        let mut envelope = json!({"success":true,"result":[]});
        if let Some(info) = info {
            envelope["result_info"] = info;
        }
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope))
            .mount(&server)
            .await;
        let value_path =
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Anew";
        Mock::given(method("GET"))
            .and(path(value_path))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(value_path))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let plan = backend.prepare_change(&payload("NeW", true)).unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert_eq!(backend.db.links.len(), 1);
        assert_eq!(backend.db.links[0].slug, "new");
        assert_eq!(writes(&server).await.len(), 1);
    }
}

#[tokio::test]
async fn local_dismiss_removes_known_pending_after_resource_identity_changes() {
    for missing_resource in [false, true] {
        let (server, mut backend, _guard) = fixture().await;
        let remote = mount_upgrade(&server, &backend.path).await;
        remote.lock().unwrap().upload_status = 503;
        assert!(apply_upgrade(&mut backend).await.is_err());
        backend.db.accounts[0].resources = if missing_resource {
            None
        } else {
            Some(Resources {
                script: "another-edge".into(),
                namespace: "another-ns".into(),
            })
        };
        backend.db.accounts[0].mac_credential_schema = 0;
        let before_resource = serde_json::to_value(&backend.db.accounts[0].resources).unwrap();
        let before = writes(&server).await.len();
        assert!(backend
            .prepare_change(&json!({"kind":"resume_worker_upgrade","accountId":"acct1"}))
            .is_err());
        mock_key_reads().lock().unwrap().clear();
        let plan = backend
            .prepare_change(&json!({"kind":"dismiss_worker_upgrade","accountId":"acct1"}))
            .unwrap();
        backend
            .dispatch("apply_plan", &json!({"planId":plan["id"]}))
            .await
            .unwrap();
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert_eq!(writes(&server).await.len(), before);
        assert_eq!(
            serde_json::to_value(&backend.db.accounts[0].resources).unwrap(),
            before_resource
        );
        assert!(backend.db.pending_worker_upgrades.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }
}

#[tokio::test]
async fn unsupported_settings_diagnostics_identify_only_fixed_protocol_fields() {
    for field in [
        "annotations",
        "cache_options",
        "observability",
        "placement",
        "usage_model",
        "limits",
        "assets",
        "migration_tag",
        "migrations",
        "exports",
        "exports_reconciliation",
        "tags",
        "tail_consumers",
        "logpush",
        "cpu_ms",
    ] {
        let (server, mut backend, _guard) = fixture().await;
        let remote = mount_upgrade(&server, &backend.path).await;
        remote.lock().unwrap().settings[field] = json!("do-not-echo-setting-value");
        let error = apply_upgrade(&mut backend).await.unwrap_err();
        assert!(error.contains(&format!("设置字段：{field}")));
        assert!(!error.contains("do-not-echo-setting-value"));
        assert!(writes(&server).await.is_empty());
        assert!(backend.db.pending_worker_upgrades.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }
}

#[tokio::test]
async fn unsupported_settings_diagnostics_never_echo_arbitrary_key_or_values() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    remote.lock().unwrap().settings["arbitrary_field_123"] =
        json!({"host":"example.org","note":"do-not-echo-setting-value"});
    let error = apply_upgrade(&mut backend).await.unwrap_err();
    assert!(error.contains("设置字段：未识别字段"));
    for forbidden in [
        "arbitrary_field_123",
        "do-not-echo-setting-value",
        "example.org",
    ] {
        assert!(!error.contains(forbidden));
    }
    assert!(writes(&server).await.is_empty());
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend.db.pending_operations.is_empty());
}

#[tokio::test]
async fn upgrade_ignores_only_readonly_annotation_in_preflight_and_readback() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    {
        let mut state = remote.lock().unwrap();
        state.settings["annotations"] = json!({
            "workers/triggered_by":"previous-server-operation",
            "workers/message":"",
            "workers/tag":""
        });
        state.annotations_after_upload = Some(json!({"workers/triggered_by":"upload"}));
    }
    apply_upgrade(&mut backend).await.unwrap();
    let mutations = writes(&server).await;
    assert_eq!(mutations.len(), 2);
    assert_eq!(mutations[0].url.path(), SCRIPT_PATH);
    assert_eq!(
        upload_metadata(&mutations[0]).await,
        json!({
            "main_module":"worker.mjs",
            "compatibility_date":"2025-01-01",
            "compatibility_flags":["nodejs_compat","streams_enable_constructors"],
            "bindings":[{"type":"kv_namespace","name":"LINKS","namespace_id":"ns1"}],
            "keep_bindings":["secret_text"]
        })
    );
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert_eq!(
        remote.lock().unwrap().schedules,
        json!({"schedules":[{"cron":"*/15 * * * *"}]})
    );
}

#[tokio::test]
async fn resume_ignores_readonly_annotation_changes_without_uploading_them() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    {
        let mut state = remote.lock().unwrap();
        state.settings["annotations"] =
            json!({"workers/triggered_by":"private-server-provenance-before"});
        state.annotations_after_upload = Some(json!({"workers/triggered_by":"upload"}));
        state.fail_manifest = true;
    }
    assert!(apply_upgrade(&mut backend).await.is_err());
    assert_eq!(backend.db.pending_worker_upgrades.len(), 1);
    let pending = &backend.db.pending_worker_upgrades[0];
    assert!(pending.settings.get("annotations").is_none());
    assert!(!serde_json::to_string(pending)
        .unwrap()
        .contains("private-server-provenance-before"));
    assert_eq!(pending.schedules, json!(["*/15 * * * *"]));
    let saved: Database = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
    assert_eq!(saved.pending_worker_upgrades[0].settings, pending.settings);
    {
        let mut state = remote.lock().unwrap();
        state.settings["annotations"] = json!({"workers/triggered_by":"another-server-operation"});
        state.fail_manifest = false;
    }
    let before = writes(&server).await.len();
    resume_upgrade(&mut backend).await.unwrap();
    let mutations = writes(&server).await;
    assert_eq!(mutations.len(), before + 1);
    assert_eq!(mutations[before].url.path(), MANIFEST_PATH);
    assert_eq!(
        mutations
            .iter()
            .filter(|request| request.url.path() == SCRIPT_PATH)
            .count(),
        1
    );
    assert!(upload_metadata(&mutations[0])
        .await
        .get("annotations")
        .is_none());
    assert!(backend.db.pending_worker_upgrades.is_empty());
}

#[tokio::test]
async fn mutable_unknown_or_malformed_annotations_reject_before_writes_with_safe_diagnostics() {
    for (annotations, label) in [
        (
            json!({"workers/triggered_by":"upload","workers/message":"do-not-echo-annotation-value"}),
            "annotations.workers/message",
        ),
        (
            json!({"workers/triggered_by":"upload","workers/tag":"do-not-echo-annotation-value"}),
            "annotations.workers/tag",
        ),
        (
            json!({"workers/triggered_by":"upload","private-annotation-key":""}),
            "annotations.未识别字段",
        ),
        (
            json!({"workers/triggered_by":true}),
            "annotations.workers/triggered_by",
        ),
        (
            json!({"workers/triggered_by":"x".repeat(1025)}),
            "annotations.workers/triggered_by",
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        let remote = mount_upgrade(&server, &backend.path).await;
        remote.lock().unwrap().settings["annotations"] = annotations;
        let error = apply_upgrade(&mut backend).await.unwrap_err();
        assert!(error.contains(label));
        assert!(!error.contains("do-not-echo-annotation-value"));
        assert!(!error.contains("private-annotation-key"));
        assert!(writes(&server).await.is_empty());
        assert!(backend.db.pending_worker_upgrades.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }
}

#[tokio::test]
async fn unsupported_setting_diagnostics_aggregate_fixed_labels_and_deduplicate_unknowns() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    {
        let mut state = remote.lock().unwrap();
        state.settings["annotations"] = json!({
            "workers/message":"do-not-echo-setting-value",
            "workers/tag":"do-not-echo-setting-value",
            "private-annotation-key":"",
            "another-private-annotation-key":false
        });
        state.settings["cache_options"] = json!({"enabled":true});
        state.settings["observability"] = json!({"enabled":true});
        state.settings["private-setting-key"] = json!("do-not-echo-setting-value");
        state.settings["another-private-setting-key"] = json!("do-not-echo-setting-value");
    }
    let error = apply_upgrade(&mut backend).await.unwrap_err();
    for label in [
        "annotations.workers/message",
        "annotations.workers/tag",
        "annotations.未识别字段",
        "cache_options",
        "observability",
    ] {
        assert_eq!(error.matches(label).count(), 1);
    }
    let labels = error
        .split("设置字段：")
        .nth(1)
        .unwrap()
        .split('）')
        .next()
        .unwrap()
        .split('、')
        .collect::<Vec<_>>();
    assert_eq!(labels.len(), 6);
    assert_eq!(
        labels
            .iter()
            .filter(|&&label| label == "未识别字段")
            .count(),
        1
    );
    for forbidden in [
        "do-not-echo-setting-value",
        "private-setting-key",
        "private-annotation-key",
    ] {
        assert!(!error.contains(forbidden));
    }
    assert!(writes(&server).await.is_empty());
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend.db.pending_operations.is_empty());
}

#[tokio::test]
async fn unsupported_setting_diagnostics_have_at_most_sixteen_fixed_labels() {
    let (server, mut backend, _guard) = fixture().await;
    let remote = mount_upgrade(&server, &backend.path).await;
    {
        let mut state = remote.lock().unwrap();
        state.settings["annotations"] = json!({
            "workers/triggered_by":false,
            "workers/message":"do-not-echo-setting-value",
            "workers/tag":"do-not-echo-setting-value",
            "private-annotation-key":""
        });
        for field in [
            "cache_options",
            "observability",
            "placement",
            "usage_model",
            "limits",
            "assets",
            "migration_tag",
            "migrations",
            "exports",
            "exports_reconciliation",
            "tags",
            "tail_consumers",
            "logpush",
            "cpu_ms",
            "private-setting-key",
        ] {
            state.settings[field] = json!("do-not-echo-setting-value");
        }
    }
    let error = apply_upgrade(&mut backend).await.unwrap_err();
    assert_eq!(
        error
            .split("设置字段：")
            .nth(1)
            .unwrap()
            .split('）')
            .next()
            .unwrap()
            .split('、')
            .count(),
        16
    );
    assert!(!error.contains("do-not-echo-setting-value"));
    assert!(!error.contains("private-setting-key"));
    assert!(!error.contains("private-annotation-key"));
    assert!(writes(&server).await.is_empty());
    assert!(backend.db.pending_worker_upgrades.is_empty());
    assert!(backend.db.pending_operations.is_empty());
}

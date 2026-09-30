//! Synthetic-only coverage for repairing missing local recovery resource identity.
use super::*;
use crate::tests::{domain, fixture, sample_pool};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn legacy_without_resources(backend: &mut Backend) {
    backend.db.accounts[0].resources = None;
    backend.db.accounts[0].has_resources = false;
    backend.db.accounts[0].needs_selftest_key = false;
    backend
        .db
        .pending_operations
        .push("重置自检密钥 acct1 (legacy)：等待核对".into());
}
fn resources_plan(backend: &mut Backend) -> Value {
    backend
        .prepare_change(&json!({"kind":"recover_selftest_resources","accountId":"acct1"}))
        .unwrap()
}
async fn apply_resources(backend: &mut Backend) -> Result<Value, String> {
    let plan = resources_plan(backend);
    backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
}
fn json_response(value: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"success":true,"result":value}))
}
async fn list_namespaces(server: &MockServer, ids: &[&str]) {
    Mock::given(method("GET"))
        .and(path("/client/v4/accounts/acct1/storage/kv/namespaces"))
        .respond_with(json_response(json!(ids
            .iter()
            .map(|id| json!({"id":id}))
            .collect::<Vec<_>>())))
        .mount(server)
        .await;
}
async fn candidate(server: &MockServer, namespace: &str, script: &str, fault: &str) {
    let mut manifest = json!({"schema":1,"accountId":"acct1","namespace":namespace,"script":script,"sourceHash":bundled_source_hash()});
    match fault {
        "foreign-account" => manifest["accountId"] = json!("acct10"),
        "foreign-namespace" => manifest["namespace"] = json!("other"),
        "unknown-schema" => manifest["schema"] = json!(2),
        "invalid-script" => manifest["script"] = json!("../other"),
        "wrong-source-hash" => manifest["sourceHash"] = json!("0".repeat(64)),
        _ => {}
    }
    let response = match fault {
        "manifest-read-error" => ResponseTemplate::new(403),
        "missing-manifest" => ResponseTemplate::new(404),
        "malformed-manifest" => ResponseTemplate::new(200).set_body_string("invalid-json"),
        _ => ResponseTemplate::new(200).set_body_string(manifest.to_string()),
    };
    Mock::given(method("GET"))
        .and(path(format!(
            "/client/v4/accounts/acct1/storage/kv/namespaces/{namespace}/values/m%3Aconfig"
        )))
        .respond_with(response)
        .mount(server)
        .await;
    let mut bindings = json!([
        {"name":"LINKS","type":"kv_namespace","namespace_id":namespace},
        {"name":"SELFTEST_KEY","type":"secret_text"}
    ]);
    if fault == "wrong-binding" {
        bindings[0]["namespace_id"] = json!("other");
    }
    if fault == "unknown-binding" {
        bindings
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"UNKNOWN","type":"secret_text"}));
    }
    Mock::given(method("GET"))
        .and(path(format!(
            "/client/v4/accounts/acct1/workers/scripts/{script}/settings"
        )))
        .respond_with(if fault == "settings-read-error" {
            ResponseTemplate::new(403)
        } else {
            json_response(json!({"bindings":bindings}))
        })
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/client/v4/accounts/acct1/workers/scripts/{script}/content/v2"
        )))
        .respond_with(if fault == "source-read-error" {
            ResponseTemplate::new(403)
        } else {
            ResponseTemplate::new(200).set_body_raw(
                if fault == "changed-source" {
                    b"export default {};".to_vec()
                } else {
                    include_bytes!("../../edge/worker.mjs").to_vec()
                },
                "application/javascript",
            )
        })
        .mount(server)
        .await;
}
async fn only_discovery_reads(server: &MockServer) {
    let calls = server.received_requests().await.unwrap();
    assert!(calls.iter().all(|r| r.method.as_str() == "GET"));
    assert!(calls
        .iter()
        .all(|r| r.url.path().starts_with("/client/v4/accounts/acct1/")));
    assert!(calls.iter().all(|r| !r.url.path().ends_with("/secrets")
        && !r.url.path().contains("/keys")
        && !r.url.path().contains("/zones")));
    assert_eq!(*mock_key_reads().lock().unwrap(), vec!["token:acct1"]);
    assert!(mock_key_mutations().lock().unwrap().is_empty());
}

#[tokio::test]
async fn resource_recovery_changes_only_target_resource_identity_and_keeps_all_journals() {
    let (server, mut backend, _dir) = fixture().await;
    let mut other = backend.db.accounts[0].clone();
    other.id = "acct10".into();
    backend.db.accounts.push(other);
    legacy_without_resources(&mut backend);
    backend
        .db
        .pending_operations
        .push("重置自检密钥 acct10 (independent)：等待恢复".into());
    backend
        .db
        .pending_monitor_changes
        .push(PendingMonitorChange {
            account_id: "acct10".into(),
            endpoint: "https://probe.example".into(),
            enabled: true,
            journal: "启用监测 acct10 (independent)".into(),
        });
    backend
        .db
        .pending_operations
        .push("启用监测 acct10 (independent)：尚未完成".into());
    backend.db.domains.push(domain());
    backend.db.pools.push(sample_pool());
    backend.db.links.push(Link {
        domain_id: "domain1".into(),
        slug: "demo".into(),
        cn_url: "https://cn.example/".into(),
        default_url: "https://other.example/".into(),
        updated: now(),
        pool_id: None,
        code: None,
    });
    let secrets = mock_keys().lock().unwrap().clone();
    let mut expected = backend.db.clone();
    expected.accounts[0].resources = Some(Resources {
        script: "edge-one".into(),
        namespace: "ns1".into(),
    });
    expected.accounts[0].has_resources = true;
    let before = backend.state();
    assert!(before["pendingActions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["kind"] == "recover_selftest_resources"
            && a["label"] == "找回检测服务配置"
            && a["accountId"] == "acct1"));
    let plan = resources_plan(&mut backend);
    assert_eq!(plan["title"], "找回检测服务配置");
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(mock_key_mutations().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
    list_namespaces(&server, &["ns1"]).await;
    candidate(&server, "ns1", "edge-one", "none").await;
    let state = backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&backend.db).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&backend.path).unwrap()).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(*mock_keys().lock().unwrap(), secrets);
    assert!(state["accounts"][0]["needsSelftestKey"].as_bool().unwrap());
    assert!(!backend.db.accounts[0].needs_selftest_key);
    assert!(state["pendingActions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["accountId"] == "acct1" && a["kind"] == "recover_selftest_rotation"));
    assert!(!state["pendingActions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["accountId"] == "acct1" && a["kind"] == "recover_selftest_resources"));
    let count = server.received_requests().await.unwrap().len();
    assert!(backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap_err()
        .contains("已被使用"));
    assert_eq!(server.received_requests().await.unwrap().len(), count);
    only_discovery_reads(&server).await;
}

#[tokio::test]
async fn resource_recovery_rejects_zero_multiple_false_or_changed_candidates_without_mutation() {
    for fault in [
        "zero",
        "multiple",
        "missing-manifest",
        "malformed-manifest",
        "foreign-account",
        "foreign-namespace",
        "unknown-schema",
        "invalid-script",
        "wrong-source-hash",
        "wrong-binding",
        "unknown-binding",
        "changed-source",
    ] {
        let (server, mut backend, _dir) = fixture().await;
        legacy_without_resources(&mut backend);
        let before = backend.database_snapshot();
        let secrets = mock_keys().lock().unwrap().clone();
        let ids = match fault {
            "zero" => vec![],
            "multiple" => vec!["ns1", "ns2"],
            _ => vec!["ns1"],
        };
        list_namespaces(&server, &ids).await;
        for id in ids {
            candidate(&server, id, &format!("edge-{id}"), fault).await;
        }
        assert!(apply_resources(&mut backend).await.is_err(), "{fault}");
        assert_eq!(backend.database_snapshot(), before, "{fault}");
        assert!(!backend.path.exists());
        assert_eq!(*mock_keys().lock().unwrap(), secrets);
        only_discovery_reads(&server).await;
    }
}

#[tokio::test]
async fn resource_recovery_stops_on_any_candidate_read_error_even_after_one_valid_match() {
    for fault in [
        "namespace-read-error",
        "manifest-read-error",
        "settings-read-error",
        "source-read-error",
    ] {
        let (server, mut backend, _dir) = fixture().await;
        legacy_without_resources(&mut backend);
        let before = backend.database_snapshot();
        if fault == "namespace-read-error" {
            Mock::given(method("GET"))
                .and(path("/client/v4/accounts/acct1/storage/kv/namespaces"))
                .respond_with(ResponseTemplate::new(403))
                .mount(&server)
                .await;
        } else {
            list_namespaces(&server, &["ns1", "ns2"]).await;
            candidate(&server, "ns1", "edge-one", "none").await;
            candidate(&server, "ns2", "edge-two", fault).await;
        }
        assert!(apply_resources(&mut backend).await.is_err(), "{fault}");
        assert_eq!(backend.database_snapshot(), before);
        assert!(!backend.path.exists());
        only_discovery_reads(&server).await;
    }
}

#[tokio::test]
async fn resource_recovery_persist_failure_restores_complete_memory_and_disk_state() {
    let (server, mut backend, _dir) = fixture().await;
    legacy_without_resources(&mut backend);
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    let disk = fs::read(&backend.path).unwrap();
    backend
        .fail_persist_at
        .store(2, std::sync::atomic::Ordering::SeqCst);
    list_namespaces(&server, &["ns1"]).await;
    candidate(&server, "ns1", "edge-one", "none").await;
    assert!(apply_resources(&mut backend)
        .await
        .unwrap_err()
        .contains("保存失败"));
    assert_eq!(backend.database_snapshot(), before);
    assert_eq!(fs::read(&backend.path).unwrap(), disk);
    only_discovery_reads(&server).await;
}

fn conflict(backend: &mut Backend, kind: &str) {
    match kind {
        "no-legacy" => backend.db.pending_operations.clear(),
        "other-account-only" => {
            backend.db.pending_operations = vec!["重置自检密钥 acct10 (other)".into()]
        }
        "resources-present" => {
            backend.db.accounts[0].resources = Some(Resources {
                script: "edge-one".into(),
                namespace: "ns1".into(),
            })
        }
        "typed-rotation" => backend
            .db
            .pending_selftest_rotations
            .push(PendingSelftestRotation {
                account_id: "acct1".into(),
                script: "edge-one".into(),
                namespace: "ns1".into(),
                journal: "rotation".into(),
                status: SelftestRotationStatus::Staged,
            }),
        "monitor" => backend
            .db
            .pending_monitor_changes
            .push(PendingMonitorChange {
                account_id: "acct1".into(),
                endpoint: "https://probe.example".into(),
                enabled: true,
                journal: "monitor".into(),
            }),
        "pool-current" => backend.db.pending_pool_changes.push(PendingPoolChange {
            pool: sample_pool(),
            previous: None,
            journal: "pool".into(),
            deleting: false,
        }),
        "pool-previous" => {
            let mut current = sample_pool();
            current.account_ids = vec!["acct10".into()];
            backend.db.pending_pool_changes.push(PendingPoolChange {
                pool: current,
                previous: Some(sample_pool()),
                journal: "pool".into(),
                deleting: true,
            });
        }
        "cleanup" => backend
            .db
            .pending_operations
            .push("清理账号 acct1 (unfinished)".into()),
        "initialization" => backend
            .db
            .pending_operations
            .push("接入新域名 example.com (unfinished)".into()),
        "unknown-journal" => backend
            .db
            .pending_operations
            .push("unclassified historical operation".into()),
        _ => panic!("unknown test case"),
    }
}

#[tokio::test]
async fn resource_recovery_rechecks_narrow_preconditions_in_prepare_and_apply() {
    for kind in [
        "no-legacy",
        "other-account-only",
        "resources-present",
        "typed-rotation",
        "monitor",
        "pool-current",
        "pool-previous",
        "cleanup",
        "initialization",
        "unknown-journal",
    ] {
        let (server, mut backend, _dir) = fixture().await;
        legacy_without_resources(&mut backend);
        conflict(&mut backend, kind);
        let before = backend.database_snapshot();
        assert!(
            !backend.db.can_recover_selftest_resources("acct1"),
            "{kind}"
        );
        assert!(backend
            .prepare_change(&json!({"kind":"recover_selftest_resources","accountId":"acct1"}))
            .is_err());
        assert!(backend
            .apply(
                PlanKind::RecoverSelftestResources {
                    account_id: "acct1".into()
                },
                false
            )
            .await
            .is_err());
        assert_eq!(backend.database_snapshot(), before);
        assert!(mock_key_reads().lock().unwrap().is_empty());
        assert!(mock_key_mutations().lock().unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn resource_recovery_expiry_snapshot_and_unknown_account_fail_before_any_access() {
    let (server, mut backend, _dir) = fixture().await;
    legacy_without_resources(&mut backend);
    assert!(backend
        .prepare_change(&json!({"kind":"recover_selftest_resources","accountId":"unknown"}))
        .is_err());
    let plan = resources_plan(&mut backend);
    backend.plans.last_mut().unwrap().expires_at = Instant::now() - Duration::from_secs(1);
    assert!(backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap_err()
        .contains("过期"));
    let plan = resources_plan(&mut backend);
    conflict(&mut backend, "monitor");
    assert!(backend
        .dispatch("apply_plan", &json!({"planId":plan["id"]}))
        .await
        .unwrap_err()
        .contains("配置已变化"));
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(mock_key_mutations().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn resource_recovery_does_not_relax_normal_recovery_or_rotate_the_key() {
    let (server, mut backend, _dir) = fixture().await;
    legacy_without_resources(&mut backend);
    assert!(backend
        .prepare_change(&json!({"kind":"recover_account","accountId":"acct1"}))
        .is_err());
    assert!(backend.recover_account("acct1").await.is_err());
    assert!(backend
        .prepare_change(&json!({"kind":"recover_selftest_rotation","accountId":"acct1"}))
        .unwrap_err()
        .contains("找回检测服务配置"));
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(mock_key_mutations().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn resource_recovery_missing_token_never_scans_cloud_or_updates_state() {
    let (server, mut backend, _dir) = fixture().await;
    legacy_without_resources(&mut backend);
    mock_keys().lock().unwrap().remove("token:acct1");
    let before = backend.database_snapshot();
    assert!(apply_resources(&mut backend).await.is_err());
    assert_eq!(backend.database_snapshot(), before);
    only_discovery_reads(&server).await;
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn resource_recovery_unmigrated_account_is_gated_before_prepare_and_apply() {
    let (server, mut backend, _dir) = fixture().await;
    legacy_without_resources(&mut backend);
    backend.db.accounts[0].mac_credential_schema = 0;
    for result in [
        backend
            .prepare_change(&json!({"kind":"recover_selftest_resources","accountId":"acct1"}))
            .map(|_| ()),
        backend.recover_selftest_resources("acct1").await,
    ] {
        assert!(result.unwrap_err().contains("需要更新本机授权"));
    }
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(mock_key_mutations().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

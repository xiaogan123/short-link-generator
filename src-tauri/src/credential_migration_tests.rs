//! Synthetic integration tests. All credential calls are in-memory mocks.
use super::*;
use crate::tests::{domain, fixture, sample_pool};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn make_legacy(backend: &mut Backend) {
    backend.db.accounts[0].mac_credential_schema = 0;
    mock_keys().lock().unwrap().clear();
    *mock_legacy_keys().lock().unwrap() = credential_migration::KINDS
        .iter()
        .map(|kind| (format!("{kind}:acct1"), format!("synthetic-old-{kind}")))
        .collect();
    mock_key_reads().lock().unwrap().clear();
    mock_key_mutations().lock().unwrap().clear();
}
fn migration_plan(backend: &mut Backend) -> Value {
    backend
        .prepare_change(&json!({"kind":"migrate_credentials","accountId":"acct1"}))
        .unwrap()
}
async fn apply_migration(backend: &mut Backend) -> Result<Value, String> {
    let plan = migration_plan(backend);
    backend
        .dispatch(
            "apply_plan",
            &json!({"planId":plan["id"],"acknowledgeCredentialMigration":true}),
        )
        .await
}
fn no_credentials() {
    assert!(mock_key_reads().lock().unwrap().is_empty());
    assert!(mock_key_mutations().lock().unwrap().is_empty());
}
fn pending_rotation(backend: &mut Backend) {
    let journal = "重置自检密钥 acct1 (synthetic-pending)".to_string();
    backend.db.pending_operations.push(journal.clone());
    backend
        .db
        .pending_selftest_rotations
        .push(PendingSelftestRotation {
            account_id: "acct1".into(),
            script: "edge-one".into(),
            namespace: "ns1".into(),
            journal,
            status: SelftestRotationStatus::Staged,
        });
}

#[tokio::test]
async fn migration_requires_exact_ack_and_consumes_each_unacknowledged_plan() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    for ack in [Value::Null, json!(false), json!("true"), json!(1)] {
        let plan = migration_plan(&mut backend);
        assert!(plan["credentialMigrationConfirmation"]
            .as_str()
            .unwrap()
            .contains("我确认"));
        let err = backend
            .dispatch(
                "apply_plan",
                &json!({"planId":plan["id"],"acknowledgeCredentialMigration":ack}),
            )
            .await
            .unwrap_err();
        assert!(err.contains("明确确认"));
        assert!(backend
            .dispatch(
                "apply_plan",
                &json!({"planId":plan["id"],"acknowledgeCredentialMigration":true})
            )
            .await
            .unwrap_err()
            .contains("已被使用"));
    }
    no_credentials();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_rejects_expired_stale_unknown_schema_and_completed_plans_before_credentials() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    let plan = migration_plan(&mut backend);
    backend.plans.last_mut().unwrap().expires_at = Instant::now() - Duration::from_secs(1);
    assert!(backend
        .dispatch(
            "apply_plan",
            &json!({"planId":plan["id"],"acknowledgeCredentialMigration":true})
        )
        .await
        .unwrap_err()
        .contains("过期"));
    let plan = migration_plan(&mut backend);
    backend.db.accounts[0].label = "changed".into();
    assert!(backend
        .dispatch(
            "apply_plan",
            &json!({"planId":plan["id"],"acknowledgeCredentialMigration":true})
        )
        .await
        .unwrap_err()
        .contains("配置已变化"));
    for schema in [1, 2, 3, 255] {
        backend.db.accounts[0].mac_credential_schema = schema;
        assert!(backend
            .prepare_change(&json!({"kind":"migrate_credentials","accountId":"acct1"}))
            .is_err());
    }
    no_credentials();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_copies_all_kinds_preserves_both_journals_and_never_replays_cloud_work() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    pending_rotation(&mut backend);
    backend
        .db
        .pending_operations
        .push("重置自检密钥 acct1 (legacy)：待恢复".into());
    let mut expected = backend.db.clone();
    expected.accounts[0].mac_credential_schema = 2;
    let old = mock_legacy_keys().lock().unwrap().clone();
    let state = apply_migration(&mut backend).await.unwrap();
    assert_eq!(state["accounts"][0]["needsCredentialMigration"], false);
    assert_eq!(
        serde_json::to_value(&backend.db).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(*mock_legacy_keys().lock().unwrap(), old);
    assert_eq!(*mock_keys().lock().unwrap(), old);
    let disk = fs::read_to_string(&backend.path).unwrap();
    assert!(!disk.contains("synthetic-old"));
    assert!(!state.to_string().contains("synthetic-old"));
    for kind in credential_migration::KINDS {
        assert_eq!(
            mock_key_reads()
                .lock()
                .unwrap()
                .iter()
                .filter(|s| *s == &format!("current:{kind}:acct1"))
                .count(),
            2
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_persist_failure_keeps_legacy_route_and_reuses_read_back_partial_items() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    pending_rotation(&mut backend);
    backend.persist().unwrap();
    let before = fs::read(&backend.path).unwrap();
    let snapshot = backend.database_snapshot();
    backend
        .fail_persist_at
        .store(2, std::sync::atomic::Ordering::SeqCst);
    assert!(apply_migration(&mut backend)
        .await
        .unwrap_err()
        .contains("保存失败"));
    assert_eq!(backend.database_snapshot(), snapshot);
    assert_eq!(fs::read(&backend.path).unwrap(), before);
    assert!(backend.require_credentials("acct1").is_err());
    assert_eq!(mock_keys().lock().unwrap().len(), 4);
    mock_key_reads().lock().unwrap().clear();
    mock_key_mutations().lock().unwrap().clear();
    apply_migration(&mut backend).await.unwrap();
    assert!(mock_key_reads()
        .lock()
        .unwrap()
        .iter()
        .all(|s| s.starts_with("current:")));
    assert!(mock_key_mutations().lock().unwrap().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_partial_save_failure_does_not_mark_ready_or_overwrite_newer_current_token() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    mock_key_set_failures()
        .lock()
        .unwrap()
        .insert("selftest:acct1".into());
    let before = backend.database_snapshot();
    assert!(apply_migration(&mut backend).await.is_err());
    assert_eq!(backend.database_snapshot(), before);
    assert_eq!(mock_keys().lock().unwrap().len(), 1);
    mock_keys()
        .lock()
        .unwrap()
        .insert("token:acct1".into(), "explicit-newer-token".into());
    mock_key_set_failures().lock().unwrap().clear();
    mock_key_reads().lock().unwrap().clear();
    apply_migration(&mut backend).await.unwrap();
    assert_eq!(
        mock_keys().lock().unwrap()["token:acct1"],
        "explicit-newer-token"
    );
    assert!(!mock_key_reads()
        .lock()
        .unwrap()
        .contains(&"legacy:token:acct1".to_owned()));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_gate_precedes_optional_staging_missing_and_all_recovery_mutations() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    backend.db.domains.push(domain());
    pending_rotation(&mut backend);
    let before = backend.database_snapshot();
    for error in [
        backend.resume_selftest_rotation("acct1").await.unwrap_err(),
        backend
            .start_selftest_rotation("acct1", true)
            .await
            .unwrap_err(),
        backend.recover_account("acct1").await.unwrap_err(),
        backend.selftest_snapshot("domain1", "demo").err().unwrap(),
    ] {
        assert!(error.contains("需要更新本机授权"), "{error}");
    }
    assert_eq!(backend.database_snapshot(), before);
    assert_eq!(
        backend.db.pending_selftest_rotations[0].status,
        SelftestRotationStatus::Staged
    );
    no_credentials();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_gate_checks_every_target_before_first_multi_account_native_or_cloud_access() {
    let (server, mut backend, _dir) = fixture().await;
    let mut second = backend.db.accounts[0].clone();
    second.id = "acct2".into();
    second.mac_credential_schema = 0;
    second.monitor_enabled = true;
    backend.db.accounts[0].monitor_enabled = true;
    backend.db.accounts.push(second);
    let mut pool = sample_pool();
    pool.account_ids.push("acct2".into());
    backend.db.pools.push(pool.clone());
    let before = backend.database_snapshot();
    assert!(backend
        .refresh_accounts(None)
        .await
        .unwrap_err()
        .contains("需要更新本机授权"));
    assert!(backend
        .apply_save_pool(pool)
        .await
        .unwrap_err()
        .contains("需要更新本机授权"));
    // A nonmember resource account also blocks deletion's cloud-leftover scan.
    backend.db.pools[0].account_ids = vec!["acct1".into()];
    assert!(backend
        .apply_delete_pool("pool1")
        .await
        .unwrap_err()
        .contains("需要更新本机授权"));
    backend.db.pools[0].account_ids.push("acct2".into());
    assert!(backend
        .health_snapshot("pool1")
        .err()
        .unwrap()
        .contains("需要更新本机授权"));
    assert!(backend
        .domain_candidates("new.example.net", Some("acct2"))
        .await
        .err()
        .unwrap()
        .contains("需要更新本机授权"));
    assert_eq!(backend.database_snapshot(), before);
    no_credentials();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_gate_keeps_disabled_health_and_local_views_available() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    backend.db.pools.push(sample_pool());
    assert_eq!(
        backend.state()["accounts"][0]["needsCredentialMigration"],
        true
    );
    assert!(backend.health_snapshot("pool1").is_ok());
    let exported = backend.export_config().unwrap();
    assert!(!exported.as_str().unwrap().contains("macCredentialSchema"));
    assert!(!exported
        .as_str()
        .unwrap()
        .contains("needsCredentialMigration"));
    no_credentials();
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_backup_rejects_imported_route_markers_and_gates_all_remote_validation() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    let snapshot = backend.database_snapshot();
    for field in ["macCredentialSchema", "needsCredentialMigration"] {
        let mut doc = json!({"schema":1,"accounts":[{"id":"acct1","label":"x"}],"domains":[],"links":[],"pools":[]});
        doc["accounts"][0][field] = json!(2);
        assert!(backend
            .import_config(&doc.to_string())
            .await
            .unwrap_err()
            .contains("不允许的字段"));
    }
    let doc = json!({"schema":1,"accounts":[],"domains":[{"accountId":"acct1","host":"example.com","prefix":"go"}],"links":[],"pools":[]});
    assert!(backend
        .import_config(&doc.to_string())
        .await
        .unwrap_err()
        .contains("需要更新本机授权"));
    assert_eq!(backend.database_snapshot(), snapshot);
    let local = json!({"schema":1,"accounts":[{"id":"acct1","label":"local-name"}],"domains":[],"links":[],"pools":[]});
    backend.import_config(&local.to_string()).await.unwrap();
    assert_eq!(backend.db.accounts[0].mac_credential_schema, 0);
    no_credentials();
    assert!(server.received_requests().await.unwrap().is_empty());
}

async fn token_api(server: &MockServer, ids: &[&str]) {
    for (endpoint, result) in [
        ("/client/v4/user/tokens/verify", json!({"status":"active"})),
        (
            "/client/v4/accounts",
            json!(ids
                .iter()
                .map(|id| json!({"id":id,"name":"Synthetic account"}))
                .collect::<Vec<_>>()),
        ),
        ("/client/v4/zones", json!([])),
    ] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"success":true,"result":result})),
            )
            .mount(server)
            .await;
    }
    for id in ids {
        for suffix in ["workers/scripts", "storage/kv/namespaces"] {
            Mock::given(method("GET"))
                .and(path(format!("/client/v4/accounts/{id}/{suffix}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"success":true,"result":[]})),
                )
                .mount(server)
                .await;
        }
    }
}

#[tokio::test]
async fn migration_token_replace_preserves_legacy_marker_and_other_old_kinds() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    let legacy = mock_legacy_keys().lock().unwrap().clone();
    token_api(&server, &["acct1"]).await;
    let token = "n".repeat(35);
    let state = backend
        .import_token(&token, true, Some("acct1"))
        .await
        .unwrap();
    assert_eq!(state["accounts"][0]["needsCredentialMigration"], true);
    assert_eq!(*mock_legacy_keys().lock().unwrap(), legacy);
    assert_eq!(mock_keys().lock().unwrap().len(), 1);
    assert_eq!(mock_keys().lock().unwrap()["token:acct1"], token);
    assert!(mock_key_reads()
        .lock()
        .unwrap()
        .iter()
        .all(|s| !s.starts_with("legacy:")));
}

#[tokio::test]
async fn migration_new_accounts_activate_only_after_all_writes_and_persistent_commit() {
    for fail in ["none", "second-write", "persist", "orphan-conflict"] {
        let (server, mut backend, _dir) = fixture().await;
        backend.db.accounts.clear();
        mock_keys().lock().unwrap().clear();
        token_api(&server, &["acct1", "acct2"]).await;
        if fail == "second-write" {
            mock_key_set_failures()
                .lock()
                .unwrap()
                .insert("token:acct2".into());
        }
        if fail == "persist" {
            backend
                .fail_persist_at
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
        if fail == "orphan-conflict" {
            mock_keys()
                .lock()
                .unwrap()
                .insert("token:acct1".into(), "orphan-newer".into());
        }
        let result = backend.import_token(&"n".repeat(35), true, None).await;
        if fail == "none" {
            assert!(result.is_ok());
            assert_eq!(backend.db.accounts.len(), 2);
            assert!(backend
                .db
                .accounts
                .iter()
                .all(|a| a.mac_credential_schema == 2));
            assert!(fs::read_to_string(&backend.path)
                .unwrap()
                .contains("macCredentialSchema"));
        } else {
            assert!(result.is_err());
            assert!(backend.db.accounts.is_empty());
            assert!(!backend.path.exists());
            if fail == "orphan-conflict" {
                assert_eq!(mock_keys().lock().unwrap()["token:acct1"], "orphan-newer");
            }
        }
    }
}

#[tokio::test]
async fn migration_removal_only_cleans_current_namespace_and_preserves_legacy_items() {
    let (server, mut backend, _dir) = fixture().await;
    make_legacy(&mut backend);
    let old = mock_legacy_keys().lock().unwrap().clone();
    *mock_keys().lock().unwrap() = old.clone();
    backend
        .dispatch("remove_account", &json!({"accountId":"acct1"}))
        .await
        .unwrap();
    assert!(backend.db.accounts.is_empty());
    assert!(mock_keys().lock().unwrap().is_empty());
    assert_eq!(*mock_legacy_keys().lock().unwrap(), old);
    assert_eq!(
        *mock_key_reads().lock().unwrap(),
        credential_migration::KINDS
            .iter()
            .map(|kind| format!("current:{kind}:acct1"))
            .collect::<Vec<_>>()
    );
    assert_eq!(mock_key_mutations().lock().unwrap().len(), 4);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_removal_failure_retains_account_and_never_touches_legacy_namespace() {
    for fail in ["probe-delete", "swallowed-delete", "persist"] {
        let (server, mut backend, _dir) = fixture().await;
        make_legacy(&mut backend);
        let old = mock_legacy_keys().lock().unwrap().clone();
        *mock_keys().lock().unwrap() = old.clone();
        let before = backend.database_snapshot();
        if fail == "probe-delete" {
            mock_key_set_failures()
                .lock()
                .unwrap()
                .insert("delete:probe:acct1".into());
        } else if fail == "swallowed-delete" {
            mock_key_set_failures()
                .lock()
                .unwrap()
                .insert("swallow-delete:probe:acct1".into());
        } else {
            backend
                .fail_persist_at
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
        let error = backend
            .dispatch("remove_account", &json!({"accountId":"acct1"}))
            .await
            .unwrap_err();
        if fail == "swallowed-delete" {
            assert!(error.contains("无法确认本机凭据已删除"));
        }
        assert_eq!(backend.database_snapshot(), before);
        assert!(!backend.path.exists());
        assert_eq!(*mock_legacy_keys().lock().unwrap(), old);
        assert!(mock_key_reads()
            .lock()
            .unwrap()
            .iter()
            .all(|call| call.starts_with("current:")));
        if fail != "persist" {
            assert!(mock_keys().lock().unwrap().contains_key("probe:acct1"));
            assert!(mock_keys()
                .lock()
                .unwrap()
                .contains_key("selftest-pending:acct1"));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

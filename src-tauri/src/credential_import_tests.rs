use super::*;
use std::sync::atomic::Ordering;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn authorize(server: &MockServer, ids: &[&str]) {
    let ok = |value: Value| {
        ResponseTemplate::new(200).set_body_json(json!({"success":true,"result":value}))
    };
    Mock::given(method("GET"))
        .and(path("/client/v4/user/tokens/verify"))
        .respond_with(ok(json!({"status":"active"})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/client/v4/accounts"))
        .respond_with(ok(json!(ids
            .iter()
            .map(|id| json!({"id":id,"name":"Example Account"}))
            .collect::<Vec<_>>())))
        .mount(server)
        .await;
    for id in ids {
        for endpoint in [
            format!("/client/v4/accounts/{id}/workers/scripts"),
            format!("/client/v4/accounts/{id}/storage/kv/namespaces"),
        ] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ok(json!([])))
                .mount(server)
                .await;
        }
    }
    Mock::given(method("GET"))
        .and(path("/client/v4/zones"))
        .respond_with(ok(json!([])))
        .mount(server)
        .await;
}
fn fail_commit(backend: &Backend, offset: usize) {
    backend.fail_persist_at.store(
        backend.persist_count.load(Ordering::SeqCst) + offset,
        Ordering::SeqCst,
    );
}
fn reload_database(backend: &mut Backend) {
    backend.db = serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap();
}

#[tokio::test]
async fn initial_import_stage_failure_never_writes_a_credential() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts.clear();
    mock_keys().lock().unwrap().clear();
    backend.persist().unwrap();
    authorize(&server, &["acct1"]).await;
    fail_commit(&backend, 1);
    assert!(backend
        .import_token(&"a".repeat(35), false, None)
        .await
        .is_err());
    assert!(backend.db.accounts.is_empty());
    assert!(mock_keys().lock().unwrap().is_empty());
    reload_database(&mut backend);
    assert!(backend.db.accounts.is_empty());
}

#[tokio::test]
async fn interrupted_initial_import_recovers_same_token_after_reload() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts.clear();
    mock_keys().lock().unwrap().clear();
    backend.persist().unwrap();
    authorize(&server, &["acct1"]).await;
    fail_commit(&backend, 2);
    let token = "a".repeat(35);
    assert!(backend
        .import_token(&token, false, None)
        .await
        .unwrap_err()
        .contains("令牌已保存"));
    assert_eq!(keyring_get("acct1", "token").unwrap(), token);
    reload_database(&mut backend);
    assert!(backend.db.accounts[0].token_import_pending);
    assert_eq!(backend.state()["accounts"][0]["needsTokenRecovery"], true);
    assert!(backend.require_credentials("acct1").is_err());
    let backup = backend.export_config().unwrap();
    assert!(!backup.as_str().unwrap().contains("tokenImportPending"));
    assert!(!backup.as_str().unwrap().contains(&token));
    backend.import_token(&token, false, None).await.unwrap();
    reload_database(&mut backend);
    assert!(!backend.db.accounts[0].token_import_pending);
    assert!(backend.require_credentials("acct1").is_ok());
}

#[tokio::test]
async fn old_orphan_and_new_failed_import_require_scoped_confirmation_to_replace() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts.clear();
    backend.persist().unwrap();
    let old = keyring_get("acct1", "token").unwrap();
    let token = "b".repeat(35);
    authorize(&server, &["acct1"]).await;
    // This is an orphan that predates the new transaction implementation.
    assert!(backend.import_token(&token, true, None).await.is_err());
    assert_eq!(keyring_get("acct1", "token").unwrap(), old);
    reload_database(&mut backend);
    assert!(backend.db.accounts[0].token_import_pending);
    assert!(backend.import_token(&token, true, None).await.is_err());
    assert_eq!(keyring_get("acct1", "token").unwrap(), old);
    assert!(backend
        .import_token(&token, false, Some("acct1"))
        .await
        .is_err());
    backend
        .import_token(&token, true, Some("acct1"))
        .await
        .unwrap();
    assert_eq!(keyring_get("acct1", "token").unwrap(), token);
    assert!(!backend.db.accounts[0].token_import_pending);
}

#[tokio::test]
async fn recovery_revalidates_account_and_never_changes_another_account() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts[0].token_import_pending = true;
    backend.persist().unwrap();
    let old = keyring_get("acct1", "token").unwrap();
    authorize(&server, &["acct2"]).await;
    assert!(backend
        .import_token(&"c".repeat(35), true, Some("acct1"))
        .await
        .unwrap_err()
        .contains("不属于"));
    assert_eq!(keyring_get("acct1", "token").unwrap(), old);
    assert!(!mock_keys().lock().unwrap().contains_key("token:acct2"));
    assert!(backend.db.accounts[0].token_import_pending);
}

#[tokio::test]
async fn recovery_stage_and_final_commit_failures_remain_retryable() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts[0].token_import_pending = true;
    backend.persist().unwrap();
    authorize(&server, &["acct1"]).await;
    let old = keyring_get("acct1", "token").unwrap();
    let token = "d".repeat(35);
    fail_commit(&backend, 1);
    assert!(backend
        .import_token(&token, true, Some("acct1"))
        .await
        .is_err());
    assert_eq!(keyring_get("acct1", "token").unwrap(), old);
    fail_commit(&backend, 2);
    assert!(backend
        .import_token(&token, true, Some("acct1"))
        .await
        .is_err());
    assert_eq!(keyring_get("acct1", "token").unwrap(), token);
    reload_database(&mut backend);
    assert!(backend.db.accounts[0].token_import_pending);
    backend
        .import_token(&token, true, Some("acct1"))
        .await
        .unwrap();
    assert!(!backend.db.accounts[0].token_import_pending);
}

#[tokio::test]
async fn native_write_failure_and_multi_account_partial_write_keep_recovery_scope() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts.clear();
    mock_keys().lock().unwrap().clear();
    backend.persist().unwrap();
    authorize(&server, &["acct1", "acct2"]).await;
    mock_key_set_failures()
        .lock()
        .unwrap()
        .insert("token:acct2".into());
    let token = "e".repeat(35);
    assert!(backend.import_token(&token, false, None).await.is_err());
    reload_database(&mut backend);
    assert_eq!(backend.db.accounts.len(), 2);
    assert!(backend.db.accounts.iter().all(|a| a.token_import_pending));
    assert_eq!(keyring_get("acct1", "token").unwrap(), token);
    assert!(keyring_get("acct2", "token").is_err());
    mock_key_set_failures().lock().unwrap().clear();
    backend.import_token(&token, false, None).await.unwrap();
    assert!(backend.db.accounts.iter().all(|a| !a.token_import_pending));
}

#[tokio::test]
async fn failed_rename_does_not_leak_into_state_or_next_commit() {
    let (_server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let old = backend.db.accounts[0].label.clone();
    fail_commit(&backend, 1);
    assert!(backend
        .dispatch(
            "rename_account",
            &json!({"accountId":"acct1","label":"unsaved"})
        )
        .await
        .is_err());
    assert_eq!(backend.db.accounts[0].label, old);
    backend.persist().unwrap();
    reload_database(&mut backend);
    assert_eq!(backend.db.accounts[0].label, old);
}

#[tokio::test]
async fn readback_mismatch_stays_gated_until_explicit_scoped_recovery() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.db.accounts.clear();
    mock_keys().lock().unwrap().clear();
    backend.persist().unwrap();
    authorize(&server, &["acct1"]).await;
    mock_key_set_failures()
        .lock()
        .unwrap()
        .insert("readback-mismatch:token:acct1".into());
    let token = "f".repeat(35);
    assert!(backend
        .import_token(&token, false, None)
        .await
        .unwrap_err()
        .contains("读回"));
    reload_database(&mut backend);
    assert!(backend.require_credentials("acct1").is_err());
    mock_key_set_failures().lock().unwrap().clear();
    assert!(backend
        .import_token(&token, false, None)
        .await
        .unwrap_err()
        .contains("冲突"));
    assert_eq!(
        keyring_get("acct1", "token").unwrap(),
        "synthetic-conflicting-readback"
    );
    backend
        .import_token(&token, true, Some("acct1"))
        .await
        .unwrap();
    assert_eq!(keyring_get("acct1", "token").unwrap(), token);
    assert!(backend.require_credentials("acct1").is_ok());
}

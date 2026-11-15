use super::*;
use std::sync::atomic::Ordering;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn authorize(server: &MockServer, ids: &[&str]) {
    authorize_except(server, ids, &[], 403).await;
}
/// Lists every id as an account of the token; ids in `refused` answer their
/// account-level reads with `refused_status` instead of succeeding.
async fn authorize_except(
    server: &MockServer,
    ids: &[&str],
    refused: &[&str],
    refused_status: u16,
) {
    for id in refused {
        Mock::given(method("GET"))
            .and(wiremock::matchers::path_regex(format!(
                "^/client/v4/accounts/{id}/"
            )))
            .respond_with(ResponseTemplate::new(refused_status))
            .mount(server)
            .await;
    }
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

fn account_requests(requests: &[wiremock::Request], id: &str) -> usize {
    requests
        .iter()
        .filter(|request| {
            request
                .url
                .path()
                .starts_with(&format!("/client/v4/accounts/{id}/"))
        })
        .count()
}

#[tokio::test]
async fn shared_token_adds_only_the_new_account_and_keeps_the_saved_token() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let saved = keyring_get("acct1", "token").unwrap();
    let before = backend.db.accounts[0].clone();
    authorize(&server, &["acct1", "acct2"]).await;
    let token = "g".repeat(35);
    let state = backend.import_token(&token, false, None).await.unwrap();
    assert_eq!(keyring_get("acct1", "token").unwrap(), saved);
    assert_eq!(keyring_get("acct2", "token").unwrap(), token);
    reload_database(&mut backend);
    assert_eq!(backend.db.accounts.len(), 2);
    assert_eq!(backend.db.accounts[0].label, before.label);
    assert_eq!(backend.db.accounts[0].checked_at, before.checked_at);
    assert!(backend.db.accounts.iter().all(|a| !a.token_import_pending));
    assert_eq!(state["importReport"]["imported"][0]["id"], "acct2");
    assert_eq!(state["importReport"]["skipped"][0]["id"], "acct1");
    assert_eq!(state["importReport"]["skipped"][0]["label"], "账号 1");
    assert_eq!(state["importReport"]["rejected"], json!([]));
    assert!(!fs::read_to_string(&backend.path)
        .unwrap()
        .contains("importReport"));
    // A skipped account is not probed with the pasted token at all.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(account_requests(&requests, "acct1"), 0);
}

#[tokio::test]
async fn broad_replace_flag_never_overwrites_a_completed_account() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let saved = keyring_get("acct1", "token").unwrap();
    authorize(&server, &["acct1", "acct2"]).await;
    let token = "h".repeat(35);
    backend.import_token(&token, true, None).await.unwrap();
    assert_eq!(keyring_get("acct1", "token").unwrap(), saved);
    assert_eq!(keyring_get("acct2", "token").unwrap(), token);
}

#[tokio::test]
async fn token_with_only_imported_accounts_changes_nothing_and_says_so() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let saved = keyring_get("acct1", "token").unwrap();
    let before = backend.database_snapshot();
    authorize(&server, &["acct1"]).await;
    for replace in [false, true] {
        let error = backend
            .import_token(&"i".repeat(35), replace, None)
            .await
            .unwrap_err();
        assert!(error.contains("都已经导入过"));
        assert!(error.contains("「账号 1」"));
        assert!(error.contains("更换本机令牌"));
    }
    assert_eq!(keyring_get("acct1", "token").unwrap(), saved);
    assert_eq!(backend.database_snapshot(), before);
    assert!(mock_key_mutations().lock().unwrap().is_empty());
}

#[tokio::test]
async fn refused_account_is_left_out_without_blocking_the_others() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    authorize_except(&server, &["acct1", "acct2", "acct3"], &["acct2"], 403).await;
    let token = "j".repeat(35);
    let state = backend.import_token(&token, false, None).await.unwrap();
    assert_eq!(keyring_get("acct3", "token").unwrap(), token);
    assert!(keyring_get("acct2", "token").is_err());
    assert!(backend.db.accounts.iter().all(|a| a.id != "acct2"));
    assert_eq!(state["importReport"]["imported"][0]["id"], "acct3");
    assert_eq!(state["importReport"]["rejected"][0]["id"], "acct2");
    assert!(state["importReport"]["rejected"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("Workers 脚本读取权限"));
    assert_eq!(state["importReport"]["skipped"][0]["id"], "acct1");
}

#[tokio::test]
async fn refused_only_account_names_the_account_and_stores_nothing() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    authorize_except(&server, &["acct1", "acct2"], &["acct2"], 403).await;
    let error = backend
        .import_token(&"k".repeat(35), false, None)
        .await
        .unwrap_err();
    assert!(error.contains("没有导入任何账号"));
    assert!(error.contains("账号「Example Account」"));
    assert!(error.contains("Workers 脚本读取权限"));
    assert!(error.contains("「账号 1」保持不变"));
    assert!(keyring_get("acct2", "token").is_err());
    assert_eq!(backend.database_snapshot(), before);
}

#[tokio::test]
async fn service_failure_stops_the_import_and_is_not_called_a_permission_problem() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    authorize_except(&server, &["acct2", "acct3"], &["acct2"], 500).await;
    let error = backend
        .import_token(&"l".repeat(35), false, None)
        .await
        .unwrap_err();
    assert!(error.contains("HTTP 500"));
    assert!(!error.contains("缺少"));
    // With several accounts the failure names the one it was about.
    assert!(
        error.starts_with("读取账户「Example Account」时出错："),
        "{error}"
    );
    assert!(error.contains("这次一个账户都没有导入"), "{error}");
    assert!(keyring_get("acct3", "token").is_err());
    assert_eq!(backend.database_snapshot(), before);
}

#[tokio::test]
async fn service_failure_of_a_single_account_keeps_its_plain_message() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    authorize_except(&server, &["acct2"], &["acct2"], 500).await;
    let error = backend
        .import_token(&"n".repeat(35), false, None)
        .await
        .unwrap_err();
    assert!(error.contains("HTTP 500"));
    assert!(!error.contains("读取账户「"), "{error}");
}

#[tokio::test]
async fn scoped_update_still_reports_a_refusal_for_the_selected_account() {
    let (server, mut backend, _guard) = tests::fixture().await;
    backend.persist().unwrap();
    let saved = keyring_get("acct1", "token").unwrap();
    authorize_except(&server, &["acct1", "acct2"], &["acct1"], 403).await;
    let error = backend
        .import_token(&"m".repeat(35), true, Some("acct1"))
        .await
        .unwrap_err();
    assert_eq!(error, "令牌缺少 Workers 脚本读取权限");
    assert_eq!(keyring_get("acct1", "token").unwrap(), saved);
    assert!(keyring_get("acct2", "token").is_err());
}

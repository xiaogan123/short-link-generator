//! Synthetic account-removal tests; the native Windows credential store is not used.
use super::*;
use crate::tests::fixture;

fn add_optional_credentials() {
    let mut keys = mock_keys().lock().unwrap();
    keys.insert("probe:acct1".into(), "synthetic-probe".into());
    keys.insert("selftest-pending:acct1".into(), "synthetic-pending".into());
}

#[tokio::test]
async fn removal_clears_all_four_kinds_even_without_a_rotation_journal() {
    let (server, mut backend, _dir) = fixture().await;
    add_optional_credentials();
    assert!(backend.db.pending_selftest_rotations.is_empty());

    backend
        .dispatch("remove_account", &json!({"accountId":"acct1"}))
        .await
        .unwrap();

    assert!(backend.db.accounts.is_empty());
    assert!(mock_keys().lock().unwrap().is_empty());
    assert_eq!(
        *mock_key_mutations().lock().unwrap(),
        credential_migration::KINDS
            .iter()
            .map(|kind| format!("delete:{kind}:acct1"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        *mock_key_reads().lock().unwrap(),
        credential_migration::KINDS
            .iter()
            .map(|kind| format!("current:{kind}:acct1"))
            .collect::<Vec<_>>()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn missing_optional_credentials_are_confirmed_and_removal_succeeds() {
    let (_server, mut backend, _dir) = fixture().await;
    assert!(!mock_keys().lock().unwrap().contains_key("probe:acct1"));
    assert!(!mock_keys()
        .lock()
        .unwrap()
        .contains_key("selftest-pending:acct1"));

    backend
        .dispatch("remove_account", &json!({"accountId":"acct1"}))
        .await
        .unwrap();

    assert!(backend.db.accounts.is_empty());
    assert!(mock_keys().lock().unwrap().is_empty());
    assert_eq!(mock_key_reads().lock().unwrap().len(), 4);
}

#[tokio::test]
async fn optional_delete_failures_preserve_account_and_retry_is_idempotent() {
    for kind in ["probe", "selftest-pending"] {
        let (server, mut backend, _dir) = fixture().await;
        add_optional_credentials();
        let before = backend.database_snapshot();
        let failure = format!("delete:{kind}:acct1");
        mock_key_set_failures()
            .lock()
            .unwrap()
            .insert(failure.clone());

        assert!(backend
            .dispatch("remove_account", &json!({"accountId":"acct1"}))
            .await
            .is_err());
        assert_eq!(backend.database_snapshot(), before);
        assert!(mock_keys()
            .lock()
            .unwrap()
            .contains_key(&format!("{kind}:acct1")));
        assert!(server.received_requests().await.unwrap().is_empty());

        mock_key_set_failures().lock().unwrap().remove(&failure);
        backend
            .dispatch("remove_account", &json!({"accountId":"acct1"}))
            .await
            .unwrap();
        assert!(backend.db.accounts.is_empty());
        assert!(mock_keys().lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn false_success_and_denied_readback_cannot_remove_the_account() {
    for failure in [
        "swallow-delete:probe:acct1",
        "swallow-delete:selftest-pending:acct1",
        "read-denied:probe:acct1",
        "read-unavailable:selftest-pending:acct1",
    ] {
        let (_server, mut backend, _dir) = fixture().await;
        add_optional_credentials();
        let before = backend.database_snapshot();
        mock_key_set_failures()
            .lock()
            .unwrap()
            .insert(failure.into());

        let error = backend
            .dispatch("remove_account", &json!({"accountId":"acct1"}))
            .await
            .unwrap_err();
        assert_eq!(backend.database_snapshot(), before);
        if failure.starts_with("swallow-delete") {
            assert!(error.contains("无法确认本机凭据已删除"));
        } else {
            assert!(error.contains("系统凭据库"));
        }

        mock_key_set_failures().lock().unwrap().remove(failure);
        backend
            .dispatch("remove_account", &json!({"accountId":"acct1"}))
            .await
            .unwrap();
        assert!(backend.db.accounts.is_empty());
        assert!(mock_keys().lock().unwrap().is_empty());
    }
}

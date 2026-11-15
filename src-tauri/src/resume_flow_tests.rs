//! Finishing interrupted removals and cleanups, undoing refused first writes,
//! reusing what the ownership check read, refreshing a stale zone ID, and the
//! texts for startup failures, multi-account import and key rotation.
use super::*;
use tests::{
    domain, fixture, mount_domain_hard_checks, mount_domain_probes,
    mount_existing_resource_domain_write, mount_owned_domain, mount_recovery_without_pool,
    mount_resource, ok, sample_pool, url_link,
};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, Request, ResponseTemplate,
};

const CONFIG_PATH: &str =
    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Aexample.com";
const KEYS_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/keys";
const ROUTES_PATH: &str = "/client/v4/zones/zone1/workers/routes";
const ROUTE_PATH: &str = "/client/v4/zones/zone1/workers/routes/route1";
const SETTINGS_PATH: &str = "/client/v4/accounts/acct1/workers/scripts/edge-one/settings";
const MANIFEST_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Aconfig";
const NAMESPACES_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces";
const NAMESPACE_PATH: &str = "/client/v4/accounts/acct1/storage/kv/namespaces/ns1";

async fn requests(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.unwrap()
}

fn writes(requests: &[Request]) -> Vec<&Request> {
    requests
        .iter()
        .filter(|r| matches!(r.method.as_str(), "PUT" | "POST" | "DELETE"))
        .collect()
}

fn count(requests: &[Request], verb: &str, at: &str) -> usize {
    requests
        .iter()
        .filter(|r| r.method.as_str() == verb && r.url.path() == at)
        .count()
}

fn saved(backend: &Backend) -> Database {
    serde_json::from_slice(&fs::read(&backend.path).unwrap()).unwrap()
}

// ---- C1: a removal that stopped after the prefix config was deleted -------

/// Owned resources, no `c:example.com`, the given cloud links and routes.
async fn mount_half_removed(server: &MockServer, links: Value, routes: Value) {
    mount_resource(server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(CONFIG_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(KEYS_PATH))
        .and(query_param("prefix", "l:example.com:"))
        .respond_with(ok(links))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(routes))
        .mount(server)
        .await;
}

fn half_removed_backend(backend: &mut Backend) {
    backend.db.domains.push(domain());
    backend.db.links.push(url_link(
        "short",
        "https://example.org/a",
        "https://example.org/b",
    ));
    backend.db.pending_operations =
        vec!["移除域名 example.com (old)：前缀配置删除结果不确定".into()];
    backend.persist().unwrap();
}

#[tokio::test]
async fn removal_retry_after_config_was_deleted_removes_route_and_local_domain() {
    let (server, mut backend, _guard) = fixture().await;
    half_removed_backend(&mut backend);
    mount_half_removed(
        &server,
        json!([]),
        json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path(ROUTE_PATH))
        .respond_with(ok(json!({"id":"route1"})))
        .expect(1)
        .mount(&server)
        .await;
    backend.apply_remove_domain("domain1").await.unwrap();
    assert!(backend.db.domains.is_empty());
    assert!(backend.db.links.is_empty());
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).domains.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
    let requests = requests(&server).await;
    let writes = writes(&requests);
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].url.path(), ROUTE_PATH);
}

#[tokio::test]
async fn removal_retry_when_route_is_gone_too_only_forgets_the_domain() {
    let (server, mut backend, _guard) = fixture().await;
    half_removed_backend(&mut backend);
    mount_half_removed(&server, json!([]), json!([])).await;
    backend.apply_remove_domain("domain1").await.unwrap();
    assert!(backend.db.domains.is_empty());
    assert!(backend.db.pending_operations.is_empty());
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn removal_retry_keeps_the_domain_when_the_cloud_is_not_half_removed() {
    // The recorded route now runs another script, or a link this computer
    // does not know is still there (with or without an earlier removal
    // record): the original ownership error stands, nothing is deleted.
    for (links, routes, record) in [
        (
            json!([]),
            json!([{"id":"route1","pattern":"example.com/go/*","script":"other-script"}]),
            true,
        ),
        (
            json!([{"name":"l:example.com:other"}]),
            json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
            true,
        ),
        (
            json!([{"name":"l:example.com:short"},{"name":"l:example.com:other"}]),
            json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
            false,
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        half_removed_backend(&mut backend);
        if !record {
            backend.db.pending_operations.clear();
            backend.persist().unwrap();
        }
        let before = backend.database_snapshot();
        mount_half_removed(&server, links.clone(), routes).await;
        let error = backend.apply_remove_domain("domain1").await.unwrap_err();
        assert!(
            error.contains("路由已变化") || error.contains("云端域名配置已丢失"),
            "{links} {error}"
        );
        assert_eq!(backend.database_snapshot(), before);
        assert!(writes(&requests(&server).await).is_empty());
    }
}

/// A read that fails inside the half-removed check is never taken for "the
/// config is gone": the original error stands and nothing is deleted.
#[tokio::test]
async fn removal_keeps_the_original_error_when_the_half_removed_check_cannot_read() {
    for failing in [CONFIG_PATH, KEYS_PATH] {
        let (server, mut backend, _guard) = fixture().await;
        half_removed_backend(&mut backend);
        backend.db.pending_operations.clear();
        backend.persist().unwrap();
        let before = backend.database_snapshot();
        Mock::given(method("GET"))
            .and(path(failing))
            .respond_with(ResponseTemplate::new(500))
            .with_priority(1)
            .mount(&server)
            .await;
        // The recorded route is gone, so the ownership check ends with the
        // route error and the half-removed check runs.
        mount_half_removed(&server, json!([{"name":"l:example.com:short"}]), json!([])).await;
        let error = backend.apply_remove_domain("domain1").await.unwrap_err();
        assert!(error.contains("路由已变化"), "{failing} {error}");
        assert_eq!(backend.database_snapshot(), before);
        assert!(writes(&requests(&server).await).is_empty());
    }
}

const SHORT_PATH: &str =
    "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Ashort";

/// The route delete was refused and the prefix config could not be put back:
/// the links of the domain are still there, the config is not. A retry
/// deletes those links and the route, with the earlier removal record or
/// after the user cleared that record by hand.
#[tokio::test]
async fn removal_retry_with_links_left_but_no_config_finishes_the_removal() {
    for record in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        half_removed_backend(&mut backend);
        backend.db.pending_operations = if record {
            vec!["移除域名 example.com (old)：回滚域名配置失败".into()]
        } else {
            Vec::new()
        };
        backend.persist().unwrap();
        mount_half_removed(
            &server,
            json!([{"name":"l:example.com:short"}]),
            json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(SHORT_PATH))
            .respond_with(ok(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(ROUTE_PATH))
            .respond_with(ok(json!({"id":"route1"})))
            .expect(1)
            .mount(&server)
            .await;
        backend.apply_remove_domain("domain1").await.unwrap();
        assert!(backend.db.domains.is_empty(), "record {record}");
        assert!(backend.db.links.is_empty());
        assert!(backend.db.pending_operations.is_empty());
        assert!(saved(&backend).pending_operations.is_empty());
        let requests = requests(&server).await;
        let writes = writes(&requests);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].url.path(), SHORT_PATH);
        assert_eq!(writes[1].url.path(), ROUTE_PATH);
    }
}

#[tokio::test]
async fn removal_retry_of_leftover_links_keeps_the_record_when_a_delete_fails() {
    // Uncertain: a new record says what happened and one more click finishes.
    // Definite: the error comes back and only the earlier record stays.
    for (status, uncertain) in [(503, true), (403, false)] {
        let (server, mut backend, _guard) = fixture().await;
        half_removed_backend(&mut backend);
        let earlier = backend.db.pending_operations.clone();
        mount_half_removed(
            &server,
            json!([{"name":"l:example.com:short"}]),
            json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let error = backend.apply_remove_domain("domain1").await.unwrap_err();
        assert_eq!(backend.db.domains.len(), 1);
        assert_eq!(backend.db.links.len(), 1);
        assert_eq!(
            error.contains("再点一次「移除域名」会接着做完"),
            uncertain,
            "{error}"
        );
        if uncertain {
            assert_eq!(backend.db.pending_operations.len(), 2);
            assert_eq!(backend.db.pending_operations[0], earlier[0]);
            assert!(backend.db.pending_operations[1].ends_with("：链接删除结果不确定"));
        } else {
            assert!(error.contains("HTTP 403"), "{error}");
            assert_eq!(backend.db.pending_operations, earlier);
        }
        assert_eq!(
            saved(&backend).pending_operations,
            backend.db.pending_operations
        );
        // The route is left alone until every link is gone.
        assert_eq!(count(&requests(&server).await, "DELETE", ROUTE_PATH), 0);
    }
}

/// A removal that stopped while deleting links leaves fewer cloud links than
/// this computer lists, with config and route still there.
#[tokio::test]
async fn removal_retry_after_some_links_were_deleted_deletes_the_rest() {
    // With the earlier record, or after the user cleared it by hand.
    for record in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(url_link(
            "short",
            "https://example.org/a",
            "https://example.org/b",
        ));
        backend.db.links.push(url_link(
            "gone",
            "https://example.org/c",
            "https://example.org/d",
        ));
        if record {
            backend.db.pending_operations =
                vec!["移除域名 example.com (old)：链接删除结果不确定".into()];
        }
        backend.persist().unwrap();
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(json!([{"name":"l:example.com:short"}])))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"rules":[],"default":"https://example.org/b","updated":"2026-01-01T00:00:00Z"}"#,
            ))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(SHORT_PATH))
            .respond_with(ok(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(CONFIG_PATH))
            .respond_with(ok(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(ROUTE_PATH))
            .respond_with(ok(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        backend.apply_remove_domain("domain1").await.unwrap();
        assert!(backend.db.domains.is_empty(), "record {record}");
        assert!(backend.db.links.is_empty());
        assert!(backend.db.pending_operations.is_empty());
        assert!(saved(&backend).pending_operations.is_empty());
    }

    // A key this computer does not know is refused before any write, with or
    // without the earlier record.
    for record in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        for slug in ["short", "gone"] {
            backend.db.links.push(url_link(
                slug,
                "https://example.org/a",
                "https://example.org/b",
            ));
        }
        if record {
            backend.db.pending_operations =
                vec!["移除域名 example.com (old)：链接删除结果不确定".into()];
        }
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(
                json!([{"name":"l:example.com:short"},{"name":"l:example.com:other"}]),
            ))
            .with_priority(1)
            .mount(&server)
            .await;
        let error = backend.apply_remove_domain("domain1").await.unwrap_err();
        assert_eq!(error, "云端链接清单与本机不同，请先找回再移除");
        assert!(writes(&requests(&server).await).is_empty());
    }
}

/// The key list may lag behind a recent save or delete. What to delete is
/// read key by key from this computer's own list, so a link the list does
/// not show yet is still deleted, and a listed key that is already gone does
/// not stop the removal.
#[tokio::test]
async fn removal_reads_its_own_links_instead_of_trusting_the_key_list() {
    const GONE_PATH: &str =
        "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/l%3Aexample.com%3Agone";
    let value =
        r#"{"rules":[],"default":"https://example.org/b","updated":"2026-01-01T00:00:00Z"}"#;
    // (keys listed, links that really exist)
    for (listed, existing) in [
        (
            json!([{"name":"l:example.com:short"}]),
            vec![SHORT_PATH, GONE_PATH],
        ),
        (
            json!([{"name":"l:example.com:short"},{"name":"l:example.com:gone"}]),
            vec![SHORT_PATH],
        ),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        for slug in ["short", "gone"] {
            backend.db.links.push(url_link(
                slug,
                "https://example.org/a",
                "https://example.org/b",
            ));
        }
        backend.persist().unwrap();
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(listed))
            .with_priority(1)
            .mount(&server)
            .await;
        for link in [SHORT_PATH, GONE_PATH] {
            let answer = if existing.contains(&link) {
                ResponseTemplate::new(200).set_body_string(value)
            } else {
                ResponseTemplate::new(404)
            };
            Mock::given(method("GET"))
                .and(path(link))
                .respond_with(answer)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .and(path(link))
                .respond_with(ok(json!({})))
                .expect(u64::from(existing.contains(&link)))
                .mount(&server)
                .await;
        }
        for other in [CONFIG_PATH, ROUTE_PATH] {
            Mock::given(method("DELETE"))
                .and(path(other))
                .respond_with(ok(json!({})))
                .expect(1)
                .mount(&server)
                .await;
        }
        backend.apply_remove_domain("domain1").await.unwrap();
        assert!(backend.db.domains.is_empty());
        assert!(backend.db.links.is_empty());
        assert!(backend.db.pending_operations.is_empty());
    }
}

/// A first removal (config and route still there) whose delete got no clear
/// answer keeps its record, and the next removal continues from it. The error
/// must say so: the pending list alone would send the user to clear the
/// record, and without the record a partly deleted link list is refused.
#[tokio::test]
async fn removal_with_an_unclear_delete_says_one_more_click_finishes_and_it_does() {
    for (failing, note) in [
        (SHORT_PATH, "链接删除结果不确定"),
        (CONFIG_PATH, "前缀配置删除结果不确定"),
        (ROUTE_PATH, "路由删除结果不确定"),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.domains.push(domain());
        backend.db.links.push(url_link(
            "short",
            "https://example.org/a",
            "https://example.org/b",
        ));
        backend.persist().unwrap();
        mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
        mount_owned_domain(&server).await;
        Mock::given(method("GET"))
            .and(path(KEYS_PATH))
            .and(query_param("prefix", "l:example.com:"))
            .respond_with(ok(json!([{"name":"l:example.com:short"}])))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SHORT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"rules":[],"default":"https://example.org/b","updated":"2026-01-01T00:00:00Z"}"#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(failing))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        for target in [SHORT_PATH, CONFIG_PATH, ROUTE_PATH] {
            Mock::given(method("DELETE"))
                .and(path(target))
                .respond_with(ok(json!({})))
                .mount(&server)
                .await;
        }
        let error = backend.apply_remove_domain("domain1").await.unwrap_err();
        assert!(error.contains("HTTP 503"), "{note}: {error}");
        assert!(error.ends_with(REMOVAL_RETRY_HINT), "{note}: {error}");
        assert_eq!(backend.db.domains.len(), 1, "{note}");
        assert_eq!(backend.db.pending_operations.len(), 1, "{note}");
        assert!(
            backend.db.pending_operations[0].starts_with("移除域名 example.com (")
                && backend.db.pending_operations[0].ends_with(&format!("：{note}")),
            "{:?}",
            backend.db.pending_operations
        );
        assert_eq!(
            saved(&backend).pending_operations,
            backend.db.pending_operations
        );
        // One more click, as the error says.
        backend.apply_remove_domain("domain1").await.unwrap();
        assert!(backend.db.domains.is_empty(), "{note}");
        assert!(backend.db.links.is_empty(), "{note}");
        assert!(backend.db.pending_operations.is_empty(), "{note}");
        assert!(saved(&backend).pending_operations.is_empty(), "{note}");
    }
}

#[tokio::test]
async fn removal_retry_with_uncertain_route_delete_says_one_more_click_finishes() {
    let (server, mut backend, _guard) = fixture().await;
    half_removed_backend(&mut backend);
    mount_half_removed(
        &server,
        json!([]),
        json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path(ROUTE_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let error = backend.apply_remove_domain("domain1").await.unwrap_err();
    assert!(error.contains("再点一次「移除域名」会接着做完"), "{error}");
    assert_eq!(backend.db.domains.len(), 1);
    assert!(backend
        .db
        .pending_operations
        .iter()
        .any(|entry| entry.contains("路由删除结果不确定")));
}

#[tokio::test]
async fn removal_retry_counts_a_route_that_answers_404_as_removed() {
    // Listed a moment ago, gone by the time of the delete.
    let (server, mut backend, _guard) = fixture().await;
    half_removed_backend(&mut backend);
    mount_half_removed(
        &server,
        json!([]),
        json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path(ROUTE_PATH))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    backend.apply_remove_domain("domain1").await.unwrap();
    assert!(backend.db.domains.is_empty());
    assert!(backend.db.links.is_empty());
    assert!(backend.db.pending_operations.is_empty());
    assert!(saved(&backend).domains.is_empty());
}

#[tokio::test]
async fn removal_retry_refused_at_the_route_delete_keeps_the_domain_and_no_new_record() {
    let (server, mut backend, _guard) = fixture().await;
    half_removed_backend(&mut backend);
    let before = backend.database_snapshot();
    mount_half_removed(
        &server,
        json!([]),
        json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path(ROUTE_PATH))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let error = backend.apply_remove_domain("domain1").await.unwrap_err();
    assert!(error.contains("HTTP 403"), "{error}");
    assert_eq!(backend.database_snapshot(), before);
    assert_eq!(
        saved(&backend).pending_operations,
        backend.db.pending_operations
    );
}

#[tokio::test]
async fn removal_that_fails_for_another_reason_is_reported_without_more_reads() {
    // A failed read (or any error other than a missing route or prefix
    // config) is not a sign of a half-finished removal: no second round of
    // ownership reads, and the error comes back as it is.
    let (server, mut backend, _guard) = fixture().await;
    half_removed_backend(&mut backend);
    let before = backend.database_snapshot();
    Mock::given(method("GET"))
        .and(path(MANIFEST_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let error = backend.apply_remove_domain("domain1").await.unwrap_err();
    assert!(error.contains("HTTP 500"), "{error}");
    assert_eq!(backend.database_snapshot(), before);
    let requests = requests(&server).await;
    assert_eq!(count(&requests, "GET", MANIFEST_PATH), 1);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn recovery_skips_a_route_whose_prefix_config_is_gone() {
    let (server, mut backend, _guard) = fixture().await;
    mount_recovery_without_pool(&server, false).await;
    // A leftover of an interrupted removal next to a complete domain.
    Mock::given(method("GET"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!([
            {"id":"route1","pattern":"example.com/go/*","script":"edge-one"},
            {"id":"route2","pattern":"www.example.com/go/*","script":"edge-one"}
        ])))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/c%3Awww.example.com",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(KEYS_PATH))
        .and(query_param("prefix", "l:www.example.com:"))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;
    backend.recover_account("acct1").await.unwrap();
    assert_eq!(backend.db.domains.len(), 1);
    assert_eq!(backend.db.domains[0].host, "example.com");
    assert_eq!(backend.db.domains[0].route_id, "route1");
    assert!(writes(&requests(&server).await).is_empty());
}

/// Skipping a route without its prefix config while its links are still in
/// the cloud would drop the local copy: recovery stops and changes nothing.
/// A host this computer does not list has nothing local to lose, so its
/// route is skipped like any other leftover and the account still recovers.
#[tokio::test]
async fn recovery_stops_when_a_route_without_config_still_has_links() {
    for local in [true, false] {
        let (server, mut backend, _guard) = fixture().await;
        if local {
            backend.db.domains.push(domain());
            backend.db.links.push(url_link(
                "short",
                "https://example.org/a",
                "https://example.org/b",
            ));
        }
        backend.db.pending_operations = vec!["移除域名 example.com (old)：回滚域名配置失败".into()];
        backend.persist().unwrap();
        let before = backend.database_snapshot();
        mount_recovery_without_pool(&server, true).await;
        Mock::given(method("GET"))
            .and(path(CONFIG_PATH))
            .respond_with(ResponseTemplate::new(404))
            .with_priority(1)
            .mount(&server)
            .await;
        let result = backend.recover_account("acct1").await;
        if local {
            assert_eq!(
                result.unwrap_err(),
                "域名 example.com 的转发规则还在，但前缀配置已经不在，云端还留着它的短链接。为了不丢本机记录，这次没有找回。如果这个域名本来就是要移除的，请到「域名管理」对它再点一次「移除域名」；否则请联系维护的人"
            );
            assert_eq!(backend.database_snapshot(), before);
        } else {
            result.unwrap();
            assert!(backend.db.domains.is_empty());
            assert!(backend.db.links.is_empty());
        }
        assert!(writes(&requests(&server).await).is_empty());
    }
}

// ---- C2: a cleanup that stopped after the Worker was deleted ---------------

/// Key names of the recorded namespace, read before it is deleted.
async fn mount_kv_keys(server: &MockServer, keys: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(KEYS_PATH))
        .respond_with(keys)
        .mount(server)
        .await;
}

fn removable_keys() -> ResponseTemplate {
    ok(json!([{"name":MANIFEST_KEY},{"name":"p:pool1"},{"name":"m:monitor:cursor"}]))
}

async fn mount_worker_gone(server: &MockServer, namespaces: Value) {
    Mock::given(method("GET"))
        .and(path(SETTINGS_PATH))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(NAMESPACES_PATH))
        .respond_with(ok(namespaces))
        .mount(server)
        .await;
}

fn cleanup_started(backend: &mut Backend) {
    let mut pool = sample_pool();
    pool.sync_status = vec![PoolSyncStatus {
        account_id: "acct1".into(),
        status: "synced".into(),
        message: "已同步".into(),
    }];
    backend.db.pools.push(pool);
    backend.db.pending_operations =
        vec!["清理账号 acct1 (old)：Worker 已删除，KV 删除未完成或结果不确定".into()];
    backend.persist().unwrap();
}

fn assert_cleaned(backend: &Backend) {
    for db in [&backend.db, &saved(backend)] {
        assert!(db.accounts[0].resources.is_none());
        assert!(!db.accounts[0].has_resources);
        assert!(db.pending_operations.is_empty());
        assert!(db.pools[0].account_ids.is_empty());
        assert!(db.pools[0].sync_status.is_empty());
    }
    assert!(mock_key_mutations()
        .lock()
        .unwrap()
        .contains(&"delete:selftest:acct1".to_string()));
}

#[tokio::test]
async fn cleanup_retry_after_worker_was_deleted_deletes_kv_and_finishes() {
    let (server, mut backend, _guard) = fixture().await;
    cleanup_started(&mut backend);
    mount_worker_gone(&server, json!([{"id":"ns1","title":"links"}])).await;
    mount_kv_keys(&server, removable_keys()).await;
    Mock::given(method("DELETE"))
        .and(path(NAMESPACE_PATH))
        .respond_with(ok(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    backend.apply_cleanup("acct1").await.unwrap();
    assert_cleaned(&backend);
    let requests = requests(&server).await;
    // The source check needs the Worker, so it is not repeated here.
    assert_eq!(count(&requests, "GET", MANIFEST_PATH), 0);
    assert_eq!(writes(&requests).len(), 1);
}

#[tokio::test]
async fn cleanup_retry_when_kv_is_gone_too_only_finishes_locally() {
    let (server, mut backend, _guard) = fixture().await;
    cleanup_started(&mut backend);
    // The selftest key may already be gone as well; that is fine.
    keyring_delete("acct1", "selftest").unwrap();
    mount_worker_gone(&server, json!([{"id":"other-namespace","title":"other"}])).await;
    backend.apply_cleanup("acct1").await.unwrap();
    assert_cleaned(&backend);
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn cleanup_retry_kv_failure_keeps_records_and_says_one_more_click_finishes() {
    let (server, mut backend, _guard) = fixture().await;
    cleanup_started(&mut backend);
    mount_worker_gone(&server, json!([{"id":"ns1","title":"links"}])).await;
    mount_kv_keys(&server, removable_keys()).await;
    Mock::given(method("DELETE"))
        .and(path(NAMESPACE_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let error = backend.apply_cleanup("acct1").await.unwrap_err();
    assert!(error.contains(CLEANUP_RETRY_HINT), "{error}");
    assert!(backend.db.accounts[0].resources.is_some());
    assert_eq!(backend.db.pending_operations.len(), 1);
    assert!(backend.db.pending_operations[0].starts_with("清理账号 acct1 (old)"));
    assert_eq!(
        saved(&backend).pending_operations,
        backend.db.pending_operations
    );
}

#[tokio::test]
async fn first_cleanup_kv_failure_points_to_the_same_button() {
    let (server, mut backend, _guard) = fixture().await;
    // A fresh cleanup without leftovers in KV, failing at the KV delete.
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(KEYS_PATH))
        .respond_with(ok(json!([{"name":MANIFEST_KEY}])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
        ))
        .respond_with(ok(json!({"schedules":[]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/client/v4/zones"))
        .respond_with(ok(
            json!([{"id":"zone1","name":"example.com","status":"active"}]),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/client/v4/accounts/acct1/workers/scripts/edge-one"))
        .respond_with(ok(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(NAMESPACE_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let error = backend.apply_cleanup("acct1").await.unwrap_err();
    assert!(error.contains("Worker 已删除"), "{error}");
    assert!(error.contains(CLEANUP_RETRY_HINT), "{error}");
}

#[tokio::test]
async fn cleanup_without_its_record_does_not_take_a_missing_worker_as_done() {
    let (server, mut backend, _guard) = fixture().await;
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    mount_worker_gone(&server, json!([{"id":"ns1","title":"links"}])).await;
    Mock::given(method("GET"))
        .and(path(MANIFEST_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                json!({"schema":SCHEMA,"accountId":"acct1","script":"edge-one",
                "namespace":"ns1","sourceHash":bundled_source_hash()})
                .to_string(),
            ),
        )
        .mount(&server)
        .await;
    assert!(backend.apply_cleanup("acct1").await.is_err());
    assert_eq!(backend.database_snapshot(), before);
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn cleanup_retry_never_deletes_a_namespace_that_holds_links_or_domains() {
    // The record exists, but its Worker was deleted outside this app and the
    // namespace has since gained a link or a prefix config (another device).
    for extra in ["l:example.com:short", "c:example.com", "something-else"] {
        let (server, mut backend, _guard) = fixture().await;
        cleanup_started(&mut backend);
        let before = backend.database_snapshot();
        mount_worker_gone(&server, json!([{"id":"ns1","title":"links"}])).await;
        mount_kv_keys(&server, ok(json!([{"name":MANIFEST_KEY},{"name":extra}]))).await;
        let error = backend.apply_cleanup("acct1").await.unwrap_err();
        assert!(error.contains("还有链接或域名记录"), "{extra}: {error}");
        assert!(error.contains("联系维护的人"), "{error}");
        assert!(error.starts_with("云端跳转服务已经删除"), "{error}");
        assert!(!error.contains("转发程序"), "{error}");
        assert_eq!(backend.database_snapshot(), before, "{extra}");
        assert!(writes(&requests(&server).await).is_empty(), "{extra}");
        assert!(!mock_key_mutations()
            .lock()
            .unwrap()
            .contains(&"delete:selftest:acct1".to_string()));
    }
}

#[tokio::test]
async fn cleanup_retry_that_cannot_read_the_key_names_deletes_nothing() {
    let (server, mut backend, _guard) = fixture().await;
    cleanup_started(&mut backend);
    mount_worker_gone(&server, json!([{"id":"ns1","title":"links"}])).await;
    mount_kv_keys(&server, ResponseTemplate::new(500)).await;
    let error = backend.apply_cleanup("acct1").await.unwrap_err();
    assert!(error.contains(CLEANUP_RETRY_HINT), "{error}");
    assert!(backend.db.accounts[0].resources.is_some());
    assert_eq!(backend.db.pending_operations.len(), 1);
    assert!(writes(&requests(&server).await).is_empty());
}

#[tokio::test]
async fn cleanup_blocked_by_a_leftover_route_names_it_and_the_way_out() {
    let (server, mut backend, _guard) = fixture().await;
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_kv_keys(&server, ok(json!([{"name":MANIFEST_KEY}]))).await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
        ))
        .respond_with(ok(json!({"schedules":[]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/client/v4/zones"))
        .respond_with(ok(
            json!([{"id":"zone1","name":"example.com","status":"active"}]),
        ))
        .mount(&server)
        .await;
    // What recovery skips after an interrupted removal: this tool's route
    // without its prefix config.
    Mock::given(method("GET"))
        .and(path(ROUTES_PATH))
        .respond_with(ok(
            json!([{"id":"route1","pattern":"example.com/go/*","script":"edge-one"}]),
        ))
        .mount(&server)
        .await;
    let error = backend.apply_cleanup("acct1").await.unwrap_err();
    assert!(error.contains("example.com/go/*"), "{error}");
    assert!(error.contains("从 Cloudflare 找回配置"), "{error}");
    assert!(error.contains("重新添加一次再移除"), "{error}");
    assert!(error.contains("删除云端短链接服务"), "{error}");
    assert!(error.contains("指向这个账户的云端跳转服务"), "{error}");
    assert!(!error.contains("转发程序"), "{error}");
    assert_eq!(backend.database_snapshot(), before);
    assert!(writes(&requests(&server).await).is_empty());
}

// ---- C3: a refused first write leaves no dead record ----------------------

async fn mount_monitor_start(server: &MockServer, secret_status: u16) {
    mount_resource(server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/workers/scripts/edge-one/schedules",
        ))
        .respond_with(ok(json!({"schedules":[]})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/m%3Amonitor",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/client/v4/accounts/acct1/workers/scripts/edge-one/secrets",
        ))
        .respond_with(ResponseTemplate::new(secret_status))
        .mount(server)
        .await;
}

#[tokio::test]
async fn monitor_start_refused_at_its_first_write_rolls_back_its_records() {
    let (server, mut backend, _guard) = fixture().await;
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    mount_monitor_start(&server, 400).await;
    let error = backend
        .apply_enable_monitor("acct1", "https://probe.example/check", &"q".repeat(48))
        .await
        .unwrap_err();
    assert!(error.contains("云端没有任何改动"), "{error}");
    assert_eq!(backend.database_snapshot(), before);
    assert!(saved(&backend).pending_monitor_changes.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
}

#[tokio::test]
async fn monitor_start_uncertain_or_retried_keeps_its_records() {
    // An uncertain answer may have changed the cloud.
    let (server, mut backend, _guard) = fixture().await;
    mount_monitor_start(&server, 503).await;
    let secret = "q".repeat(48);
    assert!(backend
        .apply_enable_monitor("acct1", "https://probe.example/check", &secret)
        .await
        .is_err());
    assert_eq!(backend.db.pending_monitor_changes.len(), 1);
    assert_eq!(backend.db.pending_operations.len(), 1);
    // A retry of an unfinished start: an earlier attempt may have written.
    server.reset().await;
    mount_monitor_start(&server, 400).await;
    assert!(backend
        .apply_enable_monitor("acct1", "https://probe.example/check", &secret)
        .await
        .is_err());
    assert_eq!(backend.db.pending_monitor_changes.len(), 1);
    assert_eq!(backend.db.pending_operations.len(), 1);
}

#[tokio::test]
async fn pool_sync_refused_at_its_first_write_restores_the_previous_version() {
    let (server, mut backend, _guard) = fixture().await;
    let mut old = sample_pool();
    old.sync_status = vec![PoolSyncStatus {
        account_id: "acct1".into(),
        status: "synced".into(),
        message: "已同步".into(),
    }];
    backend.db.pools.push(old.clone());
    backend.persist().unwrap();
    let before = backend.database_snapshot();
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(pools::cloud_value(&old)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
        ))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let mut edited = old.clone();
    edited.candidates[0].prefix = "https://new.example/path/".into();
    edited.updated = "2026-11-15T00:00:00Z".into();
    let error = backend.apply_save_pool(edited).await.unwrap_err();
    assert!(error.contains("账户「账号 1」"), "{error}");
    assert!(error.contains("云端没有任何改动"), "{error}");
    assert_eq!(backend.database_snapshot(), before);
    assert!(saved(&backend).pending_pool_changes.is_empty());
    assert!(saved(&backend).pending_operations.is_empty());
}

#[tokio::test]
async fn pool_sync_refused_after_another_account_was_written_keeps_its_records() {
    // The first account already holds the new version: nothing is rolled
    // back, the unfinished sync stays visible for "继续同步".
    let (server, mut backend, _guard) = fixture().await;
    let mut second = backend.db.accounts[0].clone();
    second.id = "acct2".into();
    second.label = "账号 2".into();
    second.resources = Some(Resources {
        script: "edge-two".into(),
        namespace: "ns2".into(),
    });
    backend.db.accounts.push(second);
    keyring_set("acct2", "token", "second-test-token").unwrap();
    backend.persist().unwrap();
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct2/storage/kv/namespaces/ns2/values/m%3Aconfig",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                json!({"schema":SCHEMA,"accountId":"acct2","script":"edge-two",
                "namespace":"ns2","sourceHash":bundled_source_hash()})
                .to_string(),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct2/workers/scripts/edge-two/settings",
        ))
        .respond_with(ok(json!({"bindings":[
            {"type":"kv_namespace","name":"LINKS","namespace_id":"ns2"},
            {"type":"secret_text","name":"SELFTEST_KEY"}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/client/v4/accounts/acct2/workers/scripts/edge-two/content/v2",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("../../edge/worker.mjs").as_bytes().to_vec(),
            "application/javascript",
        ))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/client/v4/accounts/acct1/storage/kv/namespaces/ns1/values/p%3Apool1",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/client/v4/accounts/acct2/storage/kv/namespaces/ns2/values/p%3Apool1",
        ))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let mut pool = sample_pool();
    pool.account_ids = vec!["acct1".into(), "acct2".into()];
    let error = backend.apply_save_pool(pool).await.unwrap_err();
    assert!(error.starts_with("账户「账号 2」："), "{error}");
    assert!(!error.contains("云端没有任何改动"), "{error}");
    for db in [&backend.db, &saved(&backend)] {
        assert_eq!(db.pending_pool_changes.len(), 1);
        assert_eq!(db.pending_operations.len(), 1);
        assert!(db.pending_operations[0].contains("账号同步未完成"));
        let status = &db.pools[0].sync_status;
        assert_eq!(status[0].status, "synced");
        assert_eq!(status[1].status, "failed");
    }
}

// ---- C4: the ownership check's reads are reused ----------------------------

#[tokio::test]
async fn link_ownership_check_reads_manifest_and_settings_once() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    mount_resource(&server, include_str!("../../edge/worker.mjs")).await;
    mount_owned_domain(&server).await;
    backend
        .ensure_domain_owned(&domain(), "test-token-value")
        .await
        .unwrap();
    let requests = requests(&server).await;
    assert_eq!(count(&requests, "GET", MANIFEST_PATH), 1);
    assert_eq!(count(&requests, "GET", SETTINGS_PATH), 1);
}

#[tokio::test]
async fn domain_add_on_existing_resources_reads_manifest_and_settings_once() {
    let (server, mut backend, _guard) = fixture().await;
    mount_domain_hard_checks(
        &server,
        json!([{"name":"example.com","type":"A","proxied":true}]),
        json!([]),
    )
    .await;
    mount_domain_probes(
        &server,
        ResponseTemplate::new(404),
        ResponseTemplate::new(404),
    )
    .await;
    mount_existing_resource_domain_write(&server).await;
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
        .unwrap();
    assert_eq!(backend.db.domains.len(), 1);
    let requests = requests(&server).await;
    assert_eq!(count(&requests, "GET", MANIFEST_PATH), 1);
    assert_eq!(count(&requests, "GET", SETTINGS_PATH), 1);
}

// ---- C8: a cached zone ID that Cloudflare no longer knows -------------------

async fn mount_zone_list(server: &MockServer, zones: Value) {
    Mock::given(method("GET"))
        .and(path("/client/v4/zones"))
        .and(query_param("account.id", "acct1"))
        .respond_with(ok(zones))
        .mount(server)
        .await;
}

#[tokio::test]
async fn prepare_domain_refreshes_a_stale_zone_id_and_continues() {
    let (server, mut backend, _guard) = fixture().await;
    // Cached before the domain was deleted and added again in Cloudflare.
    // Its old ID answers 404 (wiremock's default for unmounted paths).
    backend.db.accounts[0].zones[0].id = "zone-old".into();
    mount_zone_list(
        &server,
        json!([{"id":"zone1","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    mount_domain_hard_checks(
        &server,
        json!([{"name":"example.com","type":"A","proxied":true}]),
        json!([]),
    )
    .await;
    mount_domain_probes(
        &server,
        ResponseTemplate::new(404),
        ResponseTemplate::new(404),
    )
    .await;
    let result = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(result["canApply"], true, "{result}");
    assert_eq!(result["candidates"][0]["zoneId"], "zone1");
    assert_eq!(backend.db.accounts[0].zones[0].id, "zone1");
    assert_eq!(saved(&backend).accounts[0].zones[0].id, "zone1");
    let plan = backend.plans.last().unwrap();
    assert!(matches!(&plan.kind, PlanKind::Domain { zone_id, .. } if zone_id == "zone1"));
}

#[tokio::test]
async fn prepare_domain_says_the_list_is_stale_when_a_refresh_does_not_help() {
    for zones in [
        json!([]),
        json!([{"id":"zone-old","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    ] {
        let (server, mut backend, _guard) = fixture().await;
        backend.db.accounts[0].zones[0].id = "zone-old".into();
        mount_zone_list(&server, zones).await;
        let result = backend
            .dispatch(
                "prepare_domain",
                &json!({"input":"example.com","prefix":"go"}),
            )
            .await
            .unwrap();
        assert_eq!(result["canApply"], false);
        let check = result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["label"] == "云端域名归属")
            .cloned()
            .unwrap_or_else(|| panic!("{result}"));
        assert_eq!(check["ok"], false);
        assert_eq!(check["message"], ZONE_CACHE_STALE_MESSAGE);
        assert_eq!(check["reason"], ZONE_CACHE_STALE);
        assert!(!result.to_string().contains("令牌权限"), "{result}");
    }
}

#[tokio::test]
async fn prepare_domain_dns_refreshes_a_stale_zone_id() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.accounts[0].zones[0].id = "zone-old".into();
    mount_zone_list(
        &server,
        json!([{"id":"zone1","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    mount_domain_hard_checks(
        &server,
        json!([{"name":"example.com","type":"A","proxied":true}]),
        json!([]),
    )
    .await;
    let result = backend
        .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
        .await
        .unwrap();
    assert_eq!(result["candidates"][0]["zoneId"], "zone1");
    assert_eq!(result["checks"][0]["label"], "云端域名归属");
    assert_eq!(result["checks"][0]["ok"], true, "{result}");
}

#[tokio::test]
async fn prepare_domain_dns_says_the_list_is_stale_when_a_refresh_does_not_help() {
    let (server, mut backend, _guard) = fixture().await;
    backend.db.accounts[0].zones[0].id = "zone-old".into();
    mount_zone_list(
        &server,
        json!([{"id":"zone-old","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    let result = backend
        .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
        .await
        .unwrap();
    assert_eq!(result["checks"][0]["message"], ZONE_CACHE_STALE_MESSAGE);
    assert!(!result.to_string().contains("令牌权限"), "{result}");
}

// A cached zone ID may also be answered with 403. The zone list is then
// refreshed once; the 403 wording stays unless the refresh shows a new ID or
// a missing domain.

const OLD_ZONE_PATH: &str = "/client/v4/zones/zone-old";
const ZONE_LIST_PATH: &str = "/client/v4/zones";
const ZONE_403: &str = "云端请求失败（HTTP 403），请检查令牌权限与资源状态";

async fn mount_old_zone_refused(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(OLD_ZONE_PATH))
        .respond_with(ResponseTemplate::new(403))
        .mount(server)
        .await;
}

async fn mount_zone_list_failure(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(ZONE_LIST_PATH))
        .and(query_param("account.id", "acct1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(server)
        .await;
}

fn old_zone_backend(backend: &mut Backend) {
    backend.db.accounts[0].zones[0].id = "zone-old".into();
    backend.persist().unwrap();
}

/// What `prepare_domain` showed for this 403 before the refresh existed.
async fn original_preflight_checks(backend: &Backend) -> Value {
    let (checks, risk) = backend
        .preflight(
            "acct1",
            "zone-old",
            "example.com",
            "go",
            None,
            local_check::DnsMode::System,
        )
        .await;
    assert!(risk.is_none());
    serde_json::to_value(checks).unwrap()
}

#[tokio::test]
async fn prepare_domain_refreshes_a_zone_id_refused_with_403_and_continues() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list(
        &server,
        json!([{"id":"zone1","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    mount_domain_hard_checks(
        &server,
        json!([{"name":"example.com","type":"A","proxied":true}]),
        json!([]),
    )
    .await;
    mount_domain_probes(
        &server,
        ResponseTemplate::new(404),
        ResponseTemplate::new(404),
    )
    .await;
    let result = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(result["canApply"], true, "{result}");
    let candidates = result["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1, "{result}");
    assert_eq!(candidates[0]["zoneId"], "zone1");
    assert_eq!(backend.db.accounts[0].zones[0].id, "zone1");
    assert_eq!(saved(&backend).accounts[0].zones[0].id, "zone1");
    let plan = backend.plans.last().unwrap();
    assert!(matches!(&plan.kind, PlanKind::Domain { zone_id, .. } if zone_id == "zone1"));
    let requests = requests(&server).await;
    assert_eq!(count(&requests, "GET", OLD_ZONE_PATH), 1);
    assert_eq!(count(&requests, "GET", ZONE_LIST_PATH), 1);
    // The second preflight ran with the new ID.
    assert_eq!(count(&requests, "GET", "/client/v4/zones/zone1"), 1);
    assert!(!result.to_string().contains("令牌权限"), "{result}");
}

#[tokio::test]
async fn prepare_domain_keeps_the_403_check_when_the_refresh_shows_the_same_id() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list(
        &server,
        json!([{"id":"zone-old","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    let original = original_preflight_checks(&backend).await;
    assert_eq!(original[1]["message"], ZONE_403);
    // A real Cloudflare refusal, kept with its reason through the refresh.
    assert_eq!(original[1]["reason"], CLOUD_REFUSED);
    let result = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(result["canApply"], false);
    assert_eq!(result["checks"], original, "{result}");
    assert_eq!(result["candidates"][0]["zoneId"], "zone-old");
    assert_eq!(count(&requests(&server).await, "GET", ZONE_LIST_PATH), 1);
}

#[tokio::test]
async fn prepare_domain_keeps_the_403_check_when_the_refresh_fails() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list_failure(&server).await;
    let original = original_preflight_checks(&backend).await;
    let result = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(result["canApply"], false);
    assert_eq!(result["checks"], original, "{result}");
    assert!(!result.to_string().contains("无法刷新"), "{result}");
    assert_eq!(backend.db.accounts[0].zones[0].id, "zone-old");
    assert_eq!(count(&requests(&server).await, "GET", ZONE_LIST_PATH), 1);
}

#[tokio::test]
async fn prepare_domain_says_the_list_is_stale_after_a_403_when_the_domain_is_gone() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list(&server, json!([])).await;
    let result = backend
        .dispatch(
            "prepare_domain",
            &json!({"input":"example.com","prefix":"go"}),
        )
        .await
        .unwrap();
    assert_eq!(result["canApply"], false);
    let checks = result["checks"].as_array().unwrap();
    let zone_checks: Vec<_> = checks
        .iter()
        .filter(|check| check["label"] == "云端域名归属")
        .collect();
    assert_eq!(zone_checks.len(), 1, "{result}");
    assert_eq!(zone_checks[0]["message"], ZONE_CACHE_STALE_MESSAGE);
    assert_eq!(zone_checks[0]["reason"], ZONE_CACHE_STALE);
    assert!(!result.to_string().contains("令牌权限"), "{result}");
}

#[tokio::test]
async fn prepare_domain_dns_refreshes_a_zone_id_refused_with_403() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list(
        &server,
        json!([{"id":"zone1","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    mount_domain_hard_checks(
        &server,
        json!([{"name":"example.com","type":"A","proxied":true}]),
        json!([]),
    )
    .await;
    let result = backend
        .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
        .await
        .unwrap();
    let candidates = result["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1, "{result}");
    assert_eq!(candidates[0]["zoneId"], "zone1");
    assert_eq!(result["checks"][0]["label"], "云端域名归属");
    assert_eq!(result["checks"][0]["ok"], true, "{result}");
    let requests = requests(&server).await;
    assert_eq!(count(&requests, "GET", ZONE_LIST_PATH), 1);
    assert_eq!(count(&requests, "GET", "/client/v4/zones/zone1"), 1);
}

#[tokio::test]
async fn prepare_domain_dns_keeps_the_403_error_when_the_refresh_shows_the_same_id() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list(
        &server,
        json!([{"id":"zone-old","name":"example.com","status":"active","account":{"id":"acct1"}}]),
    )
    .await;
    let original = backend
        .confirmed_zone_token("acct1", "zone-old", "example.com")
        .await
        .err()
        .unwrap();
    assert_eq!(original, ZONE_403);
    let result = backend
        .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
        .await
        .unwrap();
    assert_eq!(result["canApply"], false);
    let checks = result["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "{result}");
    assert_eq!(checks[0]["label"], "云端域名归属");
    assert_eq!(checks[0]["message"], original);
    assert_eq!(checks[0]["reason"], CLOUD_REFUSED);
    assert_eq!(count(&requests(&server).await, "GET", ZONE_LIST_PATH), 1);
}

#[tokio::test]
async fn prepare_domain_dns_keeps_the_403_error_when_the_refresh_fails() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list_failure(&server).await;
    let result = backend
        .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
        .await
        .unwrap();
    assert_eq!(result["canApply"], false);
    let checks = result["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "{result}");
    assert_eq!(checks[0]["message"], ZONE_403, "{result}");
    assert_eq!(checks[0]["reason"], CLOUD_REFUSED);
    assert_eq!(backend.db.accounts[0].zones[0].id, "zone-old");
    assert_eq!(count(&requests(&server).await, "GET", ZONE_LIST_PATH), 1);
}

#[tokio::test]
async fn prepare_domain_dns_says_the_list_is_stale_after_a_403_when_the_domain_is_gone() {
    let (server, mut backend, _guard) = fixture().await;
    old_zone_backend(&mut backend);
    mount_old_zone_refused(&server).await;
    mount_zone_list(&server, json!([])).await;
    let result = backend
        .dispatch("prepare_domain_dns", &json!({"input":"example.com"}))
        .await
        .unwrap();
    assert_eq!(result["checks"][0]["message"], ZONE_CACHE_STALE_MESSAGE);
    assert!(!result.to_string().contains("令牌权限"), "{result}");
}

/// The confirm-time reviews do not refresh: a 403 keeps its wording there,
/// and only a 404 says that the cached ID is out of date.
#[tokio::test]
async fn confirming_after_a_403_on_the_zone_keeps_the_403_wording() {
    let (server, mut backend, _guard) = fixture().await;
    Mock::given(method("GET"))
        .and(path("/client/v4/zones/zone1"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let risk = PathRiskSnapshot {
        root: domain_check::ProbeRisk::Missing,
        child: domain_check::ProbeRisk::Missing,
        probe_segment: "probe-fixed".into(),
    };
    let error = backend
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
        .unwrap_err();
    assert_eq!(
        error,
        format!("复核没有通过（云端域名归属：{ZONE_403}）。云端没有任何改动，请重新检查域名。")
    );
    let error = backend
        .apply_domain_dns(
            "acct1",
            "zone1",
            "example.com",
            domain_check::DnsSnapshot::Missing(Vec::new()),
        )
        .await
        .unwrap_err();
    assert_eq!(error, ZONE_403);
    let requests = requests(&server).await;
    assert_eq!(count(&requests, "GET", ZONE_LIST_PATH), 0);
    assert!(writes(&requests).is_empty());
    assert!(backend.db.domains.is_empty());
    assert_eq!(backend.db.accounts[0].zones[0].id, "zone1");
}

// ---- C5 / C9: texts --------------------------------------------------------

#[test]
fn startup_failure_message_names_the_cause_and_the_next_step() {
    // The Dock and the window title say 短连接生成器, the window says
    // 短链接工作台: every text names both, once each.
    let names = |message: &str| {
        assert_eq!(message.matches("短连接生成器").count(), 1, "{message}");
        assert_eq!(message.matches("短链接工作台").count(), 1, "{message}");
    };
    let running = startup_failure_message("另一个本机客户端正在运行，请先正常退出后重试");
    assert!(running.contains("已经开着了，请切换到已打开的窗口"));
    names(&running);
    let windows = startup_failure_message("另一个本机客户端正在运行，或无法建立本机配置锁");
    assert_eq!(windows, running);
    // Only a config written by a newer version is helped by installing.
    let newer = startup_failure_message("本机凭据格式版本不受支持");
    names(&newer);
    assert!(newer.contains("本机凭据格式版本不受支持"), "{newer}");
    assert!(newer.contains("配置文件没有被改动"), "{newer}");
    assert!(newer.contains("请安装最新版"), "{newer}");
    assert!(newer.contains("联系维护的人"), "{newer}");
    for cause in ["无法读取本机配置", "本机配置格式无效"] {
        let message = startup_failure_message(cause);
        names(&message);
        assert!(message.contains(cause), "{message}");
        assert!(message.contains("配置文件没有被改动"), "{message}");
        assert!(!message.contains("请安装"), "{message}");
        assert!(!message.contains("请重新安装"), "{message}");
        assert!(message.contains("联系维护的人"), "{message}");
    }
    let other = startup_failure_message("本机配置目录不能经过符号链接");
    names(&other);
    assert!(
        other.ends_with("没能打开：本机配置目录不能经过符号链接"),
        "{other}"
    );
    let conf: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(conf["productName"], APP_NAME);
    assert_eq!(conf["app"]["windows"][0]["title"], APP_NAME);
}

#[test]
fn selftest_key_message_points_to_the_unfinished_update_while_rotating() {
    let rotating = selftest_key_missing_message(true);
    assert!(rotating.contains("上次没更新完"));
    // The buttons as they are labelled in the pending area.
    for button in ["继续修复", "查看修复计划", "找回本机检测配置"] {
        assert!(rotating.contains(&format!("「{button}」")), "{button}");
    }
    assert!(rotating.contains("不用重置密钥"));
    assert!(rotating.contains("页面上方“……项变更可继续处理”那一栏"));
    assert!(!rotating.contains("首页"));
    assert_eq!(
        selftest_key_missing_message(false),
        "本机没有自检密钥，请先单独确认重置密钥"
    );
}

#[tokio::test]
async fn selftest_without_a_snapshot_says_which_of_the_two_cases_it_is() {
    let (_server, mut backend, _guard) = fixture().await;
    backend.db.domains.push(domain());
    backend.db.links.push(url_link(
        "short",
        "https://example.org/a",
        "https://example.org/b",
    ));
    // The key is simply not on this computer: resetting it is the way out.
    keyring_delete("acct1", "selftest").unwrap();
    assert!(backend
        .selftest_snapshot("domain1", "short")
        .unwrap()
        .is_none());
    assert_eq!(
        backend.selftest_unavailable_message("domain1"),
        selftest_key_missing_message(false)
    );
    // An unfinished key update blocks the test even with a key present, and
    // a reset would be refused: the text must point to the pending entry.
    keyring_set("acct1", "selftest", &"a1".repeat(32)).unwrap();
    backend.db.pending_operations = vec!["重置自检密钥 acct1 (old)".into()];
    assert!(backend
        .selftest_snapshot("domain1", "short")
        .unwrap()
        .is_none());
    assert_eq!(
        backend.selftest_unavailable_message("domain1"),
        selftest_key_missing_message(true)
    );
}

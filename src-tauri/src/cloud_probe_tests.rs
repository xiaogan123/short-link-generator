use super::*;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

fn local_client(timeout: Duration) -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .unwrap()
}

#[tokio::test]
async fn probe_default_and_explicit_modes_preserve_anonymous_head_contract() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path("/client/v4/probe/example.com/out/"))
        .respond_with(ResponseTemplate::new(522))
        .expect(3)
        .mount(&server)
        .await;
    let cloud = Cloud::for_test(&format!("{}/client/v4/", server.uri()));
    assert_eq!(
        cloud.probe("https://example.com/out/", None).await.unwrap(),
        (522, None)
    );
    for mode in [DnsMode::System, DnsMode::Public] {
        assert_eq!(
            cloud
                .probe_with_mode("https://example.com/out/", None, mode)
                .await
                .unwrap(),
            (522, None)
        );
    }
    for request in server.received_requests().await.unwrap() {
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("x-selftest"));
        assert!(!request.headers.contains_key("range"));
    }
}

#[tokio::test]
async fn probe_rejects_non_https_and_url_credentials_before_transport() {
    let server = MockServer::start().await;
    let cloud = Cloud::for_test(&server.uri());
    for mode in [DnsMode::System, DnsMode::Public] {
        for input in [
            "http://example.com/out/",
            "https://username@example.com/out/",
            "https://username:synthetic@example.com/out/",
            "file:///out/",
            "not a URL",
        ] {
            let error = cloud.probe_with_mode(input, None, mode).await.unwrap_err();
            assert_eq!(error.reason, None);
            assert!(!error.message.contains("synthetic"));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn probe_405_fallback_preserves_range_and_selftest_without_following_redirect() {
    let server = MockServer::start().await;
    let endpoint = "/client/v4/probe/example.com/out/test";
    Mock::given(method("HEAD"))
        .and(path(endpoint))
        .respond_with(ResponseTemplate::new(405))
        .expect(1)
        .mount(&server)
        .await;
    let destination = format!("{}/must-not-follow", server.uri());
    Mock::given(method("GET"))
        .and(path(endpoint))
        .respond_with(ResponseTemplate::new(302).insert_header("location", destination.as_str()))
        .expect(1)
        .mount(&server)
        .await;
    let cloud = Cloud::for_test(&format!("{}/client/v4/", server.uri()));
    assert_eq!(
        cloud
            .probe_with_mode(
                "https://example.com/out/test",
                Some("synthetic-selftest".into()),
                DnsMode::Public,
            )
            .await
            .unwrap(),
        (302, Some(destination))
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(request.url.path(), endpoint);
        assert_eq!(request.headers["x-selftest"], "synthetic-selftest");
        assert!(!request.headers.contains_key("authorization"));
    }
    assert!(!requests[0].headers.contains_key("range"));
    assert_eq!(requests[1].headers["range"], "bytes=0-0");
}

#[tokio::test]
async fn probe_never_retries_http_errors_or_follows_head_redirects() {
    let server = MockServer::start().await;
    let cloud = Cloud::for_test(&format!("{}/client/v4/", server.uri()));
    for status in [200, 302, 403, 404, 429, 500, 522, 525, 526] {
        let endpoint = format!("/client/v4/probe/example.com/out/{status}");
        Mock::given(method("HEAD"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(status).insert_header("location", "/not-followed"))
            .expect(1)
            .mount(&server)
            .await;
        let result = cloud
            .probe_with_mode(
                &format!("https://example.com/out/{status}"),
                None,
                DnsMode::System,
            )
            .await
            .unwrap();
        assert_eq!(result, (status, Some("/not-followed".into())));
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 9);
    assert!(requests
        .iter()
        .all(|request| request.method == Method::HEAD));
}

#[tokio::test]
async fn probe_does_not_reuse_api_bearer_authentication() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/client/v4/zones"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success":true,"result":[]})))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/client/v4/probe/example.com/out/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let cloud = Cloud::for_test(&format!("{}/client/v4/", server.uri()));
    cloud.get("synthetic-api-token", "zones").await.unwrap();
    cloud.probe("https://example.com/out/", None).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].headers["authorization"],
        "Bearer synthetic-api-token"
    );
    assert!(!requests[1].headers.contains_key("authorization"));
}

#[tokio::test]
async fn guarded_probe_client_rejects_virtual_and_private_literals_in_both_modes() {
    // Literal addresses are classified without any DNS query or connection.
    for mode in [DnsMode::System, DnsMode::Public] {
        for (host, expected) in [
            ("198.18.0.1", "虚拟地址"),
            ("198.19.255.254", "虚拟地址"),
            ("[::ffff:198.18.0.1]", "虚拟地址"),
            ("127.0.0.1", "非公开地址"),
            ("10.0.0.1", "非公开地址"),
            ("[::1]", "非公开地址"),
            ("[fd00::1]", "非公开地址"),
        ] {
            let url = reqwest::Url::parse(&format!("https://{host}/out/")).unwrap();
            let error = crate::local_check::client_for_probe(&url, mode, PROBE_TIMEOUT)
                .await
                .unwrap_err();
            assert!(error.details().2.contains(expected), "{error:?}");
        }
    }
}

#[tokio::test]
async fn probe_transport_timeout_is_distinct_and_does_not_expose_url() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(100)))
        .mount(&server)
        .await;
    let error = probe_response(
        &local_client(Duration::from_millis(20)),
        reqwest::Url::parse(&format!("{}/synthetic-private-path", server.uri())).unwrap(),
        None,
    )
    .await
    .unwrap_err();
    assert!(error.message.contains("超时"));
    assert!(!error.message.contains("synthetic-private-path"));
    assert!(!error.uncertain);
}

#[tokio::test]
async fn probe_transport_connection_failure_is_distinct_and_sanitized() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Keep the port bound. A closed ephemeral port can produce a platform-
    // specific refusal or timeout; a plaintext reply during TLS is a stable
    // connector failure after a real local accept.
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        let _ = stream.shutdown().await;
    });
    let error = probe_response(
        &local_client(Duration::from_secs(10)),
        reqwest::Url::parse(&format!("https://{address}/synthetic-private-path")).unwrap(),
        None,
    )
    .await
    .unwrap_err();
    server.await.unwrap();
    assert!(
        error.message.contains("连接或 TLS"),
        "sanitized transport classification: {}",
        error.message
    );
    assert!(!error.message.contains("synthetic-private-path"));
    assert!(!error.message.contains(&address.to_string()));
    assert!(!error.uncertain);
}

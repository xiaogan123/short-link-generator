use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use tauri::test::{mock_builder, mock_context, noop_assets};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Public throwaway vectors from tauri-plugin-updater 2.14.1 offline_tests.
// No signing private key is stored here; payload is exactly b"test".
const PUBLIC_KEY: &str = "untrusted comment: minisign public key: A49EF4746FA6E6D7\nRWTX5qZvdPSepDGWg2bz8n6ArQnBMwgQK1geVosorcbLzcunD+KJ+cYe";
const SIGNATURE: &str = "untrusted comment: signature from tauri secret key\nRUTX5qZvdPSepPF2zsjvP/L/TQtBLRnWRvaq+4omK1UEugtQp/USrGiI1v762sDy3id3aor7bRC9ETyeot6lMHHrWoZ5hjUM1Qc=\ntrusted comment: timestamp:1791649051\tfile:payload\tversion:2.0.0\nDDq2CLOEl5cQmC2eJRHlnZPVViOZsu1CjpPKQoei4A/XBfkDqGO0B+QMrcrHgEQ5qV3mne75tdFWhJpqUXh9AA==";
const UNVERSIONED_PUBLIC_KEY: &str = "untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
const UNVERSIONED_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";
fn update(key: &str, signature: &str, version: &str) -> Update {
    configured_updater(key, Some("test-target"))
        .restore_update(json!({"version":version,"platforms":{"test-target":{"url":"https://example.com/update","signature":STANDARD.encode(signature)}}}))
        .unwrap().unwrap()
}
fn configured_updater(key: &str, target: Option<&str>) -> Updater {
    let mut context = mock_context(noop_assets());
    context.config_mut().plugins.0.insert(
        "updater".into(),
        json!({"pubkey":STANDARD.encode(key),"requireSignedVersion":true}),
    );
    let app = mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(context)
        .unwrap();
    let mut builder = app
        .updater_builder()
        .endpoints(vec!["https://example.com/manifest".parse().unwrap()])
        .unwrap()
        .executable_path("runtime-path/app");
    if let Some(target) = target {
        builder = builder.target(target);
    }
    builder.build().unwrap()
}
#[test]
fn official_verify_binds_payload_trusted_comment_and_version() {
    let signed = update(PUBLIC_KEY, SIGNATURE, "2.0.0");
    assert!(signed.verify(b"test").is_ok());
    assert!(signed.verify(b"tampered").is_err());
    assert!(update(PUBLIC_KEY, SIGNATURE, "9.0.0")
        .verify(b"test")
        .is_err());
    assert!(
        update(UNVERSIONED_PUBLIC_KEY, UNVERSIONED_SIGNATURE, "9.0.0")
            .verify(b"test")
            .is_err()
    );
    assert!(update(
        PUBLIC_KEY,
        &SIGNATURE.replace("version:2.0.0", "version:9.0.0"),
        "9.0.0"
    )
    .verify(b"test")
    .is_err());
    let config: Value = serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
    assert_eq!(config["plugins"]["updater"]["requireSignedVersion"], true);
}

async fn serve(parts: Vec<(u64, String)>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        for (delay, part) in parts {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            if socket.write_all(part.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    (format!("http://{addr}/artifact"), handle)
}
fn limits(total: u64, idle: u64, max_bytes: usize) -> DownloadPolicy {
    DownloadPolicy {
        total: Duration::from_millis(total),
        idle: Duration::from_millis(idle),
        max_bytes,
    }
}
async fn response(parts: Vec<(u64, String)>, policy: DownloadPolicy) -> Result<Vec<u8>, String> {
    let (url, server) = serve(parts).await;
    // Plain HTTP is limited to this loopback test client. Production `download`
    // constructs its own HTTPS-only client and cannot use this test helper.
    let result = read_bounded(
        Client::builder().no_proxy().build().unwrap().get(url),
        policy,
    )
    .await;
    server.abort();
    result
}
#[tokio::test]
async fn bounded_download_accepts_exact_bytes_and_rejects_lengths_status_and_oversize() {
    assert_eq!(
        response(
            vec![(0, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest".into())],
            limits(1000, 500, 4)
        )
        .await
        .unwrap(),
        b"test"
    );
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ntest",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nte",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n1\r\nx\r\n0\r\n\r\n",
        "HTTP/1.1 500 Error\r\nContent-Length: 4\r\n\r\ntest",
        "HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\ntest",
    ] {
        assert!(
            response(vec![(0, raw.into())], limits(1000, 500, 4))
                .await
                .is_err(),
            "{raw}"
        );
    }
}
#[tokio::test]
async fn slow_first_byte_and_stalled_body_hit_idle_deadline() {
    assert!(response(
        vec![(
            150,
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest".into()
        )],
        limits(1000, 30, 8)
    )
    .await
    .unwrap_err()
    .contains("超时"));
    assert!(response(
        vec![
            (0, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nt".into()),
            (150, "est".into())
        ],
        limits(1000, 30, 8)
    )
    .await
    .unwrap_err()
    .contains("超时"));
}
#[tokio::test]
async fn continuously_slow_stream_has_an_independent_total_deadline() {
    let mut parts = vec![(
        0,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".into(),
    )];
    parts.extend((0..30).map(|_| (10, "1\r\nx\r\n".into())));
    assert!(response(parts, limits(70, 100, 100))
        .await
        .unwrap_err()
        .contains("总时限"));
}
#[test]
fn artifact_and_redirect_urls_keep_https_and_reject_userinfo() {
    for text in [
        "https://example.com/file",
        "https://example.org/assets/file?signature=public",
    ] {
        assert!(require_https(&text.parse().unwrap()).is_ok());
    }
    for text in [
        "http://example.com/file",
        "file:///tmp/file",
        "https://user:pass@example.com/file",
    ] {
        assert!(require_https(&text.parse().unwrap()).is_err());
    }
}
#[tokio::test]
async fn duplicate_cancel_failure_and_dropped_future_release_single_flight() {
    let service = Service::default();
    let mut attempt = service.start().unwrap();
    assert!(service.start().is_err());
    service.cancel().unwrap();
    assert_eq!(
        attempt.downloading(async { Ok(()) }).await.unwrap_err(),
        CANCELLED
    );
    drop(attempt);
    {
        let mut attempt = service.start().unwrap();
        assert!(attempt
            .downloading(async { Err::<(), String>(DOWNLOAD_ERROR.into()) })
            .await
            .is_err());
    }
    let deadline = tokio::time::timeout(Duration::from_millis(20), async {
        let mut attempt = service.start().unwrap();
        attempt
            .downloading(std::future::pending::<Result<(), String>>())
            .await
    })
    .await;
    assert!(deadline.is_err());
    assert!(service.start().is_ok());
}
#[tokio::test]
async fn cancellation_wakes_an_inflight_download_and_prevents_install_transition() {
    let service = Service::default();
    let mut attempt = service.start().unwrap();
    let (result, _) = tokio::join!(
        attempt.downloading(std::future::pending::<Result<(), String>>()),
        async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            service.cancel().unwrap();
        }
    );
    assert_eq!(result.unwrap_err(), CANCELLED);
    assert!(attempt.begin_install().is_err());
}
#[tokio::test]
async fn download_leaves_backend_available_but_install_and_cancel_are_exclusive() {
    let (_server, backend, _fixture) = crate::tests::fixture().await;
    let state = AppState(Mutex::new(backend));
    let service = Service::default();
    let mut attempt = service.start().unwrap();
    attempt
        .downloading(async {
            let _guard = lock_backend(&state, "get_state").await?;
            Ok(())
        })
        .await
        .unwrap();
    attempt.begin_install().unwrap();
    install_exclusively(&state, || {
        assert!(state.0.try_lock().is_err());
        assert!(service.cancel().is_err());
        Ok(())
    })
    .await
    .unwrap();
    assert!(state.0.try_lock().is_ok());
    let held = state.0.lock().await;
    assert!(install_exclusively::<()>(&state, || panic!(
        "must not install during a backend mutation"
    ))
    .await
    .is_err());
    drop(held);
}

#[test]
fn legitimate_https_redirects_are_allowed_with_a_strict_hop_bound() {
    let artifact = "https://example.org/release/file?download=1"
        .parse()
        .unwrap();
    assert!(validate_redirect(&artifact, 0).is_ok());
    assert!(validate_redirect(&artifact, 4).is_ok());
    assert!(validate_redirect(&artifact, 5).is_err());
    assert!(validate_redirect(&"http://example.org/file".parse().unwrap(), 1).is_err());
    assert!(validate_redirect(&"https://user@example.org/file".parse().unwrap(), 1).is_err());
}

fn manifest(version: &str) -> Value {
    json!({"version":version,"notes":"public release notes","pub_date":"2026-11-01T00:00:00Z",
    "platforms": {
        "darwin-aarch64":{"url":"https://example.com/mac-arm","signature":STANDARD.encode(SIGNATURE)},
        "darwin-x86_64":{"url":"https://example.com/mac-intel","signature":STANDARD.encode(SIGNATURE)},
        "windows-x86_64":{"url":"https://example.com/windows","signature":STANDARD.encode(SIGNATURE)},
        "linux-x86_64":{"url":"https://example.com/linux","signature":STANDARD.encode(SIGNATURE)},
        "linux-aarch64":{"url":"https://example.com/linux-arm","signature":STANDARD.encode(SIGNATURE)},
        "test-target":{"url":"https://example.com/custom","signature":STANDARD.encode(SIGNATURE)}
    }})
}
fn ok_json(value: &Value) -> String {
    let body = serde_json::to_string(value).unwrap();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}
async fn manifest_response(
    updater: &Updater,
    parts: Vec<(u64, String)>,
    policy: DownloadPolicy,
) -> Result<Option<Update>, String> {
    let (url, server) = serve(parts).await;
    let client = Client::builder().no_proxy().build().unwrap();
    let result = available_from_request(
        updater,
        manifest_request(&client, url.parse().unwrap()),
        policy,
    )
    .await;
    server.abort();
    result
}

#[tokio::test]
async fn bounded_manifest_preserves_official_platform_version_and_signed_version_semantics() {
    let updater = configured_updater(PUBLIC_KEY, None);
    let current_platform = manifest_response(
        &updater,
        vec![(0, ok_json(&manifest("2.0.0")))],
        MANIFEST_POLICY,
    )
    .await
    .unwrap()
    .unwrap();
    let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "/mac-arm",
        ("macos", "x86_64") => "/mac-intel",
        ("windows", "x86_64") => "/windows",
        ("linux", "x86_64") => "/linux",
        ("linux", "aarch64") => "/linux-arm",
        _ => panic!("add a manifest fixture for this target"),
    };
    assert_eq!(current_platform.download_url.path(), expected);
    assert_eq!(
        current_platform.body.as_deref(),
        Some("public release notes")
    );
    assert!(current_platform.verify(b"test").is_ok());
    let custom = configured_updater(PUBLIC_KEY, Some("test-target"));
    assert_eq!(
        manifest_response(
            &custom,
            vec![(0, ok_json(&manifest("2.0.0")))],
            MANIFEST_POLICY
        )
        .await
        .unwrap()
        .unwrap()
        .download_url
        .path(),
        "/custom"
    );
    for version in [&current_platform.current_version, "0.0.0"] {
        // No update remains valid even when the current platform is absent.
        let old = json!({"version":version,"platforms":{}});
        assert!(
            manifest_response(&updater, vec![(0, ok_json(&old))], MANIFEST_POLICY)
                .await
                .unwrap()
                .is_none()
        );
    }
    let wrong_version = manifest_response(
        &updater,
        vec![(0, ok_json(&manifest("9.0.0")))],
        MANIFEST_POLICY,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(wrong_version.verify(b"test").is_err());
    let unversioned = configured_updater(UNVERSIONED_PUBLIC_KEY, None);
    let dynamic = json!({"version":"2.0.0","url":"https://example.com/dynamic","signature":STANDARD.encode(UNVERSIONED_SIGNATURE)});
    assert!(
        manifest_response(&unversioned, vec![(0, ok_json(&dynamic))], MANIFEST_POLICY)
            .await
            .unwrap()
            .unwrap()
            .verify(b"test")
            .is_err()
    );
}

#[tokio::test]
async fn manifest_handles_no_content_dynamic_format_and_rejects_invalid_metadata() {
    let updater = configured_updater(PUBLIC_KEY, None);
    assert!(manifest_response(
        &updater,
        vec![(0, "HTTP/1.1 204 No Content\r\n\r\n".into())],
        MANIFEST_POLICY
    )
    .await
    .unwrap()
    .is_none());
    let dynamic = json!({"version":"2.0.0","url":"https://example.com/dynamic","signature":STANDARD.encode(SIGNATURE)});
    let update = manifest_response(&updater, vec![(0, ok_json(&dynamic))], MANIFEST_POLICY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(update.download_url.path(), "/dynamic");
    assert!(update.verify(b"test").is_ok());
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnull".to_string(),
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\noops".to_string(),
        "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".to_string(),
        ok_json(&json!({"version":"9.0.0","platforms":{}})),
    ] {
        assert!(manifest_response(&updater, vec![(0, raw)], MANIFEST_POLICY)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn manifest_rejects_untrusted_lengths_and_chunked_or_close_delimited_oversize() {
    let updater = configured_updater(PUBLIC_KEY, None);
    let mut large = manifest("2.0.0");
    large["notes"] = Value::String("x".repeat(MANIFEST_POLICY.max_bytes));
    let body = serde_json::to_string(&large).unwrap();
    assert!(body.len() > MANIFEST_POLICY.max_bytes);
    for raw in [
        ok_json(&large),
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        ),
        format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}"),
    ] {
        let error = manifest_response(&updater, vec![(0, raw)], MANIFEST_POLICY)
            .await
            .err()
            .unwrap();
        assert!(error.contains("超过允许大小"), "{error}");
    }
    for raw in [
        "HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 20\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    ] {
        assert!(manifest_response(&updater, vec![(0, raw.into())], MANIFEST_POLICY).await.is_err());
    }
    // A correctly sized response at the exact bound is still accepted.
    let value = manifest("2.0.0");
    let size = serde_json::to_vec(&value).unwrap().len();
    assert!(manifest_response(
        &updater,
        vec![(0, ok_json(&value))],
        limits(1000, 500, size)
    )
    .await
    .unwrap()
    .is_some());
}

#[tokio::test]
async fn manifest_first_response_stall_and_continuous_slow_stream_have_deadlines() {
    let updater = configured_updater(PUBLIC_KEY, None);
    for parts in [
        vec![(150, ok_json(&manifest("2.0.0")))],
        vec![
            (0, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{".into()),
            (150, "}".into()),
        ],
    ] {
        assert!(manifest_response(&updater, parts, limits(1000, 30, 4096))
            .await
            .err()
            .unwrap()
            .contains("超时"));
    }
    let mut parts = vec![(
        0,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".into(),
    )];
    parts.extend((0..30).map(|_| (10, "1\r\n \r\n".into())));
    assert!(manifest_response(&updater, parts, limits(70, 100, 4096))
        .await
        .err()
        .unwrap()
        .contains("总时限"));
}

#[tokio::test]
async fn cancelling_manifest_header_or_body_wait_releases_the_update_attempt() {
    let updater = configured_updater(PUBLIC_KEY, None);
    for parts in [
        vec![(500, ok_json(&manifest("2.0.0")))],
        vec![
            (0, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{".into()),
            (500, "}".into()),
        ],
    ] {
        let service = Service::default();
        let mut attempt = service.start().unwrap();
        let (url, server) = serve(parts).await;
        let client = Client::builder().no_proxy().build().unwrap();
        let (result, _) = tokio::join!(
            attempt.downloading(available_from_request(
                &updater,
                manifest_request(&client, url.parse().unwrap()),
                MANIFEST_POLICY
            )),
            async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                service.cancel().unwrap();
            }
        );
        assert_eq!(result.err().unwrap(), CANCELLED);
        assert!(attempt.begin_install().is_err());
        drop(attempt);
        assert!(service.start().is_ok());
        server.abort();
    }
}

#[test]
fn manifest_endpoint_preserves_template_encoding_and_https_request_policy() {
    let template = "https://example.com/{{target}}/{{arch}}/{{current_version}}/{{bundle_type}}?version={{current_version}}&target={{target}}&arch={{arch}}&bundle={{bundle_type}}".parse().unwrap();
    let expanded =
        expand_endpoint(&template, "1.2.3+build.4", "windows", "x86_64", "nsis").unwrap();
    assert_eq!(expanded.path(), "/windows/x86_64/1.2.3%2Bbuild.4/nsis");
    assert_eq!(
        expanded
            .query_pairs()
            .find(|(k, _)| k == "version")
            .unwrap()
            .1,
        "1.2.3+build.4"
    );
    let client = https_client()
        .user_agent("tauri-plugin-updater/2.14.1")
        .build()
        .unwrap();
    let request = manifest_request(&client, expanded).build().unwrap();
    assert_eq!(request.headers()[header::ACCEPT], "application/json");
    assert!(expand_endpoint(
        &"http://example.com/manifest".parse().unwrap(),
        "1.0.0",
        "darwin",
        "aarch64",
        "app"
    )
    .is_err());
    assert!(expand_endpoint(
        &"https://user@example.com/manifest".parse().unwrap(),
        "1.0.0",
        "darwin",
        "aarch64",
        "app"
    )
    .is_err());
    assert_eq!(MANIFEST_POLICY.max_bytes, 1024 * 1024);
    assert_eq!(MANIFEST_POLICY.total, Duration::from_secs(30));
    assert_eq!(MANIFEST_POLICY.idle, Duration::from_secs(10));
}

#[tokio::test]
async fn production_manifest_client_rejects_http_before_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/manifest", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let updater = configured_updater(PUBLIC_KEY, None);
    let client = https_client().no_proxy().build().unwrap();
    assert!(available_from_request(
        &updater,
        manifest_request(&client, endpoint),
        MANIFEST_POLICY,
    )
    .await
    .is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

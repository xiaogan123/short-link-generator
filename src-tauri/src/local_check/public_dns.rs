use super::{validate_addresses, CheckIssue};
use reqwest::Client;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";
const MAX_BODY_BYTES: usize = 65_536;
const MAX_RECORDS: usize = 64;
const MAX_ALIASES: usize = 16;

struct Resolver {
    client: Client,
    #[cfg(test)]
    test_endpoint: Option<String>,
}

impl Resolver {
    fn new() -> Result<Self, CheckIssue> {
        let bootstrap = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 443),
        ];
        // The fixed HTTPS hostname supplies SNI/certificate verification. Its
        // fixed bootstrap addresses avoid consulting a system fake-IP resolver.
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .resolve_to_addrs("cloudflare-dns.com", &bootstrap)
            .build()
            .map_err(|_| CheckIssue::ClientInitialization)?;
        Ok(Self {
            client,
            #[cfg(test)]
            test_endpoint: None,
        })
    }

    fn endpoint(&self) -> &str {
        #[cfg(test)]
        if let Some(endpoint) = self.test_endpoint.as_deref() {
            return endpoint;
        }
        ENDPOINT
    }

    async fn query(&self, host: &str, record_type: u16) -> Result<Vec<IpAddr>, CheckIssue> {
        let kind = if record_type == 1 { "A" } else { "AAAA" };
        // Only the hostname and record type leave the app. Never send a target
        // URL's path, query, fragment, referral code or credentials to DNS.
        let mut response = self
            .client
            .get(self.endpoint())
            .query(&[("name", host), ("type", kind)])
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .map_err(transport_issue)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(CheckIssue::PublicDnsFailed);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/dns-json") {
            return Err(CheckIssue::PublicDnsInvalidResponse);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            return Err(CheckIssue::PublicDnsResponseTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_issue)? {
            if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(CheckIssue::PublicDnsResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        parse_answer(&body, host, record_type)
    }

    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, CheckIssue> {
        let host = public_host(host)?;
        // Require both query results. A successful family must not conceal an
        // error, malformed record, private address or virtual address in the other.
        let (v4, v6) = tokio::try_join!(self.query(&host, 1), self.query(&host, 28))?;
        let mut addresses: Vec<_> = v4
            .into_iter()
            .chain(v6)
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        validate_addresses(&addresses)?;
        Ok(addresses)
    }

    #[cfg(test)]
    fn for_test(endpoint: String, timeout: Duration) -> Self {
        Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(timeout)
                .build()
                .unwrap(),
            test_endpoint: Some(endpoint),
        }
    }
}

pub(super) async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, CheckIssue> {
    // Reject local/reserved names before constructing a network request.
    public_host(host)?;
    let resolver = Resolver::new()?;
    tokio::time::timeout(Duration::from_secs(4), resolver.resolve(host, port))
        .await
        .map_err(|_| CheckIssue::PublicDnsTimeout)?
}

fn transport_issue(error: reqwest::Error) -> CheckIssue {
    if error.is_timeout() {
        CheckIssue::PublicDnsTimeout
    } else {
        CheckIssue::PublicDnsFailed
    }
}

fn dns_name(value: &str) -> Result<String, CheckIssue> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(CheckIssue::PublicDnsInvalidResponse);
    }
    Ok(value.to_ascii_lowercase())
}

fn public_host(host: &str) -> Result<String, CheckIssue> {
    let host = dns_name(host).map_err(|_| CheckIssue::InvalidUrl)?;
    if !host.contains('.')
        || [
            "localhost",
            "local",
            "internal",
            "home.arpa",
            "invalid",
            "test",
        ]
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err(CheckIssue::NonPublicAddress);
    }
    Ok(host)
}

fn parse_answer(body: &[u8], host: &str, record_type: u16) -> Result<Vec<IpAddr>, CheckIssue> {
    if body.len() > MAX_BODY_BYTES {
        return Err(CheckIssue::PublicDnsResponseTooLarge);
    }
    let payload: Value =
        serde_json::from_slice(body).map_err(|_| CheckIssue::PublicDnsInvalidResponse)?;
    if payload["Status"].as_u64() != Some(0) || payload["TC"].as_bool() != Some(false) {
        return Err(CheckIssue::PublicDnsInvalidResponse);
    }
    let questions = payload["Question"]
        .as_array()
        .ok_or(CheckIssue::PublicDnsInvalidResponse)?;
    let host = dns_name(host)?;
    if questions.len() != 1
        || questions[0]["type"].as_u64() != Some(record_type as u64)
        || dns_name(
            questions[0]["name"]
                .as_str()
                .ok_or(CheckIssue::PublicDnsInvalidResponse)?,
        )? != host
    {
        return Err(CheckIssue::PublicDnsInvalidResponse);
    }
    let mut total_records = 0usize;
    for field in ["Answer", "Authority", "Additional"] {
        if let Some(records) = payload.get(field) {
            total_records += records
                .as_array()
                .ok_or(CheckIssue::PublicDnsInvalidResponse)?
                .len();
        }
    }
    if total_records > MAX_RECORDS {
        return Err(CheckIssue::PublicDnsResponseTooLarge);
    }
    let Some(answers) = payload.get("Answer") else {
        return Ok(Vec::new());
    };
    let answers = answers
        .as_array()
        .ok_or(CheckIssue::PublicDnsInvalidResponse)?;
    let mut aliases = HashMap::new();
    let mut addresses = Vec::new();
    for answer in answers {
        let name = dns_name(
            answer["name"]
                .as_str()
                .ok_or(CheckIssue::PublicDnsInvalidResponse)?,
        )?;
        if !answer["TTL"]
            .as_u64()
            .is_some_and(|ttl| ttl <= u32::MAX as u64)
        {
            return Err(CheckIssue::PublicDnsInvalidResponse);
        }
        let data = answer["data"]
            .as_str()
            .ok_or(CheckIssue::PublicDnsInvalidResponse)?;
        match answer["type"].as_u64() {
            Some(5) => {
                let target = dns_name(data)?;
                if aliases
                    .insert(name, target.clone())
                    .is_some_and(|old| old != target)
                {
                    return Err(CheckIssue::PublicDnsInvalidResponse);
                }
            }
            Some(kind) if kind == record_type as u64 => {
                let ip: IpAddr = data
                    .parse()
                    .map_err(|_| CheckIssue::PublicDnsInvalidResponse)?;
                if (record_type == 1 && !ip.is_ipv4()) || (record_type == 28 && !ip.is_ipv6()) {
                    return Err(CheckIssue::PublicDnsInvalidResponse);
                }
                addresses.push((name, ip));
            }
            _ => return Err(CheckIssue::PublicDnsInvalidResponse),
        }
    }
    let mut terminal = host;
    let mut visited = HashSet::new();
    while let Some(target) = aliases.get(&terminal) {
        if !visited.insert(terminal.clone()) || visited.len() > MAX_ALIASES {
            return Err(CheckIssue::PublicDnsInvalidResponse);
        }
        terminal = target.clone();
    }
    if aliases.keys().any(|name| !visited.contains(name))
        || addresses.iter().any(|(name, _)| name != &terminal)
    {
        return Err(CheckIssue::PublicDnsInvalidResponse);
    }
    Ok(addresses.into_iter().map(|(_, ip)| ip).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn answer(kind: u16, ips: &[&str]) -> Value {
        json!({
            "Status": 0, "TC": false,
            "Question": [{"name": "example.org.", "type": kind}],
            "Answer": ips.iter().map(|ip| json!({"name": "example.org.", "type":kind,"TTL":300,"data":ip})).collect::<Vec<_>>()
        })
    }

    fn parse(value: Value, kind: u16) -> Result<Vec<IpAddr>, CheckIssue> {
        parse_answer(&serde_json::to_vec(&value).unwrap(), "example.org", kind)
    }

    fn dns_response(value: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_raw(value.to_string(), "application/dns-json")
    }

    async fn mount_answer(server: &MockServer, kind: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path("/dns-query"))
            .and(query_param("name", "example.org"))
            .and(query_param("type", kind))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn resolver(server: &MockServer) -> Resolver {
        Resolver::for_test(
            format!("{}/dns-query", server.uri()),
            Duration::from_secs(1),
        )
    }

    #[test]
    fn strict_parser_accepts_ipv4_ipv6_nodata_and_order_independent_cname_chain() {
        assert_eq!(
            parse(answer(1, &["1.1.1.1"]), 1).unwrap(),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parse(answer(28, &["2606:4700:4700::1111"]), 28).unwrap(),
            vec!["2606:4700:4700::1111".parse::<IpAddr>().unwrap()]
        );
        assert!(parse(answer(28, &[]), 28).unwrap().is_empty());
        let mut nodata = answer(28, &[]);
        nodata.as_object_mut().unwrap().remove("Answer");
        assert!(parse(nodata, 28).unwrap().is_empty());
        let mut chained = answer(1, &[]);
        chained["Question"][0]["name"] = json!("EXAMPLE.ORG.");
        chained["Answer"] = json!([
            {"name":"final.example.org.","type":1,"TTL":300,"data":"1.1.1.1"},
            {"name":"cdn.example.org.","type":5,"TTL":300,"data":"final.example.org."},
            {"name":"example.org.","type":5,"TTL":300,"data":"cdn.example.org."}
        ]);
        assert_eq!(
            parse(chained, 1).unwrap(),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn strict_parser_rejects_errors_truncation_mismatches_and_malformed_records() {
        let base = answer(1, &["1.1.1.1"]);
        let mut invalid = Vec::new();
        for (field, value) in [
            ("Status", json!(3)),
            ("Status", json!("0")),
            ("TC", json!(true)),
            ("TC", Value::Null),
            ("Question", json!([])),
            ("Answer", Value::Null),
            ("Authority", json!({})),
        ] {
            let mut changed = base.clone();
            changed[field] = value;
            invalid.push(changed);
        }
        for (field, value) in [("name", json!("other.example.org")), ("type", json!(28))] {
            let mut changed = base.clone();
            changed["Question"][0][field] = value;
            invalid.push(changed);
        }
        for (field, value) in [
            ("name", json!("unrelated.example.org.")),
            ("name", json!("bad..example.org")),
            ("type", json!(28)),
            ("type", json!("1")),
            ("TTL", json!(-1)),
            ("TTL", json!(u64::MAX)),
            ("TTL", Value::Null),
            ("data", json!("2606:4700:4700::1111")),
            ("data", json!("127.1")),
            ("data", json!("1.1.1.1 junk")),
            ("data", Value::Null),
        ] {
            let mut changed = base.clone();
            changed["Answer"][0][field] = value;
            invalid.push(changed);
        }
        for value in invalid {
            assert_eq!(
                parse(value.clone(), 1),
                Err(CheckIssue::PublicDnsInvalidResponse),
                "{value}"
            );
        }
        assert_eq!(
            parse(answer(28, &["1.1.1.1"]), 28),
            Err(CheckIssue::PublicDnsInvalidResponse)
        );
        assert_eq!(
            parse_answer(b"not-json", "example.org", 1),
            Err(CheckIssue::PublicDnsInvalidResponse)
        );
        assert_eq!(
            parse_answer(b"[]", "example.org", 1),
            Err(CheckIssue::PublicDnsInvalidResponse)
        );
    }

    #[test]
    fn strict_parser_rejects_cname_cycles_branches_and_unrelated_addresses() {
        for records in [
            json!([
                {"name":"example.org.","type":5,"TTL":300,"data":"cdn.example.org."},
                {"name":"cdn.example.org.","type":5,"TTL":300,"data":"example.org."}
            ]),
            json!([
                {"name":"example.org.","type":5,"TTL":300,"data":"first.example.org."},
                {"name":"example.org.","type":5,"TTL":300,"data":"second.example.org."}
            ]),
            json!([
                {"name":"unrelated.example.org.","type":5,"TTL":300,"data":"cdn.example.org."},
                {"name":"example.org.","type":1,"TTL":300,"data":"1.1.1.1"}
            ]),
            json!([
                {"name":"example.org.","type":5,"TTL":300,"data":"cdn.example.org."},
                {"name":"unrelated.example.org.","type":1,"TTL":300,"data":"1.1.1.1"}
            ]),
        ] {
            let mut value = answer(1, &[]);
            value["Answer"] = records;
            assert_eq!(parse(value, 1), Err(CheckIssue::PublicDnsInvalidResponse));
        }
        let mut value = answer(1, &[]);
        value["Answer"] = Value::Array((0..=MAX_ALIASES).map(|i| json!({
            "name":if i == 0 { "example.org".to_owned() } else {format!("c{i}.example.org")},
            "type":5,"TTL":300,"data":format!("c{}.example.org", i + 1)
        })).collect());
        assert_eq!(parse(value, 1), Err(CheckIssue::PublicDnsInvalidResponse));
    }

    #[test]
    fn strict_parser_bounds_body_and_total_record_count() {
        assert_eq!(
            parse_answer(&vec![b' '; MAX_BODY_BYTES + 1], "example.org", 1),
            Err(CheckIssue::PublicDnsResponseTooLarge)
        );
        let mut value = answer(1, &["1.1.1.1"]);
        value["Additional"] = json!(vec![json!({}); MAX_RECORDS]);
        assert_eq!(parse(value, 1), Err(CheckIssue::PublicDnsResponseTooLarge));
    }

    #[tokio::test]
    async fn public_queries_send_only_host_and_type_and_merge_both_families() {
        let server = MockServer::start().await;
        mount_answer(&server, "A", dns_response(answer(1, &["1.1.1.1"]))).await;
        mount_answer(
            &server,
            "AAAA",
            dns_response(answer(28, &["2606:4700:4700::1111"])),
        )
        .await;
        let target =
            url::Url::parse("https://example.org/private-path?code=synthetic-secret#fragment")
                .unwrap();
        let addresses = resolver(&server)
            .resolve(target.host_str().unwrap(), 8443)
            .await
            .unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|address| address.port() == 8443));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            let query: HashMap<_, _> = request.url.query_pairs().collect();
            assert_eq!(query.len(), 2);
            assert_eq!(query["name"], "example.org");
            assert!(matches!(query["type"].as_ref(), "A" | "AAAA"));
            assert!(!request.url.as_str().contains("synthetic-secret"));
            assert!(!request.url.as_str().contains("private-path"));
            assert_eq!(request.headers["accept"], "application/dns-json");
            assert!(!request.headers.contains_key("authorization"));
            assert!(!request.headers.contains_key("cookie"));
            assert!(!request.headers.contains_key("referer"));
            assert!(request.body.is_empty());
        }
    }

    #[tokio::test]
    async fn merged_public_answers_reject_private_virtual_and_empty_results() {
        for (v4, v6, expected) in [
            (
                vec!["1.1.1.1", "127.0.0.1"],
                vec![],
                CheckIssue::NonPublicAddress,
            ),
            (
                vec!["1.1.1.1"],
                vec!["::ffff:198.18.0.1"],
                CheckIssue::VirtualAddress,
            ),
            (
                vec!["198.18.0.1"],
                vec!["2606:4700:4700::1111"],
                CheckIssue::VirtualAddress,
            ),
            (vec!["1.1.1.1"], vec!["::1"], CheckIssue::NonPublicAddress),
            (
                vec!["1.1.1.1"],
                vec!["2002:7f00:1::1"],
                CheckIssue::NonPublicAddress,
            ),
            (
                vec!["1.1.1.1"],
                vec!["2001:2::1"],
                CheckIssue::NonPublicAddress,
            ),
            (
                vec!["1.1.1.1"],
                vec!["3fff::1"],
                CheckIssue::NonPublicAddress,
            ),
            (
                vec!["1.1.1.1"],
                vec!["64:ff9b::7f00:1"],
                CheckIssue::NonPublicAddress,
            ),
            (vec![], vec![], CheckIssue::DnsEmpty),
        ] {
            let server = MockServer::start().await;
            mount_answer(&server, "A", dns_response(answer(1, &v4))).await;
            mount_answer(&server, "AAAA", dns_response(answer(28, &v6))).await;
            assert_eq!(
                resolver(&server).resolve("example.org", 443).await,
                Err(expected)
            );
        }
    }

    #[tokio::test]
    async fn public_dns_failure_in_one_family_cannot_use_the_other_as_fallback() {
        for failure in [
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_raw("not-json", "application/dns-json"),
            ResponseTemplate::new(200).set_body_json(answer(28, &[])),
        ] {
            let server = MockServer::start().await;
            mount_answer(&server, "A", dns_response(answer(1, &["1.1.1.1"]))).await;
            mount_answer(&server, "AAAA", failure).await;
            assert!(resolver(&server).resolve("example.org", 443).await.is_err());
            assert!(server.received_requests().await.unwrap().len() <= 2);
        }
    }

    #[tokio::test]
    async fn public_dns_redirects_are_never_followed() {
        let server = MockServer::start().await;
        let trap = MockServer::start().await;
        mount_answer(
            &server,
            "A",
            ResponseTemplate::new(302).insert_header("location", format!("{}/trap", trap.uri())),
        )
        .await;
        mount_answer(&server, "AAAA", dns_response(answer(28, &[]))).await;
        assert_eq!(
            resolver(&server).resolve("example.org", 443).await,
            Err(CheckIssue::PublicDnsFailed)
        );
        assert!(trap.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn public_dns_transport_enforces_timeout_and_response_size_limit() {
        let server = MockServer::start().await;
        mount_answer(
            &server,
            "A",
            dns_response(answer(1, &["1.1.1.1"])).set_delay(Duration::from_millis(250)),
        )
        .await;
        let client = Resolver::for_test(
            format!("{}/dns-query", server.uri()),
            Duration::from_millis(30),
        );
        assert_eq!(
            client.query("example.org", 1).await,
            Err(CheckIssue::PublicDnsTimeout)
        );
        server.reset().await;
        mount_answer(
            &server,
            "A",
            ResponseTemplate::new(200)
                .set_body_raw(" ".repeat(MAX_BODY_BYTES + 1), "application/dns-json"),
        )
        .await;
        assert_eq!(
            resolver(&server).query("example.org", 1).await,
            Err(CheckIssue::PublicDnsResponseTooLarge)
        );
    }

    #[tokio::test]
    async fn public_dns_rejects_local_or_invalid_names_before_any_network_request() {
        let server = MockServer::start().await;
        let resolver = resolver(&server);
        for host in [
            "localhost",
            "router.local",
            "host.localhost.",
            "host.internal",
            "home.arpa",
            "host.test",
            "host.invalid",
            "singlelabel",
            "bad..example.org",
            "example.org/path?secret",
        ] {
            assert!(resolver.resolve(host, 443).await.is_err(), "{host}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

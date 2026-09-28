# Optional measurement service

This small reference server implements the protocol in `docs/POOLS.md`. It is optional and is not part of the desktop installer. Run it on a machine whose **actual network is in mainland China**; no proxy or location claim is inferred by the code. No server or subscription is created automatically.

Use Node.js 24. Store a random 32–256 character secret containing only printable ASCII with no whitespace in a private file outside the repository with owner-only permissions. Set `PROBE_KEY_FILE` to that path. Set `PROBE_ALLOWED_HOSTS` to a comma-separated list of exact target hostnames, including any allowed redirect hosts. Wildcards and unlisted hosts are refused. `PROBE_PORT` defaults to 8789.

Start with `node probe/server.mjs`. It binds only to `127.0.0.1`. Put a trusted HTTPS reverse proxy in front of `/check`, with request size and rate limits. Do not expose the loopback HTTP listener directly. Enter the public HTTPS endpoint and the same secret in the desktop account's detection settings. Keep the secret and any real allowlist outside the public repository. Update the private allowlist when adding or changing target domains.

This reference probes the **fixed hostname root**, not a synthetic user's page. An application-level 404 for a made-up code is not evidence that the domain is inaccessible. Public IPv4 addresses are resolved and pinned for each request; mixed public/private results, private addresses, ports other than HTTPS 443, and redirect targets outside the allowlist are refused. IPv6-only targets are inconclusive in this reference implementation.

Successful HTTP responses demonstrate reachability from this node. HTTP 5xx is an explicit failed check. Authentication pages, challenges, rate limiting, DNS/TLS/transport errors and timeouts remain unknown. It cannot identify the reason for interference or prove availability on every operator's network. A production provider can combine independent regional/operator measurements before declaring a target unreachable; it must retain the same signed response protocol. The client's direct URL check separately detects actual saved-page 404/410 errors.

Requests are authenticated, bounded to 20 targets, measured with five concurrent workers and a 7.5 second batch deadline. Responses are HMAC-signed. A second simultaneous batch receives 429. No target URLs, credentials or request bodies are logged by this code. Check reverse-proxy logging separately. One instance with one secret should serve one account; use separate instances/keys for multiple accounts.

Run its offline fixtures with `node --test probe/server.test.mjs`. Tests use synthetic network responses and a loopback HTTP server, not live mainland measurements.

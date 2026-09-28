# Shared target pools

Manual links retain their current behavior. A template link references a pool by stable ID and stores only a code. The Worker composes the selected base prefix + percent-encoded code + optional suffix on each request. Updating a pool therefore updates all referencing links without rewriting them.

## Bridge extension

State adds `pools: Pool[]` (default empty). Link adds optional `poolId` and `code`; manual links omit them. Rendered `cnUrl`/`defaultUrl` may be computed for display, but storage for template links must remain references.

Pool = `{id, name, official:{prefix,suffix}, candidates:[{id,prefix,suffix,enabled}], updated, accountIds:string[], syncStatus?:{accountId,status,message}[]}`. Max 10 candidates; at least one enabled. Prefix/suffix composition with an example code must produce an absolute HTTPS URL without credentials, control characters or backslashes. The prefix must contain the complete HTTPS authority followed by `/` or `?`, with no preceding fragment marker: the code belongs only in the path or query, never the hostname, port, credentials or fragment. Composing distinct sample codes must preserve the same origin. Code matches `[A-Za-z0-9_-]{1,128}`. Preserve complete path/query structure; do not replace string fragments in unrelated manual links. Manual override is a separate manual link.

`prepare_change` adds:
- `save_pool`: `{pool: Pool}` (new pools may use id empty; backend creates stable random ID). Plans show affected accounts and reference count. Apply synchronizes `p:<poolId>` to all selected account resources; accounts without resources remain clearly unsynced until first template link usage.
- `delete_pool`: `{poolId}` only allowed if no references locally AND no matching remote references; never orphan a template link.
- `save_link` optionally accepts `{domainId,slug,poolId,code}` instead of literal URL pair.

`prepare_monitor` `{accountId,endpoint,secret}` → Plan (secret never included in PlanView, logs, backup or state). Endpoint is a user-configured trusted HTTPS mainland measurement service implementing the protocol below; app must not claim that any arbitrary provider is geographically verified. Apply saves secret in OS keyring and Worker `PROBE_KEY`, monitor configuration at `m:monitor`, and sets one cron schedule `*/15 * * * *`. Worker and KV are existing account resources; user sees all changes before confirmation. `disable_monitor` confirmed plan removes cron and monitor config, retaining links/pools. State may expose `monitorEnabled` and `monitorEndpoint` on Account, never the secret. Monitoring is optional, explicit, and unconfigured by default.

## Cloud schema

`p:<poolId>`: `{version:1,official:{prefix,suffix},candidates:[{id,prefix,suffix,enabled}],revision:<ISO timestamp>}`.
`l:<host>:<slug>` for a template link: `{poolId,code,updated}`.
`h:<poolId>`: `{revision,checkedAt:<unix seconds>,targets:{[candidateId]:{state:'healthy'|'unhealthy'|'unknown',failures,successes,checkedAt}}}`.
`m:monitor`: `{endpoint,poolIds:string[]}`. Maintain poolIds from managed pool records; never expose this key publicly. No product signatures in redirect responses.

Pool updates invalidate old health by revision. Mainland selects the first enabled candidate not marked unhealthy by fresh matching-revision health. Unknown/missing/stale (older than 3600 seconds) results keep user priority and are not labeled healthy. If every enabled candidate is freshly unhealthy, return neutral 503 (HEAD empty); do not silently substitute the other-region URL. Other countries use the official template. Selftest uses the identical choice algorithm and reports a temporarily unavailable pool truthfully.

## Measurement provider protocol

Scheduled Worker sends HTTPS POST, redirects disabled, `Authorization: Bearer <PROBE_KEY>`, body `{timestamp,targets:[{poolId,id,url}]}`. PROBE_KEY must contain 32–256 printable ASCII characters without whitespace so it can be transported exactly in the authorization header. Send the composed base with a neutral code `probe` for reachability only; do not send users' real codes. At most 20 targets per run, rotating larger sets with a persisted cursor. Provider must perform requests from actual mainland network nodes. It must not infer mainland reachability from an overseas server.

Provider response is JSON `{timestamp,results:[{poolId,id,status:'reachable'|'unreachable'|'unknown'}]}`, signed using HMAC SHA-256 over the exact response body bytes with PROBE_KEY (UTF-8), header `X-Probe-Signature: <hex>`. Timestamp difference ≤300 seconds; response bounded to 128 KiB. This authenticates the configured provider, not the geographic location of its machines. Missing, invalid, duplicated or mismatched results never count as confirmed failure. No automatic redirect following. Timeouts/auth/429/403/provider errors produce unknown and preserve quarantined status, while checkedAt becomes stale if checks remain inconclusive. Require 3 consecutive confirmed failures to mark unhealthy and 2 consecutive confirmed successes to recover; any unknown, missing, invalid or provider-error outcome resets both streak counters while preserving an existing quarantine and its last definitive per-target checkedAt. The top-level checkedAt records the monitoring attempt, not fresh evidence for every target. No real-world guarantee is made from a single network sample.

Both detection provenance and unknown state must be visible in the UI. No provider calls until configured. The project does not provision mainland nodes or purchase an external monitoring subscription.

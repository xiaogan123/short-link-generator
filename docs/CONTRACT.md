# Desktop bridge contract

The desktop frontend calls `invoke('dispatch', { request: { action, payload } })`. All JSON fields use camelCase. Responses are direct values, errors are sanitized human-readable strings. The frontend cannot supply API URLs, resource IDs for deletion, or arbitrary HTTP requests. Backend plans are authoritative, single-use and expire after five minutes. Every remote write requires a prepared plan and explicit confirmation.

## State

`get_state` → `{ accounts: Account[], domains: Domain[], links: Link[], pendingOperations: string[] }`

- Account: `{ id, label, zoneCount, checkedAt, hasResources, needsSelftestKey }`
- Domain: `{ id, accountId, zoneId, host, prefix, routeId }`
- Link: `{ domainId, slug, cnUrl, defaultUrl, updated }`
- Plan: `{ id, title, steps: string[], warnings: string[], expiresAt }`
- Check: `{ label, ok, message }`

## Actions

- `token_template` `{}` → URL string. A frontend opener opens exactly this URL in the system browser.
- `import_token` `{ token, replace: boolean }` → State. Duplicate accounts reject unless replace is true. Never return tokens. Multiple accounts may share a token reference safely.
- `rename_account` `{ accountId, label }` → State.
- `remove_account` `{ accountId }` → State. Local removal only; remove local associated records, preserve remote resources. UI confirms this distinction.
- `refresh_accounts` `{}` → State. Refresh cached zones and account checks.
- `prepare_domain` `{ input, prefix, accountId?: string }` → `{ host, prefix, candidates: { accountId, label, zoneId, status }[], checks: Check[], canApply, plan?: Plan }`. Resolve an exact hostname without silently stripping www. If more than one candidate exists, list all and require explicit account selection. Only active zones qualify. DNS must be proxied. Probe both prefix root and random child, accept only 404. Any uncertain/conflicting check stops mutation. One hostname per plan; users can add www separately.
- `prepare_change` `{ kind, ...fields }` → Plan. Kinds: `save_link` `{domainId,slug,cnUrl,defaultUrl}`; `delete_link` `{domainId,slug}`; `remove_domain` `{domainId}`; `cleanup_account` `{accountId}`; `recover_account` `{accountId}`; `rotate_selftest` `{accountId}`. Recovery discovery must stay read-only; rotating a lost selftest key is a separate confirmed write.
- `apply_plan` `{ planId }` → State. Revalidate ownership/state, serialize writes, record recovery journal, compensate changes made by this operation only. Distinguish failure, uncertain network outcome, and propagation delay.
- `selftest_link` `{domainId,slug}` → `{status:'passed'|'pending'|'failed'|'key_missing',message,checks:Check[]}`. Sign both CN and US probes, do not follow redirects, compare exact status and Location; no target reachability claims. Bound retries.
- `export_config` `{}` → JSON string without secrets. UI saves via native dialog.
- `import_config` `{json}` → State. Import non-secret local configuration after schema validation and remote ownership/read checks; never accept credentials or injected route/resource IDs as authoritative. No remote writes.

Backend stores credentials in the OS key store and non-secret state in app data, never the project tree. Exported files contain the user's domains and targets and are private backups. Preview mode must be explicitly labeled and never persist real tokens or call cloud APIs. No cloud writes are permitted during implementation without a separately supplied test hostname and credentials.

## Edge storage

Worker binding `LINKS`; secret `SELFTEST_KEY` is 64 hex characters representing 32 random bytes. HMAC SHA-256 uses decoded raw key bytes and UTF-8 message `host|path|unixSeconds|country`; request header `X-Selftest: seconds.COUNTRY.lowercaseHexSignature`, tolerance 300 seconds.

`c:<host>` contains `{prefix}`. `l:<host>:<slug>` contains `{rules:[{countries:['CN'],url}],default,updated}`. Internal recovery manifest may use `m:config` and must be checked against Worker bindings and zone routes before accepting ownership. No product signatures in public responses. Script source lives in `edge/worker.mjs` and is embedded by Rust at compile time.

Prefix `[a-z0-9-]{1,12}`. Slug `[A-Za-z0-9_-]{1,32}`. Redirects use only saved absolute HTTPS URLs. Worker handles GET/HEAD, rejects other methods, matches an exact prefix/slug path, ignores incoming query strings, defaults missing or unknown countries to default, and never fetches the destination. Responses have no product headers. KV cache is bounded in size and TTL; authenticated probes bypass process cache. KV propagation delay is not a reason to delete a successfully saved resource.

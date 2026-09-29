# Desktop bridge contract

The desktop frontend calls `invoke('dispatch', { request: { action, payload } })`. All JSON fields use camelCase. Responses are direct values, errors are sanitized human-readable strings. The frontend cannot supply API URLs, resource IDs for deletion, or arbitrary HTTP requests. Backend plans are authoritative, single-use and expire after five minutes. Every remote write requires a prepared plan and explicit confirmation.

## State

`get_state` → `{ accounts: Account[], domains: Domain[], links: Link[], pendingOperations: string[] }`

- Account: `{ id, label, cloudflareName?: string, zones: {id,name,status}[], zoneCount, checkedAt, hasResources, needsSelftestKey }`. `cloudflareName` is the provider account name, not a login email; `label` remains a local remark. Names and zones are refreshable cache, not new backup authority.
- Domain: `{ id, accountId, zoneId, host, prefix, routeId }`
- Link: `{ domainId, slug, cnUrl, defaultUrl, updated }`
- Plan: `{ id, title, steps: string[], warnings: string[], expiresAt }`
- Check: `{ label, ok, message }`
- DomainCheck: `{ label, ok, message, level: 'pass' | 'warning' | 'error' }`; used only by domain preparation. A warning is not proof that a path is empty or that routing is already working.
- Plan may include `domainTakeoverConfirmation: string`. This server-generated text describes the exact hostname and directory whose existing responses will be replaced by the short-link service.

## Actions

- `token_template` `{}` → URL string. A frontend opener opens exactly this URL in the system browser.
- `import_token` `{ token, replace: boolean, expectedAccountId?: string }` → State. Duplicate accounts reject unless replace is true. When expectedAccountId is supplied, require a matching existing account and replace=true; validate token access before changing only that account. Preserve its local label. Never return tokens. Multiple accounts may share a token reference safely.
- `rename_account` `{ accountId, label }` → State.
- `remove_account` `{ accountId }` → State. Local removal only; remove local associated records, preserve remote resources. UI confirms this distinction.
- `refresh_accounts` `{}` → State. Refresh provider names, cached zones and account checks while preserving local remarks.
- `prepare_domain` `{ input, prefix, accountId?: string }` → `{ host, prefix, candidates: { accountId, label, zoneId, status }[], checks: DomainCheck[], canApply, plan?: Plan }`. Resolve an exact hostname without silently stripping www. If more than one candidate exists, list all and require explicit account selection. Only active zones qualify. DNS must be proxied. Probe both prefix root and a random child without following redirects; HEAD may fall back to a bounded GET when unsupported. HTTP 404 passes. HTTP 2xx/3xx and origin/server 5xx responses require explicit directory takeover confirmation; they do not prove the path is unused. Access restrictions, rate limits, other unsupported responses, connection failures, ownership errors and overlapping Worker routes block a plan. `canApply` means no blocking errors, not that every check is green. One hostname and one directory per plan; users can add www separately. No website files, DNS records, redirect rules or firewall settings are changed.
- `prepare_domain_dns` `{input,accountId?:string}` → `{host,candidates,checks,dnsStatus,actions,canApply,plan?:Plan}`. Status is `ready`, `missing`, `dnsOnly`, `unsupported`, `conflict` or `readFailed`. Actions describe an exact host record creation or proxy enablement. Only a reviewed plan may change DNS. A new host uses a proxied AAAA placeholder; enabling proxy preserves existing record content. Check delegation, wildcard and incompatible records; reread zone ownership and the DNS snapshot before writing. Partial or uncertain writes remain reported for recovery; do not automatically delete or overwrite records to compensate. If a later check confirms ownership and ready DNS, clear only that host’s resolved local DNS journal; preserve it when persistence fails. A successful DNS plan does not bind the domain: prepare the directory again and obtain any takeover consent separately. DNS editing requires the token’s DNS edit permission.
- `prepare_change` `{ kind, ...fields }` → Plan. Kinds: `save_link` `{domainId,slug,cnUrl,defaultUrl}`; `delete_link` `{domainId,slug}`; `remove_domain` `{domainId}`; `cleanup_account` `{accountId}`; `recover_account` `{accountId}`; `rotate_selftest` `{accountId}`. Recovery discovery must stay read-only; rotating a lost selftest key is a separate confirmed write.
- `apply_plan` `{ planId, acknowledgeDomainTakeover?: boolean }` → State. A domain plan carrying `domainTakeoverConfirmation` requires the matching explicit acknowledgement; other plans do not gain a bypass from this flag. Revalidate ownership/state and domain path risks before any write, reusing the plan’s server-generated random child path so an echoed redirect URL stays comparable. The client cannot choose this probe path. Newly required takeover consent, materially changed warning observations, or any blocking error require a fresh check; a warning that resolves to 404 is safe. Keep the hostname, directory and account fixed to the prepared plan. Serialize writes, record recovery journal, compensate changes made by this operation only. Distinguish failure, uncertain network outcome, and propagation delay. Domain setup confirms that the cloud configuration was saved; actual redirect behavior is checked after creating a short link. Existing Cloudflare redirects or access policies can still take precedence.
- `selftest_link` `{domainId,slug}` → `{status:'passed'|'pending'|'failed'|'key_missing',message,checks:Check[]}`. Sign both CN and US probes, do not follow redirects, compare exact status and Location; no target reachability claims. Bound retries.
- `export_config` `{}` → JSON string without secrets. UI saves via native dialog.
- `import_config` `{json}` → State. Import non-secret local configuration after schema validation and remote ownership/read checks; never accept credentials or injected route/resource IDs as authoritative. No remote writes.

Backend persists credentials in the OS key store and non-secret state in app data, never the project tree. Successful secret reads may be reused briefly in Rust memory with bounded expiry, per-key loading coordination, invalidation on write/delete and clearing on window close or exit. Missing credentials are distinct from denied/cancelled access. No system password is collected by the application.

`check_link_targets` returns local checks with `status`, `message`, `source`, `url`, `checkedAt`, `reason` and `stage`. Reason/stage explain DNS, transport, redirect or HTTP outcomes without weakening public-address validation. Local checks disable application HTTP proxies, not OS routing or DNS; they never establish Mainland reachability. Exported files contain the user's domains and targets and are private backups. Preview mode must be explicitly labeled and never persist real tokens or call cloud APIs. No cloud writes are permitted during implementation without a separately supplied test hostname and credentials.

## Edge storage

Worker binding `LINKS`; secret `SELFTEST_KEY` is 64 hex characters representing 32 random bytes. HMAC SHA-256 uses decoded raw key bytes and UTF-8 message `host|path|unixSeconds|country`; request header `X-Selftest: seconds.COUNTRY.lowercaseHexSignature`, tolerance 300 seconds.

`c:<host>` contains `{prefix}`. `l:<host>:<slug>` contains `{rules:[{countries:['CN'],url}],default,updated}`. Internal recovery manifest may use `m:config` and must be checked against Worker bindings and zone routes before accepting ownership. No product signatures in public responses. Script source lives in `edge/worker.mjs` and is embedded by Rust at compile time.

Prefix `[a-z0-9-]{1,12}`. Slug `[A-Za-z0-9_-]{1,32}`. Redirects use only saved absolute HTTPS URLs. Worker handles GET/HEAD, rejects other methods, matches an exact prefix/slug path, ignores incoming query strings, defaults missing or unknown countries to default, and never fetches the destination. Responses have no product headers. KV cache is bounded in size and TTL; authenticated probes bypass process cache. KV propagation delay is not a reason to delete a successfully saved resource.

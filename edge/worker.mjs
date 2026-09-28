// The public route reads only its own config and link keys. The recovery
// manifest is intentionally never consulted by this Worker.
const PREFIX = /^[a-z0-9-]{1,12}$/;
const SLUG = /^[A-Za-z0-9_-]{1,32}$/;
const ROUTE = /^\/([a-z0-9-]{1,12})\/([A-Za-z0-9_-]{1,32})$/;
const SELFTEST = /^([0-9]{1,16})\.([A-Z]{2})\.([0-9a-f]{64})$/;
const HEX_KEY = /^[0-9a-fA-F]{64}$/;
const CACHE_TTL_MS = 60_000;
const MAX_CACHE_ENTRIES = 256;
const MAX_CONFIG_BYTES = 1024;
const MAX_LINK_BYTES = 16_384;
const MAX_URL_LENGTH = 2048;
const CODE = /^[A-Za-z0-9_-]{1,128}$/;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_POOL_BYTES = 16_384;
const MAX_HEALTH_BYTES = 16_384;
const MAX_MONITOR_BYTES = 16_384;
const HEALTH_TTL_SECONDS = 3600;
const MAX_PROBE_BODY_BYTES = 128 * 1024;
const MAX_PROBE_TARGETS = 20;
const encoder = new TextEncoder();
const caches = new WeakMap();

function response(status, body, head, extra = {}) {
  return new Response(head ? null : body, {
    status,
    headers: {
      'Cache-Control': 'private, no-store',
      'X-Robots-Tag': 'noindex, nofollow',
      ...extra,
    },
  });
}

function hexBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function selftestCountry(request, env, host, path) {
  const header = request.headers.get('X-Selftest');
  const match = header?.match(SELFTEST);
  if (!match || typeof env.SELFTEST_KEY !== 'string' || !HEX_KEY.test(env.SELFTEST_KEY)) {
    return null;
  }
  const seconds = Number(match[1]);
  if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(Date.now() / 1000) - seconds) > 300) {
    return null;
  }
  try {
    const key = await crypto.subtle.importKey(
      'raw', hexBytes(env.SELFTEST_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    const message = encoder.encode(`${host}|${path}|${match[1]}|${match[2]}`);
    // WebCrypto's verify operation compares the complete MAC without a
    // JavaScript early-exit comparison of attacker-controlled bytes.
    const valid = await crypto.subtle.verify('HMAC', key, hexBytes(match[3]), message);
    return valid ? match[2] : null;
  } catch {
    return null;
  }
}

function cacheFor(binding) {
  let cache = caches.get(binding);
  if (!cache) {
    cache = new Map();
    caches.set(binding, cache);
  }
  return cache;
}

async function readKV(binding, key, maxBytes, bypassCache, validate) {
  const cache = cacheFor(binding);
  const now = Date.now();
  if (!bypassCache) {
    const entry = cache.get(key);
    if (entry && entry.expires > now) {
      cache.delete(key);
      cache.set(key, entry);
      return entry.value;
    }
    if (entry) cache.delete(key);
  }
  // Leave Cloudflare's own KV cache at its documented default. Authenticated
  // probes bypass only this process cache; global KV propagation may lag.
  const value = await binding.get(key, 'text');
  if (value === null) return null;
  if (typeof value !== 'string' || encoder.encode(value).byteLength > maxBytes) {
    throw new Error('Invalid KV value');
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Invalid KV JSON');
  }
  if (!validate(parsed)) throw new Error('Invalid KV record');
  if (!bypassCache) {
    cache.set(key, { value: parsed, expires: now + CACHE_TTL_MS });
    while (cache.size > MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value);
  }
  return parsed;
}

function validDestination(value) {
  if (typeof value !== 'string' || value.length > MAX_URL_LENGTH ||
      !value.startsWith('https://') || /[\u0000-\u0020\u007f\\]/.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    const authority = value.slice('https://'.length).split(/[/?#]/, 1)[0];
    return url.protocol === 'https:' && Boolean(url.hostname) &&
      !authority.includes('@') && url.username === '' &&
      url.password === '' && url.port !== '0';
  } catch {
    return false;
  }
}

function validLink(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record) ||
      'poolId' in record || 'code' in record ||
      !validDestination(record.default) || !Array.isArray(record.rules) ||
      record.rules.length > 8) return false;
  // The current product contract has one country override: mainland China.
  if (record.rules.length > 1) return false;
  for (const rule of record.rules) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule) ||
        !Array.isArray(rule.countries) || rule.countries.length !== 1 ||
        rule.countries[0] !== 'CN' || !validDestination(rule.url)) return false;
  }
  return true;
}

function validTemplateLink(record) {
  return record && typeof record === 'object' && !Array.isArray(record) &&
    !('default' in record) && !('rules' in record) &&
    typeof record.poolId === 'string' && ID.test(record.poolId) &&
    typeof record.code === 'string' && CODE.test(record.code) &&
    typeof record.updated === 'string';
}

function compose(template, code) {
  const composed = `${template.prefix}${encodeURIComponent(code)}${template.suffix}`;
  if (!validDestination(composed)) throw new Error('Invalid template destination');
  return new URL(composed).href;
}

function validTemplate(template) {
  if (!template || typeof template !== 'object' || Array.isArray(template) ||
      typeof template.prefix !== 'string' || typeof template.suffix !== 'string') return false;
  // A shared health result can only apply to a fixed origin. Insert codes in
  // the path/query, never into a hostname, port, credentials or fragment.
  if (!/^https:\/\/[^/?#]+[/?]/.test(template.prefix) || template.prefix.includes('#')) return false;
  try {
    return new URL(compose(template, 'probe')).origin ===
      new URL(compose(template, 'other_code')).origin;
  } catch {
    return false;
  }
}

function validPool(pool) {
  if (!pool || typeof pool !== 'object' || Array.isArray(pool) || pool.version !== 1 ||
      !validTemplate(pool.official) || !Array.isArray(pool.candidates) ||
      pool.candidates.length < 1 || pool.candidates.length > 10 ||
      typeof pool.revision !== 'string' || !Number.isFinite(Date.parse(pool.revision))) return false;
  const ids = new Set();
  let enabled = 0;
  for (const candidate of pool.candidates) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) ||
        typeof candidate.id !== 'string' || !ID.test(candidate.id) || ids.has(candidate.id) ||
        typeof candidate.enabled !== 'boolean' || !validTemplate(candidate)) return false;
    ids.add(candidate.id);
    if (candidate.enabled) enabled++;
  }
  return enabled > 0;
}

function validHealth(health) {
  if (!health || typeof health !== 'object' || Array.isArray(health) ||
      typeof health.revision !== 'string' || !Number.isSafeInteger(health.checkedAt) ||
      !health.targets || typeof health.targets !== 'object' || Array.isArray(health.targets)) return false;
  for (const [id, target] of Object.entries(health.targets)) {
    if (!ID.test(id) || !target || typeof target !== 'object' || Array.isArray(target) ||
        !['healthy', 'unhealthy', 'unknown'].includes(target.state) ||
        !Number.isSafeInteger(target.failures) || target.failures < 0 ||
        !Number.isSafeInteger(target.successes) || target.successes < 0 ||
        !Number.isSafeInteger(target.checkedAt)) return false;
  }
  return true;
}

function freshUnhealthy(health, pool, candidate, now) {
  const target = health?.revision === pool.revision ? health.targets[candidate.id] : null;
  return target?.state === 'unhealthy' && target.checkedAt <= now &&
    now - target.checkedAt <= HEALTH_TTL_SECONDS;
}

function chooseCandidate(pool, health, now) {
  return pool.candidates.find(candidate => candidate.enabled &&
    !freshUnhealthy(health, pool, candidate, now)) ?? null;
}

function validMonitor(monitor) {
  return monitor && typeof monitor === 'object' && !Array.isArray(monitor) &&
    validEndpoint(monitor.endpoint) && Array.isArray(monitor.poolIds) &&
    monitor.poolIds.length <= 256 &&
    monitor.poolIds.every(id => typeof id === 'string' && ID.test(id)) &&
    new Set(monitor.poolIds).size === monitor.poolIds.length;
}

function validEndpoint(value) {
  if (typeof value !== 'string' || value.length > MAX_URL_LENGTH || !validDestination(value)) return false;
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    // Require a DNS name; this rules out loopback, link-local and private IP
    // literals, including their URL parser aliases, before contacting a provider.
    return !url.hash && !url.search && !url.username && !url.password &&
      host.includes('.') && !host.endsWith('.') &&
      !/\.(?:localhost|local|internal|test|invalid)$/.test(host) &&
      !['localhost', '0.0.0.0'].includes(host) &&
      !/^\d+(?:\.\d+){3}$/.test(host) && !host.includes(':');
  } catch {
    return false;
  }
}

async function hmac(keyText, bytes) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(keyText),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return { key, bytes };
}

async function boundedBytes(response) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Empty provider response');
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_PROBE_BODY_BYTES) throw new Error('Oversized provider response');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function providerResults(endpoint, secret, targets, now) {
  const requestBody = JSON.stringify({ timestamp: now, targets });
  const result = await fetch(endpoint, {
    method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10_000),
    headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },
    body: requestBody,
  });
  if (result.status !== 200) throw new Error('Provider unavailable');
  const signature = result.headers.get('X-Probe-Signature');
  if (!signature || !/^[0-9a-f]{64}$/.test(signature)) throw new Error('Invalid provider signature');
  const bytes = await boundedBytes(result);
  const signing = await hmac(secret, bytes);
  if (!await crypto.subtle.verify('HMAC', signing.key, hexBytes(signature), signing.bytes)) {
    throw new Error('Invalid provider signature');
  }
  const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!payload || !Number.isSafeInteger(payload.timestamp) ||
      Math.abs(now - payload.timestamp) > 300 || !Array.isArray(payload.results)) {
    throw new Error('Invalid provider timestamp or results');
  }
  const expected = new Set(targets.map(target => `${target.poolId}\u0000${target.id}`));
  const seen = new Map();
  for (const item of payload.results) {
    if (!item || typeof item.poolId !== 'string' || typeof item.id !== 'string') {
      throw new Error('Unexpected provider result');
    }
    const id = `${item.poolId}\u0000${item.id}`;
    if (!expected.has(id) || seen.has(id)) throw new Error('Unexpected provider result');
    seen.set(id, ['reachable', 'unreachable', 'unknown'].includes(item.status) ? item.status : 'unknown');
  }
  return seen;
}

async function monitor(env) {
  if (!env.LINKS || typeof env.LINKS.get !== 'function' || typeof env.LINKS.put !== 'function') return;
  const config = await readKV(env.LINKS, 'm:monitor', MAX_MONITOR_BYTES, true, validMonitor);
  if (!config || typeof env.PROBE_KEY !== 'string' || !/^[\x21-\x7e]{32,256}$/.test(env.PROBE_KEY)) return;
  const pools = new Map();
  const targets = [];
  for (const poolId of config.poolIds) {
    const pool = await readKV(env.LINKS, `p:${poolId}`, MAX_POOL_BYTES, true, validPool);
    if (!pool) continue;
    pools.set(poolId, pool);
    for (const candidate of pool.candidates) {
      if (candidate.enabled) targets.push({ poolId, id: candidate.id, url: compose(candidate, 'probe') });
    }
  }
  if (!targets.length) return;
  const rawCursor = await env.LINKS.get('m:monitor:cursor', 'text');
  const cursor = rawCursor === null ? 0 : Number(rawCursor);
  const start = Number.isSafeInteger(cursor) && cursor >= 0 ? cursor % targets.length : 0;
  const selected = Array.from({ length: Math.min(MAX_PROBE_TARGETS, targets.length) },
    (_, index) => targets[(start + index) % targets.length]);
  const now = Math.floor(Date.now() / 1000);
  let results = new Map();
  try {
    results = await providerResults(config.endpoint, env.PROBE_KEY, selected, now);
  } catch {
    // Failed or unauthenticated measurements supply no definite outcome.
  }
  for (const poolId of new Set(selected.map(target => target.poolId))) {
    const pool = pools.get(poolId);
    const prior = await readKV(env.LINKS, `h:${poolId}`, MAX_HEALTH_BYTES, true, validHealth);
    const health = prior?.revision === pool.revision ? prior :
      { revision: pool.revision, checkedAt: now, targets: {} };
    // Candidate IDs are data, including names such as constructor/__proto__.
    // Do not inherit counters or invoke Object.prototype setters for them.
    health.targets = Object.assign(Object.create(null), health.targets);
    health.checkedAt = now;
    for (const target of selected.filter(item => item.poolId === poolId)) {
      const id = `${poolId}\u0000${target.id}`;
      const outcome = results.get(id) ?? 'unknown';
      const before = health.targets[target.id] ??
        { state: 'unknown', failures: 0, successes: 0, checkedAt: now };
      if (outcome === 'unreachable') {
        const failures = Math.min(before.failures + 1, 3);
        health.targets[target.id] = {
          state: before.state === 'unhealthy' || failures >= 3 ? 'unhealthy' : 'unknown',
          failures, successes: 0, checkedAt: now,
        };
      } else if (outcome === 'reachable') {
        const successes = Math.min(before.successes + 1, 2);
        health.targets[target.id] = {
          state: before.state === 'unhealthy' && successes < 2 ? 'unhealthy' : 'healthy',
          failures: 0, successes, checkedAt: now,
        };
      } else {
        // Inconclusive rounds break both streaks. Preserve any quarantine and
        // its last definitive timestamp so uncertainty cannot refresh it.
        health.targets[target.id] = { ...before,
          state: before.state === 'unhealthy' ? 'unhealthy' : 'unknown',
          failures: 0, successes: 0 };
      }
    }
    await env.LINKS.put(`h:${poolId}`, JSON.stringify(health));
    cacheFor(env.LINKS).delete(`h:${poolId}`);
  }
  await env.LINKS.put('m:monitor:cursor', String((start + selected.length) % targets.length));
}

function validConfig(config) {
  return config && typeof config === 'object' && !Array.isArray(config) &&
    typeof config.prefix === 'string' && PREFIX.test(config.prefix);
}

function requestParts(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 8192) return null;
  // Extract the path before URL parsing because URL parsers normalize dot
  // segments and can erase evidence of an encoded traversal attempt.
  const raw = rawUrl.match(/^https?:\/\/([^/?#]+)([^?#]*)/i);
  if (!raw || raw[1].includes('@')) return null;
  const path = raw[2] || '/';
  if (path.length > 46) return null;
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  if (url.username || url.password || url.hash || !/^[a-z0-9.-]{1,253}$/.test(host)) {
    return null;
  }
  return { host, path };
}

export default {
  async fetch(request, env) {
    const head = request.method === 'HEAD';
    if (request.method !== 'GET' && !head) {
      return response(405, 'Method Not Allowed', false, { Allow: 'GET, HEAD' });
    }
    const parts = requestParts(request.url);
    const route = parts?.path.match(ROUTE);
    if (!route || !PREFIX.test(route[1]) || !SLUG.test(route[2])) {
      return response(404, 'Not Found', head);
    }
    const { host, path } = parts;
    const selftest = await selftestCountry(request, env, host, path);
    const country = selftest ?? (request.cf?.country === 'CN' ? 'CN' : '');
    if (!env.LINKS || typeof env.LINKS.get !== 'function') {
      return response(503, 'Service Unavailable', head);
    }
    try {
      const config = await readKV(env.LINKS, `c:${host}`, MAX_CONFIG_BYTES, selftest !== null, validConfig);
      if (config === null) return response(404, 'Not Found', head);
      if (config.prefix !== route[1]) return response(404, 'Not Found', head);
      const link = await readKV(env.LINKS, `l:${host}:${route[2]}`, MAX_LINK_BYTES,
        selftest !== null, value => validLink(value) || validTemplateLink(value));
      if (link === null) return response(404, 'Not Found', head);
      let destination;
      if (validTemplateLink(link)) {
        const pool = await readKV(env.LINKS, `p:${link.poolId}`, MAX_POOL_BYTES,
          selftest !== null, validPool);
        if (pool === null) return response(503, 'Service Unavailable', head);
        let template = pool.official;
        if (country === 'CN') {
          const health = await readKV(env.LINKS, `h:${link.poolId}`, MAX_HEALTH_BYTES,
            selftest !== null, validHealth);
          template = chooseCandidate(pool, health, Math.floor(Date.now() / 1000));
          if (!template) return response(503, 'Service Unavailable', head);
        }
        destination = compose(template, link.code);
      } else {
        destination = country === 'CN' && link.rules.length
          ? link.rules[0].url : link.default;
      }
      // Serialize validated HTTPS URLs before constructing a header: Unicode
      // hostnames need punycode and path/query characters need percent encoding.
      return response(302, null, head, { Location: new URL(destination).href });
    } catch {
      return response(503, 'Service Unavailable', head);
    }
  },
  async scheduled(_event, env) {
    try {
      await monitor(env);
    } catch {
      // A bad provider or KV record must never affect public redirect requests.
    }
  },
};

import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from './worker.mjs';

const KEY = '0123456789abcdef'.repeat(4);
const HOST = 'go.example.com';
const DEFAULT = 'https://example.org/default?kept=1';
const CN = 'https://example.com/china';
const LINK = { rules: [{ countries: ['CN'], url: CN }], default: DEFAULT, updated: '2026-01-01T00:00:00Z' };

class KV {
  constructor(values = {}) {
    this.values = new Map(Object.entries(values));
    this.reads = [];
    this.writes = [];
    this.fail = false;
  }

  async get(key, type) {
    this.reads.push([key, type]);
    if (this.fail) throw new Error('private KV failure');
    return this.values.get(key) ?? null;
  }

  put(key, value) {
    this.writes.push(key);
    this.values.set(key, typeof value === 'string' ? value : JSON.stringify(value));
  }
}

const PROBE_KEY = 'neutral-test-secret-for-signed-provider';
const POOL = {
  version: 1,
  official: { prefix: 'https://example.org/join?code=', suffix: '&source=web' },
  candidates: [
    { id: 'first', prefix: 'https://example.com/注册/', suffix: '?via=1', enabled: true },
    { id: 'second', prefix: 'https://example.org/alternate/', suffix: '', enabled: true },
  ],
  revision: '2026-01-01T00:00:00Z',
};

function templateFixture(pool = POOL, code = 'Code_1') {
  const env = fixture();
  env.LINKS.put(`l:${HOST}:Offer_1`, { poolId: 'pool_1', code, updated: '2026-01-01T00:00:00Z' });
  env.LINKS.put('p:pool_1', pool);
  return env;
}

async function signedProvider(body, secret = PROBE_KEY) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = Buffer.from(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw))).toString('hex');
  return new Response(raw, { status: 200, headers: { 'X-Probe-Signature': signature } });
}

function configureMonitor(env, poolIds = ['pool_1'], endpoint = 'https://measure.example.org/check') {
  env.PROBE_KEY = PROBE_KEY;
  env.LINKS.put('m:monitor', { endpoint, poolIds });
}

async function withProvider(handler, action) {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  try {
    return await action();
  } finally {
    globalThis.fetch = original;
  }
}

function fixture() {
  const kv = new KV();
  kv.put(`c:${HOST}`, { prefix: 'r' });
  kv.put(`l:${HOST}:Offer_1`, LINK);
  return { LINKS: kv, SELFTEST_KEY: KEY };
}

function req(url = `https://${HOST}/r/Offer_1`, country = 'US', method = 'GET', headers = {}) {
  // Plain request shape preserves a raw URL with traversal for boundary tests.
  return { url, cf: country === null ? undefined : { country }, method, headers: new Headers(headers) };
}

async function signed(host = HOST, path = '/r/Offer_1', country = 'CN', seconds = Math.floor(Date.now() / 1000), keyHex = KEY) {
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(Buffer.from(keyHex, 'hex')),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key,
    new TextEncoder().encode(`${host}|${path}|${seconds}|${country}`));
  return `${seconds}.${country}.${Buffer.from(sig).toString('hex')}`;
}

async function location(response) {
  assert.equal(response.status, 302);
  assert.equal(await response.text(), '');
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow');
  assert.equal(response.headers.get('server'), null);
  return response.headers.get('location');
}

test('country selection uses only mainland CN and never forwards incoming query', async () => {
  const env = fixture();
  assert.equal(await location(await worker.fetch(req(`https://${HOST}/r/Offer_1?source=ignored`, 'CN'), env)), CN);
  for (const country of ['HK', 'MO', 'TW', 'US', 'XX', '', null]) {
    assert.equal(await location(await worker.fetch(req(undefined, country), env)), DEFAULT, String(country));
  }
  assert.deepEqual(env.LINKS.reads.map(([key]) => key), [`c:${HOST}`, `l:${HOST}:Offer_1`]);
});

test('exact host, prefix and raw single-segment paths; absent list retains legacy exact matching', async () => {
  const env = fixture();
  assert.equal(await location(await worker.fetch(req(`https://GO.EXAMPLE.COM/r/Offer_1`), env)), DEFAULT);
  const invalid = [
    '/r', '/r/', '/R/Offer_1', '/r/offer_1', '/r/Offer_1/', '/r/Offer_1/extra',
    '/r/%4Fffer_1', '/r/Offer%2F1', '/r/Offer%5c1', '/r/../r/Offer_1',
    '/r/%2e%2e/r/Offer_1', '/r/.', '//r/Offer_1', '/r/a.b',
    `/r/${'a'.repeat(33)}`, `/${'a'.repeat(13)}/Offer_1`,
  ];
  for (const path of invalid) {
    const result = await worker.fetch(req(`https://${HOST}${path}`), env);
    assert.equal(result.status, 404, path);
    assert.equal(await result.text(), 'Not Found');
    assert.equal(result.headers.get('x-robots-tag'), 'noindex, nofollow');
  }
  assert.equal((await worker.fetch(req('https://other.example.com/r/Offer_1'), env)).status, 404);
  assert.equal(env.LINKS.reads.some(([key]) => key === 'm:config'), false);
  assert.equal(env.LINKS.reads.some(([key]) => key === 'c:other.example.com'), true);
});

test('HEAD has no body and other methods return 405 without KV reads', async () => {
  const env = fixture();
  const head = await worker.fetch(req(undefined, 'CN', 'HEAD'), env);
  assert.equal(head.status, 302);
  assert.equal(head.body, null);
  assert.equal(head.headers.get('location'), CN);
  const missing = await worker.fetch(req(`https://${HOST}/r/nope`, 'US', 'HEAD'), env);
  assert.equal(missing.status, 404);
  assert.equal(missing.body, null);
  const count = env.LINKS.reads.length;
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
    const result = await worker.fetch(req(undefined, 'US', method), env);
    assert.equal(result.status, 405);
    assert.equal(result.headers.get('allow'), 'GET, HEAD');
    assert.equal(result.headers.get('cache-control'), 'private, no-store');
  }
  assert.equal(env.LINKS.reads.length, count);
});

test('missing keys differ from corrupt data and KV failures', async () => {
  const env = fixture();
  assert.equal((await worker.fetch(req(`https://${HOST}/r/missing`), env)).status, 404);
  const badConfig = fixture();
  badConfig.LINKS.put(`c:${HOST}`, 'not-json');
  assert.equal((await worker.fetch(req(), badConfig)).status, 503);
  const corrupt = fixture();
  corrupt.LINKS.put(`l:${HOST}:Offer_1`, '{bad');
  const bad = await worker.fetch(req(), corrupt);
  assert.equal(bad.status, 503);
  assert.equal(await bad.text(), 'Service Unavailable');
  const failed = fixture();
  failed.LINKS.fail = true;
  assert.equal((await worker.fetch(req(), failed)).status, 503);
  assert.equal((await worker.fetch(req(), {})).status, 503);
});

test('runtime rejects unsafe or malformed saved destinations, including unused rules', async () => {
  const invalid = [
    'http://example.org/', 'https://user@example.org/', 'https://:pass@example.org/',
    'https://example.org/\r\nInjected: yes', 'https://example.org\\evil',
    'https://example.org/ space', 'https://', 'https://@example.org/',
    'javascript:alert(1)',
    `https://example.org/${'x'.repeat(2050)}`,
  ];
  for (const bad of invalid) {
    const env = fixture();
    env.LINKS.put(`l:${HOST}:Offer_1`, { ...LINK, default: bad });
    assert.equal((await worker.fetch(req(), env)).status, 503, bad);
    const second = fixture();
    second.LINKS.put(`l:${HOST}:Offer_1`, { ...LINK, rules: [{ countries: ['CN'], url: bad }] });
    assert.equal((await worker.fetch(req(), second)).status, 503, bad);
  }
  const env = fixture();
  env.LINKS.put(`l:${HOST}:Offer_1`, { ...LINK, rules: [{ countries: ['HK'], url: CN }] });
  assert.equal((await worker.fetch(req(), env)).status, 503);
});

test('oversized records and invalid config fail closed', async () => {
  const env = fixture();
  env.LINKS.put(`c:${HOST}`, { prefix: 'UPPER' });
  assert.equal((await worker.fetch(req(), env)).status, 503);
  const huge = fixture();
  huge.LINKS.put(`l:${HOST}:Offer_1`, `${JSON.stringify(LINK)}${' '.repeat(17_000)}`);
  assert.equal((await worker.fetch(req(), huge)).status, 503);
});

test('signed selftest selects probe country and bypasses process cache', async () => {
  const env = fixture();
  assert.equal(await location(await worker.fetch(req(), env)), DEFAULT);
  env.LINKS.put(`l:${HOST}:Offer_1`, { ...LINK, default: 'https://example.org/new' });
  assert.equal(await location(await worker.fetch(req(), env)), DEFAULT);
  const header = await signed();
  assert.equal(await location(await worker.fetch(req(undefined, 'US', 'GET', { 'X-Selftest': header }), env)), CN);
  const usHeader = await signed(HOST, '/r/Offer_1', 'US');
  assert.equal(await location(await worker.fetch(req(undefined, 'CN', 'GET', { 'X-Selftest': usHeader }), env)), 'https://example.org/new');
  assert.equal(await location(await worker.fetch(req(), env)), DEFAULT);
  assert.equal(env.LINKS.reads.length, 6);
});

test('invalid, expired, future, and replayed selftests are ignored', async () => {
  const env = fixture();
  const now = Math.floor(Date.now() / 1000);
  const headers = [
    await signed('other.example.com'),
    await signed(HOST, '/r/another'),
    await signed(HOST, '/r/Offer_1', 'CN', now - 301),
    await signed(HOST, '/r/Offer_1', 'CN', now + 301),
    await signed(HOST, '/r/Offer_1', 'CN', now, 'fedcba9876543210'.repeat(4)),
    'broken',
    (await signed()).toUpperCase(),
  ];
  for (const header of headers) {
    assert.equal(await location(await worker.fetch(req(undefined, 'US', 'GET', { 'X-Selftest': header }), env)), DEFAULT);
  }
  const valid = await signed();
  const otherHost = fixture();
  otherHost.LINKS.put('c:other.example.com', { prefix: 'r' });
  otherHost.LINKS.put('l:other.example.com:Offer_1', LINK);
  assert.equal(await location(await worker.fetch(req('https://other.example.com/r/Offer_1', 'US', 'GET', { 'X-Selftest': valid }), otherHost)), DEFAULT);
  const otherPath = fixture();
  otherPath.LINKS.put(`l:${HOST}:Another`, LINK);
  assert.equal(await location(await worker.fetch(req(`https://${HOST}/r/Another`, 'US', 'GET', { 'X-Selftest': valid }), otherPath)), DEFAULT);
});

test('selftest signing requires a 32-byte hex secret', async () => {
  const env = fixture();
  env.SELFTEST_KEY = 'abc';
  assert.equal(await location(await worker.fetch(req(undefined, 'US', 'GET', { 'X-Selftest': await signed() }), env)), DEFAULT);
});

test('selftest accepts the exact 300-second boundary', async () => {
  const env = fixture();
  const now = Math.floor(Date.now() / 1000);
  const header = await signed(HOST, '/r/Offer_1', 'CN', now - 300);
  assert.equal(await location(await worker.fetch(req(undefined, 'US', 'GET', { 'X-Selftest': header }), env)), CN);
});

test('process cache expires after 60 seconds and evicts beyond its entry cap', async () => {
  const env = fixture();
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    assert.equal(await location(await worker.fetch(req(), env)), DEFAULT);
    env.LINKS.put(`l:${HOST}:Offer_1`, { ...LINK, default: 'https://example.org/revised' });
    now += 59_999;
    assert.equal(await location(await worker.fetch(req(), env)), DEFAULT);
    now += 2;
    assert.equal(await location(await worker.fetch(req(), env)), 'https://example.org/revised');
  } finally {
    Date.now = realNow;
  }

  for (let i = 0; i < 257; i++) {
    env.LINKS.put(`l:${HOST}:s${i}`, LINK);
    assert.equal((await worker.fetch(req(`https://${HOST}/r/s${i}`), env)).status, 302);
  }
  const count = env.LINKS.reads.length;
  assert.equal((await worker.fetch(req(`https://${HOST}/r/s0`), env)).status, 302);
  assert.equal(env.LINKS.reads.length, count + 1);
});

test('native Request and Response objects work with the exported fetch handler', async () => {
  const env = fixture();
  const result = await worker.fetch(new Request(`https://${HOST}/r/Offer_1`), env);
  assert.equal(await location(result), DEFAULT);
});

test('Unicode destinations serialize safely for both countries and GET/HEAD', async () => {
  const destinations = [
    ['https://例子.example/', 'https://xn--fsqu00a.example/'],
    ['https://example.org/路径', 'https://example.org/%E8%B7%AF%E5%BE%84'],
    ['https://example.org/?q=中文', 'https://example.org/?q=%E4%B8%AD%E6%96%87'],
  ];
  for (const [saved, expected] of destinations) {
    for (const country of ['CN', 'US']) {
      const env = fixture();
      env.LINKS.put(`l:${HOST}:Offer_1`, {
        ...LINK,
        default: country === 'US' ? saved : DEFAULT,
        rules: [{ countries: ['CN'], url: country === 'CN' ? saved : CN }],
      });
      for (const method of ['GET', 'HEAD']) {
        assert.equal(await location(await worker.fetch(req(undefined, country, method), env)), expected);
      }
    }
  }
});

test('native Request normalizes dot segments before the handler sees the URL', async () => {
  const rawUrl = `https://${HOST}/r/../r/Offer_1`;
  assert.equal((await worker.fetch(req(rawUrl), fixture())).status, 404);
  const nativeRequest = new Request(rawUrl);
  assert.equal(nativeRequest.url, `https://${HOST}/r/Offer_1`);
  assert.equal(await location(await worker.fetch(nativeRequest, fixture())), DEFAULT);
});

test('parallel requests keep country decisions isolated', async () => {
  const env = fixture();
  const countries = Array.from({ length: 80 }, (_, i) => i % 4 === 0 ? 'CN' : 'US');
  const results = await Promise.all(countries.map(country => worker.fetch(req(undefined, country), env)));
  const locations = await Promise.all(results.map(location));
  assert.deepEqual(locations, countries.map(country => country === 'CN' ? CN : DEFAULT));
});

test('template links compose path and query without changing manual links', async () => {
  const env = templateFixture();
  assert.equal(await location(await worker.fetch(req(undefined, 'US'), env)),
    'https://example.org/join?code=Code_1&source=web');
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
    'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
  assert.equal(await location(await worker.fetch(req(undefined, 'CN', 'HEAD'), env)),
    'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
  env.LINKS.put(`l:${HOST}:Manual`, LINK);
  assert.equal(await location(await worker.fetch(req(`https://${HOST}/r/Manual`, 'CN'), env)), CN);
});

test('template pool changes update all references after bounded cache expiry and probes bypass cache', async () => {
  const env = templateFixture();
  env.LINKS.put(`l:${HOST}:Other`, { poolId: 'pool_1', code: 'Other', updated: POOL.revision });
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
      'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
    env.LINKS.put('p:pool_1', { ...POOL,
      candidates: [{ ...POOL.candidates[0], prefix: 'https://example.org/new/' }, POOL.candidates[1]],
      revision: '2026-01-02T00:00:00Z' });
    assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
      'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
    const probe = await signed();
    assert.equal(await location(await worker.fetch(req(undefined, 'US', 'GET', { 'X-Selftest': probe }), env)),
      'https://example.org/new/Code_1?via=1');
    now += 60_001;
    assert.equal(await location(await worker.fetch(req(`https://${HOST}/r/Other`, 'CN'), env)),
      'https://example.org/new/Other?via=1');
  } finally {
    Date.now = realNow;
  }
});

test('template rejects invalid code and malformed or unsafe pool definitions', async () => {
  for (const code of ['', 'a/b', 'bad?query', 'x'.repeat(129)]) {
    assert.equal((await worker.fetch(req(), templateFixture(POOL, code))).status, 503, code);
  }
  for (const pool of [
    { ...POOL, official: { prefix: 'http://example.org/', suffix: '' } },
    { ...POOL, candidates: [{ ...POOL.candidates[0], prefix: 'https://user@example.org/' }] },
    { ...POOL, candidates: [{ ...POOL.candidates[0], suffix: '\r\nInjected:yes' }] },
    { ...POOL, candidates: [] },
    { ...POOL, candidates: [POOL.candidates[0], POOL.candidates[0]] },
    { ...POOL, candidates: [{ ...POOL.candidates[0], enabled: false }] },
  ]) {
    assert.equal((await worker.fetch(req(undefined, 'US'), templateFixture(pool))).status, 503);
  }
  const missing = templateFixture();
  missing.LINKS.values.delete('p:pool_1');
  assert.equal((await worker.fetch(req(), missing)).status, 503);
});

test('CN excludes only fresh unhealthy candidates and fails neutral when all are fresh unhealthy', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = templateFixture();
  const bad = { state: 'unhealthy', failures: 3, successes: 0, checkedAt: now };
  env.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now, targets: { first: bad } });
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
    'https://example.org/alternate/Code_1');
  assert.equal(await location(await worker.fetch(req(undefined, 'US'), env)),
    'https://example.org/join?code=Code_1&source=web');
  env.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now,
    targets: { first: bad, second: bad } });
  const probe = await signed();
  const cn = await worker.fetch(req(undefined, 'US', 'GET', { 'X-Selftest': probe }), env);
  assert.equal(cn.status, 503);
  assert.equal(cn.headers.get('location'), null);
  const head = await worker.fetch(req(undefined, 'CN', 'HEAD', { 'X-Selftest': probe }), env);
  assert.equal(head.status, 503);
  assert.equal(head.body, null);
  assert.equal(await location(await worker.fetch(req(undefined, 'US'), env)),
    'https://example.org/join?code=Code_1&source=web');
  const stale = templateFixture();
  stale.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now - 3601,
    targets: { first: { ...bad, checkedAt: now - 3601 } } });
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), stale)),
    'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
  const revised = templateFixture({ ...POOL, revision: '2026-01-02T00:00:00Z' });
  revised.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now, targets: { first: bad } });
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), revised)),
    'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
});

test('scheduler remains inert when unconfigured or endpoint is local', async () => {
  const env = templateFixture();
  const writes = env.LINKS.writes.length;
  await withProvider(() => { throw new Error('must not call'); }, () => worker.scheduled({}, env));
  assert.equal(env.LINKS.writes.length, writes);
  configureMonitor(env, ['pool_1'], 'https://127.0.0.1/check');
  const configuredWrites = env.LINKS.writes.length;
  await withProvider(() => { throw new Error('must not call'); }, () => worker.scheduled({}, env));
  assert.equal(env.LINKS.writes.length, configuredWrites);
});

test('scheduler uses neutral probe code and requires authenticated timely exact results', async () => {
  const env = templateFixture();
  configureMonitor(env);
  let request;
  await withProvider(async (url, options) => {
    request = { url, options, body: JSON.parse(options.body) };
    return signedProvider({ timestamp: Math.floor(Date.now() / 1000),
      results: request.body.targets.map(({ poolId, id }) => ({ poolId, id, status: 'unreachable' })) });
  }, () => worker.scheduled({}, env));
  assert.equal(request.url, 'https://measure.example.org/check');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.redirect, 'manual');
  assert.equal(request.options.headers.Authorization, `Bearer ${PROBE_KEY}`);
  assert.equal(request.body.targets.length, 2);
  assert.ok(request.body.targets.every(target => target.url.includes('probe') && !target.url.includes('Code_1')));
  assert.equal(JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first.failures, 1);
  await withProvider(async () => signedProvider({ timestamp: Math.floor(Date.now() / 1000) - 301,
    results: [{ poolId: 'pool_1', id: 'first', status: 'unreachable' }] }),
  () => worker.scheduled({}, env));
  assert.equal(JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first.failures, 0);
  await withProvider(async () => new Response('{}', { headers: { 'X-Probe-Signature': 'a'.repeat(64) } }),
    () => worker.scheduled({}, env));
  assert.equal(JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first.failures, 0);
  await withProvider(async () => signedProvider({ timestamp: Math.floor(Date.now() / 1000), results: [
    { poolId: 'pool_1', id: 'first', status: 'unreachable' },
    { poolId: 'pool_1', id: 'first', status: 'unreachable' },
  ] }), () => worker.scheduled({}, env));
  assert.equal(JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first.failures, 0);
});

test('three definite failures quarantine and two definite successes recover', async () => {
  const env = templateFixture();
  configureMonitor(env);
  async function round(status) {
    await withProvider(async (_url, options) => signedProvider({
      timestamp: Math.floor(Date.now() / 1000),
      results: JSON.parse(options.body).targets.map(({ poolId, id }) =>
        ({ poolId, id, status: id === 'first' ? status : 'reachable' })),
    }), () => worker.scheduled({}, env));
    return JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first;
  }
  assert.equal((await round('unreachable')).state, 'unknown');
  assert.equal((await round('unreachable')).state, 'unknown');
  assert.equal((await round('unreachable')).state, 'unhealthy');
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
    'https://example.org/alternate/Code_1');
  assert.equal((await round('reachable')).state, 'unhealthy');
  assert.equal((await round('reachable')).state, 'healthy');
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
    'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
});

test('scheduler caps each request at 20 targets and rotates across pools', async () => {
  const env = templateFixture();
  const ids = Array.from({ length: 3 }, (_, i) => `pool_${i}`);
  for (const id of ids) env.LINKS.put(`p:${id}`, { ...POOL,
    candidates: Array.from({ length: 10 }, (_, i) => ({ ...POOL.candidates[1], id: `c${i}` })) });
  configureMonitor(env, ids);
  const batches = [];
  await withProvider(async (_url, options) => {
    const request = JSON.parse(options.body);
    batches.push(request.targets.map(item => `${item.poolId}:${item.id}`));
    return signedProvider({ timestamp: request.timestamp, results: request.targets.map(({ poolId, id }) =>
      ({ poolId, id, status: 'unknown' })) });
  }, async () => {
    await worker.scheduled({}, env);
    await worker.scheduled({}, env);
  });
  assert.equal(batches[0].length, 20);
  assert.equal(batches[1].length, 20);
  assert.deepEqual(batches[0].slice(0, 2), ['pool_0:c0', 'pool_0:c1']);
  assert.deepEqual(batches[1].slice(0, 2), ['pool_2:c0', 'pool_2:c1']);
  assert.equal(env.LINKS.values.get('m:monitor:cursor'), '10');
});

test('scheduler treats provider errors, oversized bodies and extra targets as unknown', async () => {
  const env = templateFixture();
  configureMonitor(env);
  const now = Math.floor(Date.now() / 1000);
  env.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now,
    targets: { first: { state: 'unhealthy', failures: 3, successes: 0, checkedAt: now } } });
  const initial = JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first;
  const handlers = [
    async () => new Response('forbidden', { status: 403 }),
    async () => new Response('rate limited', { status: 429 }),
    async () => { throw new Error('timeout'); },
    async () => signedProvider(' '.repeat(128 * 1024 + 1)),
    async () => signedProvider({ timestamp: now, results: [
      { poolId: 'pool_1', id: 'first', status: 'unreachable' },
      { poolId: 'extra', id: 'first', status: 'unreachable' },
    ] }),
  ];
  for (const handler of handlers) {
    await withProvider(handler, () => worker.scheduled({}, env));
    assert.deepEqual(JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first, { ...initial, failures: 0, successes: 0 });
    assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
      'https://example.org/alternate/Code_1');
  }
});

test('inconclusive provider check changes prior healthy state to unknown', async () => {
  const env = templateFixture();
  configureMonitor(env);
  const now = Math.floor(Date.now() / 1000);
  env.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now,
    targets: { first: { state: 'healthy', failures: 0, successes: 1, checkedAt: now } } });
  await withProvider(async () => new Response('unavailable', { status: 503 }),
    () => worker.scheduled({}, env));
  const target = JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first;
  assert.equal(target.state, 'unknown');
  assert.equal(target.checkedAt, now);
  assert.equal(await location(await worker.fetch(req(undefined, 'CN'), env)),
    'https://example.com/%E6%B3%A8%E5%86%8C/Code_1?via=1');
});

test('scheduler discards old health counters after pool revision', async () => {
  const env = templateFixture({ ...POOL, revision: '2026-02-01T00:00:00Z' });
  configureMonitor(env);
  const now = Math.floor(Date.now() / 1000);
  env.LINKS.put('h:pool_1', { revision: POOL.revision, checkedAt: now,
    targets: { first: { state: 'unhealthy', failures: 3, successes: 0, checkedAt: now } } });
  await withProvider(async (_url, options) => signedProvider({ timestamp: now,
    results: JSON.parse(options.body).targets.map(({ poolId, id }) =>
      ({ poolId, id, status: 'unreachable' })) }), () => worker.scheduled({}, env));
  const health = JSON.parse(env.LINKS.values.get('h:pool_1'));
  assert.equal(health.revision, '2026-02-01T00:00:00Z');
  assert.equal(health.targets.first.failures, 1);
  assert.equal(health.targets.first.state, 'unknown');
});

test('prototype-named candidate IDs remain ordinary health entries', async () => {
  const ids = ['__proto__', 'constructor', 'toString'];
  const env = templateFixture({ ...POOL, candidates: ids.map(id => ({ ...POOL.candidates[1], id })) });
  configureMonitor(env);
  async function round(status) {
    await withProvider(async (_url, options) => {
      const request = JSON.parse(options.body);
      return signedProvider({ timestamp: request.timestamp,
        results: request.targets.map(({ poolId, id }) => ({ poolId, id, status })) });
    }, () => worker.scheduled({}, env));
    return JSON.parse(env.LINKS.values.get('h:pool_1')).targets;
  }
  for (let failures = 1; failures <= 3; failures++) {
    const targets = await round('unreachable');
    assert.deepEqual(Object.keys(targets), ids);
    for (const id of ids) {
      assert.equal(targets[id].failures, failures);
      assert.equal(targets[id].state, failures === 3 ? 'unhealthy' : 'unknown');
    }
    assert.equal((await worker.fetch(req(undefined, 'CN'), env)).status, failures === 3 ? 503 : 302);
  }
  for (let successes = 1; successes <= 2; successes++) {
    const targets = await round('reachable');
    for (const id of ids) {
      assert.equal(targets[id].successes, successes);
      assert.equal(targets[id].state, successes === 2 ? 'healthy' : 'unhealthy');
    }
  }
  assert.equal((await worker.fetch(req(undefined, 'CN'), env)).status, 302);
});

test('template insertion stays within a fixed origin path or query', async () => {
  for (const template of [
    { prefix: 'https://', suffix: '.example.org/' },
    { prefix: 'https://example.org:', suffix: '/' },
    { prefix: 'https://example.org', suffix: '.example.com/' },
    { prefix: 'https://example.org/#code=', suffix: '' },
  ]) {
    for (const field of ['official', 'candidate']) {
      const pool = structuredClone(POOL);
      if (field === 'official') pool.official = template;
      else Object.assign(pool.candidates[0], template);
      assert.equal((await worker.fetch(req(undefined, 'CN'), templateFixture(pool))).status, 503);
    }
  }
  for (const template of [
    { prefix: 'https://example.org/', suffix: '?source=1' },
    { prefix: 'https://example.org?code=', suffix: '&source=1' },
    { prefix: 'https://例子.example/join?code=', suffix: '#register' },
  ]) {
    const env = templateFixture({ ...POOL, official: template });
    assert.equal(await location(await worker.fetch(req(undefined, 'US'), env)),
      new URL(`${template.prefix}Code_1${template.suffix}`).href);
  }
});

test('unknown breaks failure and recovery streaks without refreshing quarantine evidence', async () => {
  const env = templateFixture();
  configureMonitor(env);
  const originalNow = Date.now;
  let now = originalNow();
  Date.now = () => now;
  try {
    async function round(status) {
      now += 900_000;
      await withProvider(async (_url, options) => {
        const request = JSON.parse(options.body);
        return signedProvider({ timestamp: request.timestamp,
          results: request.targets.map(({ poolId, id }) => ({ poolId, id, status })) });
      }, () => worker.scheduled({}, env));
      return JSON.parse(env.LINKS.values.get('h:pool_1')).targets.first;
    }
    assert.equal((await round('unreachable')).failures, 1);
    assert.equal((await round('unknown')).failures, 0);
    assert.equal((await round('unreachable')).failures, 1);
    assert.equal((await round('unreachable')).failures, 2);
    assert.equal((await round('unknown')).failures, 0);
    await round('unreachable');
    await round('unreachable');
    assert.equal((await round('unreachable')).state, 'unhealthy');
    const oneSuccess = await round('reachable');
    assert.equal(oneSuccess.state, 'unhealthy');
    const inconclusive = await round('unknown');
    assert.deepEqual(inconclusive, { ...oneSuccess, failures: 0, successes: 0 });
    assert.equal((await round('reachable')).state, 'unhealthy');
    assert.equal((await round('reachable')).state, 'healthy');
  } finally {
    Date.now = originalNow;
  }
});

test('scheduler refuses untransportable provider secrets without calling provider', async () => {
  for (const secret of ['x'.repeat(31), 'x'.repeat(257), 'x'.repeat(31) + '中', 'x'.repeat(31) + ' ', 'x'.repeat(31) + '\x7f']) {
    const env = templateFixture();
    configureMonitor(env);
    env.PROBE_KEY = secret;
    let called = false;
    await withProvider(() => { called = true; throw new Error('must not call'); }, () => worker.scheduled({}, env));
    assert.equal(called, false);
    assert.equal(env.LINKS.values.has('h:pool_1'), false);
  }
});

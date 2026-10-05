import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from './worker.mjs';

const host = 'go.example.com';
const secret = '0123456789abcdef'.repeat(4);
function fixture(slugs = ['Legacy']) {
  const values = new Map([[`c:${host}`, JSON.stringify({ prefix: 'r' })]]);
  for (const slug of slugs) values.set(`l:${host}:${slug}`, JSON.stringify({
    default: `https://example.org/join/Code_${slug}?ref=MixedCase`,
    rules: [{ countries: ['CN'], url: `https://example.com/join/Code_${slug}` }],
  }));
  const calls = [];
  const env = { SELFTEST_KEY: secret, LINKS: {
    get: async key => values.get(key) ?? null,
    list: async options => {
      calls.push(options);
      return { keys: [...values.keys()].filter(key => key.startsWith(options.prefix)).map(name => ({ name })), list_complete: true };
    },
  } };
  return { env, values, calls };
}
function request(slug, country = 'US', headers = {}) {
  return { url: `https://${host}/r/${slug}`, method: 'GET', cf: { country }, headers: new Headers(headers) };
}
async function probe(f, slug, country = 'US', authenticated = false) {
  let headers = {};
  if (authenticated) {
    const seconds = Math.floor(Date.now() / 1000);
    const key = await crypto.subtle.importKey('raw', Buffer.from(secret, 'hex'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${host}|/r/${slug}|${seconds}|${country}`));
    headers = { 'X-Selftest': `${seconds}.${country}.${Buffer.from(mac).toString('hex')}` };
  }
  return worker.fetch(request(slug, country, headers), f.env);
}

test('canonical lowercase variants avoid list and preserve referral case and countries', async () => {
  const f = fixture(['offer']);
  for (const slug of ['offer', 'Offer', 'OFFER']) {
    assert.equal((await probe(f, slug)).headers.get('location'), 'https://example.org/join/Code_offer?ref=MixedCase');
    assert.equal((await probe(f, slug, 'CN')).headers.get('location'), 'https://example.com/join/Code_offer');
  }
  assert.equal(f.calls.length, 0);
});

test('legacy unique names resolve variants using only complete own-host name listings', async () => {
  const f = fixture();
  assert.equal((await probe(f, 'Legacy')).status, 302);
  assert.equal(f.calls.length, 0);
  for (const slug of ['legacy', 'LEGACY', 'lEgAcY']) assert.equal((await probe(f, slug)).status, 302);
  assert.deepEqual(f.calls, [{ prefix: `l:${host}:`, limit: 1000 }]);
});

test('legacy collisions preserve both exact targets and fail ambiguous fallback', async () => {
  const f = fixture(['OK', 'Ok']);
  assert.match((await probe(f, 'OK')).headers.get('location'), /Code_OK/);
  assert.match((await probe(f, 'Ok')).headers.get('location'), /Code_Ok/);
  assert.equal((await probe(f, 'ok')).status, 404);
  assert.equal((await probe(f, 'oK')).status, 404);
  const canonical = fixture(['OK', 'ok']);
  assert.match((await probe(canonical, 'OK')).headers.get('location'), /Code_OK/);
  assert.match((await probe(canonical, 'Ok')).headers.get('location'), /Code_ok/);
  assert.equal(canonical.calls.length, 0);
});

test('empty partial pages continue; malformed or foreign names are ignored', async () => {
  const f = fixture();
  f.env.LINKS.list = async options => {
    f.calls.push(options);
    return !options.cursor
      ? { keys: [], list_complete: false, cursor: 'next' }
      : { keys: [null, {}, { name: 'l:other.example.com:Legacy' }, { name: `l:${host}:bad/name` }, { name: `l:${host}:Legacy` }], list_complete: true };
  };
  assert.equal((await probe(f, 'legacy')).status, 302);
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[1].cursor, 'next');
});

test('cursor cycles, invalid envelopes, and list failures never use a partial unique match', async () => {
  for (const mode of ['cycle', 'missing-complete', 'missing-cursor', 'throw', 'oversized']) {
    const f = fixture();
    f.env.LINKS.list = async options => {
      f.calls.push(options);
      const keys = [{ name: `l:${host}:Legacy` }];
      if (mode === 'throw') throw new Error('sensitive provider detail');
      if (mode === 'missing-complete') return { keys };
      if (mode === 'missing-cursor') return { keys, list_complete: false };
      if (mode === 'oversized') return { keys: Array(1001).fill(keys[0]), list_complete: true };
      return { keys, list_complete: false, cursor: f.calls.length % 2 ? 'a' : 'b' };
    };
    const result = await probe(f, 'legacy');
    assert.equal(result.status, 404, mode);
    assert.equal(await result.text(), 'Not Found');
    assert.equal((await probe(f, 'Legacy')).status, 302, mode);
  }
});

test('partial scans stop at the page bound and exact matching needs no list support', async () => {
  const f = fixture();
  f.env.LINKS.list = async options => {
    f.calls.push(options);
    return { keys: [{ name: `l:${host}:Legacy` }], list_complete: false, cursor: `page-${f.calls.length}` };
  };
  assert.equal((await probe(f, 'legacy')).status, 404);
  assert.equal(f.calls.length, 20);
  delete f.env.LINKS.list;
  assert.equal((await probe(f, 'Legacy')).status, 302);
  assert.equal((await probe(f, 'legacy')).status, 404);
});

test('concurrent legacy misses share a scan', async () => {
  const f = fixture();
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const list = f.env.LINKS.list;
  f.env.LINKS.list = async options => { await gate; return list(options); };
  const pending = ['legacy', 'LEGACY', 'lEgAcY'].map(slug => probe(f, slug));
  await new Promise(resolve => setTimeout(resolve, 0));
  release();
  assert.deepEqual((await Promise.all(pending)).map(result => result.status), [302, 302, 302]);
  assert.equal(f.calls.length, 1);
});

test('authenticated probes bypass the legacy index while honoring scan budget', async () => {
  const f = fixture();
  assert.equal((await probe(f, 'legacy')).status, 302);
  f.values.set(`l:${host}:LEGACY`, f.values.get(`l:${host}:Legacy`));
  assert.equal((await probe(f, 'legacy', 'CN', true)).status, 404);
  for (let i = 0; i < 8; i++) await probe(f, 'missing', 'US', true);
  assert.equal(f.calls.length, 6);
  assert.equal((await probe(f, 'Legacy', 'CN', true)).status, 302);
});

test('hourly list-call budget stops scans midway without accepting incomplete data', async () => {
  const f = fixture();
  f.env.LINKS.list = async options => {
    f.calls.push(options);
    return { keys: [{ name: `l:${host}:Legacy` }], list_complete: false, cursor: `page-${f.calls.length}` };
  };
  for (let i = 0; i < 4; i++) assert.equal((await probe(f, 'legacy')).status, 404);
  assert.equal(f.calls.length, 24);
  assert.equal((await probe(f, 'Legacy')).status, 302);
});

test('expired indexes refresh and hourly scan budgets reset', async () => {
  const f = fixture();
  const original = Date.now;
  let now = original();
  Date.now = () => now;
  try {
    assert.equal((await probe(f, 'legacy')).status, 302);
    f.values.set(`l:${host}:LEGACY`, f.values.get(`l:${host}:Legacy`));
    now += 10 * 60_000;
    assert.equal((await probe(f, 'legacy')).status, 404);
    assert.equal(f.calls.length, 2);
    for (let i = 0; i < 8; i++) await probe(f, 'absent', 'US', true);
    assert.equal(f.calls.length, 6);
    now += 60 * 60_000;
    await probe(f, 'absent');
    assert.equal(f.calls.length, 7);
  } finally { Date.now = original; }
});

test('case fallback does not change the directory or broaden invalid path syntax', async () => {
  const f = fixture();
  for (const path of ['/R/legacy', '/r/lega%63y', '/r/../legacy', '/r/legacy/extra']) {
    assert.equal((await worker.fetch({ ...request('legacy'), url: `https://${host}${path}` }, f.env)).status, 404);
  }
  assert.equal(f.calls.length, 0);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from './worker.mjs';

const HOST = 'go.example.com';
const KEY = '0123456789abcdef'.repeat(4);
const POOL = {
  version: 1,
  official: { prefix: 'https://example.org/join?code=', suffix: '' },
  candidates: [{ id: 'first', prefix: 'https://example.com/join/', suffix: '', enabled: true }],
  revision: '2026-01-01T00:00:00Z',
};

function fixture(values = {}) {
  const store = new Map(Object.entries({
    [`c:${HOST}`]: { prefix: 'r' },
    [`l:${HOST}:plain`]: { default: 'https://example.org/plain', rules: [] },
    [`l:${HOST}:pooled`]: { poolId: 'pool_1', code: 'Code_1', updated: '2026-01-01T00:00:00Z' },
    'p:pool_1': POOL,
    ...values,
  }).map(([key, value]) => [key, typeof value === 'string' ? value : JSON.stringify(value)]));
  const env = {
    SELFTEST_KEY: KEY,
    fail: false,
    LINKS: {
      get: async key => {
        if (env.fail) throw new Error('private KV failure');
        return store.get(key) ?? null;
      },
    },
  };
  return { env, store };
}

function req(slug, country = 'US', method = 'GET') {
  return { url: `https://${HOST}/r/${slug}`, method, cf: { country }, headers: new Headers() };
}

async function expect503(result, reason, head = false) {
  assert.equal(result.status, 503);
  assert.equal(result.headers.get('x-reason'), reason);
  assert.equal(result.headers.get('location'), null);
  assert.equal(result.headers.get('cache-control'), 'private, no-store');
  if (head) assert.equal(result.body, null);
  else assert.equal(await result.text(), 'Service Unavailable');
}

test('a platform address missing from KV answers 503 with pool_missing', async () => {
  const { env, store } = fixture();
  store.delete('p:pool_1');
  for (const country of ['US', 'CN']) {
    await expect503(await worker.fetch(req('pooled', country), env), 'pool_missing');
    await expect503(await worker.fetch(req('pooled', country, 'HEAD'), env), 'pool_missing', true);
  }
});

test('mainland visitors with every backup address down get no_candidate', async () => {
  const now = Math.floor(Date.now() / 1000);
  const bad = { state: 'unhealthy', failures: 3, successes: 0, checkedAt: now };
  const { env } = fixture({ 'h:pool_1': { revision: POOL.revision, checkedAt: now, targets: { first: bad } } });
  await expect503(await worker.fetch(req('pooled', 'CN'), env), 'no_candidate');
  await expect503(await worker.fetch(req('pooled', 'CN', 'HEAD'), env), 'no_candidate', true);
  const other = await worker.fetch(req('pooled', 'US'), env);
  assert.equal(other.status, 302);
  assert.equal(other.headers.get('x-reason'), null);
});

test('unexpected failures caught by the fallback answer 503 with internal', async () => {
  const corrupt = fixture({ [`l:${HOST}:plain`]: '{bad' });
  await expect503(await worker.fetch(req('plain'), corrupt.env), 'internal');
  const badPool = fixture({ 'p:pool_1': { ...POOL, candidates: [] } });
  await expect503(await worker.fetch(req('pooled'), badPool.env), 'internal');
  const failing = fixture();
  failing.env.fail = true;
  await expect503(await worker.fetch(req('plain'), failing.env), 'internal');
  await expect503(await worker.fetch(req('plain', 'US', 'HEAD'), failing.env), 'internal', true);
});

test('every other response carries no reason header', async () => {
  const { env } = fixture();
  const responses = [
    await worker.fetch(req('plain'), env),
    await worker.fetch(req('pooled', 'CN'), env),
    await worker.fetch(req('missing'), env),
    await worker.fetch(req('a/b'), env),
    await worker.fetch(req('plain', 'US', 'POST'), env),
    await worker.fetch(req('plain'), {}),
  ];
  const limited = fixture();
  limited.env.CLICK_RATE_LIMITER = { limit: async () => ({ success: false }) };
  responses.push(await worker.fetch({ ...req('plain'), headers: new Headers({ 'CF-Connecting-IP': '192.0.2.1' }) },
    limited.env));
  assert.deepEqual(responses.map(result => result.status), [302, 302, 404, 404, 405, 503, 429]);
  for (const result of responses) assert.equal(result.headers.get('x-reason'), null);
});

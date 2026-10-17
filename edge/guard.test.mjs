import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from './worker.mjs';

const HOST = 'go.example.com';
const SECRET = '0123456789abcdef'.repeat(4);
const DEST = 'https://example.org/target';

function fixture(slugs = ['offer']) {
  const values = new Map([[`c:${HOST}`, JSON.stringify({ prefix: 'r' })]]);
  for (const slug of slugs) values.set(`l:${HOST}:${slug}`, JSON.stringify({ default: DEST, rules: [] }));
  const reads = [];
  const points = [];
  const env = {
    SELFTEST_KEY: SECRET,
    LINKS: {
      get: async key => { reads.push(key); return values.get(key) ?? null; },
      list: async ({ prefix }) => ({
        keys: [...values.keys()].filter(key => key.startsWith(prefix)).map(name => ({ name })),
        list_complete: true,
      }),
    },
    CLICK_EVENTS: { writeDataPoint: point => { points.push(point); } },
  };
  return { env, values, reads, points };
}

function req({ slug = 'offer', ip = '192.0.2.1', ua = 'Browser/1', method = 'GET',
  query = '', headers = {} } = {}) {
  return {
    url: `https://${HOST}/r/${slug}${query}`,
    method,
    headers: new Headers({ 'CF-Connecting-IP': ip, 'User-Agent': ua, ...headers }),
    cf: { country: 'US' },
  };
}

async function signed(slug = 'offer') {
  const seconds = Math.floor(Date.now() / 1000);
  const key = await crypto.subtle.importKey('raw', Buffer.from(SECRET, 'hex'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = Buffer.from(await crypto.subtle.sign('HMAC', key,
    new TextEncoder().encode(`${HOST}|/r/${slug}|${seconds}|US`))).toString('hex');
  return `${seconds}.US.${signature}`;
}

test('100 per ten seconds uses opaque per-IP/link keys, folds case and ignores query', async () => {
  const f = fixture();
  const buckets = new Map();
  const keys = [];
  let now = Date.now();
  const original = Date.now;
  Date.now = () => now;
  f.env.CLICK_RATE_LIMITER = { limit: async ({ key }) => {
    keys.push(key);
    const bucket = buckets.get(key);
    if (!bucket || now - bucket.start >= 10_000) {
      buckets.set(key, { start: now, count: 1 });
      return { success: true };
    }
    bucket.count++;
    return { success: bucket.count <= 100 };
  } };
  try {
    for (let i = 0; i < 100; i++) {
      const result = await worker.fetch(req({ slug: i % 2 ? 'OFFER' : 'offer',
        query: `?noise=${i}`, method: i === 0 ? 'HEAD' : 'GET' }), f.env);
      assert.equal(result.status, 302);
      assert.equal(result.headers.get('location'), DEST);
    }
    assert.equal((await worker.fetch(req(), f.env)).status, 429);
    assert.equal(f.points.length, 99);
    assert.equal(new Set(keys).size, 1);
    assert.match(keys[0], /^[0-9a-f]{64}$/);
    assert.equal(keys[0].includes('192.0.2.1'), false);
    assert.equal((await worker.fetch(req({ ip: '192.0.2.2' }), f.env)).status, 302);
    now += 10_000;
    assert.equal((await worker.fetch(req(), f.env)).status, 302);
  } finally {
    Date.now = original;
  }
});

test('different links have separate buckets and only valid selftests bypass the limiter', async () => {
  const f = fixture(['offer', 'other']);
  const keys = [];
  f.env.CLICK_RATE_LIMITER = { limit: async ({ key }) => { keys.push(key); return { success: false }; } };
  assert.equal((await worker.fetch(req(), f.env)).status, 429);
  assert.equal((await worker.fetch(req({ slug: 'other' }), f.env)).status, 429);
  assert.notEqual(keys[0], keys[1]);
  const valid = await signed();
  assert.equal((await worker.fetch(req({ headers: { 'X-Selftest': valid } }), f.env)).status, 302);
  assert.equal(keys.length, 2);
  assert.equal(f.points.length, 0);
  const forged = `${Math.floor(Date.now() / 1000)}.US.${'0'.repeat(64)}`;
  assert.equal((await worker.fetch(req({ headers: { 'X-Selftest': forged } }), f.env)).status, 429);
  assert.equal(keys.length, 3);
});

test('disabled, absent, malformed and failing limiters preserve redirects', async () => {
  for (const limiter of [undefined, {}, { limit: () => { throw Error('fail'); } },
    { limit: async () => { throw Error('fail'); } },
    { limit: () => new Promise(() => {}) }]) {
    const f = fixture();
    f.env.CLICK_RATE_LIMITER = limiter;
    const result = await worker.fetch(req(), f.env);
    assert.equal(result.status, 302);
    assert.equal(result.headers.get('location'), DEST);
  }
  const f = fixture();
  f.env.CLICK_GUARD_DISABLED = '1';
  f.env.CLICK_RATE_LIMITER = { limit: () => { throw Error('must not run'); } };
  assert.equal((await worker.fetch(req(), f.env)).status, 302);
});

test('missing or malformed IP does not create a shared limiter identity', async () => {
  const f = fixture();
  let calls = 0;
  f.env.CLICK_RATE_LIMITER = { limit: () => { calls++; return { success: false }; } };
  for (const ip of ['', '192.0.2.999', '192.0.2.1, 198.51.100.1', 'example.com', 'fe80::1%eth0']) {
    assert.equal((await worker.fetch(req({ ip }), f.env)).status, 302);
  }
  assert.equal(calls, 0);
  assert.equal((await worker.fetch(req({ ip: '2001:db8::1' }), f.env)).status, 429);
  assert.equal(calls, 1);
});

test('a missing selftest secret uses a private runtime key for limiter identities', async () => {
  const f = fixture();
  delete f.env.SELFTEST_KEY;
  const keys = [];
  f.env.CLICK_RATE_LIMITER = { limit: ({ key }) => { keys.push(key); return { success: true }; } };
  assert.equal((await worker.fetch(req(), f.env)).status, 302);
  assert.equal((await worker.fetch(req(), f.env)).status, 302);
  assert.equal(keys.length, 2);
  assert.equal(keys[0], keys[1]);
  assert.match(keys[0], /^[0-9a-f]{64}$/);
});

test('dedup counts first and repeat for canonical link/IP/UA, then expires without sliding', async () => {
  const f = fixture();
  const isolated = (await import('./worker.mjs?dedup-expiry')).default;
  const visit = options => req({ ip: '192.0.2.33', ...options });
  let now = Date.now();
  const original = Date.now;
  Date.now = () => now;
  try {
    assert.equal((await isolated.fetch(visit({ slug: 'OFFER' }), f.env)).status, 302);
    now += 29 * 60_000;
    assert.equal((await isolated.fetch(visit({ query: '?x=2' }), f.env)).status, 302);
    now += 60_001;
    assert.equal((await isolated.fetch(visit(), f.env)).status, 302);
    assert.deepEqual(f.points.map(point => point.doubles), [[1, 1, 0], [1, 0, 1], [1, 1, 0]]);
    assert.deepEqual(f.points.map(point => point.blobs.slice(0, 4)),
      Array(3).fill(['v1', HOST, 'r', 'offer']));
    assert.equal((await isolated.fetch(req({ ip: '192.0.2.2' }), f.env)).status, 302);
    assert.deepEqual(f.points.at(-1).doubles, [1, 1, 0]);
  } finally { Date.now = original; }
});

test('missing signals and preview/prefetch do not pollute dedup; HEAD never emits', async () => {
  const f = fixture();
  await worker.fetch(req({ ip: '' }), f.env);
  await worker.fetch(req({ ua: '' }), f.env);
  await worker.fetch(req({ ip: '192.0.2.34', headers: { 'User-Agent': 'Slackbot/1' } }), f.env);
  await worker.fetch(req({ ip: '192.0.2.34', headers: { Purpose: 'prefetch' } }), f.env);
  await worker.fetch(req({ ip: '192.0.2.34', method: 'HEAD' }), f.env);
  await worker.fetch(req({ ip: '192.0.2.34' }), f.env);
  assert.deepEqual(f.points.map(point => point.doubles),
    [[1, 0, 0], [1, 0, 0], [1, 0, 0], [1, 0, 0], [1, 1, 0]]);
});

test('dedup memory saturation marks new identities uncovered while preserving known repeats', async () => {
  const f = fixture();
  const isolated = (await import('./worker.mjs?dedup-saturation')).default;
  const original = Date.now;
  Date.now = () => original() + 31 * 60_000;
  try {
    for (let i = 0; i < 4096; i++) await isolated.fetch(req({ ua: `Browser/${i}` }), f.env);
    await isolated.fetch(req({ ua: 'Browser/overflow' }), f.env);
    await isolated.fetch(req({ ua: 'Browser/0' }), f.env);
    assert.deepEqual(f.points.at(-2).doubles, [1, 0, 0]);
    assert.deepEqual(f.points.at(-1).doubles, [1, 0, 1]);
  } finally { Date.now = original; }
});

test('missing KV names use short negative cache, expire and authenticated probes bypass it', async () => {
  const f = fixture([]);
  let now = Date.now();
  const original = Date.now;
  Date.now = () => now;
  try {
    assert.equal((await worker.fetch(req(), f.env)).status, 404);
    const count = f.reads.length;
    assert.equal((await worker.fetch(req(), f.env)).status, 404);
    assert.equal(f.reads.length, count);
    f.values.set(`l:${HOST}:offer`, JSON.stringify({ default: DEST, rules: [] }));
    assert.equal((await worker.fetch(req(), f.env)).status, 404);
    assert.equal((await worker.fetch(req({ headers: { 'X-Selftest': await signed() } }), f.env)).status, 302);
    now += 3_001;
    assert.equal((await worker.fetch(req(), f.env)).status, 302);
  } finally { Date.now = original; }
});

test('concurrent misses share one KV read and failed reads are retried', async () => {
  const f = fixture([]);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const original = f.env.LINKS.get;
  let attempts = 0;
  f.env.LINKS.get = async key => {
    if (key === `l:${HOST}:offer`) { attempts++; await gate; }
    return original(key);
  };
  const requests = Array.from({ length: 5 }, () => worker.fetch(req(), f.env));
  await new Promise(resolve => setTimeout(resolve, 0));
  release();
  assert.deepEqual((await Promise.all(requests)).map(result => result.status), [404, 404, 404, 404, 404]);
  assert.equal(attempts, 1);

  const broken = fixture([]);
  let failures = 0;
  broken.env.LINKS.get = async key => {
    if (key === `l:${HOST}:offer` && failures++ === 0) throw Error('KV unavailable');
    return broken.values.get(key) ?? null;
  };
  assert.equal((await worker.fetch(req(), broken.env)).status, 503);
  assert.equal((await worker.fetch(req(), broken.env)).status, 404);
  assert.equal(failures, 2);
});

test('random missing names do not evict hot positive KV records', async () => {
  const f = fixture();
  assert.equal((await worker.fetch(req(), f.env)).status, 302);
  for (let i = 0; i < 150; i++) {
    assert.equal((await worker.fetch(req({ slug: `missing${i}` }), f.env)).status, 404);
  }
  assert.equal((await worker.fetch(req(), f.env)).status, 302);
  assert.equal(f.reads.filter(key => key === `c:${HOST}`).length, 1);
  assert.equal(f.reads.filter(key => key === `l:${HOST}:offer`).length, 1);
});

test('execution context keeps slow analytics outside the redirect path', async () => {
  const f = fixture();
  const isolated = (await import('./worker.mjs?ctx-waituntil')).default;
  let release;
  const write = new Promise(resolve => { release = resolve; });
  f.env.CLICK_EVENTS.writeDataPoint = point => { f.points.push(point); return write; };
  const pending = [];
  const ctx = { waitUntil: promise => pending.push(promise) };
  let timer;
  try {
    const result = await Promise.race([
      isolated.fetch(req({ ip: '192.0.2.80' }), f.env, ctx),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('redirect blocked by analytics')), 100); }),
    ]);
    assert.equal(result.status, 302);
    assert.equal(result.headers.get('location'), DEST);
    assert.equal(pending.length, 1);
    release();
    await Promise.all(pending);
    assert.deepEqual(f.points[0].doubles, [1, 1, 0]);
  } finally {
    clearTimeout(timer);
    release();
  }
});

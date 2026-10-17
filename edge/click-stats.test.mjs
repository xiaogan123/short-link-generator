import assert from 'node:assert/strict';
import { setImmediate as delay } from 'node:timers/promises';
import { test } from 'node:test';
import worker from './worker.mjs';

const HOST = 'go.example.com';
const PREFIX = 'r';
const KEY = '0123456789abcdef'.repeat(4);
const DEFAULT = 'https://example.org/join/Private_Code?secret=destination';
const CN = 'https://example.com/join/Private_CN_Code';
const LINK = { default: DEFAULT, rules: [{ countries: ['CN'], url: CN }] };

class MockAnalytics {
  constructor(write) {
    this.points = [];
    this.write = write;
  }

  writeDataPoint(point) {
    this.points.push(point);
    return this.write?.(point);
  }
}

function fixture(slugs = { Offer_1: LINK }, analytics = new MockAnalytics()) {
  const values = new Map([[`c:${HOST}`, JSON.stringify({ prefix: PREFIX })]]);
  for (const [slug, link] of Object.entries(slugs)) {
    values.set(`l:${HOST}:${slug}`, JSON.stringify(link));
  }
  return {
    analytics,
    env: {
      SELFTEST_KEY: KEY,
      CLICK_EVENTS: analytics,
      LINKS: {
        get: async key => values.get(key) ?? null,
        list: async ({ prefix }) => ({
          keys: [...values.keys()].filter(key => key.startsWith(prefix)).map(name => ({ name })),
          list_complete: true,
        }),
      },
    },
  };
}

function request({
  slug = 'Offer_1', method = 'GET', headers = {}, country = 'US', botManagement,
  verifiedBotCategory,
  query = '?private_query=do-not-store',
} = {}) {
  return {
    url: `https://${HOST}/${PREFIX}/${slug}${query}`,
    method,
    headers: new Headers(headers),
    cf: {
      country,
      colo: 'SIN',
      ...(botManagement === undefined ? {} : { botManagement }),
      ...(verifiedBotCategory === undefined ? {} : { verifiedBotCategory }),
    },
  };
}

async function signedSelftest(slug = 'Offer_1', country = 'CN') {
  const seconds = Math.floor(Date.now() / 1000);
  const key = await crypto.subtle.importKey(
    'raw', Buffer.from(KEY, 'hex'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const bytes = new TextEncoder().encode(`${HOST}|/${PREFIX}/${slug}|${seconds}|${country}`);
  const signature = Buffer.from(await crypto.subtle.sign('HMAC', key, bytes)).toString('hex');
  return `${seconds}.${country}.${signature}`;
}

function classification(point) {
  return point.blobs.slice(4);
}

test('successful browser navigation writes the fixed privacy-bounded schema without network activity', async () => {
  const { env, analytics } = fixture();
  const originalFetch = globalThis.fetch;
  let networkCalls = 0;
  globalThis.fetch = () => {
    networkCalls++;
    throw new Error('analytics must not fetch');
  };
  try {
    const result = await worker.fetch(request({ headers: {
      'User-Agent': 'Mozilla/5.0 Sensitive-UA Chrome/123.0.0.0 Safari/537.36',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-User': '?1',
      Referer: 'https://private.example/secret-referrer',
      'CF-Connecting-IP': '192.0.2.123',
    } }), env);
    assert.equal(result.status, 302);
    assert.equal(result.headers.get('location'), DEFAULT);
    assert.equal(await result.text(), '');
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(networkCalls, 0);
  assert.deepEqual(analytics.points, [{
    indexes: [HOST],
    blobs: ['v1', HOST, PREFIX, 'Offer_1', 'likely_human', 'click', 'browser_navigation'],
    doubles: [1, 1, 0],
  }]);
  const serialized = JSON.stringify(analytics.points[0]);
  for (const forbidden of [
    'Sensitive-UA', 'private.example', '192.0.2.123', 'private_query',
    'Private_Code', 'destination', 'secret-referrer',
  ]) assert.equal(serialized.includes(forbidden), false, forbidden);
});

test('preview, prefetch, automation, bot and uncertain requests keep distinct risk labels', async () => {
  const { env, analytics } = fixture();
  const cases = [
    {
      headers: { 'User-Agent': 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' },
      expected: ['likely_bot', 'preview', 'ua_preview'],
    },
    {
      headers: {
        'User-Agent': 'Mozilla/5.0 Chrome/123.0.0.0 Safari/537.36',
        Purpose: 'prefetch',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-User': '?1',
      },
      expected: ['unknown', 'prefetch', 'prefetch_header'],
    },
    { headers: { 'User-Agent': 'curl/8.7.1' }, expected: ['likely_bot', 'click', 'ua_automation'] },
    { headers: { 'User-Agent': 'Googlebot/2.1' }, expected: ['likely_bot', 'click', 'ua_bot'] },
    { headers: {}, expected: ['unknown', 'click', 'missing_user_agent'] },
    { headers: { 'User-Agent': 'ExampleClient/1.0' }, expected: ['unknown', 'click', 'insufficient_signals'] },
  ];
  for (const item of cases) {
    assert.equal((await worker.fetch(request({ headers: item.headers }), env)).status, 302);
  }
  assert.deepEqual(analytics.points.map(classification), cases.map(item => item.expected));
});

test('Chrome prerender stays unknown prefetch even with a high Cloudflare bot score', async () => {
  const { env, analytics } = fixture();
  const result = await worker.fetch(request({
    headers: {
      'User-Agent': 'Mozilla/5.0 Chrome/123.0.0.0 Safari/537.36',
      'Sec-Purpose': 'prefetch;prerender',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-User': '?1',
    },
    botManagement: { score: 99 },
  }), env);
  assert.equal(result.status, 302);
  assert.deepEqual(classification(analytics.points[0]), ['unknown', 'prefetch', 'prefetch_header']);
});

test('optional Cloudflare verified-bot and valid score signals refine classification', async () => {
  const { env, analytics } = fixture();
  const cases = [
    {
      botManagement: { verifiedBot: true, score: 99 },
      expected: ['likely_bot', 'click', 'cf_verified_bot'],
    },
    {
      verifiedBotCategory: 'Search Engine Crawler',
      headers: {
        'User-Agent': 'Mozilla/5.0 Chrome/123.0.0.0 Safari/537.36',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-User': '?1',
      },
      expected: ['likely_bot', 'click', 'cf_verified_bot_category'],
    },
    { botManagement: { score: 10 }, expected: ['likely_bot', 'click', 'cf_score_low'] },
    { botManagement: { score: 99 }, expected: ['likely_human', 'click', 'cf_score_high'] },
    { botManagement: { score: 0 }, expected: ['unknown', 'click', 'insufficient_signals'] },
    { verifiedBotCategory: '   ', expected: ['unknown', 'click', 'insufficient_signals'] },
    { expected: ['unknown', 'click', 'insufficient_signals'] },
  ];
  for (const item of cases) {
    const result = await worker.fetch(request({
      headers: item.headers ?? { 'User-Agent': 'ExampleClient/1.0' },
      botManagement: item.botManagement,
      verifiedBotCategory: item.verifiedBotCategory,
    }), env);
    assert.equal(result.status, 302);
  }
  assert.deepEqual(analytics.points.map(classification), cases.map(item => item.expected));
});

test('only ordinary successful GET redirects emit; authenticated selftests and failures do not', async () => {
  const { env, analytics } = fixture();
  assert.equal((await worker.fetch(request({ method: 'HEAD' }), env)).status, 302);

  const valid = await signedSelftest();
  const probe = await worker.fetch(request({ headers: { 'X-Selftest': valid } }), env);
  assert.equal(probe.status, 302);
  assert.equal(probe.headers.get('location'), CN);

  const invalid = `${Math.floor(Date.now() / 1000)}.CN.${'0'.repeat(64)}`;
  const ordinary = await worker.fetch(request({ headers: { 'X-Selftest': invalid } }), env);
  assert.equal(ordinary.status, 302);
  assert.equal(ordinary.headers.get('location'), DEFAULT);

  assert.equal((await worker.fetch(request({ slug: 'missing' }), env)).status, 404);
  assert.equal((await worker.fetch(request({ method: 'POST' }), env)).status, 405);
  assert.equal((await worker.fetch(request(), { CLICK_EVENTS: analytics })).status, 503);

  const corrupt = fixture({}, analytics);
  corrupt.env.LINKS.get = async () => '{broken';
  assert.equal((await worker.fetch(request(), corrupt.env)).status, 503);
  assert.equal(analytics.points.length, 1);
  assert.deepEqual(classification(analytics.points[0]), ['unknown', 'click', 'missing_user_agent']);
});

test('analytics sync throws and rejected thenables cannot change a redirect', async () => {
  const sync = fixture({ Offer_1: LINK }, new MockAnalytics(() => {
    throw new Error('analytics unavailable');
  }));
  const first = await worker.fetch(request(), sync.env);
  assert.equal(first.status, 302);
  assert.equal(first.headers.get('location'), DEFAULT);

  const rejected = fixture({ Offer_1: LINK }, new MockAnalytics(() => ({
    then(_resolve, reject) {
      reject(new Error('analytics rejected'));
    },
  })));
  const second = await worker.fetch(request(), rejected.env);
  assert.equal(second.status, 302);
  assert.equal(second.headers.get('location'), DEFAULT);
  await delay();
});

test('actual matched case is recorded across lowercase aliases and unique legacy fallback', async () => {
  const lower = fixture({ ok: LINK });
  assert.equal((await worker.fetch(request({ slug: 'oK' }), lower.env)).status, 302);
  assert.equal(lower.analytics.points[0].blobs[3], 'ok');

  const legacy = fixture({ OK: LINK });
  assert.equal((await worker.fetch(request({ slug: 'oK' }), legacy.env)).status, 302);
  assert.equal(legacy.analytics.points[0].blobs[3], 'OK');

  const distinct = fixture({ OK: LINK, ok: { ...LINK, default: 'https://example.org/lower' } });
  assert.equal((await worker.fetch(request({ slug: 'OK' }), distinct.env)).headers.get('location'), DEFAULT);
  assert.equal(distinct.analytics.points[0].blobs[3], 'OK');
});

test('an absent analytics binding preserves the existing redirect behavior', async () => {
  const { env } = fixture();
  delete env.CLICK_EVENTS;
  const result = await worker.fetch(request({ country: 'CN' }), env);
  assert.equal(result.status, 302);
  assert.equal(result.headers.get('location'), CN);
  assert.equal(await result.text(), '');
});

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import worker from './worker.mjs';

const HOST = 'go.example.com';
const KEY = '0123456789abcdef'.repeat(4);
const DEFAULT = 'https://example.org/default';
const CN = 'https://example.com/china';

function link(name) {
  return JSON.stringify({ default: `${DEFAULT}/${name}`, rules: [{ countries: ['CN'], url: `${CN}/${name}` }] });
}

function fixture(slugs = ['Offer_1']) {
  const values = new Map([[`c:${HOST}`, JSON.stringify({ prefix: 'r' })]]);
  for (const slug of slugs) values.set(`l:${HOST}:${slug}`, link(slug));
  const reads = [];
  const points = [];
  const env = {
    SELFTEST_KEY: KEY,
    LINKS: {
      get: async key => { reads.push(key); return values.get(key) ?? null; },
      list: async ({ prefix }) => ({
        keys: [...values.keys()].filter(key => key.startsWith(prefix)).map(name => ({ name })),
        list_complete: true,
      }),
    },
    CLICK_EVENTS: { writeDataPoint: point => { points.push(point); } },
  };
  return { env, reads, points };
}

function req(path, { country = 'US', method = 'GET', headers = {} } = {}) {
  return {
    url: `https://${HOST}${path}`,
    method,
    cf: { country },
    headers: new Headers({ 'CF-Connecting-IP': '192.0.2.1', 'User-Agent': 'Browser/1', ...headers }),
  };
}

async function signed(path, country = 'CN') {
  const seconds = Math.floor(Date.now() / 1000);
  const key = await crypto.subtle.importKey('raw', Buffer.from(KEY, 'hex'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key,
    new TextEncoder().encode(`${HOST}|${path}|${seconds}|${country}`));
  return `${seconds}.${country}.${Buffer.from(mac).toString('hex')}`;
}

const ENDINGS = [
  '/', '.', ',', ';', ':', '!', ')', ']', "'", '%22', '%7D', '%3F',
  '...', '.)', '!!', '),', '%2E', '%2e%2c', '%29',
  '%E3%80%82', '%e3%80%82', '%EF%BC%8C', '%EF%BC%9B', '%EF%BC%9A', '%EF%BC%81', '%EF%BC%9F',
  '%EF%BC%89', '%E3%80%91', '%E3%80%8B', '%E3%80%8D', '%E3%80%8F', '%E2%80%9D', '%E2%80%99',
  '%E3%80%81', '%E3%80%82%E2%80%9D', '%EF%BC%89%E3%80%82',
  '/.', '/。', '/%E3%80%82', '/).', './', ')./','%E3%80%82/', '/.%E3%80%82',
];

test('a trailing slash or trailing punctuation still reaches the right link', async () => {
  for (const ending of ENDINGS) {
    const f = fixture();
    const result = await worker.fetch(req(`/r/Offer_1${ending}`), f.env);
    assert.equal(result.status, 302, ending);
    assert.equal(result.headers.get('location'), `${DEFAULT}/Offer_1`, ending);
    assert.equal(f.points.length, 1, ending);
    assert.equal(f.points[0].blobs[3], 'Offer_1', ending);
    const cn = await worker.fetch(req(`/r/Offer_1${ending}`, { country: 'CN', method: 'HEAD' }), f.env);
    assert.equal(cn.status, 302, ending);
    assert.equal(cn.headers.get('location'), `${CN}/Offer_1`, ending);
  }
});

// Written out here on purpose instead of being derived from the Worker's own
// list, so a mark dropped or mistyped there turns this test red.
const ASCII_MARKS = ['.', ',', ';', ':', '!', '?', ')', ']', '}', "'", '"'];
const WIDE_MARKS = ['。', '，', '；', '：', '！', '？', '）', '】', '》', '」', '』', '”', '’', '、'];

function encoded(mark) {
  return Array.from(new TextEncoder().encode(mark),
    byte => `%${byte.toString(16).toUpperCase().padStart(2, '0')}`).join('');
}

test('every listed mark is dropped, literal and percent-encoded in either case', async () => {
  assert.equal(ASCII_MARKS.length + WIDE_MARKS.length, 25);
  const f = fixture();
  for (const mark of [...ASCII_MARKS, ...WIDE_MARKS]) {
    const forms = [encoded(mark), encoded(mark).toLowerCase()];
    // A literal "?" starts the query string, which was always ignored.
    forms.push(mark === '?' ? '?' : mark);
    for (const form of forms) {
      for (const ending of [form, `/${form}`, `${form}/`, `${form}${form}`]) {
        const result = await worker.fetch(req(`/r/Offer_1${ending}`, { method: 'HEAD' }), f.env);
        assert.equal(result.status, 302, ending);
        assert.equal(result.headers.get('location'), `${DEFAULT}/Offer_1`, ending);
      }
    }
  }
  const query = await worker.fetch(req('/r/Offer_1.?from=chat', { method: 'HEAD' }), f.env);
  assert.equal(query.headers.get('location'), `${DEFAULT}/Offer_1`);
});

test('the deployed script stays plain ASCII', async () => {
  // The desktop app compares a hash of the bytes Cloudflare hands back with
  // the bundled source. ASCII bytes cannot be re-encoded on the way.
  const source = await readFile(new URL('./worker.mjs', import.meta.url));
  const at = source.findIndex(byte => byte > 0x7e || (byte < 0x20 && byte !== 0x0a));
  assert.equal(at, -1, at < 0 ? '' : `non-ASCII byte near line ${
    source.subarray(0, at).toString('latin1').split('\n').length}`);
});

test('names ending with a hyphen or underscore keep those characters', async () => {
  const f = fixture(['end', 'end-', 'end_', 'a-_']);
  for (const [path, expected] of [
    ['/r/end-', 'end-'], ['/r/end-/', 'end-'], ['/r/end-.', 'end-'], ['/r/end-%E3%80%82', 'end-'],
    ['/r/end_', 'end_'], ['/r/end_)', 'end_'], ['/r/end_/.', 'end_'],
    ['/r/a-_', 'a-_'], ['/r/a-_!', 'a-_'], ['/r/end.', 'end'],
  ]) {
    const result = await worker.fetch(req(path), f.env);
    assert.equal(result.status, 302, path);
    assert.equal(result.headers.get('location'), `${DEFAULT}/${expected}`, path);
  }
});

test('normalizing never turns an unrelated 404 path into a hit', async () => {
  const f = fixture(['Offer_1', 'r']);
  const invalid = [
    '/r/Offer_1//', '/r/Offer_1/extra', '/r/Offer_1/extra.', '/r/Offer_1/..', '/r/Offer_1/%2e%2e',
    '/r/Offer_1/../', '/r/Offer_1/%2E%2E/', '/r/Offer_1/...', '/r/.', '/r/)', '/r/', '/r//', '/r/。',
    '/r/%E3%80%82', '/r/Offer_1%2F', '/r/Offer_1%20', '/r/Offer_1%E3%80', '/r/Offer_1.ext',
    '/r/Offer_1-.x', '/R/Offer_1.', '/r/../r/Offer_1.', '/r/%2e%2e/r/Offer_1/', '/r.', '/r/',
    '/r/Offer_1%2D', '/r/Offer_1%5F', '/r/Offer_1%41', '/r/Offer_1x.', '/r/Offer_1@', '/r/Offer_1*',
    '/r/Offer_1(', '/r/Offer_1[', '/r/Offer_1%EF%BC%88', '/r/Offer_1/%2F', '/x/Offer_1.',
    `/r/Offer_1${'%E3%80%82'.repeat(14)}`, `/r/${'a'.repeat(33)}.`,
  ];
  for (const path of invalid) {
    const result = await worker.fetch(req(path), f.env);
    assert.equal(result.status, 404, path);
    assert.equal(await result.text(), 'Not Found', path);
    assert.equal(result.headers.get('x-reason'), null, path);
  }
  assert.equal(f.points.length, 0);
});

test('only an allowed amount of trailing punctuation is accepted', async () => {
  const f = fixture();
  const fits = `/r/Offer_1${'%E3%80%82'.repeat(13)}`;
  assert.equal(fits.length, 127);
  assert.equal((await worker.fetch(req(fits), f.env)).status, 302);
  const atLimit = `/r/Offer_1${'.'.repeat(118)}`;
  assert.equal(atLimit.length, 128);
  assert.equal((await worker.fetch(req(atLimit), f.env)).status, 302);
  const tooLong = `/r/Offer_1${'.'.repeat(119)}`;
  assert.equal(tooLong.length, 129);
  const before = f.reads.length;
  assert.equal((await worker.fetch(req(tooLong), f.env)).status, 404);
  assert.equal(f.reads.length, before);
});

test('case fallback works on the normalized name and records the matched name', async () => {
  const lower = fixture(['offer']);
  const result = await worker.fetch(req('/r/OFFER/%E3%80%82'), lower.env);
  assert.equal(result.headers.get('location'), `${DEFAULT}/offer`);
  assert.equal(lower.points[0].blobs[3], 'offer');
  const legacy = fixture(['Legacy']);
  const second = await worker.fetch(req('/r/lEgAcY.'), legacy.env);
  assert.equal(second.headers.get('location'), `${DEFAULT}/Legacy`);
  assert.equal(legacy.points[0].blobs[3], 'Legacy');
});

test('selftest signatures are checked against the normalized path', async () => {
  const f = fixture();
  const good = await signed('/r/Offer_1');
  for (const ending of ['', '/', '.', '%E3%80%82', '/%EF%BC%89']) {
    const result = await worker.fetch(req(`/r/Offer_1${ending}`, { headers: { 'X-Selftest': good } }), f.env);
    assert.equal(result.headers.get('location'), `${CN}/Offer_1`, ending);
  }
  assert.equal(f.points.length, 0);
  // A signature over the raw, un-normalized path is not a valid selftest.
  const raw = await signed('/r/Offer_1/');
  const ignored = await worker.fetch(req('/r/Offer_1/', { headers: { 'X-Selftest': raw } }), f.env);
  assert.equal(ignored.headers.get('location'), `${DEFAULT}/Offer_1`);
  assert.equal(f.points.length, 1);
});

test('the rate limit key is the same with or without trailing marks', async () => {
  const f = fixture(['offer']);
  const keys = [];
  f.env.CLICK_RATE_LIMITER = { limit: async ({ key }) => { keys.push(key); return { success: true }; } };
  for (const path of ['/r/offer', '/r/offer/', '/r/offer.', '/r/OFFER%E3%80%82', '/r/offer/)']) {
    assert.equal((await worker.fetch(req(path), f.env)).status, 302, path);
  }
  assert.equal(keys.length, 5);
  assert.equal(new Set(keys).size, 1);
});

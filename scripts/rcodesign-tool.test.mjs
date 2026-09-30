import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { extractSignerArchive, installRcodesignTool, verifyRcodesignTool, RCODESIGN_PINS, RCODESIGN_VERSION } from './rcodesign-tool.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const root = `apple-codesign-${RCODESIGN_VERSION}-aarch64-apple-darwin`;
const binary = Buffer.from('independent synthetic signing-tool bytes');
function header(name, type, body = Buffer.alloc(0), link = '') {
  const h = Buffer.alloc(512);
  h.write(name, 0); h.write('0000755\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(body.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
  h.fill(32, 148, 156); h.write(type, 156); h.write(link, 157); h.write('ustar  \0', 257);
  h.write([...h].reduce((a, b) => a + b, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([h, body, Buffer.alloc((512 - body.length % 512) % 512)]);
}
function fixture(entries = [header(root + '/', '5'), header(root + '/COPYING', '0', Buffer.from('license')), header(root + '/rcodesign', '0', binary)], tail = Buffer.alloc(1024)) {
  const archive = gzipSync(Buffer.concat([...entries, tail]));
  return { archive, options: { arch: 'arm64', pins: { arm64: { target: 'aarch64-apple-darwin', archive: hash(archive), binary: hash(binary) } } } };
}
test('the reviewed tool is pinned separately for the two native architectures', () => {
  assert.equal(RCODESIGN_VERSION, '0.29.0');
  assert.deepEqual(Object.keys(RCODESIGN_PINS), ['arm64', 'x64']);
  assert.notEqual(RCODESIGN_PINS.arm64.binary, RCODESIGN_PINS.x64.binary);
  assert.ok(Object.isFrozen(RCODESIGN_PINS) && Object.isFrozen(RCODESIGN_PINS.arm64));
});
test('strict signer archive reader returns only exact binary and license bytes', () => {
  const f = fixture(); const result = extractSignerArchive(f.archive, f.options);
  assert.deepEqual(result.binary, binary); assert.equal(result.license.toString(), 'license');
  assert.throws(() => extractSignerArchive(f.archive, { arch: 'arm64' }), /verification failed/);
});
test('archive integrity and executable integrity are independent mandatory checks', () => {
  const f = fixture();
  const changed = Buffer.from(f.archive); changed[changed.length - 1] ^= 1;
  assert.throws(() => extractSignerArchive(changed, f.options));
  const wrong = structuredClone(f.options); wrong.pins.arm64.binary = '0'.repeat(64);
  assert.throws(() => extractSignerArchive(f.archive, wrong));
});
test('unexpected paths, traversal, links, duplicate files and missing members are rejected', () => {
  for (const entries of [
    [header(root+'/', '5'), header(root+'/COPYING', '0', Buffer.from('license')), header('../rcodesign', '0', binary)],
    [header(root+'/', '5'), header(root+'/COPYING', '0', Buffer.from('license')), header(root+'/rcodesign', '2', Buffer.alloc(0), '/etc/passwd')],
    [header(root+'/', '5'), header(root+'/COPYING', '0', Buffer.from('license')), header(root+'/rcodesign', '0', binary), header(root+'/rcodesign', '0', binary)],
    [header(root+'/', '5'), header(root+'/rcodesign', '0', binary)],
  ]) { const f = fixture(entries); assert.throws(() => extractSignerArchive(f.archive, f.options)); }
});
test('checksum corruption and nonzero trailing archive data are rejected even with a matching archive digest', () => {
  const malformed = header(root+'/', '5'); malformed[100] ^= 1;
  for (const f of [fixture([malformed]), fixture(undefined, Buffer.concat([Buffer.alloc(1024), Buffer.from('hidden')]))]) {
    assert.throws(() => extractSignerArchive(f.archive, f.options));
  }
});
test('tool verification never executes native commands for unsupported, changed, or symlinked inputs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'slg-tool-test-'));
  let calls = 0; const run = async () => { calls++; return Buffer.from('arm64'); };
  try {
    const path = join(dir, 'tool'); writeFileSync(path, binary, { mode: 0o500 });
    const link = join(dir, 'link'); symlinkSync(path, link);
    for (const [file, options] of [[path, { arch: 'arm64', platform: 'darwin' }], [link, { arch: 'arm64', platform: 'darwin' }],
      [path, { arch: 'arm64', platform: 'linux' }], [path, { arch: 'ia32', platform: 'darwin' }], ['relative', { arch: 'arm64', platform: 'darwin' }]]) {
      await assert.rejects(verifyRcodesignTool(file, { ...options, run }));
    }
    assert.equal(calls, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('acquisition uses the exact immutable upstream URL and refuses unverified archive bytes before install', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'slg-tool-install-test-'));
  let url, verifies = 0;
  try {
    await assert.rejects(installRcodesignTool({ arch: 'x64', platform: 'darwin', tempRoot: dir,
      fetchArchive: async value => { url = value; return fixture().archive; }, verify: async () => { verifies++; } }));
    assert.equal(url, 'https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign/0.29.0/apple-codesign-0.29.0-x86_64-apple-darwin.tar.gz');
    assert.equal(verifies, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

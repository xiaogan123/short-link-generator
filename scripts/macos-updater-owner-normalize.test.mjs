import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  symlinkSync, writeFileSync, mkdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';
import { readMacUpdater } from './macos-artifact.mjs';
import { isAppInput } from './release-app-inputs.mjs';
import { bundleEntries, pax, tarBytes } from './test-fixtures/macos-artifact.mjs';
import {
  encodeCanonicalMacUpdater, locateMacUpdater, normalizeMacUpdater, normalizeOptionalMacUpdater,
  requireDisabledCoreDumps, signCanonicalUpdater, signerInvocation,
} from './macos-updater-owner-normalize.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const scratch = fn => {
  const dir = mkdtempSync(join(tmpdir(), 'mac-updater-owner-test-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
};
const setOctal = (header, offset, width, number) => {
  header.fill(0, offset, offset + width);
  header.write(number.toString(8).padStart(width - 1, '0'), offset, width - 1, 'ascii');
};
function withOwnerMetadata(tar) {
  const bytes = Buffer.from(tar);
  for (let offset = 0; offset < bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const size = parseInt(header.toString('ascii', 124, 136), 8);
    setOctal(header, 108, 8, 501);
    setOctal(header, 116, 8, 20);
    header.write('local-owner', 265, 'ascii');
    header.write('local-group', 297, 'ascii');
    setOctal(header, 136, 12, 1712345678);
    header.fill(32, 148, 156);
    const sum = header.reduce((total, byte) => total + byte, 0);
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'latin1');
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return bytes;
}
function assertCanonicalHeaders(gzip) {
  assert.equal(gzip[3], 0);
  assert.deepEqual([...gzip.subarray(4, 8)], [0, 0, 0, 0]);
  assert.equal(gzip[9], 255);
  const bytes = gunzipSync(gzip);
  let headers = 0;
  for (let offset = 0; offset < bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      assert.ok(bytes.subarray(offset).every(byte => byte === 0));
      break;
    }
    headers++;
    assert.equal(parseInt(header.toString('ascii', 108, 116), 8), 0);
    assert.equal(parseInt(header.toString('ascii', 116, 124), 8), 0);
    assert.equal(parseInt(header.toString('ascii', 136, 148), 8), 0);
    assert.ok(header.subarray(265, 345).every(byte => byte === 0));
    assert.ok(header.subarray(500, 512).every(byte => byte === 0));
    const size = parseInt(header.toString('ascii', 124, 136), 8);
    const data = bytes.subarray(offset + 512, offset + 512 + size);
    if (header[156] === 'x'.charCodeAt(0)) {
      assert.doesNotMatch(data.toString('utf8'), /(?:^|\n)(?:uid|gid|uname|gname)=/);
    }
    assert.ok(bytes.subarray(offset + 512 + size, offset + 512 + Math.ceil(size / 512) * 512).every(byte => byte === 0));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  assert.ok(headers >= 5);
}
function signedFixture(dir, tar) {
  const signer = versionedSigner();
  const updater = join(dir, 'Example_0.1.13_aarch64.app.tar.gz');
  const signature = `${updater}.sig`;
  const bytes = gzipSync(tar);
  writeFileSync(updater, bytes);
  writeFileSync(signature, signer.sign(bytes));
  return { updater, signature, publicKey: signer.publicKey, signer, bytes };
}

function versionedSigner(version = '0.1.13') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const id = Buffer.from('12345678');
  const packet = Buffer.concat([Buffer.from('Ed'), id,
    publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]);
  const encodedPublicKey = Buffer.from(`untrusted comment: synthetic test key\n${packet.toString('base64')}\n`).toString('base64');
  return { publicKey: encodedPublicKey, sign(data, signedVersion = version) {
    const signature = sign(null, createHash('blake2b512').update(data).digest(), privateKey);
    const trusted = `timestamp:1\t${signedVersion === null ? '' : `version:${signedVersion}\t`}file:test`;
    const global = sign(null, Buffer.concat([signature, Buffer.from(trusted)]), privateKey);
    const signaturePacket = Buffer.concat([Buffer.from('ED'), id, signature]);
    return Buffer.from(`untrusted comment: synthetic test signature\n${signaturePacket.toString('base64')}\ntrusted comment: ${trusted}\n${global.toString('base64')}\n`).toString('base64');
  } };
}

// Canonicalization removes both raw TAR owner fields and ignored PAX owner overrides.
test('normalizes owner metadata, re-signs a pure mock, and preserves the bundle manifest', () => scratch(dir => {
  const entries = [
    { path: 'PaxHeader', type: 'x', data: pax({ uid: '501', gid: '20', uname: 'local-owner', gname: 'local-group' }) },
    ...bundleEntries(),
  ];
  const fixture = signedFixture(dir, withOwnerMetadata(tarBytes(entries)));
  const before = readMacUpdater(fixture.updater).manifest;
  let called = 0;
  const receipt = normalizeMacUpdater({ ...fixture, version: '0.1.13', sign(staged, version) {
    called++;
    assert.equal(version, '0.1.13');
    assert.ok(staged.includes('.owner-normalize-'));
    const bytes = readFileSync(staged);
    writeFileSync(`${staged}.sig`, fixture.signer.sign(bytes));
  } });
  assert.equal(called, 1);
  assert.equal(receipt.manifestSha256, before.sha256);
  assert.equal(readMacUpdater(fixture.updater).manifest.sha256, before.sha256);
  assert.notEqual(hash(readFileSync(fixture.updater)), hash(fixture.bytes));
  assertCanonicalHeaders(readFileSync(fixture.updater));
  assert.equal(readdirSync(dir).filter(name => name.startsWith('.owner-normalize-')).length, 0);
}));

test('PAX round-trip preserves Unicode long paths, long symlink targets, modes and bytes', () => scratch(dir => {
  const nested = 'Example.app/Contents/Resources/子目录';
  const leaf = 'a'.repeat(130);
  const longFile = `${nested}/${leaf}`;
  const linkpath = `子目录/${leaf}`;
  const entries = [
    ...bundleEntries(),
    { path: 'Example.app/Contents/Resources', type: '5', mode: 0o755 },
    { path: 'pax-dir', type: 'x', data: pax({ path: nested }) },
    { path: 'directory-placeholder', type: '5', mode: 0o700 },
    { path: 'pax-file', type: 'x', data: pax({ path: longFile }) },
    { path: 'file-placeholder', data: Buffer.from('long-unicode-file\0data'), mode: 0o600 },
    { path: 'pax-link', type: 'x', data: pax({ linkpath }) },
    { path: 'Example.app/Contents/Resources/alias', type: '2', target: '', mode: 0o777 },
  ];
  const fixture = signedFixture(dir, tarBytes(entries));
  const before = readMacUpdater(fixture.updater);
  const first = encodeCanonicalMacUpdater(before.entries);
  const second = encodeCanonicalMacUpdater(before.entries);
  assert.deepEqual(first, second);
  const scratchArchive = join(dir, 'canonical.app.tar.gz');
  writeFileSync(scratchArchive, first);
  assert.deepEqual(readMacUpdater(scratchArchive).manifest.entries, before.manifest.entries);
  assertCanonicalHeaders(first);
  const receipt = normalizeMacUpdater({ ...fixture, version: '0.1.13', sign(staged) {
    writeFileSync(`${staged}.sig`, fixture.signer.sign(readFileSync(staged)));
  } });
  assert.equal(receipt.manifestSha256, before.manifest.sha256);
}));

test('bad original signature and failed signer leave original archive and signature untouched', () => scratch(dir => {
  const fixture = signedFixture(dir, tarBytes(bundleEntries()));
  const originalSignature = readFileSync(fixture.signature);
  assert.throws(() => normalizeMacUpdater({ ...fixture, publicKey: 'invalid', version: '0.1.13',
    sign() { assert.fail('must not sign'); } }));
  assert.deepEqual(readFileSync(fixture.updater), fixture.bytes);
  assert.deepEqual(readFileSync(fixture.signature), originalSignature);
  assert.throws(() => normalizeMacUpdater({ ...fixture, version: '0.1.13',
    sign() { throw Error('synthetic signer failure'); } }));
  assert.deepEqual(readFileSync(fixture.updater), fixture.bytes);
  assert.deepEqual(readFileSync(fixture.signature), originalSignature);
  assert.equal(readdirSync(dir).filter(name => name.startsWith('.owner-normalize-')).length, 0);
}));

test('invalid new signature fails closed before replacement', () => scratch(dir => {
  const fixture = signedFixture(dir, tarBytes(bundleEntries()));
  const oldSignature = readFileSync(fixture.signature);
  assert.throws(() => normalizeMacUpdater({ ...fixture, version: '0.1.13', sign(staged) {
    writeFileSync(`${staged}.sig`, 'not-a-signature');
  } }));
  assert.deepEqual(readFileSync(fixture.updater), fixture.bytes);
  assert.deepEqual(readFileSync(fixture.signature), oldSignature);
}));

for (const signedVersion of [null, '0.1.12']) {
  test(`missing or wrong original version ${signedVersion} blocks before signing`, () => scratch(dir => {
    const fixture = signedFixture(dir, tarBytes(bundleEntries()));
    const originalSignature = fixture.signer.sign(fixture.bytes, signedVersion);
    writeFileSync(fixture.signature, originalSignature);
    assert.throws(() => normalizeMacUpdater({ ...fixture, version: '0.1.13',
      sign() { assert.fail('no new signer call'); } }));
    assert.deepEqual(readFileSync(fixture.updater), fixture.bytes);
    assert.deepEqual(readFileSync(fixture.signature), Buffer.from(originalSignature));
  }));
  test(`missing or wrong new version ${signedVersion} preserves original pair`, () => scratch(dir => {
    const fixture = signedFixture(dir, tarBytes(bundleEntries()));
    const originalSignature = readFileSync(fixture.signature);
    assert.throws(() => normalizeMacUpdater({ ...fixture, version: '0.1.13', sign(staged) {
      writeFileSync(`${staged}.sig`, fixture.signer.sign(readFileSync(staged), signedVersion));
    } }));
    assert.deepEqual(readFileSync(fixture.updater), fixture.bytes);
    assert.deepEqual(readFileSync(fixture.signature), originalSignature);
  }));
}

test('standalone signer refuses nonzero core limits before reading a key or starting signer', () => {
  let secretReads = 0; let signerCalls = 0;
  const secretEnv = {};
  Object.defineProperty(secretEnv, 'TAURI_SIGNING_PRIVATE_KEY', { get() { secretReads++; return 'synthetic-secret'; } });
  const badCore = (command, args, options) => {
    assert.equal(command, '/bin/sh'); assert.deepEqual(args, ['-c', 'ulimit -S -c; ulimit -H -c']);
    assert.deepEqual(options.env, { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' });
    return { status: 0, stdout: 'unlimited\n0\n' };
  };
  assert.throws(() => signCanonicalUpdater('/synthetic/archive', '0.1.13', secretEnv,
    { coreRun: badCore, signerRun() { signerCalls++; assert.fail('must not spawn'); } }));
  assert.equal(secretReads, 0); assert.equal(signerCalls, 0);
  requireDisabledCoreDumps(() => ({ status: 0, stdout: '0\n0\n' }));
});

test('only one regular updater/signature is accepted for a fixed Mac target', () => scratch(dir => {
  const macos = join(dir, 'macos'); mkdirSync(macos);
  const fixture = signedFixture(macos, tarBytes(bundleEntries()));
  assert.deepEqual(locateMacUpdater(dir, 'aarch64-apple-darwin'),
    { updater: fixture.updater, signature: fixture.signature });
  assert.throws(() => locateMacUpdater(dir, 'x86_64-pc-windows-msvc'));
  writeFileSync(join(macos, 'other.app.tar.gz'), fixture.bytes);
  assert.throws(() => locateMacUpdater(dir, 'aarch64-apple-darwin'));
  rmSync(join(macos, 'other.app.tar.gz'));
  mkdirSync(join(macos, '.owner-normalize-stale'));
  assert.throws(() => locateMacUpdater(dir, 'aarch64-apple-darwin'));
  rmSync(join(macos, '.owner-normalize-stale'), { recursive: true });
  rmSync(fixture.updater);
  symlinkSync('missing', fixture.updater);
  assert.ok(lstatSync(fixture.updater).isSymbolicLink());
  assert.throws(() => locateMacUpdater(dir, 'aarch64-apple-darwin'));
}));

test('signer argv binds exact version while environment carries only updater credentials', () => {
  const value = signerInvocation('/private/temp/archive.app.tar.gz', '0.1.13', {
    TAURI_SIGNING_PRIVATE_KEY: 'synthetic-key', TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'synthetic-password',
    SLG_MACOS_SIGNING_P12_BASE64: 'forbidden-extra', APPLE_SIGNING_IDENTITY: 'forbidden-extra',
  });
  assert.deepEqual(value.args.slice(1), ['signer', 'sign', '--app-version', '0.1.13', '/private/temp/archive.app.tar.gz']);
  assert.deepEqual(value.env, { TAURI_SIGNING_PRIVATE_KEY: 'synthetic-key', TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'synthetic-password' });
  assert.ok(!value.args.join(' ').includes('synthetic-key'));
  assert.throws(() => signerInvocation('x', '0.1.13', {}));
});

test('optional bundle path skips absent archives and rejects partial updater pairs', () => scratch(dir => {
  const macos = join(dir, 'macos'); mkdirSync(macos);
  assert.deepEqual(normalizeOptionalMacUpdater({ bundle: dir, target: 'aarch64-apple-darwin' }), { present: false });
  writeFileSync(join(macos, 'partial.app.tar.gz.sig'), 'synthetic');
  assert.throws(() => normalizeOptionalMacUpdater({ bundle: dir, target: 'aarch64-apple-darwin' }));
}));

test('release wrapper normalizes before verification and supplies the public key without changing app inputs', () => {
  const workflow = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  const wrapper = readFileSync(new URL('./stable-macos-sign.mjs', import.meta.url), 'utf8');
  const build = workflow.indexOf('id: package');
  const smoke = workflow.indexOf('id: native_smoke');
  const upload = workflow.indexOf('actions/upload-artifact');
  assert.ok(build > 0 && build < smoke && smoke < upload);
  assert.match(workflow.slice(build, smoke), /SLG_UPDATER_PUBLIC_KEY: \$\{\{ vars\.UPDATER_PUBLIC_KEY \}\}/);
  assert.ok(wrapper.indexOf("stage = 'updater-normalize'") < wrapper.indexOf("stage = 'verify'"));
  assert.match(wrapper, /normalizeUpdater\(\{ bundle: bundleRoot, target/);
  assert.equal(isAppInput('scripts/macos-updater-owner-normalize.mjs'), false);
  assert.equal(isAppInput('scripts/macos-updater-owner-normalize.test.mjs'), false);
  assert.equal(isAppInput('scripts/stable-macos-sign.mjs'), false);
  assert.equal(isAppInput('scripts/stable-macos-sign.test.mjs'), false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { bundleManifest, extractMacUpdater, readMacUpdater, validateMacArtifactEvidence, verifyMacArtifactSet } from './macos-artifact.mjs';
import { artifactEvidence, bundleEntries, CERT_PIN, HELPER_TREE_PIN, nativeSigning, pack, pax, tarBytes } from './test-fixtures/macos-artifact.mjs';
import { helperTreeDigest, REVIEWED_HELPER_INFO_SHA256 } from './macos-credential-helper-bytes.mjs';
import { inspect } from './privacy-check.mjs';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'mac-artifact-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const archive = join(dir, 'Example.app.tar.gz');
  writeFileSync(archive, pack(bundleEntries()));
  return { dir, archive };
}

test('extracts a complete bundle with exact bytes and modes independently of umask', t => {
  const { dir, archive } = fixture(t); const before = process.umask(0o077);
  try {
    const extracted = extractMacUpdater(archive, join(dir, 'unpacked'));
    assert.deepEqual(bundleManifest(extracted.app), readMacUpdater(archive).manifest);
    assert.equal(readFileSync(join(extracted.app, 'Contents/MacOS/short-link-generator'), 'utf8'), 'synthetic-executable');
    assert.equal(extracted.manifest.entries.find(entry => entry.path.includes('short-link-generator')).mode, 0o755);
    assert.throws(() => extractMacUpdater(archive, join(dir, 'unpacked')), /EEXIST/);
  } finally { process.umask(before); }
});

test('supports PAX UTF-8 paths, GNU long names and safe framework-style symlink chains', t => {
  const { dir, archive } = fixture(t);
  const entries = bundleEntries(); const root = 'Example.app/Contents';
  entries.push({ path: `${root}/Versions`, type: '5' }, { path: `${root}/Versions/A`, type: '5' },
    { path: `${root}/Versions/A/Library`, data: 'framework' },
    { path: `${root}/Versions/Current`, type: '2', target: 'A' },
    { path: `${root}/Library`, type: '2', target: 'Versions/Current/Library' },
    { path: 'PaxHeader', type: 'x', data: pax({ path: `${root}/本地化`, mtime: '1.234' }) },
    { path: 'placeholder', data: 'localized' },
    { path: '././@LongLink', type: 'L', data: `${root}/${'long'.repeat(30)}\0` }, { path: 'placeholder', data: 'long' });
  writeFileSync(archive, pack(entries));
  const extracted = extractMacUpdater(archive, join(dir, 'unpacked'));
  assert.equal(readFileSync(join(extracted.app, 'Contents/Library'), 'utf8'), 'framework');
  assert.equal(readFileSync(join(extracted.app, 'Contents/本地化'), 'utf8'), 'localized');
  assert.deepEqual(bundleManifest(extracted.app), extracted.manifest);
});

test('rejects path, metadata, link, alias and special-file tricks before creating output', async t => {
  const { dir, archive } = fixture(t);
  const bad = [
    ['parent traversal', [{ path: 'Example.app/../outside', data: 'bad' }]],
    ['absolute path', [{ path: '/outside', data: 'bad' }]],
    ['backslash', [{ path: 'Example.app/Contents\\outside', data: 'bad' }]],
    ['colon alias', [{ path: 'Example.app/Contents/file:fork', data: 'bad' }]],
    ['dot path', [{ path: 'Example.app/./file', data: 'bad' }]],
    ['empty component', [{ path: 'Example.app//file', data: 'bad' }]],
    ['duplicate file', [{ path: 'Example.app/Contents/Info.plist', data: 'bad' }]],
    ['case alias', [{ path: 'Example.app/Contents/info.plist', data: 'bad' }]],
    ['Unicode alias', [{ path: 'Example.app/Contents/é', data: 'a' }, { path: 'Example.app/Contents/e\u0301', data: 'b' }]],
    ['another app', [{ path: 'Other.app', type: '5' }]],
    ['implicit parent', [{ path: 'Example.app/Missing/file', data: 'bad' }]],
    ['symlink escape', [{ path: 'Example.app/Contents/link', type: '2', target: '../../outside' }]],
    ['absolute symlink', [{ path: 'Example.app/Contents/link', type: '2', target: '/tmp' }]],
    ['symlink parent', [{ path: 'Example.app/link', type: '2', target: 'Contents' }, { path: 'Example.app/link/new', data: 'bad' }]],
    ['reordered symlink parent', [{ path: 'Example.app/link/new', data: 'bad' }, { path: 'Example.app/link', type: '2', target: 'Contents' }]],
    ['broken symlink', [{ path: 'Example.app/link', type: '2', target: 'missing' }]],
    ['cyclic symlink', [{ path: 'Example.app/a', type: '2', target: 'b' }, { path: 'Example.app/b', type: '2', target: 'a' }]],
    ['hardlink', [{ path: 'Example.app/hard', type: '1', target: 'Example.app/Contents/Info.plist' }]],
    ['device', [{ path: 'Example.app/device', type: '3' }]],
    ['fifo', [{ path: 'Example.app/fifo', type: '6' }]],
    ['sparse file', [{ path: 'Example.app/sparse', type: 'S' }]],
    ['setuid', [{ path: 'Example.app/setuid', data: 'bad', mode: 0o4755 }]],
    ['bad type mode', [{ path: 'Example.app/mode', data: 'bad', mode: 0o40755 }]],
    ['PAX path traversal', [{ path: 'Pax', type: 'x', data: pax({ path: '../outside' }) }, { path: 'placeholder', data: 'bad' }]],
    ['PAX link traversal', [{ path: 'Pax', type: 'x', data: pax({ linkpath: '../../outside' }) }, { path: 'Example.app/link', type: '2', target: 'Contents' }]],
    ['PAX extraction extension', [{ path: 'Pax', type: 'x', data: pax({ 'SCHILY.xattr.user.test': 'bad' }) }, { path: 'Example.app/file', data: 'bad' }]],
    ['PAX duplicate key', [{ path: 'Pax', type: 'x', data: Buffer.concat([pax({ path: 'Example.app/a' }), pax({ path: 'Example.app/b' })]) }, { path: 'placeholder' }]],
    ['PAX malformed length', [{ path: 'Pax', type: 'x', data: '2 path=x\n' }, { path: 'placeholder' }]],
    ['PAX missing equals', [{ path: 'Pax', type: 'x', data: '10 mtimeX\n' }, { path: 'Example.app/file', data: 'bad' }]],
    ['global PAX', [{ path: 'Pax', type: 'g', data: pax({ path: 'Example.app/a' }) }]],
    ['GNU long traversal', [{ path: 'Long', type: 'L', data: '../outside\0' }, { path: 'placeholder', data: 'bad' }]],
    ['dangling metadata', [{ path: 'Pax', type: 'x', data: pax({ path: 'Example.app/new' }) }]],
    ['invalid UTF-8', [{ path: 'Pax', type: 'x', data: Buffer.from([0xff]) }, { path: 'placeholder' }]],
  ];
  for (const [name, appended] of bad) await t.test(name, () => {
    writeFileSync(archive, pack([...bundleEntries(), ...appended]));
    const output = join(dir, 'must-not-exist');
    assert.throws(() => extractMacUpdater(archive, output), /Unsafe or unsupported/);
    assert.equal(existsSync(output), false);
  });
});

test('rejects corrupt checksums, trailers, truncated members and bounded archive inputs', t => {
  const { dir, archive } = fixture(t);
  const broken = tarBytes(bundleEntries()); broken[0] ^= 1;
  const oversized = tarBytes([{ path: 'Example.app', type: '5' }]);
  oversized.write('77777777777', 124, 11); oversized.fill(32, 148, 156);
  oversized.write(oversized.subarray(0, 512).reduce((n, byte) => n + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  for (const data of [broken, oversized, tarBytes(bundleEntries(), { trailer: Buffer.alloc(512) }),
    Buffer.concat([tarBytes(bundleEntries()), Buffer.alloc(512, 1)]), tarBytes(bundleEntries()).subarray(0, 1500)]) {
    writeFileSync(archive, gzipSync(data)); assert.throws(() => readMacUpdater(archive), /Unsafe or unsupported/);
  }
  writeFileSync(archive, ''); truncateSync(archive, 256 * 1024 * 1024 + 1);
  assert.throws(() => readMacUpdater(archive), /Unsafe or unsupported/);
  rmSync(archive); symlinkSync(join(dir, 'missing'), archive);
  assert.throws(() => readMacUpdater(archive), /Unsafe or unsupported/);
});

test('bundle manifest rejects external links, hardlinks and mode-only differences', t => {
  const { dir, archive } = fixture(t);
  const { app, manifest } = extractMacUpdater(archive, join(dir, 'unpacked'));
  const binary = join(app, 'Contents/MacOS/short-link-generator');
  chmodSync(binary, 0o644); assert.notEqual(bundleManifest(app).sha256, manifest.sha256); chmodSync(binary, 0o755);
  linkSync(binary, join(app, 'hard')); assert.throws(() => bundleManifest(app)); rmSync(join(app, 'hard'));
  symlinkSync(dir, join(app, 'escape')); assert.throws(() => bundleManifest(app)); rmSync(join(app, 'escape'));
  mkdirSync(join(app, 'extra')); assert.notEqual(bundleManifest(app).sha256, manifest.sha256);
});

test('expanded privacy inspection covers ignored PAX, USTAR owner and member padding before extraction', t => {
  const { dir, archive } = fixture(t);
  const synthetic = ['', 'Users', 'fixture-user', 'metadata'].join('/');
  const paxOwner = tarBytes([{ path: 'Pax', type: 'x', data: pax({ uname: synthetic }) }, ...bundleEntries()]);
  const ustarOwner = tarBytes(bundleEntries());
  ustarOwner.write(synthetic, 265, 32); ustarOwner.fill(32, 148, 156);
  ustarOwner.write(ustarOwner.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  const padding = tarBytes(bundleEntries());
  const endOfBinary = padding.indexOf('synthetic-executable') + Buffer.byteLength('synthetic-executable');
  padding.write(synthetic, endOfBinary);
  for (const [index, bytes] of [paxOwner, ustarOwner, padding].entries()) {
    writeFileSync(archive, gzipSync(bytes));
    assert.deepEqual(inspect(readFileSync(archive)), []);
    assert.deepEqual(inspect(JSON.stringify(readMacUpdater(archive).manifest)), []);
    const destination = join(dir, `private-${index}`); let calls = 0;
    const extracted = extractMacUpdater(archive, destination, { inspectExpanded(expanded) {
      calls++; assert.equal(existsSync(destination), false);
      assert.deepEqual(expanded, bytes); assert.ok(inspect(expanded).includes('home-directory'));
    } });
    assert.equal(calls, 1);
    assert.deepEqual(inspect(readFileSync(join(extracted.app, 'Contents/MacOS/short-link-generator'))), []);
  }
  const rejected = join(dir, 'callback-rejected');
  assert.throws(() => extractMacUpdater(archive, rejected, { inspectExpanded() { throw new Error('privacy rejected'); } }), /privacy rejected/);
  assert.equal(existsSync(rejected), false);
});

test('verifies exact DMG, updater and build bundles plus independent stable identities', t => {
  const { dir, archive } = fixture(t);
  const installedApp = extractMacUpdater(archive, join(dir, 'installed')).app;
  const builtApp = extractMacUpdater(archive, join(dir, 'built')).app;
  let calls = [];
  const verify = (app, pin) => { calls.push(app); assert.equal(pin, CERT_PIN); return { ...nativeSigning }; };
  const helperCalls = [];
  const verifyHelper = (app, pin) => { helperCalls.push(app); assert.equal(pin, HELPER_TREE_PIN);
    return { treeSha256: pin, infoSha256: REVIEWED_HELPER_INFO_SHA256 }; };
  const result = verifyMacArtifactSet({ updater: archive, installedApp, builtApp, destination: join(dir, 'checked'),
    pin: CERT_PIN, helperTreePin: HELPER_TREE_PIN, verify, verifyHelper });
  assert.equal(calls.length, 3); assert.equal(new Set(calls).size, 3);
  assert.equal(helperCalls.length, 3); assert.equal(new Set(helperCalls).size, 3);
  validateMacArtifactEvidence(result.macArtifacts, CERT_PIN, readMacUpdater(archive).manifest, result.nativeSigning, HELPER_TREE_PIN);
  const executable = join(builtApp, 'Contents/MacOS/short-link-generator'); chmodSync(executable, 0o644);
  assert.throws(() => verifyMacArtifactSet({ updater: archive, installedApp, builtApp, destination: join(dir, 'mode'),
    pin: CERT_PIN, helperTreePin: HELPER_TREE_PIN, verify, verifyHelper }), /Build and packaged/);
  chmodSync(executable, 0o755); writeFileSync(join(installedApp, 'Contents/Info.plist'), 'changed'); calls = [];
  assert.throws(() => verifyMacArtifactSet({ updater: archive, installedApp, destination: join(dir, 'changed'),
    pin: CERT_PIN, helperTreePin: HELPER_TREE_PIN, verify, verifyHelper }), /DMG and updater/);
  assert.equal(calls.length, 0);
});

test('native artifact path checks the helper in all three actual app trees', t => {
  const { dir, archive } = fixture(t);
  const root = 'Example.app/Contents/XPCServices/credential-helper.xpc';
  const reviewedInfo = readFileSync(resolve(import.meta.dirname, '../src-tauri/native/credential-core/helper-Info.plist'));
  const helperEntries = [
    { path: 'Example.app/Contents/XPCServices', type: '5' },
    { path: root, type: '5' },
    { path: `${root}/Contents`, type: '5' },
    { path: `${root}/Contents/Info.plist`, data: reviewedInfo },
    { path: `${root}/Contents/MacOS`, type: '5' },
    { path: `${root}/Contents/MacOS/credential-helper`, data: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), mode: 0o755 },
    { path: `${root}/Contents/_CodeSignature`, type: '5' },
    { path: `${root}/Contents/_CodeSignature/CodeResources`, data: 'mock-signature-only' },
  ];
  writeFileSync(archive, pack([...bundleEntries(), ...helperEntries]));
  const installedApp = extractMacUpdater(archive, join(dir, 'installed')).app;
  const builtApp = extractMacUpdater(archive, join(dir, 'built')).app;
  const pin = helperTreeDigest(join(installedApp, 'Contents/XPCServices/credential-helper.xpc'));
  const verify = () => ({ ...nativeSigning });
  const result = verifyMacArtifactSet({ updater: archive, installedApp, builtApp,
    destination: join(dir, 'updater'), pin: CERT_PIN, helperTreePin: pin, verify });
  assert.equal(result.macArtifacts.helperVerifiedAppCount, 3);
  assert.equal(result.macArtifacts.helperTreeSha256, pin);
  writeFileSync(archive, pack(bundleEntries()));
  const missing = extractMacUpdater(archive, join(dir, 'missing-installed')).app;
  assert.throws(() => verifyMacArtifactSet({ updater: archive, installedApp: missing,
    destination: join(dir, 'missing-updater'), pin: CERT_PIN, helperTreePin: pin, verify }));
});

test('rejects stripped, forged and mismatched archive evidence including missing stable pin', t => {
  const { archive } = fixture(t); const manifest = readMacUpdater(archive).manifest;
  const evidence = artifactEvidence(manifest);
  for (const patch of [{ updaterBundleVerified: false }, { contentMatchVerified: false }, { modesMatchVerified: false },
    { schema: 0 }, { bundleManifestSha256: 'a'.repeat(64) }, { entryCount: 0 }, { fileCount: 999 },
    { updaterSigning: undefined }, { buildSigning: undefined }, { buildBundleCompared: false },
    { helperTreeSha256: 'a'.repeat(64) }, { helperInfoSha256: 'a'.repeat(64) },
    { helperByteIdentityVerified: false }, { helperMetadataVerified: false }, { helperVerifiedAppCount: 2 },
    { updaterSigning: { ...nativeSigning, certificateSha256: 'b'.repeat(64) } },
    { updaterSigning: { ...nativeSigning, designatedRequirement: 'identifier org.shortlink.generator' } }]) {
    assert.throws(() => validateMacArtifactEvidence({ ...evidence, ...patch }, CERT_PIN, manifest, nativeSigning, HELPER_TREE_PIN));
  }
  assert.throws(() => validateMacArtifactEvidence(evidence, undefined, manifest, nativeSigning, HELPER_TREE_PIN));
  assert.throws(() => validateMacArtifactEvidence(evidence, CERT_PIN, manifest, nativeSigning, undefined));
  assert.throws(() => validateMacArtifactEvidence(evidence, CERT_PIN, manifest, nativeSigning, 'b'.repeat(64)));
  assert.throws(() => validateMacArtifactEvidence(evidence, 'b'.repeat(64), manifest, nativeSigning, HELPER_TREE_PIN));
  assert.throws(() => validateMacArtifactEvidence(evidence, CERT_PIN, manifest, { ...nativeSigning, certificateSha1: '1'.repeat(40) }, HELPER_TREE_PIN));
});

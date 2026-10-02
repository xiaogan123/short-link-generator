import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { normalizeOptionalMacDmg } from './macos-dmg-owner-stage.mjs';
import { isAppInput } from './release-app-inputs.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
const scratch = async fn => {
  const root = mkdtempSync(join(tmpdir(), 'slg-dmg-stage-mock-'));
  try { return await fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
};
function fixture(root) {
  const bundle = join(root, 'bundle'); const directory = join(bundle, 'dmg'); const app = join(bundle, 'macos/Example.app');
  mkdirSync(directory, { recursive: true }); mkdirSync(app, { recursive: true });
  const original = join(directory, 'Example_0.1.13_aarch64.dmg');
  const initial = Buffer.from('synthetic-original-signed-dmg'); writeFileSync(original, initial);
  const script = join(root, 'normalizer.py'); writeFileSync(script, '# synthetic command placeholder\n');
  return { bundle, directory, app, original, initial, script };
}
function safeReceipt(input, output) {
  return { inputDmgSha256: sha(readFileSync(input)), outputDmgSha256: sha(readFileSync(output)),
    inputRawSha256: 'a'.repeat(64), normalizedRawSha256: 'b'.repeat(64), catalogObjects: 23,
    noncanonicalObjectsBefore: 23, allOwnersZeroAfter: true,
    onlyCatalogOwnerGroupFieldsChanged: true, allFileForksPreserved: true,
    roundtripRawExact: true, hdiutilVerified: true,
    sourceTree: { entries: 16, files: 8, links: 0, manifestSha256: 'c'.repeat(64) },
    outputSigned: false };
}
function harness(f, { pythonFailure = false, badEvidence = false, badForkEvidence = false,
  signFailure = false, finalVerifyFailure = false } = {}) {
  const calls = []; let inspections = 0;
  return {
    calls,
    args: { bundle: f.bundle, app: f.app, target: 'aarch64-apple-darwin', certificateSha1: 'a'.repeat(40),
      certificateSha256: 'b'.repeat(64), shim: '/private/fixed/codesign', script: f.script, env: { PATH: '/usr/bin' },
      verifySignature: async (path, pin, prefix) => {
        inspections++; calls.push('verify');
        assert.equal(pin, 'b'.repeat(64)); assert.ok(prefix.includes('.owner-normalize-'));
        if (finalVerifyFailure && inspections === 3) throw Error('synthetic final verification failure');
        assert.ok(existsSync(path));
      },
      run: async (command, args, options) => {
        assert.deepEqual(options.env, { PATH: '/usr/bin' });
        if (command === '/usr/bin/python3') {
          calls.push('python'); assert.deepEqual(args.slice(0, 4), ['-I', '-S', '-B', f.script]);
          assert.equal(args[4], f.original); assert.equal(args[6], f.app); assert.equal(args[7], '--evidence');
          if (pythonFailure) throw Error('synthetic hdiutil failure');
          writeFileSync(args[5], Buffer.from('synthetic-canonical-unsigned-dmg'));
          const receipt = safeReceipt(args[4], args[5]);
          if (badEvidence) receipt.allOwnersZeroAfter = false;
          if (badForkEvidence) receipt.allFileForksPreserved = false;
          writeFileSync(args[8], JSON.stringify(receipt));
          return Buffer.alloc(0);
        }
        assert.equal(command, '/private/fixed/codesign'); calls.push('sign');
        assert.deepEqual(args.slice(0, 3), ['--force', '-s', 'a'.repeat(40)]);
        assert.ok(args[3].endsWith('/normalized.dmg')); assert.notEqual(args[3], f.original);
        if (signFailure) throw Error('synthetic signing failure');
        writeFileSync(args[3], Buffer.from('synthetic-canonical-signed-dmg'));
        return Buffer.alloc(0);
      } },
  };
}

test('app-only bundles skip DMG normalization without script/signature calls', async () => scratch(async root => {
  const bundle = join(root, 'bundle'); const app = join(bundle, 'macos/Example.app'); mkdirSync(app, { recursive: true });
  const result = await normalizeOptionalMacDmg({ bundle, app, target: 'aarch64-apple-darwin',
    run() { assert.fail('no native tools when container is absent'); } });
  assert.deepEqual(result, { present: false });
}));

test('dangling DMG directory symlink is not treated as an absent container', async () => scratch(async root => {
  const bundle = join(root, 'bundle'); const app = join(bundle, 'macos/Example.app'); mkdirSync(app, { recursive: true });
  symlinkSync('missing', join(bundle, 'dmg'));
  await assert.rejects(normalizeOptionalMacDmg({ bundle, app, target: 'aarch64-apple-darwin',
    run() { assert.fail('native tool must not start'); } }));
}));

test('fresh DMG is normalized, only that DMG is signed, verified and swapped', async () => scratch(async root => {
  const f = fixture(root); const h = harness(f);
  const result = await normalizeOptionalMacDmg(h.args);
  assert.equal(result.present, true);
  assert.equal(result.noncanonicalObjectsBefore, 23);
  assert.equal(result.sourceTreeSha256, 'c'.repeat(64));
  assert.deepEqual(h.calls, ['verify', 'python', 'sign', 'verify', 'verify']);
  assert.deepEqual(readFileSync(f.original), Buffer.from('synthetic-canonical-signed-dmg'));
  assert.deepEqual(readdirSync(f.directory), [f.original.split('/').at(-1)]);
}));

for (const mode of ['pythonFailure', 'badEvidence', 'badForkEvidence', 'signFailure', 'finalVerifyFailure']) {
  test(`${mode} preserves the previously signed DMG and cleans only owned staging`, async () => scratch(async root => {
    const f = fixture(root); const h = harness(f, { [mode]: true });
    await assert.rejects(normalizeOptionalMacDmg(h.args), /not approved/);
    assert.deepEqual(readFileSync(f.original), f.initial);
    assert.deepEqual(readdirSync(f.directory), [f.original.split('/').at(-1)]);
    if (mode === 'badEvidence' || mode === 'badForkEvidence') assert.equal(h.calls.includes('sign'), false);
  }));
}

test('invalid target, duplicate/symlink DMG and stale staging all fail before native commands', async () => scratch(async root => {
  const f = fixture(root); const h = harness(f);
  await assert.rejects(normalizeOptionalMacDmg({ ...h.args, target: 'x86_64-pc-windows-msvc' }));
  writeFileSync(join(f.directory, 'another.dmg'), 'synthetic');
  await assert.rejects(normalizeOptionalMacDmg(h.args));
  rmSync(join(f.directory, 'another.dmg'));
  mkdirSync(join(f.directory, '.owner-normalize-stale'));
  await assert.rejects(normalizeOptionalMacDmg(h.args));
  rmSync(join(f.directory, '.owner-normalize-stale'), { recursive: true });
  rmSync(f.original); symlinkSync('missing', f.original);
  assert.ok(lstatSync(f.original).isSymbolicLink());
  await assert.rejects(normalizeOptionalMacDmg(h.args));
  assert.deepEqual(h.calls, []);
}));

test('DMG integration sources and tests remain release-only inputs', () => {
  for (const path of ['scripts/macos-dmg-owner-stage.mjs', 'scripts/macos-dmg-owner-stage.test.mjs',
    'scripts/normalize-macos-dmg-owners.py', 'tests/test_normalize_macos_dmg_owners.py']) {
    assert.equal(isAppInput(path), false);
  }
});

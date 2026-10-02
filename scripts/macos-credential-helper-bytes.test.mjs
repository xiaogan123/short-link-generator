import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { helperPinForTarget, helperTreeDigest, REVIEWED_HELPER_INFO_SHA256,
  verifyEmbeddedHelper, verifyPackagedHelper } from './macos-credential-helper-bytes.mjs';

function fixture(t) {
  const base = mkdtempSync(join(tmpdir(), 'helper-bytes-mock-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const stage = join(base, 'stage', 'credential-helper.xpc');
  const packaged = join(base, 'package', 'credential-helper.xpc');
  mkdirSync(join(stage, 'Contents', 'MacOS'), { recursive: true });
  mkdirSync(join(stage, 'Contents', '_CodeSignature'), { recursive: true });
  // These are inert bytes, not an executable or a real signature.
  writeFileSync(join(stage, 'Contents', 'Info.plist'), '<plist/>');
  writeFileSync(join(stage, 'Contents', 'MacOS', 'credential-helper'), Buffer.from([0xcf, 0xfa, 0xed, 0xfe]));
  writeFileSync(join(stage, 'Contents', '_CodeSignature', 'CodeResources'), 'mock-only');
  cpSync(stage, packaged, { recursive: true });
  return { stage, packaged };
}

test('approved signed-archive tree bytes are preserved through package copy', t => {
  const { stage, packaged } = fixture(t);
  const approved = helperTreeDigest(stage);
  assert.deepEqual(verifyPackagedHelper(stage, packaged, approved),
    { bytesPreserved: true, treeSha256: approved });
});

test('tampered or extra packaged bytes fail closed', t => {
  const { stage, packaged } = fixture(t);
  const approved = helperTreeDigest(stage);
  writeFileSync(join(packaged, 'Contents', 'MacOS', 'credential-helper'), 'changed');
  assert.throws(() => verifyPackagedHelper(stage, packaged, approved));
  cpSync(stage, packaged, { recursive: true, force: true });
  writeFileSync(join(packaged, 'unexpected'), 'extra');
  assert.throws(() => verifyPackagedHelper(stage, packaged, approved));
});

test('bundle root mode is part of the frozen tree identity', t => {
  const { stage, packaged } = fixture(t);
  const approved = helperTreeDigest(stage);
  chmodSync(packaged, 0o700);
  assert.throws(() => verifyPackagedHelper(stage, packaged, approved));
});

test('missing signature file, symlink and wrong approved pin fail closed', t => {
  const { stage, packaged } = fixture(t);
  const approved = helperTreeDigest(stage);
  assert.throws(() => verifyPackagedHelper(stage, packaged, '0'.repeat(64)));
  rmSync(join(packaged, 'Contents', '_CodeSignature', 'CodeResources'));
  assert.throws(() => helperTreeDigest(packaged));
  symlinkSync('/tmp', join(stage, 'linked'));
  assert.throws(() => helperTreeDigest(stage));
  assert.throws(() => verifyPackagedHelper(stage, packaged, approved));
});

test('every embedded app must carry the reviewed identity/session metadata and target pin', t => {
  const { stage, packaged } = fixture(t);
  const app = join(packaged, '..', 'App.app');
  const embedded = join(app, 'Contents', 'XPCServices', 'credential-helper.xpc');
  mkdirSync(join(app, 'Contents', 'XPCServices'), { recursive: true });
  cpSync(stage, embedded, { recursive: true });
  const info = readFileSync(resolve(import.meta.dirname, '../src-tauri/native/credential-core/helper-Info.plist'));
  writeFileSync(join(embedded, 'Contents', 'Info.plist'), info);
  const approved = helperTreeDigest(stage);
  assert.throws(() => verifyEmbeddedHelper(app, approved));
  const actual = helperTreeDigest(embedded);
  assert.deepEqual(verifyEmbeddedHelper(app, actual),
    { treeSha256: actual, infoSha256: REVIEWED_HELPER_INFO_SHA256 });
  assert.equal(helperPinForTarget('aarch64-apple-darwin',
    { SLG_MACOS_HELPER_TREE_SHA256_ARM64: actual }), actual);
  assert.throws(() => helperPinForTarget('x86_64-apple-darwin',
    { SLG_MACOS_HELPER_TREE_SHA256_ARM64: actual }));
  writeFileSync(join(embedded, 'Contents', 'Info.plist'), '<plist/>');
  assert.throws(() => verifyEmbeddedHelper(app, actual));
});

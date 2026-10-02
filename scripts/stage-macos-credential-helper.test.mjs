import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, cpSync, existsSync, linkSync, mkdirSync, mkdtempSync,
  readFileSync, readdirSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { helperTreeDigest, REVIEWED_HELPER_INFO_SHA256 } from './macos-credential-helper-bytes.mjs';
import { approvedArchiveRecord, inspectSignedHelper, loadPinnedApproval,
  stageCheckedInFrozenHelper, stageFrozenHelper } from './stage-macos-credential-helper.mjs';
import { VALID_MACOS_11_LOAD_COMMANDS } from './test-fixtures/macos-build-version.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const TARGET = 'aarch64-apple-darwin';
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'frozen-helper-stage-mock-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const archive = join(root, 'approved.zip');
  writeFileSync(archive, 'inert archive bytes');
  const bundle = join(root, 'credential-helper.xpc');
  mkdirSync(join(bundle, 'Contents', 'MacOS'), { recursive: true });
  mkdirSync(join(bundle, 'Contents', '_CodeSignature'), { recursive: true });
  const info = readFileSync(resolve(import.meta.dirname, '../src-tauri/native/credential-core/helper-Info.plist'));
  writeFileSync(join(bundle, 'Contents', 'Info.plist'), info);
  writeFileSync(join(bundle, 'Contents', 'MacOS', 'credential-helper'), Buffer.from([0xcf, 0xfa, 0xed, 0xfe]));
  writeFileSync(join(bundle, 'Contents', '_CodeSignature', 'CodeResources'), 'mock-only');
  const approval = structuredClone(loadPinnedApproval());
  approval.state = 'APPROVED';
  approval.archives[TARGET] = { architecture: 'arm64', archiveSha256: sha256(readFileSync(archive)),
    treeSha256: helperTreeDigest(bundle), signerCertificateSha256: 'a'.repeat(64),
    cdhash: 'b'.repeat(40), helperSourceManifestSha256: 'c'.repeat(64), helperVersion: '0.1.0' };
  return { root, archive, bundle, approval, output: join(root, 'stage') };
}

test('pinned source approval binds both archives and rejects unapproved or tampered metadata', t => {
  const f = fixture(t);
  assert.equal(loadPinnedApproval().state, 'APPROVED');
  const current = loadPinnedApproval();
  for (const target of ['aarch64-apple-darwin', 'x86_64-apple-darwin']) {
    assert.deepEqual(approvedArchiveRecord(current, target), current.archives[target]);
    assert.throws(() => approvedArchiveRecord({ ...current, state: 'UNAPPROVED' }, target));
  }
  const tampered = join(f.root, 'tampered-approval.json');
  writeFileSync(tampered, `${JSON.stringify(f.approval)}\n`);
  assert.throws(() => loadPinnedApproval(tampered));
  assert.throws(() => stageFrozenHelper({ target: TARGET, archive: f.archive,
    extractedBundle: f.bundle, platform: 'darwin', output: f.output }));
  assert.equal(existsSync(f.output), false);
});

test('approved record binds arch, archive, tree, signer, CDHash, source and version', t => {
  const f = fixture(t);
  assert.equal(approvedArchiveRecord(f.approval, TARGET).cdhash, 'b'.repeat(40));
  for (const [field, value] of [
    ['architecture', 'x86_64'], ['archiveSha256', null], ['treeSha256', 'bad'],
    ['signerCertificateSha256', null], ['cdhash', 'bad'],
    ['helperSourceManifestSha256', null], ['helperVersion', null],
  ]) {
    const invalid = structuredClone(f.approval);
    invalid.archives[TARGET][field] = value;
    assert.throws(() => approvedArchiveRecord(invalid, TARGET), field);
  }
  const wrongCore = structuredClone(f.approval);
  wrongCore.embeddedClientCoreManifestSha256 = 'f'.repeat(64);
  assert.throws(() => approvedArchiveRecord(wrongCore, TARGET));
  assert.throws(() => approvedArchiveRecord(f.approval, 'other-target'));
});

test('pure mock staging copies exact bytes once and rejects mismatched inputs', t => {
  const f = fixture(t);
  const inspect = (_bundle, record) => ({ signatureVerified: true,
    identifier: f.approval.helperBundleIdentifier,
    certificateSha256: record.signerCertificateSha256, cdhash: record.cdhash,
    architecture: record.architecture, helperVersion: record.helperVersion,
    joinExistingSession: true });
  const receipt = stageFrozenHelper({ target: TARGET, archive: f.archive,
    extractedBundle: f.bundle, platform: 'darwin', approval: f.approval,
    inspect, output: f.output });
  assert.equal(receipt.staged, true);
  assert.equal(helperTreeDigest(join(f.output, 'credential-helper.xpc')), receipt.treeSha256);
  assert.throws(() => stageFrozenHelper({ target: TARGET, archive: f.archive,
    extractedBundle: f.bundle, platform: 'darwin', approval: f.approval,
    inspect, output: f.output }));
  const otherOutput = join(f.root, 'other-stage');
  writeFileSync(f.archive, 'different archive bytes');
  assert.throws(() => stageFrozenHelper({ target: TARGET, archive: f.archive,
    extractedBundle: f.bundle, platform: 'darwin', approval: f.approval,
    inspect, output: otherOutput }));
  assert.equal(existsSync(otherOutput), false);
  writeFileSync(f.archive, 'inert archive bytes');
  writeFileSync(join(f.bundle, 'Contents', 'Info.plist'), 'changed metadata');
  assert.throws(() => stageFrozenHelper({ target: TARGET, archive: f.archive,
    extractedBundle: f.bundle, platform: 'darwin', approval: f.approval,
    inspect, output: otherOutput }));
  assert.equal(existsSync(otherOutput), false);
});

test('actual signed-helper inspector enforces build version and name-only provenance policy before codesign', t => {
  const f = fixture(t);
  const record = { ...f.approval.archives[TARGET], helperVersion: '1.0.1' };
  function probe(loadCommands, listedAttributes = '') {
    const calls = [];
    const run = (command, args) => {
      calls.push([command, args[0]]);
      if (command === '/usr/libexec/PlistBuddy') {
        return {
          'Print :CFBundleIdentifier': 'org.shortlink.generator.credential-helper',
          'Print :CFBundleExecutable': 'credential-helper',
          'Print :CFBundleShortVersionString': '1.0.1',
          'Print :XPCService:JoinExistingSession': 'true',
        }[args[1]];
      }
      if (command === '/usr/bin/xcrun' && args[0] === 'lipo') return 'arm64';
      if (command === '/usr/bin/xcrun' && args[0] === 'otool') return loadCommands;
      if (command === '/usr/bin/xattr') {
        assert.equal(args.length, 1, 'list names only, never values');
        return listedAttributes;
      }
      if (command === '/usr/bin/codesign') throw new Error('mock stop before signature inspection');
      throw new Error('unexpected native command');
    };
    assert.throws(() => inspectSignedHelper(f.bundle, record, run));
    return calls;
  }
  for (const invalid of [
    VALID_MACOS_11_LOAD_COMMANDS.replace('minos 11.0\n', 'minos 11.0.1\n'),
    VALID_MACOS_11_LOAD_COMMANDS.replace('platform 1\n', 'platform 2\n'),
    VALID_MACOS_11_LOAD_COMMANDS.replace('minos 11.0\n', 'minos 10.15\n')
      .replace('cmdsize 72\n', 'cmdsize 72\n minos 11.0\n'),
  ]) {
    const calls = probe(invalid);
    assert.deepEqual(calls.at(-1), ['/usr/bin/xcrun', 'otool']);
    assert.equal(calls.some(([tool]) => tool === '/usr/bin/codesign'), false);
  }
  for (const rejected of ['com.apple.quarantine\n', 'user.example\n']) {
    const calls = probe(VALID_MACOS_11_LOAD_COMMANDS, rejected);
    assert.equal(calls.at(-1)[0], '/usr/bin/xattr');
    assert.equal(calls.some(([tool]) => tool === '/usr/bin/codesign'), false);
  }
  for (const allowed of ['', 'com.apple.provenance\n']) {
    const calls = probe(VALID_MACOS_11_LOAD_COMMANDS, allowed);
    const examined = calls.filter(([tool]) => tool === '/usr/bin/xattr');
    assert.equal(examined.length, 7, 'bundle root, every directory and every file');
    assert.ok(examined.some(([, path]) => path.endsWith('/Contents/MacOS/credential-helper')));
    assert.ok(examined.some(([, path]) => path.endsWith('/Contents/_CodeSignature/CodeResources')));
    assert.deepEqual(calls.at(-1), ['/usr/bin/codesign', '--verify']);
  }
});

function checkedInFixture(t) {
  const f = fixture(t);
  const archiveRoot = join(f.root, 'archives');
  mkdirSync(archiveRoot);
  copyFileSync(f.archive, join(archiveRoot, `${TARGET}.zip`));
  const inspect = (_bundle, record) => ({ signatureVerified: true,
    identifier: f.approval.helperBundleIdentifier,
    certificateSha256: record.signerCertificateSha256, cdhash: record.cdhash,
    architecture: record.architecture, helperVersion: record.helperVersion,
    joinExistingSession: true });
  return { ...f, archiveRoot, inspect };
}

test('checked-in archive is copied from approved bytes and staged once with temporary extraction removed', t => {
  const f = checkedInFixture(t);
  const calls = [];
  const extract = (archive, destination) => {
    calls.push(archive);
    assert.equal(sha256(readFileSync(archive)), f.approval.archives[TARGET].archiveSha256);
    assert.notEqual(archive, join(f.archiveRoot, `${TARGET}.zip`));
    cpSync(f.bundle, join(destination, 'credential-helper.xpc'), { recursive: true });
  };
  const args = { target: TARGET, platform: 'darwin', approval: f.approval,
    archiveRoot: f.archiveRoot, output: f.output, extract, inspect: f.inspect };
  const result = stageCheckedInFrozenHelper(args);
  assert.equal(result.staged, true);
  assert.equal(calls.length, 1);
  assert.deepEqual(readdirSync(f.output), ['credential-helper.xpc']);
  assert.equal(helperTreeDigest(join(f.output, 'credential-helper.xpc')), result.treeSha256);
  assert.throws(() => stageCheckedInFrozenHelper(args));
  assert.equal(calls.length, 1, 'collision must stop before extraction');
});

test('tampered, linked and unapproved archives stop before extraction', t => {
  const f = checkedInFixture(t);
  let extracts = 0;
  const args = { target: TARGET, platform: 'darwin', approval: f.approval,
    archiveRoot: f.archiveRoot, output: f.output,
    extract: () => { extracts++; }, inspect: f.inspect };
  const archive = join(f.archiveRoot, `${TARGET}.zip`);
  writeFileSync(archive, 'changed');
  assert.throws(() => stageCheckedInFrozenHelper(args));
  assert.equal(extracts, 0);
  assert.equal(existsSync(f.output), false);
  rmSync(archive);
  symlinkSync(f.archive, archive);
  assert.throws(() => stageCheckedInFrozenHelper(args));
  assert.equal(extracts, 0);
  assert.equal(existsSync(f.output), false);
  assert.throws(() => stageCheckedInFrozenHelper({ ...args, approval: loadPinnedApproval() }));
  assert.throws(() => stageCheckedInFrozenHelper({ ...args, target: 'windows-x86_64' }));
  assert.equal(extracts, 0);
});

test('empty, directory, hard-linked and oversized archive inputs fail before extraction', t => {
  const f = checkedInFixture(t);
  let extracts = 0;
  const args = { target: TARGET, platform: 'darwin', approval: f.approval,
    archiveRoot: f.archiveRoot, output: f.output,
    extract: () => { extracts++; }, inspect: f.inspect };
  const archive = join(f.archiveRoot, `${TARGET}.zip`);
  writeFileSync(archive, '');
  assert.throws(() => stageCheckedInFrozenHelper(args));
  rmSync(archive);
  mkdirSync(archive);
  assert.throws(() => stageCheckedInFrozenHelper(args));
  rmSync(archive, { recursive: true });
  copyFileSync(f.archive, archive);
  linkSync(archive, join(f.archiveRoot, 'alias.zip'));
  assert.throws(() => stageCheckedInFrozenHelper(args));
  rmSync(join(f.archiveRoot, 'alias.zip'));
  truncateSync(archive, 128 * 1024 * 1024 + 1);
  assert.throws(() => stageCheckedInFrozenHelper(args));
  assert.equal(extracts, 0);
  assert.equal(existsSync(f.output), false);
});

test('malformed extraction fails closed and removes its temporary bytes', t => {
  const f = checkedInFixture(t);
  const extract = (_archive, destination) => {
    cpSync(f.bundle, join(destination, 'credential-helper.xpc'), { recursive: true });
    writeFileSync(join(destination, 'extra'), 'inert');
  };
  assert.throws(() => stageCheckedInFrozenHelper({ target: TARGET, platform: 'darwin',
    approval: f.approval, archiveRoot: f.archiveRoot, output: f.output,
    extract, inspect: f.inspect }));
  assert.deepEqual(readdirSync(f.output), []);
  assert.throws(() => stageCheckedInFrozenHelper({ target: TARGET, platform: 'darwin',
    approval: f.approval, archiveRoot: f.archiveRoot, output: f.output,
    extract: () => { throw new Error('mock extractor failed'); }, inspect: f.inspect }));
  assert.deepEqual(readdirSync(f.output), []);
});

test('release workflow stages only checked-in target archive before macOS packaging', () => {
  const workflow = readFileSync(resolve(import.meta.dirname, '../.github/workflows/release.yml'), 'utf8');
  const stage = workflow.indexOf('Stage approved frozen macOS credential helper');
  const packageStep = workflow.indexOf('Build installers locally on native runner');
  assert.ok(stage > 0 && packageStep > stage);
  assert.match(workflow.slice(stage, packageStep), /if: runner\.os == 'macOS'[\s\S]*run: node scripts\/stage-macos-credential-helper\.mjs \$\{\{ matrix\.target \}\}/);
  assert.doesNotMatch(workflow, /SLG_MACOS_HELPER_(?:ARCHIVE_PATH|EXTRACTED_BUNDLE_PATH)/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import YAML from 'yaml';
import { isWindowsX64Executable, selectArtifacts } from './native-smoke.mjs';
import { isAppInput, matchingAppInputs } from './release-app-inputs.mjs';
import { updaterPublicKeySha256 } from './updater-signature.mjs';
import { hash } from './macos-signature.mjs';
import { readMacUpdater } from './macos-artifact.mjs';
import { WINDOWS_UPGRADE_BASELINE } from './windows-upgrade-evidence.mjs';
import { artifactEvidence, bundleEntries, CERT_PIN, HELPER_TREE_PIN, nativeSigning, pack, testUpdaterSigner } from './test-fixtures/macos-artifact.mjs';

const root = resolve('.');
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const signer = testUpdaterSigner();
const TEST_PUBLIC_KEY = signer.publicKey;
const TEST_SIGNATURE = signer.sign(Buffer.from('test'));
const TEST_ARCHIVE = pack(bundleEntries());
const TEST_ARCHIVE_SIGNATURE = signer.sign(TEST_ARCHIVE);
const TEST_PUBLIC_KEY_SHA256 = updaterPublicKeySha256(TEST_PUBLIC_KEY);
const MAC_TARGETS = ['aarch64-apple-darwin', 'x86_64-apple-darwin'];
const WINDOWS_TARGET = 'x86_64-pc-windows-msvc';
function fixture(version = '0.1.1') {
  const dir = mkdtempSync(join(tmpdir(), 'release-selective-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ version, type: 'module' }));
  return dir;
}
function put(path, value) { mkdirSync(resolve(path, '..'), { recursive: true }); writeFileSync(path, value); }
// Synthetic native records exercise the strict assembler with signed bytes. They are not native verification.
function putSyntheticHostedCandidate(dir, target, tag, sha) {
  const base = join(dir, 'candidates', `candidate-${target}`);
  const mac = MAC_TARGETS.includes(target);
  const installer = join(base, mac ? 'dmg' : 'nsis', mac ? 'Example.dmg' : 'Example-setup.exe');
  const updater = mac ? join(base, 'macos', 'Example.app.tar.gz') : installer;
  put(installer, `installer-${target}`); put(updater, mac ? TEST_ARCHIVE : 'test');
  put(`${updater}.sig`, mac ? TEST_ARCHIVE_SIGNATURE : TEST_SIGNATURE);
  put(join(base, 'native-smoke.json'), JSON.stringify({ schema: 1, tag, sha, target,
    host: target === MAC_TARGETS[0] ? 'darwin-arm64' : target === MAC_TARGETS[1] ? 'darwin-x64' : 'win32-x64',
    processAlive: true, updaterSignaturePresent: true, updaterSignatureVerified: true,
    updaterSignature: `${updater.split('/').at(-1)}.sig`, updaterSignatureSha256: digest(`${updater}.sig`),
    updaterPublicKeySha256: TEST_PUBLIC_KEY_SHA256, architectureVerified: true,
    signatureVerified: mac ? true : null, windowObserved: mac ? null : true,
    installer: installer.split('/').at(-1), installerSha256: digest(installer),
    ...(mac ? { nativeSigning, macArtifacts: artifactEvidence(readMacUpdater(updater).manifest) } : {}),
    updater: updater.split('/').at(-1), updaterSha256: digest(updater) }));
  return base;
}
// Assembly fixture only: the native checker, not these unit tests, observes Windows.
function putSyntheticWindowsUpgrade(base, tag, sha, installer) {
  const startup = { processAlive: true, windowObserved: true, startupSeconds: 2,
    processExitedAfterObservation: true };
  const evidence = { schema: 1, tag, sha, target: 'x86_64-pc-windows-msvc',
    baselineTag: WINDOWS_UPGRADE_BASELINE.tag,
    baselineInstallerSha256: WINDOWS_UPGRADE_BASELINE.installerSha256,
    baselineSignatureSha256: WINDOWS_UPGRADE_BASELINE.signatureSha256,
    installerSha256: digest(installer), updaterSignatureSha256: digest(`${installer}.sig`),
    updaterPublicKeySha256: TEST_PUBLIC_KEY_SHA256, host: 'win32-x64',
    checkedAt: '2026-10-01T00:00:00.000Z',
    baselineBinarySha256: 'a'.repeat(64), candidateBinarySha256: 'b'.repeat(64),
    startups: { baseline: startup, candidate: { ...startup } }, sameInstallDirectory: true,
    syntheticConfigurationPreserved: true, nativeRoamingAndLocalDataVerified: true,
    processExitConfirmed: true, nsisRegistrationAndShortcutsCleaned: true,
    credentialContinuityTested: false,
    scope: 'NSIS covering installation, exact executable versions, two native windows and saved synthetic configuration' };
  put(join(base, 'windows-upgrade-smoke.json'), JSON.stringify(evidence));
}

test('dispatch selection defaults to Windows and preserves explicit native targets', () => {
  const dir = fixture();
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
    git('init', '-q'); git('config', 'user.name', 'Example'); git('config', 'user.email', 'example@example.org');
    git('add', '.'); git('commit', '-qm', 'fixture'); git('tag', 'v0.1.1');
    const runners = { [MAC_TARGETS[0]]: 'macos-15', [MAC_TARGETS[1]]: 'macos-15-intel', [WINDOWS_TARGET]: 'windows-2022' };
    for (const [target, expected] of [
      [undefined, [WINDOWS_TARGET]], ['windows', [WINDOWS_TARGET]],
      ['mac-arm', [MAC_TARGETS[0]]], ['mac-intel', [MAC_TARGETS[1]]],
      ['windows-intel', [WINDOWS_TARGET, MAC_TARGETS[1]]], ['mac', MAC_TARGETS],
      ['all', [...MAC_TARGETS, WINDOWS_TARGET]],
    ]) {
      const output = join(dir, 'output');
      writeFileSync(output, '');
      const run = spawnSync(process.execPath, [join(root, 'scripts/release-config.mjs'), '--validate-tag'], {
        cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.1', RELEASE_TARGET: target, GITHUB_OUTPUT: output },
      });
      assert.equal(run.status, 0, run.stderr);
      const builds = JSON.parse(readFileSync(output, 'utf8').match(/^builds=(.+)$/m)[1]);
      assert.deepEqual(builds.map(build => build.target), expected);
      assert.deepEqual(builds.map(build => build.os), expected.map(item => runners[item]));
      assert.deepEqual(builds.map(build => build.bundles), expected.map(item => item.includes('windows') ? 'nsis' : 'app,dmg'));
    }
    const invalid = spawnSync(process.execPath, [join(root, 'scripts/release-config.mjs'), '--validate-tag'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.1', RELEASE_TARGET: 'unknown', GITHUB_OUTPUT: join(dir, 'output') },
    });
    assert.notEqual(invalid.status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('native smoke selects signed packages and identifies x64 PE files', () => {
  const dir = fixture();
  try {
    const dmg = join(dir, 'dmg', 'Example.dmg');
    const tar = join(dir, 'macos', 'Example.app.tar.gz');
    put(dmg, 'installer'); put(tar, 'updater'); put(`${tar}.sig`, 'signature');
    assert.deepEqual([selectArtifacts(dir, 'aarch64-apple-darwin').installer, selectArtifacts(dir, 'aarch64-apple-darwin').updater], [dmg, tar]);
    const exe = join(dir, 'nsis', 'Example-setup.exe');
    put(exe, 'installer'); put(`${exe}.sig`, 'signature');
    assert.equal(selectArtifacts(dir, 'x86_64-pc-windows-msvc').updater, exe);
    rmSync(`${exe}.sig`);
    assert.throws(() => selectArtifacts(dir, 'x86_64-pc-windows-msvc'), /signature/);
    const pe = Buffer.alloc(128);
    pe.write('MZ'); pe.writeUInt32LE(64, 0x3c); pe.write('PE\0\0', 64); pe.writeUInt16LE(0x8664, 68);
    put(join(dir, 'binary.exe'), pe);
    assert.equal(isWindowsX64Executable(join(dir, 'binary.exe')), true);
    pe.writeUInt16LE(0x14c, 68); put(join(dir, 'binary.exe'), pe);
    assert.equal(isWindowsX64Executable(join(dir, 'binary.exe')), false);
    put(`${exe}.sig`, 'signature');
    const blocked = spawnSync(process.execPath, [join(root, 'scripts/native-smoke.mjs'), dir, 'x86_64-pc-windows-msvc'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, GITHUB_ACTIONS: '', RUNNER_ENVIRONMENT: '' },
    });
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /GitHub-hosted runner/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('strict assembly checks source and artifact hashes and includes latest.json in SHA256SUMS', () => {
  const dir = fixture('0.1.6');
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', encoding: 'utf8' }).trim();
    git('init', '-q'); git('config', 'user.name', 'Example'); git('config', 'user.email', 'example@example.org');
    git('add', '.'); git('commit', '-qm', 'fixture'); git('tag', 'v0.1.6');
    const sha = git('rev-parse', 'HEAD');
    for (const target of MAC_TARGETS) putSyntheticHostedCandidate(dir, target, 'v0.1.6', sha);
    const windowsBase = putSyntheticHostedCandidate(dir, WINDOWS_TARGET, 'v0.1.6', sha);
    put(join(windowsBase, 'msi', 'Example.msi'), 'unverified alternate installer');
    const run = (extraEnv = {}) => spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', '--require-evidence'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.6', RELEASE_SHA: sha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: TEST_PUBLIC_KEY, SLG_MACOS_CERT_SHA256: CERT_PIN,
        SLG_MACOS_HELPER_TREE_SHA256_ARM64: HELPER_TREE_PIN, SLG_MACOS_HELPER_TREE_SHA256_X64: HELPER_TREE_PIN, ...extraEnv },
    });
    assert.match(run().stderr, /Missing exact Windows upgrade evidence/);
    assert.equal(existsSync(join(dir, 'latest.json')), false);
    putSyntheticWindowsUpgrade(windowsBase, 'v0.1.6', sha, join(windowsBase, 'nsis', 'Example-setup.exe'));
    assert.equal(run().status, 0);
    const windowsUpgradeEvidence = join(windowsBase, 'windows-upgrade-smoke.json');
    const passedWindowsUpgrade = readFileSync(windowsUpgradeEvidence, 'utf8');
    put(windowsUpgradeEvidence, JSON.stringify({ ...JSON.parse(passedWindowsUpgrade), syntheticConfigurationPreserved: false }));
    assert.match(run().stderr, /cleanup evidence is incomplete/);
    put(windowsUpgradeEvidence, JSON.stringify({ ...JSON.parse(passedWindowsUpgrade), installerSha256: 'f'.repeat(64) }));
    assert.match(run().stderr, /does not bind the exact signed candidate/);
    put(windowsUpgradeEvidence, passedWindowsUpgrade);
    const windowsEvidence = join(dir, 'candidates', 'candidate-x86_64-pc-windows-msvc', 'native-smoke.json');
    const passedWindowsEvidence = readFileSync(windowsEvidence, 'utf8');
    const toolchain = { node: '24.10.0', npm: '11.6.0',
      rustc: 'rustc 1.90.0 (123456789 2025-09-18)', cargo: 'cargo 1.90.0 (abcdef123 2025-09-18)' };
    put(windowsEvidence, JSON.stringify({ ...JSON.parse(passedWindowsEvidence), toolchain }));
    assert.equal(run().status, 0);
    put(windowsEvidence, JSON.stringify({ ...JSON.parse(passedWindowsEvidence),
      toolchain: { ...toolchain, npm: '11.6.0\nsynthetic-private-diagnostic' } }));
    assert.match(run().stderr, /Invalid npm version evidence/);
    rmSync(windowsEvidence);
    assert.match(run().stderr, /Missing unique native startup evidence/);
    put(windowsEvidence, JSON.stringify({ ...JSON.parse(passedWindowsEvidence), windowObserved: false }));
    assert.match(run().stderr, /Native runner evidence is invalid/);
    put(windowsEvidence, passedWindowsEvidence);
    assert.equal(run().status, 0);
    // These synthetic records prove assembly policy, not native codesign execution.
    const macPaths = ['aarch64-apple-darwin', 'x86_64-apple-darwin'].map(target => join(dir, 'candidates', `candidate-${target}`, 'native-smoke.json'));
    const originals = macPaths.map(path => readFileSync(path, 'utf8'));
    assert.notEqual(run({ SLG_MACOS_CERT_SHA256: 'f'.repeat(64) }).status, 0);
    assert.notEqual(run({ SLG_MACOS_CERT_SHA256: '' }).status, 0);
    for (const patch of [
      { nativeSigning: undefined }, { macArtifacts: undefined },
      { nativeSigning: { ...nativeSigning, designatedRequirement: 'identifier org.shortlink.generator', designatedRequirementSha256: hash('identifier org.shortlink.generator') } },
      ...[
        { bundleManifestSha256: 'a'.repeat(64) }, { entryCount: 999 }, { updaterBundleVerified: false },
        { contentMatchVerified: false }, { modesMatchVerified: false }, { updaterSigning: undefined },
        { updaterSigning: { ...nativeSigning, certificateSha256: 'f'.repeat(64) } },
        { buildBundleCompared: false, buildSigning: undefined },
      ].map(patch => ({ macArtifacts: { ...JSON.parse(originals[0]).macArtifacts, ...patch } })),
    ]) {
      put(macPaths[0], JSON.stringify({ ...JSON.parse(originals[0]), ...patch }));
      assert.notEqual(run().status, 0);
    }
    macPaths.forEach((path, i) => put(path, originals[i]));
    assert.equal(run().status, 0);
    const sums = readFileSync(join(dir, 'SHA256SUMS'), 'utf8');
    assert.match(sums, new RegExp(`${digest(join(dir, 'latest.json'))}  latest\\.json`));
    assert.equal(sums.includes('.sig'), false);
    assert.equal(sums.includes('.msi'), false);
    const extra = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'other.exe');
    put(extra, 'unreviewed executable');
    assert.match(run().stderr, /Unreviewed publishable artifact/);
    rmSync(extra);
    const extraSignature = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'other.exe.sig');
    put(extraSignature, 'unreviewed signature');
    assert.match(run().stderr, /Unreviewed updater signature/);
    rmSync(extraSignature);
    const updater = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'macos', 'Example.app.tar.gz');
    // Re-sign altered tar bytes and update outer hashes: only the inner bundle gate can reject these.
    const originalEvidence = JSON.parse(originals[0]);
    for (const entries of [
      bundleEntries().map(entry => entry.path.endsWith('Info.plist') ? { ...entry, data: 'different' } : entry),
      bundleEntries().map(entry => entry.path.endsWith('short-link-generator') ? { ...entry, mode: 0o644 } : entry),
      bundleEntries().filter(entry => !entry.path.endsWith('Info.plist')),
      [...bundleEntries(), { path: 'Example.app/extra', data: 'extra' }],
      [...bundleEntries(), { path: 'Example.app/../outside', data: 'unsafe' }],
    ]) {
      const changed = pack(entries); put(updater, changed); put(`${updater}.sig`, signer.sign(changed));
      put(macPaths[0], JSON.stringify({ ...originalEvidence, updaterSha256: digest(updater), updaterSignatureSha256: digest(`${updater}.sig`) }));
      const rejected = run(); assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, /does not match its native comparison evidence|Unsafe or unsupported/);
    }
    put(updater, TEST_ARCHIVE); put(`${updater}.sig`, TEST_ARCHIVE_SIGNATURE); put(macPaths[0], originals[0]);
    put(updater, 'tampered updater');
    assert.notEqual(run().status, 0);
    put(updater, TEST_ARCHIVE);
    const signature = `${updater}.sig`;
    const validSignature = readFileSync(signature, 'utf8');
    put(signature, 'NOT_A_SIGNATURE');
    assert.notEqual(run().status, 0);
    put(signature, validSignature);
    const wrongKey = testUpdaterSigner().publicKey;
    const wrongKeyRun = spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', '--require-evidence'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.6', RELEASE_SHA: sha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: wrongKey },
    });
    assert.notEqual(wrongKeyRun.status, 0);
    const bad = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'native-smoke.json');
    const evidence = JSON.parse(readFileSync(bad, 'utf8')); evidence.sha = 'b'.repeat(40); put(bad, JSON.stringify(evidence));
    assert.notEqual(run().status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('Mac-only assembly requires both signed Mac candidates and rejects mixed inputs', () => {
  const dir = fixture('0.1.6');
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', encoding: 'utf8' }).trim();
    git('init', '-q'); git('config', 'user.name', 'Example'); git('config', 'user.email', 'example@example.org');
    git('add', '.'); git('commit', '-qm', 'fixture'); git('tag', 'v0.1.6');
    const sha = git('rev-parse', 'HEAD');
    const [arm, intel] = MAC_TARGETS.map(target => putSyntheticHostedCandidate(dir, target, 'v0.1.6', sha));
    const run = (...args) => spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', ...args], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.6', RELEASE_SHA: sha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: TEST_PUBLIC_KEY, SLG_MACOS_CERT_SHA256: CERT_PIN,
        SLG_MACOS_HELPER_TREE_SHA256_ARM64: HELPER_TREE_PIN, SLG_MACOS_HELPER_TREE_SHA256_X64: HELPER_TREE_PIN },
    });
    const macOnly = () => run('--require-evidence', '--platforms=macos');
    assert.match(run('--require-evidence').stderr, /Missing unique native startup evidence for x86_64-pc-windows-msvc/);
    for (const [base, target] of [[arm, MAC_TARGETS[0]], [intel, MAC_TARGETS[1]]]) {
      const held = join(dir, 'held');
      renameSync(base, held);
      assert.match(macOnly().stderr, new RegExp(`Missing unique native startup evidence for ${target}`));
      renameSync(held, base);
    }
    const windows = putSyntheticHostedCandidate(dir, WINDOWS_TARGET, 'v0.1.6', sha);
    assert.match(macOnly().stderr, /only the two macOS candidate folders/);
    rmSync(windows, { recursive: true });
    const extra = join(arm, 'macos', 'Unexpected.msi');
    put(extra, 'unreviewed alternate installer');
    assert.match(macOnly().stderr, /Unreviewed Mac-only candidate file/);
    rmSync(extra);
    const signature = join(intel, 'macos', 'Example.app.tar.gz.sig');
    put(signature, 'broken signature');
    assert.notEqual(macOnly().status, 0);
    put(signature, TEST_ARCHIVE_SIGNATURE);
    for (const args of [
      ['--platforms=macos'], ['--require-evidence', '--platforms=windows'],
      ['--require-evidence', '--platforms=macos', '--platforms=all'],
      ['--require-evidence', '--platforms'], ['--require-evidence', '--platform=macos'],
      ['--require-evidence', 'second-directory', '--platforms=macos'],
    ]) assert.notEqual(run(...args).status, 0, args.join(' '));
    assert.equal(existsSync(join(dir, 'latest.json')), false);
    assert.equal(existsSync(join(dir, 'release-assets')), false);

    // Real build artifacts include Tauri's staging files; they must not be published.
    put(join(arm, 'dmg', 'bundle_dmg.sh'), 'fixture support script');
    put(join(arm, 'dmg', 'icon.icns'), 'fixture icon');
    put(join(intel, 'share', 'create-dmg', 'support', 'template.applescript'), 'fixture DMG template');
    put(join(intel, 'macos', 'Example.app', 'Contents', 'Info.plist'), 'fixture build app');
    const stale = join(dir, 'release-assets', 'previous_windows-x86_64.exe');
    put(stale, 'stale installer');
    assert.match(macOnly().stderr, /needs an empty release-assets directory/);
    rmSync(stale);
    const result = macOnly();
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(readFileSync(join(dir, 'latest.json'), 'utf8'));
    assert.deepEqual(Object.keys(manifest.platforms), ['darwin-aarch64', 'darwin-x86_64']);
    const expectedAssets = Object.keys(manifest.platforms).flatMap(platform =>
      ['.dmg', '.app.tar.gz', '.app.tar.gz.sig'].map(suffix => `short-link-generator_0.1.6_${platform}${suffix}`));
    assert.deepEqual(readdirSync(join(dir, 'release-assets')).sort(), expectedAssets.toSorted());
    const uploads = JSON.parse(readFileSync(join(dir, 'release-assets.json'), 'utf8'));
    assert.deepEqual(uploads, [...expectedAssets.map(name => join('release-assets', name)), 'latest.json', 'SHA256SUMS']);
    const sums = readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trimEnd().split('\n');
    assert.deepEqual(sums, uploads.filter(path => !path.endsWith('.sig') && path !== 'SHA256SUMS')
      .map(path => `${digest(join(dir, path))}  ${path.split('/').at(-1)}`));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('manual ARM reuse derives the application tree from both commits and rejects dirty inputs', () => {
  const dir = fixture('0.1.6');
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', encoding: 'utf8' }).trim();
    const inputs = {
      'index.html': '<html></html>', 'package-lock.json': '{}', 'vite.config.ts': 'export default {};',
      'tsconfig.json': '{}', 'LICENSE': 'fixture', 'THIRD-PARTY-NOTICES.md': 'fixture',
      'src/App.tsx': 'export default null;',
      'src-tauri/tauri.conf.json': JSON.stringify({ bundle: { macOS: { minimumSystemVersion: '11.0' } } }),
      'edge/worker.mjs': 'export default {};', 'public/app-icon.svg': '<svg/>',
    };
    for (const [path, content] of Object.entries(inputs)) put(join(dir, path), content);
    git('init', '-q'); git('config', 'user.name', 'Example'); git('config', 'user.email', 'example@example.org');
    git('add', '.'); git('commit', '-qm', 'built application');
    const buildSha = git('rev-parse', 'HEAD');
    put(join(dir, 'docs', 'release-only.md'), 'release guide');
    git('add', '.'); git('commit', '-qm', 'release process'); git('tag', 'v0.1.6');
    const reviewedSha = git('rev-parse', 'HEAD');
    const expected = matchingAppInputs(buildSha, reviewedSha, dir);
    assert.equal(expected.fileCount, 11);
    assert.equal(isAppInput('src-tauri/icons/icon.icns'), true);
    assert.equal(isAppInput('edge/worker.mjs'), true);
    assert.equal(isAppInput('.cargo/config.toml'), true);
    assert.equal(isAppInput('tsconfig.build.json'), true);
    assert.equal(isAppInput('.npmrc'), true);
    assert.equal(isAppInput('public/local.tsbuildinfo'), true);
    assert.equal(isAppInput('tsconfig.tsbuildinfo'), false);
    assert.equal(isAppInput('docs/release-only.md'), false);
    for (const target of ['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc']) {
      const base = join(dir, 'candidates', `candidate-${target}`);
      const mac = target.includes('apple');
      const installer = join(base, mac ? 'dmg' : 'nsis', mac ? 'Example.dmg' : 'Example-setup.exe');
      const updater = mac ? join(base, 'macos', 'Example.app.tar.gz') : installer;
      put(installer, `installer-${target}`); put(updater, mac ? TEST_ARCHIVE : 'test');
      put(`${updater}.sig`, mac ? TEST_ARCHIVE_SIGNATURE : TEST_SIGNATURE);
      const evidence = { tag: 'v0.1.6', target,
        host: target === 'aarch64-apple-darwin' ? 'darwin-arm64' : target === 'x86_64-apple-darwin' ? 'darwin-x64' : 'win32-x64',
        processAlive: true, updaterSignaturePresent: true, updaterSignatureVerified: true,
        updaterSignature: `${updater.split('/').at(-1)}.sig`, updaterSignatureSha256: digest(`${updater}.sig`),
        updaterPublicKeySha256: TEST_PUBLIC_KEY_SHA256, architectureVerified: true,
        signatureVerified: mac ? true : null, windowObserved: mac ? null : true,
        installer: installer.split('/').at(-1), installerSha256: digest(installer),
        ...(mac ? { nativeSigning, macArtifacts: artifactEvidence(readMacUpdater(updater).manifest) } : {}),
        updater: updater.split('/').at(-1), updaterSha256: digest(updater) };
      if (target === 'aarch64-apple-darwin') Object.assign(evidence, {
        schema: 2, method: 'manual-local', reviewedSha, buildSha, osVersion: '26.5.3',
        guiObserved: true, updaterSignatureVerified: true,
        minimumSystemVersionMetadata: '11.0', minimumSystemRuntimeTested: true,
        minimumSystemRuntime: {
          osVersion: '11.0.0', host: 'darwin-arm64', architectureVerified: true,
          processAlive: true, guiObserved: true, reportSha256: 'd'.repeat(64),
          installerSha256: digest(installer), updaterSha256: digest(updater),
        },
        nativeSigning: {
          ...nativeSigning, reportSha256: 'e'.repeat(64),
        },
        environmentVerification: {
          differencesReviewed: true, compatibleWithRelease: true, reportSha256: 'f'.repeat(64),
        },
        appInputManifestSha256: expected.sha256, appInputFileCount: expected.fileCount,
        buildConfiguration: {
          releaseConfigSha256: 'a'.repeat(64), updaterPublicKeySha256: TEST_PUBLIC_KEY_SHA256,
          updaterEndpoint: 'https://github.com/sample/short-link-generator/releases/latest/download/latest.json',
          encodedRustflagsSha256: 'c'.repeat(64), normalizedRustflags: ['workspace-path-remap', 'home-path-remap'],
        },
      });
      else Object.assign(evidence, { schema: 1, sha: reviewedSha });
      put(join(base, 'native-smoke.json'), JSON.stringify(evidence));
      if (!mac) putSyntheticWindowsUpgrade(base, 'v0.1.6', reviewedSha, installer);
    }
    const evidenceFile = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'native-smoke.json');
    const run = (releaseSha = reviewedSha) => spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', '--require-evidence'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.6', RELEASE_SHA: releaseSha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: TEST_PUBLIC_KEY, SLG_MACOS_CERT_SHA256: CERT_PIN,
        SLG_MACOS_HELPER_TREE_SHA256_ARM64: HELPER_TREE_PIN, SLG_MACOS_HELPER_TREE_SHA256_X64: HELPER_TREE_PIN },
    });
    const assembled = run();
    assert.equal(assembled.status, 0, assembled.stderr);
    const valid = JSON.parse(readFileSync(evidenceFile, 'utf8'));
    // These are synthetic attestations only; no test here proves real macOS compatibility or signing.
    for (const [label, patch, expectedError] of [
      ['malformed host OS', { osVersion: 'unknown' }, /Manual local ARM evidence is incomplete/],
      ['host older than minimum', { osVersion: '10.15.7' }, /minimum-system runtime evidence/],
      ['wrong metadata minimum', { minimumSystemVersionMetadata: '12.0' }, /minimum-system runtime evidence/],
      ['metadata-only historical evidence', { osVersion: '26.5.2', minimumSystemRuntimeTested: false }, /minimum-system runtime evidence/],
      ['missing runtime record', { minimumSystemRuntime: undefined }, /minimum-system runtime evidence/],
      ...[
        ['newer runtime OS', { osVersion: '11.1' }],
        ['newer runtime patch', { osVersion: '11.0.1' }],
        ['older runtime OS', { osVersion: '10.15.7' }],
        ['wrong native host', { host: 'darwin-x64' }],
        ['unverified architecture', { architectureVerified: false }],
        ['unobserved minimum-system GUI', { guiObserved: false }],
        ['failed minimum-system startup', { processAlive: false }],
        ['missing runtime report', { reportSha256: undefined }],
        ['non-string runtime report hash', { reportSha256: ['d'.repeat(64)] }],
        ['different installer', { installerSha256: 'a'.repeat(64) }],
        ['different updater', { updaterSha256: 'a'.repeat(64) }],
      ].map(([label, patch]) => [label, { minimumSystemRuntime: { ...valid.minimumSystemRuntime, ...patch } }, /minimum-system runtime evidence/]),
      ['missing signing record', { nativeSigning: undefined }, /native signing and notarization status/],
      ...[
        ['unknown signing identity', { identity: 'unknown' }],
        ['unverified signing identity', { identityVerified: false }],
        ['unknown notarization status', { notarization: 'unknown' }],
        ['contradictory notarization claim', { notarization: 'verified' }],
        ['missing signing report', { reportSha256: undefined }],
      ].map(([label, patch]) => [label, { nativeSigning: { ...valid.nativeSigning, ...patch } }, /native signing and notarization status/]),
      ['missing environment record', { environmentVerification: undefined }, /build-environment differences/],
      ...[
        ['unreviewed environment differences', { differencesReviewed: false }],
        ['incompatible environment', { compatibleWithRelease: false }],
        ['missing environment report', { reportSha256: undefined }],
      ].map(([label, patch]) => [label, { environmentVerification: { ...valid.environmentVerification, ...patch } }, /build-environment differences/]),
    ]) {
      put(evidenceFile, JSON.stringify({ ...valid, ...patch }));
      const rejected = run();
      assert.notEqual(rejected.status, 0, label);
      assert.match(rejected.stderr, expectedError, label);
    }
    // Host OS snapshots may change. Equivalent zero-patch metadata remains the same minimum.
    for (const patch of [
      { osVersion: '15.7', minimumSystemVersionMetadata: '11.0.0' },
      { minimumSystemRuntime: { ...valid.minimumSystemRuntime, osVersion: '11.0' } },
    ]) {
      put(evidenceFile, JSON.stringify({ ...valid, ...patch }));
      const accepted = run();
      assert.equal(accepted.status, 0, accepted.stderr);
    }
    for (const identity of ['ad-hoc', 'developer-id']) {
      put(evidenceFile, JSON.stringify({ ...valid, nativeSigning: { ...valid.nativeSigning, identity } }));
      assert.match(run().stderr, /Stable macOS signing evidence/);
    }
    // A freshly built and manually verified local package can use the reviewed commit itself.
    put(evidenceFile, JSON.stringify({ ...valid, buildSha: reviewedSha }));
    const sameCommit = run();
    assert.equal(sameCommit.status, 0, sameCommit.stderr);
    put(evidenceFile, JSON.stringify({ ...valid, buildSha: 'b'.repeat(40) }));
    assert.notEqual(run().status, 0);
    put(evidenceFile, JSON.stringify({ ...valid, reviewedSha: buildSha }));
    assert.notEqual(run().status, 0);
    put(evidenceFile, JSON.stringify(valid));
    put(join(dir, 'src', 'new.ts'), 'untracked source');
    assert.throws(() => matchingAppInputs(buildSha, reviewedSha, dir), /local changes/);
    assert.notEqual(run().status, 0);
    rmSync(join(dir, 'src', 'new.ts'));
    put(join(dir, '.env.production'), 'VITE_EXAMPLE=fixture');
    assert.throws(() => matchingAppInputs(buildSha, reviewedSha, dir), /Vite environment/);
    rmSync(join(dir, '.env.production'));
    const exclude = join(dir, '.git', 'info', 'exclude');
    writeFileSync(exclude, `${readFileSync(exclude, 'utf8')}\n*.pem\n.npmrc\n*.tsbuildinfo\n`);
    put(join(dir, 'public', 'local.pem'), 'ignored fixture');
    assert.throws(() => matchingAppInputs(buildSha, reviewedSha, dir), /Ignored files inside application inputs/);
    rmSync(join(dir, 'public', 'local.pem'));
    put(join(dir, '.npmrc'), 'ignore-scripts=false');
    assert.throws(() => matchingAppInputs(buildSha, reviewedSha, dir), /Ignored files inside application inputs/);
    rmSync(join(dir, '.npmrc'));
    put(join(dir, 'tsconfig.tsbuildinfo'), 'generated compiler metadata');
    assert.deepEqual(matchingAppInputs(buildSha, reviewedSha, dir), expected);
    put(join(dir, 'public', 'local.tsbuildinfo'), 'ignored public fixture');
    assert.throws(() => matchingAppInputs(buildSha, reviewedSha, dir), /Ignored files inside application inputs/);
    rmSync(join(dir, 'public', 'local.tsbuildinfo'));
    put(join(dir, '.cargo', 'config.toml'), '[build]\nrustflags=[]\n');
    git('add', '.cargo/config.toml'); git('commit', '-qm', 'changed Rust build configuration');
    const cargoSha = git('rev-parse', 'HEAD');
    assert.throws(() => matchingAppInputs(buildSha, cargoSha, dir), /changed between/);
    put(join(dir, 'src', 'App.tsx'), 'changed app');
    git('add', 'src/App.tsx'); git('commit', '-qm', 'changed application');
    const changedSha = git('rev-parse', 'HEAD');
    assert.throws(() => matchingAppInputs(buildSha, changedSha, dir), /changed between/);
    assert.throws(() => matchingAppInputs('b'.repeat(40), reviewedSha, dir));
    // A synthetic future policy proves that the gate reads the reviewed config, not a fixed OS floor.
    // The application's real minimum remains unchanged by this fixture.
    put(join(dir, 'src-tauri', 'tauri.conf.json'), JSON.stringify({ bundle: { macOS: { minimumSystemVersion: '12.3' } } }));
    git('add', 'src-tauri/tauri.conf.json'); git('commit', '-qm', 'synthetic minimum-system policy');
    const policySha = git('rev-parse', 'HEAD');
    git('tag', '-d', 'v0.1.6'); git('tag', 'v0.1.6');
    const policyInputs = matchingAppInputs(policySha, policySha, dir);
    const policyEvidence = { ...valid, buildSha: policySha, reviewedSha: policySha,
      appInputManifestSha256: policyInputs.sha256, appInputFileCount: policyInputs.fileCount,
      minimumSystemVersionMetadata: '12.3', minimumSystemRuntime: { ...valid.minimumSystemRuntime, osVersion: '12.3' },
    };
    put(evidenceFile, JSON.stringify(policyEvidence));
    for (const target of ['x86_64-apple-darwin', 'x86_64-pc-windows-msvc']) {
      const path = join(dir, 'candidates', `candidate-${target}`, 'native-smoke.json');
      put(path, JSON.stringify({ ...JSON.parse(readFileSync(path, 'utf8')), sha: policySha }));
    }
    const windowsBase = join(dir, 'candidates', 'candidate-x86_64-pc-windows-msvc');
    putSyntheticWindowsUpgrade(windowsBase, 'v0.1.6', policySha, join(windowsBase, 'nsis', 'Example-setup.exe'));
    const configuredMinimum = run(policySha);
    assert.equal(configuredMinimum.status, 0, configuredMinimum.stderr);
    put(evidenceFile, JSON.stringify({ ...policyEvidence,
      minimumSystemVersionMetadata: '11.0', minimumSystemRuntime: valid.minimumSystemRuntime,
    }));
    assert.match(run(policySha).stderr, /minimum-system runtime evidence/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('release workflow is manual, selective, and scans before one-day upload', () => {
  const release = YAML.parse(readFileSync('.github/workflows/release.yml', 'utf8'));
  assert.deepEqual(Object.keys(release.on), ['workflow_dispatch']);
  assert.equal(release.on.workflow_dispatch.inputs.target.default, 'windows');
  const targets = release.on.workflow_dispatch.inputs.target.options;
  assert.deepEqual(targets, ['windows', 'mac-arm', 'mac-intel', 'windows-intel', 'mac', 'all']);
  assert.match(release.jobs.build.strategy.matrix.include, /fromJSON\(needs.prepare.outputs.builds\)/);
  const drafts = Function('inputs', `return (${release.jobs.draft.if})`);
  assert.deepEqual(targets.filter(target => drafts({ target })), ['mac', 'all']);
  assert.deepEqual(release.jobs.draft.needs, ['prepare', 'build']);
  const steps = release.jobs.build.steps;
  const smoke = steps.findIndex(step => step.name?.includes('startup') || step.name?.includes('Install and launch'));
  const scan = steps.findIndex(step => step.name?.includes('Inspect candidate'));
  const upload = steps.findIndex(step => step.uses?.startsWith('actions/upload-artifact@'));
  assert.ok(smoke >= 0 && scan > smoke && upload > scan);
  assert.equal(steps.find(step => step.name === 'Build installers locally on native runner').id, 'package');
  assert.equal(steps[smoke].id, 'native_smoke');
  assert.equal(steps[smoke].env.SLG_UPDATER_PUBLIC_KEY, '${{ vars.UPDATER_PUBLIC_KEY }}');
  assert.equal(steps[smoke].env.SLG_MACOS_CERT_SHA256, '${{ vars.MACOS_SIGNING_CERT_SHA256 }}');
  assert.equal(steps[smoke].env.SLG_MACOS_HELPER_TREE_SHA256_ARM64, '${{ vars.MACOS_HELPER_TREE_SHA256_ARM64 }}');
  assert.equal(steps[smoke].env.SLG_MACOS_HELPER_TREE_SHA256_X64, '${{ vars.MACOS_HELPER_TREE_SHA256_X64 }}');
  const baseline = steps.findIndex(step => step.name === 'Download the pinned public Windows upgrade baseline');
  const upgrade = steps.findIndex(step => step.id === 'windows_upgrade');
  assert.ok(baseline >= 0 && upgrade > baseline && smoke > upgrade);
  assert.equal(steps[baseline].if, "runner.os == 'Windows'");
  assert.match(steps[baseline].run, /gh release download v0\.1\.5/);
  assert.match(steps[baseline].run, /LASTEXITCODE -ne 0/);
  assert.equal(steps[upgrade].if, "runner.os == 'Windows'");
  assert.equal(steps[upgrade].env.SLG_UPDATER_PUBLIC_KEY, '${{ vars.UPDATER_PUBLIC_KEY }}');
  assert.equal(steps[upgrade].env.RELEASE_SHA, '${{ needs.prepare.outputs.sha }}');
  assert.match(steps[upgrade].run, /windows-upgrade-smoke\.mjs "\$baselineInstaller" src-tauri\/target/);
  assert.match(steps[upgrade].run, /LASTEXITCODE -ne 0/);
  const packageStep = steps.find(step => step.id === 'package');
  const signerStep = steps.find(step => step.name === 'Prepare pinned macOS signing tool');
  const helperStageStep = steps.find(step => step.name === 'Stage approved frozen macOS credential helper');
  assert.ok(steps.indexOf(signerStep) < steps.indexOf(packageStep));
  assert.ok(steps.indexOf(signerStep) < steps.indexOf(helperStageStep) && steps.indexOf(helperStageStep) < steps.indexOf(packageStep));
  assert.equal(helperStageStep.if, "runner.os == 'macOS'");
  assert.match(helperStageStep.run, /stage-macos-credential-helper\.mjs.*matrix\.target/);
  assert.equal(helperStageStep.env, undefined);
  const helperStageSource = readFileSync(join(root, 'scripts/stage-macos-credential-helper.mjs'), 'utf8');
  assert.match(helperStageSource, /checkedInArchiveRoot = resolve\(scriptDir, '\.\.\/src-tauri\/native\/credential-helper-archives'\)/);
  assert.match(helperStageSource, /archive = join\(archiveRoot, `\$\{target\}\.zip`\)/);
  assert.equal(signerStep.if, "runner.os == 'macOS'");
  assert.equal(signerStep.env, undefined);
  assert.equal(signerStep.run, 'node scripts/rcodesign-tool.mjs --install');
  assert.match(packageStep.run, /ulimit -S -c 0\s+ulimit -H -c 0\s+node scripts\/stable-macos-sign/);
  assert.match(packageStep.run, /stable-macos-sign\.mjs -- npm run tauri/);
  assert.ok(packageStep.run.includes("${{ matrix.target == 'x86_64-apple-darwin' && '--verbose' || '' }}"));
  assert.match(packageStep.env.SLG_MACOS_SIGNING_P12_BASE64, /runner\.os == 'macOS'/);
  assert.equal(steps[scan].id, 'privacy');
  assert.match(steps[scan].env.SLG_MACOS_SIGNING_P12_BASE64, /runner\.os == 'macOS'/);
  assert.match(steps[scan].env.SLG_MACOS_SIGNING_P12_PASSWORD, /runner\.os == 'macOS'/);
  assert.match(steps[scan].run, /ulimit -S -c 0\s+ulimit -H -c 0/);
  assert.equal(steps[scan].if, "${{ !cancelled() && steps.package.outcome == 'success' }}");
  assert.equal(steps[upload].if, "${{ !cancelled() && steps.native_smoke.outcome == 'success' && steps.privacy.outcome == 'success' && (runner.os != 'Windows' || steps.windows_upgrade.outcome == 'success') }}");
  assert.equal(steps[upload].with['retention-days'], 1);
  const assemble = release.jobs.draft.steps.find(step => step.name?.includes('assemble the draft assets'));
  assert.equal(assemble.env.SLG_UPDATER_PUBLIC_KEY, '${{ vars.UPDATER_PUBLIC_KEY }}');
  assert.equal(assemble.env.SLG_MACOS_CERT_SHA256, '${{ vars.MACOS_SIGNING_CERT_SHA256 }}');
  assert.equal(assemble.env.SLG_MACOS_HELPER_TREE_SHA256_ARM64, '${{ vars.MACOS_HELPER_TREE_SHA256_ARM64 }}');
  assert.equal(assemble.env.SLG_MACOS_HELPER_TREE_SHA256_X64, '${{ vars.MACOS_HELPER_TREE_SHA256_X64 }}');
  assert.equal(assemble.run, "node scripts/release-manifest.mjs candidates --require-evidence ${{ inputs.target == 'mac' && '--platforms=macos' || '' }}");
  assert.equal(release.jobs.draft.steps.at(-1).run, 'node scripts/publish-draft.mjs');
  assert.match(readFileSync(join(root, 'scripts/publish-draft.mjs'), 'utf8'), /'--verify-tag','--draft'/);
  assert.equal(existsSync('.github/workflows/release.yml'), true);
});

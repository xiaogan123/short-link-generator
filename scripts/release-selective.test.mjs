import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import YAML from 'yaml';
import { isWindowsX64Executable, selectArtifacts } from './native-smoke.mjs';
import { isAppInput, matchingAppInputs } from './release-app-inputs.mjs';
import { updaterPublicKeySha256 } from './updater-signature.mjs';

const root = resolve('.');
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const TEST_PUBLIC_KEY = Buffer.from(`untrusted comment: minisign public key E7620F1842B4E81F
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
`).toString('base64');
const TEST_SIGNATURE = Buffer.from(`untrusted comment: signature from minisign secret key
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=
trusted comment: timestamp:1556193335\tfile:test
y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==
`).toString('base64');
const TEST_PUBLIC_KEY_SHA256 = updaterPublicKeySha256(TEST_PUBLIC_KEY);
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'release-selective-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ version: '0.1.1', type: 'module' }));
  return dir;
}
function put(path, value) { mkdirSync(resolve(path, '..'), { recursive: true }); writeFileSync(path, value); }

test('dispatch selection defaults to Windows and preserves explicit native targets', () => {
  const dir = fixture();
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
    git('init', '-q'); git('config', 'user.name', 'Example'); git('config', 'user.email', 'example@example.org');
    git('add', '.'); git('commit', '-qm', 'fixture'); git('tag', 'v0.1.1');
    for (const [target, expected] of [[undefined, ['x86_64-pc-windows-msvc']], ['mac-arm', ['aarch64-apple-darwin']], ['windows-intel', ['x86_64-pc-windows-msvc', 'x86_64-apple-darwin']], ['all', ['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc']]]) {
      const output = join(dir, 'output');
      writeFileSync(output, '');
      const run = spawnSync(process.execPath, [join(root, 'scripts/release-config.mjs'), '--validate-tag'], {
        cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.1', RELEASE_TARGET: target, GITHUB_OUTPUT: output },
      });
      assert.equal(run.status, 0, run.stderr);
      const builds = JSON.parse(readFileSync(output, 'utf8').match(/^builds=(.+)$/m)[1]);
      assert.deepEqual(builds.map(build => build.target), expected);
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
  const dir = fixture();
  try {
    const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', encoding: 'utf8' }).trim();
    git('init', '-q'); git('config', 'user.name', 'Example'); git('config', 'user.email', 'example@example.org');
    git('add', '.'); git('commit', '-qm', 'fixture'); git('tag', 'v0.1.1');
    const sha = git('rev-parse', 'HEAD');
    for (const target of ['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc']) {
      const base = join(dir, 'candidates', `candidate-${target}`);
      const mac = target.includes('apple');
      const installer = join(base, mac ? 'dmg' : 'nsis', mac ? 'Example.dmg' : 'Example-setup.exe');
      const updater = mac ? join(base, 'macos', 'Example.app.tar.gz') : installer;
      put(installer, `installer-${target}`); put(updater, 'test'); put(`${updater}.sig`, TEST_SIGNATURE);
      if (!mac) put(join(base, 'msi', 'Example.msi'), 'unverified alternate installer');
      put(join(base, 'native-smoke.json'), JSON.stringify({ schema: 1, tag: 'v0.1.1', sha, target,
        host: target === 'aarch64-apple-darwin' ? 'darwin-arm64' : target === 'x86_64-apple-darwin' ? 'darwin-x64' : 'win32-x64',
        processAlive: true, updaterSignaturePresent: true, updaterSignatureVerified: true,
        updaterSignature: `${updater.split('/').at(-1)}.sig`, updaterSignatureSha256: digest(`${updater}.sig`),
        updaterPublicKeySha256: TEST_PUBLIC_KEY_SHA256, architectureVerified: true,
        signatureVerified: mac ? true : null, windowObserved: mac ? null : true,
        installer: installer.split('/').at(-1), installerSha256: digest(installer),
        updater: updater.split('/').at(-1), updaterSha256: digest(updater) }));
    }
    const run = () => spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', '--require-evidence'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.1', RELEASE_SHA: sha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: TEST_PUBLIC_KEY },
    });
    assert.equal(run().status, 0);
    const windowsEvidence = join(dir, 'candidates', 'candidate-x86_64-pc-windows-msvc', 'native-smoke.json');
    const passedWindowsEvidence = readFileSync(windowsEvidence, 'utf8');
    rmSync(windowsEvidence);
    assert.match(run().stderr, /Missing unique native startup evidence/);
    put(windowsEvidence, JSON.stringify({ ...JSON.parse(passedWindowsEvidence), windowObserved: false }));
    assert.match(run().stderr, /Native runner evidence is invalid/);
    put(windowsEvidence, passedWindowsEvidence);
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
    put(updater, 'tampered updater');
    assert.notEqual(run().status, 0);
    put(updater, 'test');
    const signature = `${updater}.sig`;
    const validSignature = readFileSync(signature, 'utf8');
    put(signature, 'NOT_A_SIGNATURE');
    assert.notEqual(run().status, 0);
    put(signature, validSignature);
    const wrongKey = Buffer.from(Buffer.from(TEST_PUBLIC_KEY, 'base64').toString('utf8').replace(
      'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3',
      'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO2',
    )).toString('base64');
    const wrongKeyRun = spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', '--require-evidence'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.1', RELEASE_SHA: sha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: wrongKey },
    });
    assert.notEqual(wrongKeyRun.status, 0);
    const bad = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'native-smoke.json');
    const evidence = JSON.parse(readFileSync(bad, 'utf8')); evidence.sha = 'b'.repeat(40); put(bad, JSON.stringify(evidence));
    assert.notEqual(run().status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('manual ARM reuse derives the application tree from both commits and rejects dirty inputs', () => {
  const dir = fixture();
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
    git('add', '.'); git('commit', '-qm', 'release process'); git('tag', 'v0.1.1');
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
      put(installer, `installer-${target}`); put(updater, 'test'); put(`${updater}.sig`, TEST_SIGNATURE);
      const evidence = { tag: 'v0.1.1', target,
        host: target === 'aarch64-apple-darwin' ? 'darwin-arm64' : target === 'x86_64-apple-darwin' ? 'darwin-x64' : 'win32-x64',
        processAlive: true, updaterSignaturePresent: true, updaterSignatureVerified: true,
        updaterSignature: `${updater.split('/').at(-1)}.sig`, updaterSignatureSha256: digest(`${updater}.sig`),
        updaterPublicKeySha256: TEST_PUBLIC_KEY_SHA256, architectureVerified: true,
        signatureVerified: mac ? true : null, windowObserved: mac ? null : true,
        installer: installer.split('/').at(-1), installerSha256: digest(installer),
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
          identity: 'ad-hoc', identityVerified: true, notarization: 'not-notarized', reportSha256: 'e'.repeat(64),
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
    }
    const evidenceFile = join(dir, 'candidates', 'candidate-aarch64-apple-darwin', 'native-smoke.json');
    const run = (releaseSha = reviewedSha) => spawnSync(process.execPath, [join(root, 'scripts/release-manifest.mjs'), 'candidates', '--require-evidence'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v0.1.1', RELEASE_SHA: releaseSha,
        GITHUB_REPOSITORY: 'sample/short-link-generator', SLG_UPDATER_PUBLIC_KEY: TEST_PUBLIC_KEY },
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
      { nativeSigning: { ...valid.nativeSigning, identity: 'developer-id' } },
      { nativeSigning: { ...valid.nativeSigning, identity: 'developer-id', notarization: 'verified' } },
    ]) {
      put(evidenceFile, JSON.stringify({ ...valid, ...patch }));
      const accepted = run();
      assert.equal(accepted.status, 0, accepted.stderr);
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
    git('tag', '-d', 'v0.1.1'); git('tag', 'v0.1.1');
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
  assert.deepEqual(release.on.workflow_dispatch.inputs.target.options, ['windows', 'mac-arm', 'mac-intel', 'windows-intel', 'all']);
  assert.match(release.jobs.build.strategy.matrix.include, /fromJSON\(needs.prepare.outputs.builds\)/);
  assert.equal(release.jobs.draft.if, "inputs.target == 'all'");
  const steps = release.jobs.build.steps;
  const smoke = steps.findIndex(step => step.name?.includes('startup') || step.name?.includes('Install and launch'));
  const scan = steps.findIndex(step => step.name?.includes('Inspect candidate'));
  const upload = steps.findIndex(step => step.uses?.startsWith('actions/upload-artifact@'));
  assert.ok(smoke >= 0 && scan > smoke && upload > scan);
  assert.equal(steps.find(step => step.name === 'Build installers locally on native runner').id, 'package');
  assert.equal(steps[smoke].id, 'native_smoke');
  assert.equal(steps[smoke].env.SLG_UPDATER_PUBLIC_KEY, '${{ vars.UPDATER_PUBLIC_KEY }}');
  assert.equal(steps[scan].id, 'privacy');
  assert.equal(steps[scan].if, "${{ !cancelled() && steps.package.outcome == 'success' }}");
  assert.equal(steps[upload].if, "${{ !cancelled() && steps.native_smoke.outcome == 'success' && steps.privacy.outcome == 'success' }}");
  assert.equal(steps[upload].with['retention-days'], 1);
  const assemble = release.jobs.draft.steps.find(step => step.name?.includes('assemble the draft assets'));
  assert.equal(assemble.env.SLG_UPDATER_PUBLIC_KEY, '${{ vars.UPDATER_PUBLIC_KEY }}');
  assert.equal(existsSync('.github/workflows/release.yml'), true);
});

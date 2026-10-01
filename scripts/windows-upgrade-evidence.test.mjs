import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  WINDOWS_UPGRADE_BASELINE, readWindowsUpgradeEvidence, validateWindowsUpgradeEvidence,
} from './windows-upgrade-evidence.mjs';

const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const TAG = 'v0.1.6';
const SHA = 'a'.repeat(40);
const PUBLIC_KEY_SHA = 'c'.repeat(64);
const startup = () => ({ processAlive: true, windowObserved: true, startupSeconds: 2,
  processExitedAfterObservation: true });

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'windows-upgrade-evidence-'));
  const candidateRoot = join(root, 'candidate-x86_64-pc-windows-msvc');
  const installer = join(candidateRoot, 'nsis', 'Example-setup.exe');
  mkdirSync(join(candidateRoot, 'nsis'), { recursive: true });
  writeFileSync(installer, 'signed synthetic candidate');
  const signature = `${installer}.sig`;
  writeFileSync(signature, 'synthetic signature');
  const nativeEvidence = { schema: 1, tag: TAG, sha: SHA, target: 'x86_64-pc-windows-msvc', host: 'win32-x64',
    installer: 'Example-setup.exe', installerSha256: digest(installer),
    updater: 'Example-setup.exe', updaterSha256: digest(installer),
    updaterSignature: 'Example-setup.exe.sig', updaterSignatureSha256: digest(signature),
    updaterPublicKeySha256: PUBLIC_KEY_SHA };
  const receipt = { schema: 1, tag: TAG, sha: SHA, target: 'x86_64-pc-windows-msvc',
    baselineTag: WINDOWS_UPGRADE_BASELINE.tag,
    baselineInstallerSha256: WINDOWS_UPGRADE_BASELINE.installerSha256,
    baselineSignatureSha256: WINDOWS_UPGRADE_BASELINE.signatureSha256,
    installerSha256: digest(installer), updaterSignatureSha256: digest(signature),
    updaterPublicKeySha256: PUBLIC_KEY_SHA, host: 'win32-x64',
    checkedAt: '2026-10-01T00:00:00.000Z',
    baselineBinarySha256: 'd'.repeat(64), candidateBinarySha256: 'e'.repeat(64),
    startups: { baseline: startup(), candidate: startup() }, sameInstallDirectory: true,
    syntheticConfigurationPreserved: true, nativeRoamingAndLocalDataVerified: true,
    processExitConfirmed: true, nsisRegistrationAndShortcutsCleaned: true,
    credentialContinuityTested: false,
    scope: 'NSIS covering installation, exact executable versions, two native windows and saved synthetic configuration' };
  const file = join(candidateRoot, 'windows-upgrade-smoke.json');
  const options = { tag: TAG, sha: SHA, nativeEvidence, installer, updater: installer,
    signature, publicKeySha256: PUBLIC_KEY_SHA };
  return { root, candidateRoot, file, receipt, options };
}

test('reads only the exact bounded regular Windows upgrade receipt', () => {
  const f = fixture();
  try {
    assert.throws(() => readWindowsUpgradeEvidence(f.candidateRoot), /Missing exact Windows upgrade evidence/);
    writeFileSync(join(f.candidateRoot, 'other.json'), JSON.stringify(f.receipt));
    assert.throws(() => readWindowsUpgradeEvidence(f.candidateRoot), /Missing exact Windows upgrade evidence/);
    symlinkSync(join(f.candidateRoot, 'other.json'), f.file);
    assert.throws(() => readWindowsUpgradeEvidence(f.candidateRoot), /bounded regular file/);
    rmSync(f.file);
    writeFileSync(f.file, JSON.stringify(f.receipt));
    assert.deepEqual(readWindowsUpgradeEvidence(f.candidateRoot), f.receipt);
    writeFileSync(f.file, 'x'.repeat(32 * 1024 + 1));
    assert.throws(() => readWindowsUpgradeEvidence(f.candidateRoot), /bounded regular file/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('accepts the checker-shaped receipt bound to the exact signed candidate', () => {
  const f = fixture();
  try {
    assert.equal(validateWindowsUpgradeEvidence(f.receipt, f.options), true);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('fails closed on source, baseline, artifact, executable, startup and cleanup drift', () => {
  const f = fixture();
  try {
    const rejects = [
      { ...f.receipt, tag: 'v0.1.5' },
      { ...f.receipt, sha: 'b'.repeat(40) },
      { ...f.receipt, baselineTag: 'v0.1.4' },
      { ...f.receipt, baselineInstallerSha256: 'f'.repeat(64) },
      { ...f.receipt, baselineSignatureSha256: 'f'.repeat(64) },
      { ...f.receipt, installerSha256: 'f'.repeat(64) },
      { ...f.receipt, updaterSignatureSha256: 'f'.repeat(64) },
      { ...f.receipt, updaterPublicKeySha256: 'f'.repeat(64) },
      { ...f.receipt, host: 'darwin-arm64' },
      { ...f.receipt, candidateBinarySha256: f.receipt.baselineBinarySha256 },
      { ...f.receipt, startups: { ...f.receipt.startups, candidate: { ...startup(), windowObserved: false } } },
      { ...f.receipt, startups: { ...f.receipt.startups, baseline: { ...startup(), processExitedAfterObservation: false } } },
      { ...f.receipt, sameInstallDirectory: false },
      { ...f.receipt, syntheticConfigurationPreserved: false },
      { ...f.receipt, nativeRoamingAndLocalDataVerified: false },
      { ...f.receipt, processExitConfirmed: false },
      { ...f.receipt, nsisRegistrationAndShortcutsCleaned: false },
      { ...f.receipt, credentialContinuityTested: true },
      { ...f.receipt, extra: true },
    ];
    for (const receipt of rejects) assert.throws(() => validateWindowsUpgradeEvidence(receipt, f.options));
    assert.throws(() => validateWindowsUpgradeEvidence(f.receipt, { ...f.options, tag: 'v0.1.5' }));
    assert.throws(() => validateWindowsUpgradeEvidence(f.receipt, { ...f.options, publicKeySha256: 'f'.repeat(64) }));
    assert.throws(() => validateWindowsUpgradeEvidence(f.receipt, {
      ...f.options, nativeEvidence: { ...f.options.nativeEvidence, updaterSha256: 'f'.repeat(64) },
    }));
    writeFileSync(f.options.installer, 'changed candidate bytes');
    assert.throws(() => validateWindowsUpgradeEvidence(f.receipt, f.options));
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

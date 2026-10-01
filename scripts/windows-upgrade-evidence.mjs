import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';

// Independent assembly pins; drift from the native checker fails the release closed.
export const WINDOWS_UPGRADE_BASELINE = Object.freeze({
  tag: 'v0.1.5',
  installerSha256: 'a3a164cde70cff7f278ea35a2a9e41e054e1854143ec4996b3dd88ec252a8610',
  signatureSha256: '3b93310090f3bb4525d57b3528ac1341d90159607f9f5afa1a8f80391a8de70e',
});

const TARGET = 'x86_64-pc-windows-msvc';
const HOST = 'win32-x64';
const SCOPE = 'NSIS covering installation, exact executable versions, two native windows and saved synthetic configuration';
const RECEIPT_KEYS = [
  'schema', 'tag', 'sha', 'target', 'baselineTag', 'baselineInstallerSha256',
  'baselineSignatureSha256', 'installerSha256', 'updaterSignatureSha256',
  'updaterPublicKeySha256', 'host', 'checkedAt', 'baselineBinarySha256',
  'candidateBinarySha256', 'startups', 'sameInstallDirectory',
  'syntheticConfigurationPreserved', 'nativeRoamingAndLocalDataVerified',
  'processExitConfirmed', 'nsisRegistrationAndShortcutsCleaned',
  'credentialContinuityTested', 'scope',
].sort();
const STARTUP_KEYS = ['processAlive', 'windowObserved', 'startupSeconds', 'processExitedAfterObservation'].sort();
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const exactKeys = (value, expected) => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected);
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');

function newerVersion(candidate, baseline) {
  const parse = value => /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value ?? '')?.slice(1).map(BigInt);
  const next = parse(candidate);
  const old = parse(baseline);
  if (!next || !old) return false;
  const first = next.findIndex((part, index) => part !== old[index]);
  return first >= 0 && next[first] > old[first];
}

export function readWindowsUpgradeEvidence(candidateRoot) {
  const directory = lstatSync(candidateRoot);
  if (!directory.isDirectory() || directory.isSymbolicLink()) {
    throw new Error('Windows upgrade candidate directory must be a real directory.');
  }
  const path = join(candidateRoot, 'windows-upgrade-smoke.json');
  let info;
  try { info = lstatSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error('Missing exact Windows upgrade evidence.');
    throw error;
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size < 2 || info.size > 32 * 1024) {
    throw new Error('Windows upgrade evidence must be one bounded regular file.');
  }
  const bytes = readFileSync(path);
  if (bytes.length !== info.size) throw new Error('Windows upgrade evidence changed while reading.');
  return JSON.parse(bytes.toString('utf8'));
}

export function validateWindowsUpgradeEvidence(receipt, {
  tag, sha, nativeEvidence, installer, updater, signature, publicKeySha256,
}) {
  if (!exactKeys(receipt, RECEIPT_KEYS) || receipt.schema !== 1 ||
      receipt.tag !== tag || receipt.sha !== sha || !/^[0-9a-f]{40}$/.test(sha ?? '') ||
      receipt.target !== TARGET || receipt.host !== HOST ||
      receipt.baselineTag !== WINDOWS_UPGRADE_BASELINE.tag ||
      receipt.baselineInstallerSha256 !== WINDOWS_UPGRADE_BASELINE.installerSha256 ||
      receipt.baselineSignatureSha256 !== WINDOWS_UPGRADE_BASELINE.signatureSha256 ||
      !newerVersion(tag, receipt.baselineTag) ||
      typeof receipt.checkedAt !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(receipt.checkedAt) ||
      Number.isNaN(Date.parse(receipt.checkedAt)) ||
      new Date(receipt.checkedAt).toISOString() !== receipt.checkedAt ||
      receipt.scope !== SCOPE) {
    throw new Error('Windows upgrade receipt schema, source or pinned baseline is invalid.');
  }
  if (installer !== updater || signature !== `${updater}.sig` ||
      nativeEvidence?.target !== TARGET || nativeEvidence?.host !== HOST ||
      nativeEvidence?.tag !== tag || nativeEvidence?.sha !== sha ||
      nativeEvidence.installer !== basename(installer) ||
      nativeEvidence.updater !== basename(updater) ||
      nativeEvidence.updaterSignature !== basename(signature) ||
      !hex(receipt.installerSha256) || !hex(receipt.updaterSignatureSha256) ||
      !hex(receipt.updaterPublicKeySha256) ||
      receipt.installerSha256 !== digest(installer) ||
      receipt.installerSha256 !== nativeEvidence.installerSha256 ||
      receipt.installerSha256 !== nativeEvidence.updaterSha256 ||
      receipt.updaterSignatureSha256 !== digest(signature) ||
      receipt.updaterSignatureSha256 !== nativeEvidence.updaterSignatureSha256 ||
      receipt.updaterPublicKeySha256 !== publicKeySha256 ||
      receipt.updaterPublicKeySha256 !== nativeEvidence.updaterPublicKeySha256) {
    throw new Error('Windows upgrade receipt does not bind the exact signed candidate.');
  }
  if (!hex(receipt.baselineBinarySha256) || !hex(receipt.candidateBinarySha256) ||
      receipt.baselineBinarySha256 === receipt.candidateBinarySha256 ||
      !exactKeys(receipt.startups, ['baseline', 'candidate']) ||
      !['baseline', 'candidate'].every(phase => {
        const startup = receipt.startups[phase];
        return exactKeys(startup, STARTUP_KEYS) && startup.processAlive === true &&
          startup.windowObserved === true && startup.processExitedAfterObservation === true &&
          Number.isInteger(startup.startupSeconds) && startup.startupSeconds >= 1 &&
          startup.startupSeconds <= 120;
      }) || receipt.sameInstallDirectory !== true ||
      receipt.syntheticConfigurationPreserved !== true ||
      receipt.nativeRoamingAndLocalDataVerified !== true ||
      receipt.processExitConfirmed !== true ||
      receipt.nsisRegistrationAndShortcutsCleaned !== true ||
      receipt.credentialContinuityTested !== false) {
    throw new Error('Windows upgrade executable, native-window or cleanup evidence is incomplete.');
  }
  return true;
}

// Runs only on a fresh native Windows hosted runner, before the ordinary installer smoke.
// The baseline is public, pinned and updater-signed. No account or real credential is used.
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join, resolve, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isWindowsX64Executable, observeStartup, selectArtifacts } from './native-smoke.mjs';
import { updaterPublicKeySha256, verifyUpdaterSignatureFile } from './updater-signature.mjs';

export const WINDOWS_BASELINE = Object.freeze({
  tag: 'v0.1.5',
  filename: 'short-link-generator_0.1.5_windows-x86_64.exe',
  sha256: 'a3a164cde70cff7f278ea35a2a9e41e054e1854143ec4996b3dd88ec252a8610',
  signatureSha256: '3b93310090f3bb4525d57b3528ac1341d90159607f9f5afa1a8f80391a8de70e',
});
const target = 'x86_64-pc-windows-msvc';
const appId = 'org.shortlink.generator';
const ownerFile = 'upgrade-smoke-owner';
const hostScript = fileURLToPath(new URL('./windows-upgrade-host.ps1', import.meta.url));
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');

export const WINDOWS_UPGRADE_STAGES = Object.freeze({
  BASELINE_INSTALL: 'baseline-install',
  BASELINE_REGISTRATION: 'baseline-registration',
  BASELINE_VERSION: 'baseline-version',
  BASELINE_STARTUP: 'baseline-startup',
  BASELINE_SAVED_STATE: 'baseline-saved-state',
  CANDIDATE_INSTALL: 'candidate-install',
  CANDIDATE_REGISTRATION: 'candidate-registration',
  CANDIDATE_VERSION: 'candidate-version',
  CANDIDATE_STARTUP: 'candidate-startup',
  CANDIDATE_SAVED_STATE: 'candidate-saved-state',
  CLEANUP: 'cleanup',
});

const stageValues = new Set(Object.values(WINDOWS_UPGRADE_STAGES));
const phaseStages = Object.freeze({
  baseline: Object.freeze({
    install: WINDOWS_UPGRADE_STAGES.BASELINE_INSTALL,
    registration: WINDOWS_UPGRADE_STAGES.BASELINE_REGISTRATION,
    version: WINDOWS_UPGRADE_STAGES.BASELINE_VERSION,
    startup: WINDOWS_UPGRADE_STAGES.BASELINE_STARTUP,
    state: WINDOWS_UPGRADE_STAGES.BASELINE_SAVED_STATE,
  }),
  candidate: Object.freeze({
    install: WINDOWS_UPGRADE_STAGES.CANDIDATE_INSTALL,
    registration: WINDOWS_UPGRADE_STAGES.CANDIDATE_REGISTRATION,
    version: WINDOWS_UPGRADE_STAGES.CANDIDATE_VERSION,
    startup: WINDOWS_UPGRADE_STAGES.CANDIDATE_STARTUP,
    state: WINDOWS_UPGRADE_STAGES.CANDIDATE_SAVED_STATE,
  }),
});
const diagnosticMessages = Object.freeze({
  'operation-failed': 'Windows upgrade smoke operation failed.',
  'native-command-failed': 'Native upgrade command failed.',
  'nsis-command-failed': 'Owned NSIS operation did not complete successfully.',
  'missing-or-invalid-registration': 'NSIS registration is missing or invalid.',
  'outside-current-user-hive': 'NSIS registration is outside the owned current-user hive.',
  'uninstall-location-mismatch': 'NSIS uninstall location does not belong to this run.',
  'uninstaller-path-mismatch': 'NSIS uninstaller path does not belong to this run.',
  'uninstall-version-missing': 'NSIS uninstall version is missing.',
  'uninstall-version-mismatch': 'NSIS uninstall version does not match the installed package.',
  'location-value-mismatch': 'NSIS install-location value does not belong to this run.',
  'unknown-kind': 'Unknown NSIS registration type.',
  'missing-uninstall': 'NSIS uninstall registration is missing.',
  'shortcut-target-mismatch': 'Product shortcut target does not belong to this run.',
});
const safeErrorCodes = new Set([
  'EACCES', 'EAGAIN', 'EBUSY', 'ECONNRESET', 'EEXIST', 'EIO', 'EISDIR', 'EMFILE',
  'ENFILE', 'ENOENT', 'ENOMEM', 'ENOSPC', 'ENOTDIR', 'ENOTEMPTY', 'EPERM', 'EPIPE',
  'ETIMEDOUT', 'UNKNOWN', 'ERR_CHILD_PROCESS_IPC_REQUIRED',
  'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', 'ERR_INVALID_ARG_VALUE',
]);
const safeSignals = new Set([
  'SIGABRT', 'SIGALRM', 'SIGBUS', 'SIGCHLD', 'SIGCONT', 'SIGFPE', 'SIGHUP', 'SIGILL',
  'SIGINT', 'SIGIO', 'SIGKILL', 'SIGPIPE', 'SIGPROF', 'SIGQUIT', 'SIGSEGV', 'SIGSTOP',
  'SIGSYS', 'SIGTERM', 'SIGTRAP', 'SIGTSTP', 'SIGTTIN', 'SIGTTOU', 'SIGURG',
  'SIGUSR1', 'SIGUSR2', 'SIGVTALRM', 'SIGWINCH', 'SIGXCPU', 'SIGXFSZ',
]);
const hostDiagnosticPrefix = 'SLG_WINDOWS_HOST_DIAGNOSTIC:';
const hostDiagnosticStages = new Set([
  'initialize', 'owned-location', 'known-folders', 'registry', 'shortcuts', 'serialize',
]);
const hostDiagnosticExceptions = new Set([
  'MethodInvocationException', 'RuntimeException', 'ArgumentException',
  'UnauthorizedAccessException', 'COMException', 'IOException', 'Other',
]);
const signedInt32 = value => Number.isInteger(value) && value >= -2147483648 && value <= 2147483647;
const readSafeProperty = (value, key) => {
  try { return value !== null && (typeof value === 'object' || typeof value === 'function') ? value[key] : undefined; }
  catch { return undefined; }
};
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());

function parseWindowsHostDiagnostic(stderr) {
  let text;
  if (Buffer.isBuffer(stderr)) {
    if (stderr.length > 4096) return null;
    text = stderr.toString('utf8');
  } else if (typeof stderr === 'string' && stderr.length <= 4096) text = stderr;
  else return null;
  const matches = text.split(/\r?\n/).filter(line => line.startsWith(hostDiagnosticPrefix));
  if (matches.length !== 1 || Buffer.byteLength(matches[0], 'utf8') > 512) return null;
  let record;
  try { record = JSON.parse(matches[0].slice(hostDiagnosticPrefix.length)); }
  catch { return null; }
  if (!exactKeys(record, ['stage', 'exception', 'category', 'hresult'])
      || !hostDiagnosticStages.has(record.stage)
      || !hostDiagnosticExceptions.has(record.exception)
      || !signedInt32(record.category) || !signedInt32(record.hresult)) return null;
  return Object.freeze({ hostStage: record.stage, exceptionClass: record.exception,
    category: record.category, hresult: record.hresult });
}

function controlledProcessDetails(error, hostDiagnostic = null) {
  const details = {};
  const status = readSafeProperty(error, 'status');
  const code = readSafeProperty(error, 'code');
  const signal = readSafeProperty(error, 'signal');
  if (signedInt32(status)) details.exitStatus = status;
  else if (signedInt32(code)) details.exitStatus = code;
  if (typeof code === 'string' && safeErrorCodes.has(code)) details.errorCode = code;
  if (typeof signal === 'string' && safeSignals.has(signal)) details.signal = signal;
  if (hostDiagnostic) Object.assign(details, hostDiagnostic);
  return Object.freeze(details);
}

class UpgradeCommandError extends Error {
  constructor(reason, cause, hostDiagnostic = null) {
    super(diagnosticMessages[reason], { cause });
    this.name = 'UpgradeCommandError';
    this.reason = reason;
    this.diagnostic = controlledProcessDetails(cause, hostDiagnostic);
  }
}

class UpgradeReasonError extends Error {
  constructor(reason, message) {
    super(message);
    this.name = 'UpgradeReasonError';
    this.reason = reason;
  }
}

class UpgradeStageError extends Error {
  constructor(stage, cause) {
    super('Windows upgrade smoke stage failed.', { cause });
    this.name = 'UpgradeStageError';
    this.stage = stage;
  }
}

class UpgradeLifecycleError extends AggregateError {
  constructor(failures) {
    super(failures.map(failure => failure.error), 'Windows upgrade smoke lifecycle failed.');
    this.name = 'UpgradeLifecycleError';
    this.failures = failures;
  }
}

async function runUpgradeStage(stage, action) {
  if (!stageValues.has(stage)) throw new Error('Unknown Windows upgrade smoke stage.');
  try { return await action(); }
  catch (error) {
    if (error instanceof UpgradeStageError && error.stage === stage) throw error;
    throw new UpgradeStageError(stage, error);
  }
}

export function formatWindowsUpgradeFailure(error, { baselineOnly = false } = {}) {
  const diagnostics = [];
  const seen = new Set();
  let truncated = false;
  const append = (reason, context, details = {}) => {
    if (diagnostics.length >= 16) { truncated = true; return; }
    const diagnostic = { reason, message: diagnosticMessages[reason] };
    if (context.origin === 'execution' || context.origin === 'cleanup') diagnostic.origin = context.origin;
    if (stageValues.has(context.stage)) diagnostic.stage = context.stage;
    Object.assign(diagnostic, details);
    diagnostics.push(diagnostic);
  };
  const visit = (value, context = {}) => {
    if (diagnostics.length >= 16) { truncated = true; return; }
    if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
      if (seen.has(value)) { append('operation-failed', context); return; }
      seen.add(value);
    }
    if (value instanceof UpgradeLifecycleError) {
      for (const failure of value.failures) visit(failure.error, { ...context, origin: failure.origin });
      return;
    }
    if (value instanceof UpgradeStageError) {
      visit(value.cause, { ...context, stage: value.stage });
      return;
    }
    if (value instanceof UpgradeCommandError) {
      append(value.reason, context, value.diagnostic);
      return;
    }
    if (value instanceof UpgradeReasonError) {
      append(value.reason, context);
      return;
    }
    if (value instanceof AggregateError) {
      if (value.errors.length === 0) append('operation-failed', context);
      else for (const nested of value.errors) visit(nested, context);
      return;
    }
    const cause = readSafeProperty(value, 'cause');
    if (cause !== undefined && cause !== value) visit(cause, context);
    else append('operation-failed', context, controlledProcessDetails(value));
  };
  visit(error);
  if (diagnostics.length === 0) diagnostics.push({ reason: 'operation-failed',
    message: diagnosticMessages['operation-failed'] });
  return JSON.stringify({ schema: 1, result: 'failed', baselineOnly: baselineOnly === true,
    message: 'Windows upgrade smoke failed.', diagnostics, ...(truncated ? { diagnosticsTruncated: true } : {}) });
}

export const runUpgradeCommand = (command, args, execute = execFileSync) => {
  try {
    return execute(command, args, {
      encoding: 'utf8', stdio: 'pipe', windowsHide: true, timeout: 120_000,
    }).trim();
  } catch (error) {
    const hostDiagnostic = basename(command).toLowerCase() === 'pwsh.exe'
      ? parseWindowsHostDiagnostic(readSafeProperty(error, 'stderr')) : null;
    throw new UpgradeCommandError('native-command-failed', error, hostDiagnostic);
  }
};
const run = runUpgradeCommand;

export function runOwnedNsis(binary, install, uninstall = false, execute = execFileSync) {
  for (const path of [binary, install]) {
    if (typeof path !== 'string' || !win32.isAbsolute(path) || /["\r\n\0]/.test(path)) {
      throw new Error('NSIS requires exact unquoted absolute Windows paths.');
    }
  }
  // NSIS consumes /D= and _?= as the final raw suffix, including spaces.
  // _?= keeps the uninstaller in this process so completion can be awaited.
  // https://nsis.sourceforge.io/Docs/Chapter3.html#installerusage
  try {
    execute(binary, ['/S', `${uninstall ? '_?=' : '/D='}${install}`], {
      argv0: `"${binary}"`, windowsVerbatimArguments: true, shell: false,
      encoding: 'utf8', stdio: 'pipe', windowsHide: true, timeout: 120_000,
    });
  } catch (error) { throw new UpgradeCommandError('nsis-command-failed', error); }
}

export function validateUpgradeContext(env, platform, arch, cwd, head) {
  if (platform !== 'win32' || arch !== 'x64' || env.GITHUB_ACTIONS !== 'true'
      || env.RUNNER_ENVIRONMENT !== 'github-hosted' || env.RUNNER_OS !== 'Windows'
      || env.RUNNER_ARCH !== 'X64' || !env.RUNNER_TEMP || !env.APPDATA || !env.LOCALAPPDATA
      || resolve(env.GITHUB_WORKSPACE ?? '') !== resolve(cwd)) {
    throw new Error('Upgrade smoke requires a fresh matching Windows hosted runner.');
  }
  if (!/^v\d+\.\d+\.\d+$/.test(env.RELEASE_TAG ?? '')
      || !/^[0-9a-f]{40}$/.test(env.RELEASE_SHA ?? '') || head !== env.RELEASE_SHA) {
    throw new Error('Reviewed stable release tag and exact source SHA are required.');
  }
  const parts = env.RELEASE_TAG.slice(1).split('.').map(BigInt);
  const older = [0n, 1n, 5n];
  const first = parts.findIndex((part, i) => part !== older[i]);
  if (first < 0 || parts[first] < older[first]) throw new Error('Candidate must be newer than the pinned baseline.');
}

export function verifyWindowsBaseline(installer, publicKey) {
  const signature = `${installer}.sig`;
  if (basename(installer) !== WINDOWS_BASELINE.filename
      || !lstatSync(installer).isFile() || !lstatSync(signature).isFile()
      || digest(installer) !== WINDOWS_BASELINE.sha256
      || digest(signature) !== WINDOWS_BASELINE.signatureSha256) {
    throw new Error('The reviewed Windows baseline bytes have changed.');
  }
  verifyUpdaterSignatureFile(installer, signature, publicKey, WINDOWS_BASELINE.tag);
}

function installedBinary(install) {
  const visit = dir => readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) throw new Error('Unexpected filesystem link in installed application.');
    return entry.isDirectory() ? visit(path) : [path];
  });
  const binaries = visit(install).filter(path => basename(path).toLowerCase() === 'short-link-generator.exe');
  if (binaries.length !== 1 || !isWindowsX64Executable(binaries[0])) throw new Error('Installed x64 application is missing or ambiguous.');
  return binaries[0];
}

export function assertInstalledVersion(actual, expected) {
  if (actual !== expected && actual !== `${expected}.0`) throw new Error('Installed executable version does not match its signed package.');
}

const pathKey = value => {
  if (typeof value !== 'string' || !win32.isAbsolute(value)) throw new Error('Expected an absolute Windows path.');
  return win32.normalize(value).replace(/[\\/]+$/, '').toLowerCase();
};
const samePath = (left, right) => pathKey(left) === pathKey(right);
const unquote = value => {
  const match = /^"([^"]+)"$/.exec(value ?? '');
  if (!match) throw new Error('NSIS registration contains an unexpected path format.');
  return match[1];
};
const registeredPathMatches = (value, expected, quoted = false) => {
  try { return samePath(quoted ? unquote(value) : value, expected); }
  catch { return false; }
};
const nativeHost = () => {
  const data = JSON.parse(run('pwsh.exe', ['-NoLogo', '-NoProfile', '-NonInteractive',
    '-File', hostScript, '-Mode', 'Inspect']));
  if (!Array.isArray(data.registrations) || !Array.isArray(data.shortcuts)) {
    throw new Error('Windows host inspection returned an invalid record.');
  }
  return data;
};
const statOrAbsent = (path, stat = lstatSync) => {
  try { return stat(path); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
};
const markerAt = path => join(path, ownerFile);
const realDirectory = (path, stat = lstatSync) => {
  const value = statOrAbsent(path, stat);
  if (!value?.isDirectory() || value.isSymbolicLink()) {
    throw new Error('A protected Windows directory is missing or is a filesystem link.');
  }
};
const realFile = (path, stat = lstatSync) => {
  const value = statOrAbsent(path, stat);
  if (!value?.isFile() || value.isSymbolicLink()) {
    throw new Error('The exact owned uninstaller is missing or is a filesystem link.');
  }
};
const assertNoLinksInside = dir => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    const info = lstatSync(path);
    if (info.isSymbolicLink()) throw new Error('Owned cleanup tree contains a filesystem link.');
    if (info.isDirectory()) assertNoLinksInside(path);
  }
};

export function assertCleanWindowsHost(host, env, stat = lstatSync) {
  if (!samePath(host.roaming, env.APPDATA) || !samePath(host.local, env.LOCALAPPDATA)) {
    throw new Error('Native Known Folder paths differ from the runner environment.');
  }
  if (host.roamingReparse !== false || host.localReparse !== false) {
    throw new Error('A native application data root is a reparse point or was not verified.');
  }
  realDirectory(host.roaming, stat);
  realDirectory(host.local, stat);
  const appData = win32.join(host.roaming, appId);
  const appLocalData = win32.join(host.local, appId);
  if (samePath(appData, appLocalData) || statOrAbsent(appData, stat) || statOrAbsent(appLocalData, stat)) {
    throw new Error('Upgrade fixture requires both native application data directories to be absent.');
  }
  if (!Array.isArray(host.registrations) || host.registrations.length
      || !Array.isArray(host.shortcuts) || host.shortcuts.length) {
    throw new Error('An existing NSIS registration or product shortcut blocks the upgrade fixture.');
  }
  return { appData, appLocalData };
}

export function createOwnedDataDirectories({ appData, appLocalData, marker, owned,
  mkdir = mkdirSync, write = writeFileSync }) {
  mkdir(appData); owned.roaming = true;
  write(markerAt(appData), marker, { flag: 'wx' });
  mkdir(appLocalData); owned.local = true;
  write(markerAt(appLocalData), marker, { flag: 'wx' });
}

export function removeOwnedDataDirectories({ appData, appLocalData, marker, owned,
  stat = lstatSync, read = readFileSync, checkTree = assertNoLinksInside,
  remove = path => rmSync(path, { recursive: true }) }) {
  for (const [kind, path] of [['local', appLocalData], ['roaming', appData]]) {
    if (!owned[kind]) continue;
    realDirectory(path, stat);
    if (read(markerAt(path), 'utf8') !== marker) {
      throw new Error('Upgrade fixture ownership changed; retained for investigation.');
    }
    checkTree(path);
    remove(path);
  }
}

export function assertOwnedRegistration(host, install, allowedVersions, requireVersion = false) {
  if (!Array.isArray(host?.registrations) || !Array.isArray(host?.shortcuts)
      || host.registrations.length === 0) {
    throw new UpgradeReasonError('missing-or-invalid-registration', 'NSIS registration is missing or invalid.');
  }
  const expectedUninstaller = win32.join(install, 'uninstall.exe');
  const expectedBinary = win32.join(install, 'short-link-generator.exe');
  for (const record of host.registrations) {
    if (record === null || typeof record !== 'object') {
      throw new UpgradeReasonError('missing-or-invalid-registration', 'NSIS registration is missing or invalid.');
    }
    if (record.hive !== 'CurrentUser' || !['Registry64', 'Registry32'].includes(record.view)) {
      throw new UpgradeReasonError('outside-current-user-hive', 'NSIS registration is outside the owned current-user hive.');
    }
    if (record.kind === 'uninstall') {
      if (!registeredPathMatches(record.installLocation, install, true)) {
        throw new UpgradeReasonError('uninstall-location-mismatch', 'NSIS uninstall registration does not belong to this run.');
      }
      if (!registeredPathMatches(record.uninstallString, expectedUninstaller, true)) {
        throw new UpgradeReasonError('uninstaller-path-mismatch', 'NSIS uninstall registration does not belong to this run.');
      }
      if (requireVersion && !record.displayVersion) {
        throw new UpgradeReasonError('uninstall-version-missing', 'NSIS uninstall registration does not belong to this run.');
      }
      if (record.displayVersion && !allowedVersions.some(version => {
        try { assertInstalledVersion(record.displayVersion, version); return true; } catch { return false; }
      })) {
        throw new UpgradeReasonError('uninstall-version-mismatch', 'NSIS uninstall registration does not belong to this run.');
      }
    } else if (record.kind === 'location') {
      if (!registeredPathMatches(record.defaultValue, install)) {
        throw new UpgradeReasonError('location-value-mismatch', 'NSIS install-location registration does not belong to this run.');
      }
    } else throw new UpgradeReasonError('unknown-kind', 'Unknown NSIS registration type.');
  }
  if (requireVersion && !host.registrations.some(record => record.kind === 'uninstall')) {
    throw new UpgradeReasonError('missing-uninstall', 'NSIS uninstall registration is missing.');
  }
  for (const shortcut of host.shortcuts) {
    if (!registeredPathMatches(shortcut?.target, expectedBinary)) {
      throw new UpgradeReasonError('shortcut-target-mismatch', 'Product shortcut target does not belong to this run.');
    }
  }
  return expectedUninstaller;
}

const assertNoExternalFootprint = host => {
  if (!Array.isArray(host.registrations) || host.registrations.length
      || !Array.isArray(host.shortcuts) || host.shortcuts.length) {
    throw new Error('NSIS registration or product shortcut remains after uninstall.');
  }
};

export async function cleanupUpgradeFixture({ inspect, install, allowedVersions,
  assertUninstaller, uninstall, removeOwnedLocation, removeData, removeTemp }) {
  let host = await inspect();
  if (host.registrations.length) {
    const uninstaller = assertOwnedRegistration(host, install, allowedVersions);
    await assertUninstaller(uninstaller);
    await uninstall(uninstaller);
    host = await inspect();
    if (host.shortcuts.length || host.registrations.some(record => record.kind === 'uninstall')) {
      throw new Error('NSIS uninstaller left an uninstall registration or shortcut.');
    }
    for (let attempt = 0; host.registrations.length && attempt < 2; ++attempt) {
      assertOwnedRegistration(host, install, allowedVersions);
      await removeOwnedLocation(host.registrations[0].view, install);
      host = await inspect();
    }
    assertNoExternalFootprint(host);
  } else {
    assertNoExternalFootprint(host);
  }
  await removeData();
  await removeTemp();
}

export async function runUpgradeLifecycle({ execute, cleanup, publish }) {
  let result;
  let executionError;
  try { result = await execute(); } catch (error) { executionError = error; }
  let cleanupError;
  try { await runUpgradeStage(WINDOWS_UPGRADE_STAGES.CLEANUP, cleanup); }
  catch (error) { cleanupError = error; }
  const failures = [];
  if (executionError) failures.push({ origin: 'execution', error: executionError });
  if (cleanupError) failures.push({ origin: 'cleanup', error: cleanupError });
  if (failures.length) throw new UpgradeLifecycleError(failures);
  await publish(result);
  return result;
}

// Dependency injection keeps failure-order tests off the Windows installer and user storage.
export async function checkUpgradeSequence({ install, assertRegistration, inspect,
  launch, assertState, baselineOnly = false }) {
  const baselineStages = phaseStages.baseline;
  await runUpgradeStage(baselineStages.install, () => install('baseline'));
  await runUpgradeStage(baselineStages.registration, () => assertRegistration('baseline'));
  const before = await runUpgradeStage(baselineStages.version, () => inspect('baseline'));
  await runUpgradeStage(baselineStages.startup, () => launch('baseline'));
  await runUpgradeStage(baselineStages.state, assertState);
  if (baselineOnly === true) return { baselineBinarySha256: before.sha256 };

  const candidateStages = phaseStages.candidate;
  await runUpgradeStage(candidateStages.install, () => install('candidate'));
  await runUpgradeStage(candidateStages.registration, () => assertRegistration('candidate'));
  const after = await runUpgradeStage(candidateStages.version, async () => {
    const observation = await inspect('candidate');
    if (before.sha256 === observation.sha256) throw new Error('Upgrade left the old executable in place.');
    return observation;
  });
  // Check once after installation and again after first launch. Both belong to the
  // same fixed saved-state stage so public diagnostics cannot contain free-form labels.
  await runUpgradeStage(candidateStages.state, assertState);
  await runUpgradeStage(candidateStages.startup, () => launch('candidate'));
  await runUpgradeStage(candidateStages.state, assertState);
  return { baselineBinarySha256: before.sha256, candidateBinarySha256: after.sha256 };
}

export async function runUpgradeMode({ baselineOnly = false, prepare = () => {}, actions, cleanup,
  buildResult = result => result, publishReceipt, publishBaselineSummary }) {
  return runUpgradeLifecycle({
    execute: async () => {
      await runUpgradeStage(WINDOWS_UPGRADE_STAGES.BASELINE_SAVED_STATE, prepare);
      const sequence = await checkUpgradeSequence({ ...actions, baselineOnly: baselineOnly === true });
      return buildResult(sequence);
    },
    cleanup,
    publish: result => baselineOnly === true ? publishBaselineSummary(result) : publishReceipt(result),
  });
}

export function parseWindowsUpgradeArgs(args) {
  if (args.length === 2 && args[0] === '--baseline-only') {
    return { baselineOnly: true, baselineArg: args[1], bundleArg: null };
  }
  if (args.length === 2 && !args.includes('--baseline-only')) {
    return { baselineOnly: false, baselineArg: args[0], bundleArg: args[1] };
  }
  throw new Error('Usage: windows-upgrade-smoke.mjs [--baseline-only] <reviewed-baseline.exe> [candidate-bundle]');
}

export async function main(args = process.argv.slice(2)) {
  const { baselineOnly, baselineArg, bundleArg } = parseWindowsUpgradeArgs(args);
  validateUpgradeContext(process.env, process.platform, process.arch, '.', run('git', ['rev-parse', 'HEAD']));
  const key = process.env.SLG_UPDATER_PUBLIC_KEY;
  if (!key) throw new Error('Configured updater public key is required.');
  const baseline = resolve(baselineArg);
  verifyWindowsBaseline(baseline, key);
  let bundle = null;
  let installer = null;
  let signature = null;
  let receipt = null;
  if (!baselineOnly) {
    bundle = resolve(bundleArg);
    const artifacts = selectArtifacts(bundle, target);
    installer = artifacts.installer;
    signature = artifacts.signature;
    verifyUpdaterSignatureFile(artifacts.updater, signature, key, process.env.RELEASE_TAG);
    const config = JSON.parse(readFileSync(fileURLToPath(new URL('../src-tauri/tauri.conf.json', import.meta.url)), 'utf8'));
    if (config.productName !== '短连接生成器' || config.identifier !== appId
        || config.app?.appDirectoriesOverride || config.app?.windows?.some(window => window.dataDirectory)
        || config.bundle?.publisher || config.bundle?.windows) {
      throw new Error('Candidate packaging no longer matches the reviewed Windows installation footprint.');
    }
    receipt = join(bundle, 'windows-upgrade-smoke.json');
    if (statOrAbsent(receipt)) throw new Error('An earlier upgrade smoke receipt already exists.');
  }
  const { appData, appLocalData } = assertCleanWindowsHost(nativeHost(), process.env);
  const temp = mkdtempSync(join(process.env.RUNNER_TEMP, 'slg-upgrade-smoke-'));
  const install = join(temp, 'installed');
  const marker = randomUUID();
  const owned = { roaming: false, local: false };
  const versions = baselineOnly
    ? { baseline: WINDOWS_BASELINE.tag.slice(1) }
    : { baseline: WINDOWS_BASELINE.tag.slice(1), candidate: process.env.RELEASE_TAG.slice(1) };
  const installers = baselineOnly ? { baseline } : { baseline, candidate: installer };
  const startups = {};
  const state = JSON.stringify({ accounts: [], domains: [], links: [], pools: [],
    pendingOperations: [`Synthetic upgrade fixture ${marker}`] }, null, 2);
  const versionScript = fileURLToPath(new URL('./windows-installed-version.ps1', import.meta.url));
  const verifyMarker = path => {
    realDirectory(path);
    if (readFileSync(markerAt(path), 'utf8') !== marker) {
      throw new Error('Upgrade fixture ownership changed; retained for investigation.');
    }
  };
  writeFileSync(markerAt(temp), marker, { flag: 'wx' });
  await runUpgradeMode({
    baselineOnly,
    prepare: () => {
      createOwnedDataDirectories({ appData, appLocalData, marker, owned });
      writeFileSync(join(appData, 'state.json'), state, { flag: 'wx' });
      mkdirSync(install);
    },
    actions: {
      install: phase => {
        runOwnedNsis(installers[phase], install);
      },
      assertRegistration: phase => {
        assertOwnedRegistration(nativeHost(), install, [versions[phase]], true);
      },
      inspect: phase => {
        const binary = installedBinary(install);
        assertInstalledVersion(run('pwsh.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', versionScript,
          '-TargetBinary', binary]), versions[phase]);
        return { sha256: digest(binary) };
      },
      launch: async phase => {
        const startup = await observeStartup(installedBinary(install), install, process.env, true);
        if (startup.processExitedAfterObservation !== true) {
          throw new Error('Observed application exit was not confirmed.');
        }
        startups[phase] = startup;
      },
      assertState: () => {
        verifyMarker(appData);
        verifyMarker(appLocalData);
        if (readFileSync(join(appData, 'state.json'), 'utf8') !== state) throw new Error('Upgrade changed or removed the saved synthetic configuration.');
      },
    },
    buildResult: result => baselineOnly ? result : ({
      schema: 1, tag: process.env.RELEASE_TAG, sha: process.env.RELEASE_SHA, target,
      baselineTag: WINDOWS_BASELINE.tag, baselineInstallerSha256: digest(baseline),
      baselineSignatureSha256: digest(`${baseline}.sig`), installerSha256: digest(installer),
      updaterSignatureSha256: digest(signature), updaterPublicKeySha256: updaterPublicKeySha256(key),
      host: 'win32-x64', checkedAt: new Date().toISOString(), ...result, startups,
      sameInstallDirectory: true, syntheticConfigurationPreserved: true,
      nativeRoamingAndLocalDataVerified: true, processExitConfirmed: true,
      nsisRegistrationAndShortcutsCleaned: true,
      credentialContinuityTested: false, scope: 'NSIS covering installation, exact executable versions, two native windows and saved synthetic configuration',
    }),
    cleanup: () => cleanupUpgradeFixture({
      inspect: nativeHost, install, allowedVersions: Object.values(versions),
      assertUninstaller: path => { realDirectory(install); realFile(path); },
      uninstall: path => runOwnedNsis(path, install, true),
      removeOwnedLocation: view => {
        const result = run('pwsh.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', hostScript,
          '-Mode', 'RemoveOwnedLocation', '-ExpectedInstall', install, '-RegistryView', view]);
        if (result !== 'OWNED_LOCATION_REMOVED') throw new Error('Owned NSIS location-key cleanup was not confirmed.');
      },
      removeData: () => removeOwnedDataDirectories({ appData, appLocalData, marker, owned }),
      removeTemp: () => { verifyMarker(temp); assertNoLinksInside(temp); rmSync(temp, { recursive: true }); },
    }),
    publishReceipt: evidence => {
      writeFileSync(receipt, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx' });
      console.log(JSON.stringify({ result: 'passed', baselineTag: WINDOWS_BASELINE.tag, tag: evidence.tag }));
    },
    publishBaselineSummary: () => console.log(JSON.stringify({
      result: 'passed', baselineOnly: true, baselineTag: WINDOWS_BASELINE.tag,
    })),
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const baselineOnly = process.argv[2] === '--baseline-only';
  main().catch(error => { console.error(formatWindowsUpgradeFailure(error, { baselineOnly })); process.exitCode = 1; });
}

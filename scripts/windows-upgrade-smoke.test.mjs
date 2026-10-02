import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { join, resolve, win32 } from 'node:path';
import { tmpdir } from 'node:os';
import { stopObservedWindowsProcess } from './native-smoke.mjs';
import { assertCleanWindowsHost, assertInstalledVersion, assertOwnedRegistration, checkUpgradeSequence,
  cleanupUpgradeFixture, createOwnedDataDirectories, formatWindowsUpgradeFailure, parseWindowsUpgradeArgs,
  removeOwnedDataDirectories, runUpgradeCommand, runUpgradeLifecycle, runUpgradeMode, runOwnedNsis,
  validateUpgradeContext, verifyWindowsBaseline, WINDOWS_BASELINE,
  WINDOWS_UPGRADE_STAGES } from './windows-upgrade-smoke.mjs';

async function rejected(promise) {
  let failure;
  try { await promise; } catch (error) { failure = error; }
  assert.ok(failure, 'expected rejection');
  return failure;
}

const failureReport = (error, options) => JSON.parse(formatWindowsUpgradeFailure(error, options));

async function rejectsAt(promise, stage) {
  const report = failureReport(await rejected(promise));
  assert.equal(report.diagnostics.some(diagnostic => diagnostic.stage === stage), true);
  return report;
}

test('NSIS uses a quoted executable and final unquoted spaced directory, waiting for the real uninstaller', () => {
  const binary = 'C:\\Runner Temp\\setup or uninstall.exe';
  const install = 'C:\\Runner Temp\\owned install';
  for (const uninstall of [false, true]) {
    let calls = 0;
    runOwnedNsis(binary, install, uninstall, (file, args, options) => {
      calls++;
      assert.equal(file, binary);
      assert.deepEqual(args, ['/S', `${uninstall ? '_?=' : '/D='}${install}`]);
      assert.equal(options.argv0, `"${binary}"`);
      assert.equal(options.windowsVerbatimArguments, true);
      assert.equal(options.shell, false);
      assert.equal(options.timeout, 120_000);
    });
    assert.equal(calls, 1);
    assert.throws(() => runOwnedNsis(binary, install, uninstall, () => { throw new Error('timeout'); }), /did not complete/);
  }
  for (const path of ['relative', 'C:\\bad"path', 'C:\\bad\npath', 'C:\\bad\0path']) {
    assert.throws(() => runOwnedNsis(binary, path, false, () => assert.fail('must not run')), /absolute Windows paths/);
  }
});

const sha = 'a'.repeat(40);
const context = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'Windows',
  RUNNER_ARCH: 'X64', RUNNER_TEMP: 'temporary-runner', APPDATA: 'C:\\Runner\\AppData\\Roaming',
  LOCALAPPDATA: 'C:\\Runner\\AppData\\Local',
  GITHUB_WORKSPACE: resolve('.'), RELEASE_TAG: 'v0.1.13', RELEASE_SHA: sha };

test('upgrade refuses wrong host, unreviewed source, missing isolated paths and non-upgrades', () => {
  assert.doesNotThrow(() => validateUpgradeContext(context, 'win32', 'x64', '.', sha));
  for (const patch of [
    { GITHUB_ACTIONS: '' }, { RUNNER_ENVIRONMENT: 'self-hosted' }, { RUNNER_OS: 'macOS' },
    { RUNNER_ARCH: 'ARM64' }, { RUNNER_TEMP: '' }, { APPDATA: '' }, { LOCALAPPDATA: '' }, { GITHUB_WORKSPACE: '/elsewhere' },
    { RELEASE_TAG: 'v0.1.5' }, { RELEASE_TAG: 'v0.1.4' }, { RELEASE_TAG: 'v0.1.13-beta' },
    { RELEASE_TAG: 'bad' }, { RELEASE_SHA: 'b'.repeat(40) },
  ]) assert.throws(() => validateUpgradeContext({ ...context, ...patch }, 'win32', 'x64', '.', sha));
  assert.throws(() => validateUpgradeContext(context, 'darwin', 'arm64', '.', sha));
});

test('installed version must match the package, not merely be a running executable', () => {
  for (const version of ['0.1.13', '0.1.13.0']) assert.doesNotThrow(() => assertInstalledVersion(version, '0.1.13'));
  for (const version of ['0.1.5', '0.1.130', '0.1.13-dev', '0.1.13\nother']) assert.throws(() => assertInstalledVersion(version, '0.1.13'));
});

test('baseline replacement is rejected before any signature or installer invocation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'upgrade-baseline-test-'));
  try {
    const file = join(dir, WINDOWS_BASELINE.filename);
    writeFileSync(file, 'unreviewed installer'); writeFileSync(`${file}.sig`, 'unreviewed signature');
    assert.throws(() => verifyWindowsBaseline(file, 'not-a-key'), /baseline bytes/);
  } finally { rmSync(dir, { recursive: true }); }
});

test('CLI preserves the release mode and accepts only the pinned baseline-only shape', () => {
  assert.deepEqual(parseWindowsUpgradeArgs(['baseline.exe', 'candidate']), {
    baselineOnly: false, baselineArg: 'baseline.exe', bundleArg: 'candidate',
  });
  assert.deepEqual(parseWindowsUpgradeArgs(['--baseline-only', 'baseline.exe']), {
    baselineOnly: true, baselineArg: 'baseline.exe', bundleArg: null,
  });
  for (const args of [[], ['--baseline-only'], ['--baseline-only', 'baseline.exe', 'candidate'],
    ['baseline.exe', '--baseline-only']]) assert.throws(() => parseWindowsUpgradeArgs(args));
});

function formattedCommandFailure(stderr, overrides = {}) {
  let failure;
  try {
    runUpgradeCommand('pwsh.exe', ['private-argument'], () => {
      throw Object.assign(new Error('private-message C:\\private\\fixture'), {
        status: 1603, code: 'ENOENT', signal: 'SIGTERM', stderr,
        stdout: 'private-stdout', path: 'C:\\private\\fixture', argv: ['private-argument'],
        environment: { PRIVATE_TOKEN: 'private-token' }, ...overrides,
      });
    });
  } catch (error) { failure = error; }
  assert.ok(failure);
  return formatWindowsUpgradeFailure(failure);
}

test('PowerShell host diagnostics accept only the exact bounded safe contract', () => {
  const secret = 'private-host-output';
  const valid = formattedCommandFailure(`${secret}\nSLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"registry","exception":"UnauthorizedAccessException","category":18,"hresult":-2147024891}`);
  assert.equal(valid.includes(secret), false);
  assert.deepEqual(JSON.parse(valid).diagnostics[0], {
    reason: 'native-command-failed', message: 'Native upgrade command failed.',
    exitStatus: 1603, errorCode: 'ENOENT', signal: 'SIGTERM', hostStage: 'registry',
    exceptionClass: 'UnauthorizedAccessException', category: 18, hresult: -2147024891,
  });

  const rejectedStderr = [
    'arbitrary private stderr C:\\private\\fixture',
    'SLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"registry","exception":"Other","category":1,"hresult":2,"extra":"private-extra"}',
    'SLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"private-stage","exception":"Other","category":1,"hresult":2}',
    'SLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"registry","exception":"PrivateException","category":1,"hresult":2}',
    'SLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"registry","exception":"Other","category":2147483648,"hresult":2}',
    'SLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"registry","exception":"Other","category":1,"hresult":1.5}',
    `SLG_WINDOWS_HOST_DIAGNOSTIC:{"stage":"registry","exception":"Other","category":1,"hresult":2}${' '.repeat(600)}`,
  ];
  for (const stderr of rejectedStderr) {
    const text = formattedCommandFailure(stderr);
    const diagnostic = JSON.parse(text).diagnostics[0];
    assert.equal('hostStage' in diagnostic, false);
    assert.equal('exceptionClass' in diagnostic, false);
    assert.equal(text.includes('private'), false);
    assert.equal(text.includes('fixture'), false);
  }
});

function sequence({ failAt, sameBinary = false } = {}) {
  const calls = [];
  let states = 0;
  const step = name => { calls.push(name); if (name === failAt) throw new Error('injected failure'); };
  return { calls, actions: {
    install: phase => step(`install:${phase}`),
    assertRegistration: phase => step(`registration:${phase}`),
    inspect: phase => { step(`inspect:${phase}`); return { sha256: sameBinary ? 'same' : phase }; },
    launch: phase => step(`launch:${phase}`),
    assertState: () => step(`state:${++states}`),
  } };
}
test('baseline must start and preserve configuration before the candidate is installed', async () => {
  for (const [failAt, stage] of [
    ['install:baseline', WINDOWS_UPGRADE_STAGES.BASELINE_INSTALL],
    ['registration:baseline', WINDOWS_UPGRADE_STAGES.BASELINE_REGISTRATION],
    ['inspect:baseline', WINDOWS_UPGRADE_STAGES.BASELINE_VERSION],
    ['launch:baseline', WINDOWS_UPGRADE_STAGES.BASELINE_STARTUP],
    ['state:1', WINDOWS_UPGRADE_STAGES.BASELINE_SAVED_STATE],
  ]) {
    const f = sequence({ failAt });
    await rejectsAt(checkUpgradeSequence(f.actions), stage);
    assert.equal(f.calls.includes('install:candidate'), false);
  }
});
test('failed install, stale binary or lost configuration cannot be reported as an upgrade', async () => {
  for (const [failAt, stage] of [
    ['install:candidate', WINDOWS_UPGRADE_STAGES.CANDIDATE_INSTALL],
    ['registration:candidate', WINDOWS_UPGRADE_STAGES.CANDIDATE_REGISTRATION],
    ['inspect:candidate', WINDOWS_UPGRADE_STAGES.CANDIDATE_VERSION],
    ['state:2', WINDOWS_UPGRADE_STAGES.CANDIDATE_SAVED_STATE],
    ['launch:candidate', WINDOWS_UPGRADE_STAGES.CANDIDATE_STARTUP],
    ['state:3', WINDOWS_UPGRADE_STAGES.CANDIDATE_SAVED_STATE],
  ]) {
    const f = sequence({ failAt });
    await rejectsAt(checkUpgradeSequence(f.actions), stage);
    assert.equal(f.calls.at(-1), failAt);
  }
  const f = sequence({ sameBinary: true });
  await rejectsAt(checkUpgradeSequence(f.actions), WINDOWS_UPGRADE_STAGES.CANDIDATE_VERSION);
  assert.equal(f.calls.includes('launch:candidate'), false);
});
test('successful covering upgrade records two distinct executables and checks state after both launches', async () => {
  const f = sequence();
  assert.deepEqual(await checkUpgradeSequence(f.actions), { baselineBinarySha256: 'baseline', candidateBinarySha256: 'candidate' });
  assert.deepEqual(f.calls, ['install:baseline', 'registration:baseline', 'inspect:baseline', 'launch:baseline', 'state:1',
    'install:candidate', 'registration:candidate', 'inspect:candidate', 'state:2', 'launch:candidate', 'state:3']);
});

test('nested aggregate and filesystem failures expose only fixed stages and controlled codes', async () => {
  const secret = 'private-nested-message C:\\private\\state.json';
  const filesystemError = Object.assign(new Error(secret), {
    code: 'ENOENT', path: 'C:\\private\\state.json', stdout: secret, stderr: secret,
  });
  const f = sequence();
  f.actions.install = phase => {
    f.calls.push(`install:${phase}`);
    throw new AggregateError([
      new AggregateError([filesystemError], secret),
      Object.assign(new Error(secret), { code: 'PRIVATE_SECRET_CODE', signal: 'PRIVATE_SIGNAL' }),
    ], secret);
  };
  const text = formatWindowsUpgradeFailure(await rejected(checkUpgradeSequence(f.actions)));
  const report = JSON.parse(text);
  assert.equal(report.diagnostics.length, 2);
  assert.equal(report.diagnostics.every(diagnostic =>
    diagnostic.stage === WINDOWS_UPGRADE_STAGES.BASELINE_INSTALL), true);
  assert.equal(report.diagnostics[0].errorCode, 'ENOENT');
  assert.equal('errorCode' in report.diagnostics[1], false);
  assert.equal('signal' in report.diagnostics[1], false);
  assert.equal(text.includes('private'), false);
  assert.equal(text.includes('state.json'), false);
});

test('execution and cleanup diagnostics are both retained while cleanup still runs and receipt stays absent', async () => {
  const calls = [];
  let published = false;
  const f = sequence();
  f.actions.install = phase => {
    calls.push(`install:${phase}`);
    runOwnedNsis('C:\\Runner\\baseline.exe', 'C:\\Runner\\owned', false, () => {
      throw Object.assign(new Error('private installer path C:\\private\\baseline.exe'), {
        status: 1603, stdout: 'private stdout', stderr: 'private stderr',
      });
    });
  };
  const failure = await rejected(runUpgradeLifecycle({
    execute: () => checkUpgradeSequence(f.actions),
    cleanup: () => {
      calls.push('cleanup');
      throw Object.assign(new Error('private cleanup C:\\private\\owned'), {
        code: 'EACCES', path: 'C:\\private\\owned',
      });
    },
    publish: () => { published = true; },
  }));
  const text = formatWindowsUpgradeFailure(failure);
  const diagnostics = JSON.parse(text).diagnostics;
  assert.deepEqual(diagnostics.map(({ origin, stage, reason }) => ({ origin, stage, reason })), [
    { origin: 'execution', stage: WINDOWS_UPGRADE_STAGES.BASELINE_INSTALL, reason: 'nsis-command-failed' },
    { origin: 'cleanup', stage: WINDOWS_UPGRADE_STAGES.CLEANUP, reason: 'operation-failed' },
  ]);
  assert.equal(diagnostics[0].exitStatus, 1603);
  assert.equal(diagnostics[1].errorCode, 'EACCES');
  assert.equal(calls.includes('cleanup'), true);
  assert.equal(published, false);
  assert.equal(text.includes('private'), false);
});

test('baseline-only reuses the staged sequence, never reaches candidate or formal receipt, and publishes after cleanup', async () => {
  const f = sequence();
  let receiptPublished = false;
  let summaryPublished = false;
  const result = await runUpgradeMode({
    baselineOnly: true,
    prepare: () => { f.calls.push('prepare'); },
    actions: f.actions,
    cleanup: () => { f.calls.push('cleanup'); },
    publishReceipt: () => { receiptPublished = true; },
    publishBaselineSummary: () => { summaryPublished = true; f.calls.push('baseline-summary'); },
  });
  assert.deepEqual(result, { baselineBinarySha256: 'baseline' });
  assert.deepEqual(f.calls, ['prepare', 'install:baseline', 'registration:baseline', 'inspect:baseline',
    'launch:baseline', 'state:1', 'cleanup', 'baseline-summary']);
  assert.equal(f.calls.some(call => call.includes('candidate')), false);
  assert.equal(receiptPublished, false);
  assert.equal(summaryPublished, true);

  const failed = sequence();
  receiptPublished = false;
  summaryPublished = false;
  const report = failureReport(await rejected(runUpgradeMode({
    baselineOnly: true,
    actions: failed.actions,
    cleanup: () => { throw new Error('private cleanup failure'); },
    publishReceipt: () => { receiptPublished = true; },
    publishBaselineSummary: () => { summaryPublished = true; },
  })), { baselineOnly: true });
  assert.equal(report.baselineOnly, true);
  assert.equal(report.diagnostics[0].stage, WINDOWS_UPGRADE_STAGES.CLEANUP);
  assert.equal(receiptPublished, false);
  assert.equal(summaryPublished, false);
});

const installPath = 'C:\\Runner\\Temp\\slg-upgrade\\installed';
const emptyHost = () => ({ roaming: context.APPDATA, local: context.LOCALAPPDATA,
  roamingReparse: false, localReparse: false, registrations: [], shortcuts: [] });
const directoryStat = () => ({ isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false });
const missing = () => Object.assign(new Error('missing'), { code: 'ENOENT' });
const absentAppStat = path => {
  if ([context.APPDATA, context.LOCALAPPDATA].some(root => win32.normalize(root) === win32.normalize(path))) return directoryStat();
  throw missing();
};
const registered = (version = '0.1.5') => ({ ...emptyHost(), registrations: [
  { hive: 'CurrentUser', view: 'Registry64', kind: 'uninstall', installLocation: `"${installPath}"`,
    uninstallString: `"${win32.join(installPath, 'uninstall.exe')}"`, displayVersion: version },
  { hive: 'CurrentUser', view: 'Registry64', kind: 'location', defaultValue: installPath },
], shortcuts: [{ path: 'product.lnk', target: win32.join(installPath, 'short-link-generator.exe') }] });

test('native Roaming and Local roots must match the environment and both app paths must be absent', () => {
  const paths = assertCleanWindowsHost(emptyHost(), context, absentAppStat);
  assert.equal(paths.appData, win32.join(context.APPDATA, 'org.shortlink.generator'));
  assert.equal(paths.appLocalData, win32.join(context.LOCALAPPDATA, 'org.shortlink.generator'));
  assert.throws(() => assertCleanWindowsHost(emptyHost(), { ...context, APPDATA: 'C:\\Bypass' }, absentAppStat), /differ/);
  assert.throws(() => assertCleanWindowsHost(emptyHost(), { ...context, LOCALAPPDATA: 'C:\\Bypass' }, absentAppStat), /differ/);
  assert.throws(() => assertCleanWindowsHost({ ...emptyHost(), localReparse: true }, context, absentAppStat), /reparse/);
  for (const path of [paths.appData, paths.appLocalData]) {
    assert.throws(() => assertCleanWindowsHost(emptyHost(), context,
      value => value === path ? directoryStat() : absentAppStat(value)), /both native/);
  }
  assert.throws(() => assertCleanWindowsHost(registered(), context, absentAppStat), /existing NSIS/);
  assert.throws(() => assertCleanWindowsHost({ ...emptyHost(), shortcuts: [{ path: 'existing.lnk' }] }, context, absentAppStat), /existing NSIS/);
});

test('failure creating the second app directory cleans only the first owned directory', () => {
  const paths = { appData: 'roaming-app', appLocalData: 'local-app', marker: 'private-marker',
    owned: { roaming: false, local: false } };
  const created = [], removed = [];
  assert.throws(() => createOwnedDataDirectories({ ...paths,
    mkdir: path => { if (path === paths.appLocalData) throw new Error('local create failed'); created.push(path); },
    write: () => {},
  }), /local create failed/);
  assert.deepEqual(created, [paths.appData]);
  assert.deepEqual(paths.owned, { roaming: true, local: false });
  removeOwnedDataDirectories({ ...paths, stat: directoryStat, read: () => paths.marker, checkTree: () => {},
    remove: path => removed.push(path) });
  assert.deepEqual(removed, [paths.appData]);
  assert.throws(() => removeOwnedDataDirectories({ ...paths, stat: directoryStat, checkTree: () => {},
    read: () => 'changed', remove: path => removed.push(path) }), /ownership changed/);
  assert.deepEqual(removed, [paths.appData]);
});

test('NSIS registration and shortcuts must bind to the exact owned install', async () => {
  assert.equal(assertOwnedRegistration(registered(), installPath, ['0.1.5'], true), win32.join(installPath, 'uninstall.exe'));
  const base = registered();
  const cases = [
    ['missing-or-invalid-registration', emptyHost(), 'NSIS registration is missing or invalid.'],
    ['outside-current-user-hive', { ...base, registrations: [{ ...base.registrations[0], hive: 'LocalMachine' }, base.registrations[1]] }, 'NSIS registration is outside the owned current-user hive.'],
    ['uninstall-location-mismatch', { ...base, registrations: [{ ...base.registrations[0], installLocation: '"C:\\Other"' }, base.registrations[1]] }, 'NSIS uninstall registration does not belong to this run.'],
    ['uninstaller-path-mismatch', { ...base, registrations: [{ ...base.registrations[0], uninstallString: '"C:\\Other\\uninstall.exe"' }, base.registrations[1]] }, 'NSIS uninstall registration does not belong to this run.'],
    ['uninstall-version-missing', { ...base, registrations: [{ ...base.registrations[0], displayVersion: '' }, base.registrations[1]] }, 'NSIS uninstall registration does not belong to this run.'],
    ['uninstall-version-mismatch', registered('9.9.9'), 'NSIS uninstall registration does not belong to this run.'],
    ['location-value-mismatch', { ...base, registrations: [base.registrations[0], { ...base.registrations[1], defaultValue: 'C:\\Other' }] }, 'NSIS install-location registration does not belong to this run.'],
    ['unknown-kind', { ...base, registrations: [base.registrations[0], { ...base.registrations[1], kind: 'other' }] }, 'Unknown NSIS registration type.'],
    ['missing-uninstall', { ...base, registrations: [base.registrations[1]] }, 'NSIS uninstall registration is missing.'],
    ['shortcut-target-mismatch', { ...base, shortcuts: [{ path: 'product.lnk', target: 'C:\\Other\\app.exe' }] }, 'Product shortcut target does not belong to this run.'],
  ];
  for (const [reason, host, legacyMessage] of cases) {
    assert.throws(() => assertOwnedRegistration(host, installPath, ['0.1.5'], true),
      error => error.message === legacyMessage);
    const f = sequence();
    f.actions.assertRegistration = () => assertOwnedRegistration(host, installPath, ['0.1.5'], true);
    const report = failureReport(await rejected(checkUpgradeSequence(f.actions)));
    assert.equal(report.diagnostics[0].stage, WINDOWS_UPGRADE_STAGES.BASELINE_REGISTRATION);
    assert.equal(report.diagnostics[0].reason, reason);
    assert.equal(typeof report.diagnostics[0].message, 'string');
    assert.equal(JSON.stringify(report).includes(installPath), false);
  }
});

function cleanupActions(snapshots, { failUninstall = false } = {}) {
  const calls = [];
  return { calls, actions: {
    inspect: () => { calls.push('inspect'); return snapshots.shift() ?? emptyHost(); },
    install: installPath,
    allowedVersions: ['0.1.5', '0.1.13'],
    assertUninstaller: path => { calls.push(`assert:${path}`); },
    uninstall: () => { calls.push('uninstall'); if (failUninstall) throw new Error('uninstaller failed'); },
    removeOwnedLocation: view => { calls.push(`remove-location:${view}`); },
    removeData: () => { calls.push('remove-data'); },
    removeTemp: () => { calls.push('remove-temp'); },
  } };
}

test('partial install runs only the exact owned uninstaller, then removes owned registry residue', async () => {
  const residue = { ...emptyHost(), registrations: [registered().registrations[1]] };
  const f = cleanupActions([registered(), residue, emptyHost()]);
  let published = false;
  const report = failureReport(await rejected(runUpgradeLifecycle({
    execute: () => { throw new Error('partial candidate install'); },
    cleanup: () => cleanupUpgradeFixture(f.actions),
    publish: () => { published = true; },
  })));
  assert.equal(report.diagnostics[0].origin, 'execution');
  assert.deepEqual(f.calls, ['inspect', `assert:${win32.join(installPath, 'uninstall.exe')}`,
    'uninstall', 'inspect', 'remove-location:Registry64', 'inspect', 'remove-data', 'remove-temp']);
  assert.equal(published, false);
});

test('uninstaller failure and residual registration stop cleanup before data removal or success receipt', async () => {
  for (const f of [cleanupActions([registered()], { failUninstall: true }),
    cleanupActions([registered(), registered()])]) {
    let published = false;
    const report = failureReport(await rejected(runUpgradeLifecycle({
      execute: () => ({ passed: true }),
      cleanup: () => cleanupUpgradeFixture(f.actions),
      publish: () => { published = true; },
    })));
    assert.equal(report.diagnostics[0].stage, WINDOWS_UPGRADE_STAGES.CLEANUP);
    assert.equal(published, false);
    assert.equal(f.calls.includes('remove-data'), false);
    assert.equal(f.calls.includes('remove-temp'), false);
  }
});

test('success receipt is published only after all cleanup stages pass', async () => {
  const f = cleanupActions([registered(), emptyHost()]);
  await runUpgradeLifecycle({ execute: () => ({ passed: true }),
    cleanup: () => cleanupUpgradeFixture(f.actions),
    publish: () => { f.calls.push('publish'); } });
  assert.deepEqual(f.calls.slice(-3), ['remove-data', 'remove-temp', 'publish']);
  const calls = [];
  const report = failureReport(await rejected(runUpgradeLifecycle({ execute: () => ({ passed: true }),
    cleanup: () => { calls.push('cleanup'); throw new Error('marker changed'); },
    publish: () => calls.push('publish') })));
  assert.equal(report.diagnostics[0].stage, WINDOWS_UPGRADE_STAGES.CLEANUP);
  assert.deepEqual(calls, ['cleanup']);
});

function observedChild() {
  const child = new EventEmitter();
  child.pid = 1234; child.exitCode = null; child.signalCode = null;
  child.kill = () => { queueMicrotask(() => { child.signalCode = 'SIGTERM'; child.emit('exit'); }); return true; };
  return child;
}

test('Windows process exit must be observed within a bound after tree kill', async () => {
  const child = observedChild();
  await stopObservedWindowsProcess(child, { killTree: () => {
    setTimeout(() => { child.exitCode = 0; child.emit('exit'); }, 5);
  }, timeoutMs: 100 });
  await assert.rejects(stopObservedWindowsProcess(observedChild(), {
    killTree: () => {}, timeoutMs: 5,
  }), /did not exit/);
  await assert.rejects(stopObservedWindowsProcess(observedChild(), {
    killTree: () => { throw new Error('taskkill failed'); }, timeoutMs: 100,
  }), /taskkill failed/);
  const noFallback = observedChild();
  noFallback.kill = () => false;
  await assert.rejects(stopObservedWindowsProcess(noFallback, {
    killTree: () => { throw new Error('taskkill failed'); }, timeoutMs: 100,
  }), /fallback both failed/);
});

test('candidate install waits for baseline exit proof and stops on late or failed exit', async () => {
  const f = sequence();
  f.actions.launch = async phase => {
    f.calls.push(`launch:${phase}`);
    if (phase !== 'baseline') return;
    await stopObservedWindowsProcess(observedChild(), { killTree: () => {}, timeoutMs: 5 });
  };
  await rejectsAt(checkUpgradeSequence(f.actions), WINDOWS_UPGRADE_STAGES.BASELINE_STARTUP);
  assert.equal(f.calls.includes('install:candidate'), false);
  const late = sequence();
  late.actions.launch = async phase => {
    late.calls.push(`launch:${phase}`);
    const child = observedChild();
    await stopObservedWindowsProcess(child, { killTree: () => {
      setTimeout(() => { child.exitCode = 0; child.emit('exit'); }, 5);
    }, timeoutMs: 100 });
  };
  await checkUpgradeSequence(late.actions);
  assert.equal(late.calls.includes('install:candidate'), true);
});

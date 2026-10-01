import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { join, resolve, win32 } from 'node:path';
import { tmpdir } from 'node:os';
import { stopObservedWindowsProcess } from './native-smoke.mjs';
import { assertCleanWindowsHost, assertInstalledVersion, assertOwnedRegistration, checkUpgradeSequence,
  cleanupUpgradeFixture, createOwnedDataDirectories, removeOwnedDataDirectories, runUpgradeLifecycle,
  runOwnedNsis, validateUpgradeContext, verifyWindowsBaseline, WINDOWS_BASELINE } from './windows-upgrade-smoke.mjs';

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

function sequence({ failAt, sameBinary = false } = {}) {
  const calls = [];
  let states = 0;
  const step = name => { calls.push(name); if (name === failAt) throw new Error('injected failure'); };
  return { calls, actions: {
    install: phase => step(`install:${phase}`),
    inspect: phase => { step(`inspect:${phase}`); return { sha256: sameBinary ? 'same' : phase }; },
    launch: phase => step(`launch:${phase}`),
    assertState: () => step(`state:${++states}`),
  } };
}
test('baseline must start and preserve configuration before the candidate is installed', async () => {
  for (const failAt of ['install:baseline', 'inspect:baseline', 'launch:baseline', 'state:1']) {
    const f = sequence({ failAt });
    await assert.rejects(checkUpgradeSequence(f.actions), /injected failure/);
    assert.equal(f.calls.includes('install:candidate'), false);
  }
});
test('failed install, stale binary or lost configuration cannot be reported as an upgrade', async () => {
  for (const failAt of ['install:candidate', 'inspect:candidate', 'state:2', 'launch:candidate', 'state:3']) {
    const f = sequence({ failAt });
    await assert.rejects(checkUpgradeSequence(f.actions), /injected failure/);
    assert.equal(f.calls.at(-1), failAt);
  }
  const f = sequence({ sameBinary: true });
  await assert.rejects(checkUpgradeSequence(f.actions), /old executable/);
  assert.equal(f.calls.includes('launch:candidate'), false);
});
test('successful covering upgrade records two distinct executables and checks state after both launches', async () => {
  const f = sequence();
  assert.deepEqual(await checkUpgradeSequence(f.actions), { baselineBinarySha256: 'baseline', candidateBinarySha256: 'candidate' });
  assert.deepEqual(f.calls, ['install:baseline', 'inspect:baseline', 'launch:baseline', 'state:1',
    'install:candidate', 'inspect:candidate', 'state:2', 'launch:candidate', 'state:3']);
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

test('NSIS registration and shortcuts must bind to the exact owned install', () => {
  assert.equal(assertOwnedRegistration(registered(), installPath, ['0.1.5'], true), win32.join(installPath, 'uninstall.exe'));
  assert.throws(() => assertOwnedRegistration({ ...registered(), registrations: [
    { ...registered().registrations[0], hive: 'LocalMachine' }, registered().registrations[1],
  ] }, installPath, ['0.1.5'], true), /owned current-user/);
  assert.throws(() => assertOwnedRegistration({ ...registered(), registrations: [
    { ...registered().registrations[0], uninstallString: '"C:\\Other\\uninstall.exe"' }, registered().registrations[1],
  ] }, installPath, ['0.1.5'], true), /does not belong/);
  assert.throws(() => assertOwnedRegistration({ ...registered(), shortcuts: [
    { path: 'product.lnk', target: 'C:\\Other\\app.exe' },
  ] }, installPath, ['0.1.5'], true), /shortcut target/);
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
  await assert.rejects(runUpgradeLifecycle({
    execute: () => { throw new Error('partial candidate install'); },
    cleanup: () => cleanupUpgradeFixture(f.actions),
    publish: () => { published = true; },
  }), /partial candidate install/);
  assert.deepEqual(f.calls, ['inspect', `assert:${win32.join(installPath, 'uninstall.exe')}`,
    'uninstall', 'inspect', 'remove-location:Registry64', 'inspect', 'remove-data', 'remove-temp']);
  assert.equal(published, false);
});

test('uninstaller failure and residual registration stop cleanup before data removal or success receipt', async () => {
  for (const f of [cleanupActions([registered()], { failUninstall: true }),
    cleanupActions([registered(), registered()])]) {
    let published = false;
    await assert.rejects(runUpgradeLifecycle({
      execute: () => ({ passed: true }),
      cleanup: () => cleanupUpgradeFixture(f.actions),
      publish: () => { published = true; },
    }), /uninstaller failed|left an uninstall registration/);
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
  await assert.rejects(runUpgradeLifecycle({ execute: () => ({ passed: true }),
    cleanup: () => { calls.push('cleanup'); throw new Error('marker changed'); },
    publish: () => calls.push('publish') }), /marker changed/);
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
  await assert.rejects(checkUpgradeSequence(f.actions), /did not exit/);
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

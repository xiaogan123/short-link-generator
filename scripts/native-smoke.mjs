import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  updaterPublicKeySha256, verifyUpdaterSignatureFile,
} from './updater-signature.mjs';
import { observeWindowsWindow } from './windows-window-observer.mjs';
import { bundleManifest, verifyMacArtifactSet } from './macos-artifact.mjs';
import { helperPinForTarget } from './macos-credential-helper-bytes.mjs';

const targets = {
  'aarch64-apple-darwin': { host: 'darwin', arch: 'arm64', binaryArch: 'arm64', updater: '.app.tar.gz' },
  'x86_64-apple-darwin': { host: 'darwin', arch: 'x64', binaryArch: 'x86_64', updater: '.app.tar.gz' },
  'x86_64-pc-windows-msvc': { host: 'win32', arch: 'x64', updater: '-setup.exe' },
};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const run = (command, args, options = {}) => execFileSync(command, args, {
  encoding: 'utf8', timeout: 120_000, stdio: 'pipe', ...options,
}).trim();

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) throw new Error('Native artifacts must not contain filesystem links.');
    return entry.isDirectory() ? (entry.name.endsWith('.app') ? [] : walk(path)) : [path];
  });
}

export function selectArtifacts(bundle, target) {
  if (!lstatSync(bundle).isDirectory()) throw new Error('Native artifact root must be a real directory.');
  const config = targets[target];
  if (!config) throw new Error('Unsupported native target.');
  const files = walk(bundle);
  const installerMatches = files.filter(path => config.host === 'darwin'
    ? path.endsWith('.dmg') : path.endsWith('-setup.exe') && path.includes(`${sep}nsis${sep}`));
  const updaterMatches = files.filter(path => path.endsWith(config.updater));
  if (installerMatches.length !== 1 || updaterMatches.length !== 1) {
    throw new Error('Expected exactly one native installer and one updater package.');
  }
  const [installer] = installerMatches;
  const [updater] = updaterMatches;
  const signature = `${updater}.sig`;
  if (![installer, updater].every(path => lstatSync(path).isFile())) throw new Error('Native artifacts must be regular files.');
  if (!files.includes(signature) || !lstatSync(signature).isFile() || !readFileSync(signature, 'utf8').trim()) {
    throw new Error('Signed updater package is missing its nonempty signature.');
  }
  return { installer, updater, signature, config };
}

export function isWindowsX64Executable(path) {
  const data = readFileSync(path);
  if (data.length < 64 || data.toString('ascii', 0, 2) !== 'MZ') return false;
  const header = data.readUInt32LE(0x3c);
  return header + 6 <= data.length && data.toString('ascii', header, header + 4) === 'PE\0\0'
    && data.readUInt16LE(header + 4) === 0x8664;
}

function running(child) {
  return child.pid && child.exitCode === null && child.signalCode === null;
}

export function nativeGuiSpawnOptions(cwd, env) {
  return { cwd, env, stdio: 'ignore', windowsHide: false };
}

export async function stopObservedWindowsProcess(child, {
  killTree = pid => run('taskkill.exe', ['/PID', String(pid), '/T', '/F'], { timeout: 10_000 }),
  timeoutMs = 10_000,
} = {}) {
  if (!running(child)) return;
  let treeKillFailed = false;
  try { killTree(child.pid); }
  catch { treeKillFailed = true; }
  if (treeKillFailed) {
    let fallbackSent = false;
    try { fallbackSent = child.kill() === true; } catch { /* report below */ }
    if (!fallbackSent) throw new Error('Windows application tree kill and fallback both failed.');
  }
  if (running(child)) {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error('Windows application did not exit before cleanup deadline.')), timeoutMs);
      const onExit = () => finish();
      const onError = () => finish(new Error('Windows application exit could not be confirmed.'));
      function finish(error) {
        clearTimeout(timer);
        child.off('exit', onExit);
        child.off('error', onError);
        if (error) reject(error);
        else resolve();
      }
      child.once('exit', onExit);
      child.once('error', onError);
      if (!running(child)) finish();
    });
  }
  if (running(child)) throw new Error('Windows application exit could not be confirmed.');
  if (treeKillFailed) throw new Error('Windows taskkill failed; upgrade sequence halted after fallback cleanup.');
}

export async function observeStartup(binary, cwd, env, expectWindow, args = []) {
  const child = spawn(binary, args, nativeGuiSpawnOptions(cwd, env));
  let launchError;
  child.on('error', error => { launchError = error; });
  let windowObserved = null;
  let startupSeconds = 0;
  let result;
  try {
    if (expectWindow) {
      const startedAt = Date.now();
      await pause(250);
      if (launchError || !running(child)) {
        throw new Error(`Installed application exited during startup (${launchError?.code ?? child.exitCode ?? child.signalCode}).`);
      }
      await observeWindowsWindow(child.pid);
      const remainingStableMs = Math.max(0, 3_000 - (Date.now() - startedAt));
      if (remainingStableMs) await pause(remainingStableMs);
      if (launchError || !running(child)) {
        throw new Error(`Installed application exited after its window appeared (${launchError?.code ?? child.exitCode ?? child.signalCode}).`);
      }
      result = { processAlive: true, windowObserved: true, startupSeconds: Math.ceil((Date.now() - startedAt) / 1_000) };
      return result;
    }
    for (let second = 0; second < 12; second++) {
      await pause(1_000);
      startupSeconds = second + 1;
      if (launchError || !running(child)) {
        throw new Error(`Installed application exited during startup (${launchError?.code ?? child.exitCode ?? child.signalCode}).`);
      }
    }
    result = { processAlive: true, windowObserved, startupSeconds };
    return result;
  } finally {
    if (running(child)) {
      if (process.platform === 'win32') {
        await stopObservedWindowsProcess(child);
        if (result) result.processExitedAfterObservation = true;
      } else {
        child.kill('SIGTERM');
        await pause(1_000);
        if (running(child)) child.kill('SIGKILL');
      }
    } else if (process.platform === 'win32' && result) {
      result.processExitedAfterObservation = true;
    }
  }
}

async function smokeMac(installer, updater, bundle, config, temp, target) {
  const mount = join(temp, 'mount');
  mkdirSync(mount);
  let attached = false;
  try {
    run('hdiutil', ['attach', '-readonly', '-nobrowse', '-mountpoint', mount, installer]);
    attached = true;
    const apps = readdirSync(mount).filter(name => name.endsWith('.app'));
    if (apps.length !== 1 || !lstatSync(join(mount, apps[0])).isDirectory()) throw new Error('DMG must contain exactly one real application directory.');
    const mountedManifest = bundleManifest(join(mount, apps[0]));
    const app = join(temp, 'installed.app');
    run('ditto', [join(mount, apps[0]), app]);
    if (bundleManifest(app).sha256 !== mountedManifest.sha256) throw new Error('Copied application differs from the mounted DMG.');
    const builtApps = readdirSync(join(bundle, 'macos')).filter(name => name.endsWith('.app'));
    if (builtApps.length !== 1) throw new Error('Expected exactly one built macOS application.');
    const { nativeSigning, macArtifacts } = verifyMacArtifactSet({ updater, installedApp: app,
      builtApp: join(bundle, 'macos', builtApps[0]), destination: join(temp, 'updater'),
      pin: process.env.SLG_MACOS_CERT_SHA256,
      helperTreePin: helperPinForTarget(target, process.env) });
    const binary = join(app, 'Contents', 'MacOS', 'short-link-generator');
    const archs = run('lipo', ['-archs', binary]).split(/\s+/);
    if (archs.length !== 1 || archs[0] !== config.binaryArch) {
      throw new Error('Installed application architecture does not match the native runner.');
    }
    const startup = await observeStartup(binary, join(app, 'Contents', 'MacOS'), process.env, false);
    return { installation: 'read-only DMG mount and copied app', signatureVerified: true, nativeSigning, macArtifacts,
      architectureVerified: true, ...startup };
  } finally {
    if (attached) run('hdiutil', ['detach', mount]);
  }
}

async function smokeWindows(installer, temp) {
  const install = join(temp, 'installed');
  mkdirSync(install);
  run(installer, ['/S', `/D=${install}`], { windowsHide: true });
  const binaries = walk(install).filter(path => basename(path).toLowerCase() === 'short-link-generator.exe');
  if (binaries.length !== 1) throw new Error('NSIS installation did not produce one application executable.');
  if (!isWindowsX64Executable(binaries[0])) throw new Error('Installed application is not a Windows x64 executable.');
  const startup = await observeStartup(binaries[0], install, process.env, true);
  return { installation: 'silent NSIS into temporary directory', signatureVerified: null,
    architectureVerified: true, ...startup };
}

export async function main(args = process.argv.slice(2)) {
  const [bundleArg, target, mode] = args;
  if (!bundleArg || !targets[target]) throw new Error('Usage: node scripts/native-smoke.mjs <bundle> <target> [--plan]');
  const bundle = resolve(bundleArg);
  const { installer, updater, signature, config } = selectArtifacts(bundle, target);
  if (mode === '--plan') {
    console.log(JSON.stringify({ target, installer: basename(installer), updater: basename(updater) }));
    return;
  }
  if (mode) throw new Error('Unknown smoke mode.');
  const runnerOs = config.host === 'darwin' ? 'macOS' : 'Windows';
  const runnerArch = config.arch === 'arm64' ? 'ARM64' : 'X64';
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted' ||
      process.env.RUNNER_OS !== runnerOs || process.env.RUNNER_ARCH !== runnerArch ||
      !process.env.RUNNER_TEMP || resolve(process.env.GITHUB_WORKSPACE ?? '') !== resolve('.')) {
    throw new Error('Installed-app smoke is restricted to the matching fresh GitHub-hosted runner.');
  }
  if (process.platform !== config.host || process.arch !== config.arch) {
    throw new Error('Native installer smoke must run on the matching host architecture.');
  }
  const tag = process.env.RELEASE_TAG;
  const sha = process.env.RELEASE_SHA;
  if (!/^v\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(tag ?? '') || !/^[0-9a-f]{40}$/.test(sha ?? '')) {
    throw new Error('Validated release tag and source SHA are required.');
  }
  if (run('git', ['rev-parse', 'HEAD']) !== sha) throw new Error('Source SHA changed after preparation.');
  const updaterPublicKey = process.env.SLG_UPDATER_PUBLIC_KEY;
  if (!updaterPublicKey) throw new Error('Configured updater public key is required.');
  verifyUpdaterSignatureFile(updater, signature, updaterPublicKey, tag);
  const publicKeySha256 = updaterPublicKeySha256(updaterPublicKey);
  const temp = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'slg-native-smoke-'));
  try {
    const result = config.host === 'darwin'
      ? await smokeMac(installer, updater, bundle, config, temp, target)
      : await smokeWindows(installer, temp);
    const evidence = { schema: 1, tag, sha, target,
      host: `${process.platform}-${process.arch}`, checkedAt: new Date().toISOString(),
      installer: basename(installer), installerSha256: digest(installer),
      updater: basename(updater), updaterSha256: digest(updater),
      updaterSignature: basename(signature), updaterSignatureSha256: digest(signature),
      updaterPublicKeySha256: publicKeySha256,
      updaterSignaturePresent: true, updaterSignatureVerified: true, ...result };
    writeFileSync(join(bundle, 'native-smoke.json'), `${JSON.stringify(evidence, null, 2)}\n`);
    console.log(JSON.stringify({ target, result: 'passed', ...result }));
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}

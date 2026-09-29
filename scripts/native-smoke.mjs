import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

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
    return entry.isDirectory() ? walk(path) : [path];
  });
}

export function selectArtifacts(bundle, target) {
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
  if (!files.includes(`${updater}.sig`) || !readFileSync(`${updater}.sig`, 'utf8').trim()) {
    throw new Error('Signed updater package is missing its nonempty signature.');
  }
  return { installer, updater, config };
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

async function observeStartup(binary, cwd, env, expectWindow) {
  const child = spawn(binary, [], { cwd, env, stdio: 'ignore' });
  let launchError;
  child.on('error', error => { launchError = error; });
  let windowObserved = null;
  let startupSeconds = 0;
  try {
    for (let second = 0; second < 12; second++) {
      await pause(1_000);
      startupSeconds = second + 1;
      if (launchError || !running(child)) {
        throw new Error(`Installed application exited during startup (${launchError?.code ?? child.exitCode ?? child.signalCode}).`);
      }
      if (expectWindow) {
        const output = run('powershell.exe', [
          '-NoProfile', '-NonInteractive', '-Command',
          `$p=Get-Process -Id ${child.pid} -ErrorAction Stop; if ($p.MainWindowHandle -ne 0) { 'yes' } else { 'no' }`,
        ], { timeout: 10_000 });
        windowObserved = output === 'yes';
        if (windowObserved && second >= 2) break;
      }
    }
    if (expectWindow && !windowObserved) throw new Error('Installed application did not show a native window.');
    return { processAlive: true, windowObserved, startupSeconds };
  } finally {
    if (running(child)) {
      if (process.platform === 'win32') {
        try { run('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { timeout: 10_000 }); }
        catch { child.kill(); }
      } else {
        child.kill('SIGTERM');
        await pause(1_000);
        if (running(child)) child.kill('SIGKILL');
      }
    }
  }
}

async function smokeMac(installer, config, temp) {
  const mount = join(temp, 'mount');
  mkdirSync(mount);
  let attached = false;
  try {
    run('hdiutil', ['attach', '-readonly', '-nobrowse', '-mountpoint', mount, installer]);
    attached = true;
    const apps = readdirSync(mount).filter(name => name.endsWith('.app'));
    if (apps.length !== 1) throw new Error('DMG must contain exactly one application.');
    const app = join(temp, 'installed.app');
    run('ditto', [join(mount, apps[0]), app]);
    run('codesign', ['--verify', '--deep', '--strict', app]);
    const binary = join(app, 'Contents', 'MacOS', 'short-link-generator');
    const archs = run('lipo', ['-archs', binary]).split(/\s+/);
    if (archs.length !== 1 || archs[0] !== config.binaryArch) {
      throw new Error('Installed application architecture does not match the native runner.');
    }
    const startup = await observeStartup(binary, join(app, 'Contents', 'MacOS'), process.env, false);
    return { installation: 'read-only DMG mount and copied app', signatureVerified: true,
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
  const { installer, updater, config } = selectArtifacts(bundle, target);
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
  const temp = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), 'slg-native-smoke-'));
  try {
    const result = config.host === 'darwin'
      ? await smokeMac(installer, config, temp)
      : await smokeWindows(installer, temp);
    const evidence = { schema: 1, tag, sha, target,
      host: `${process.platform}-${process.arch}`, checkedAt: new Date().toISOString(),
      installer: basename(installer), installerSha256: digest(installer),
      updater: basename(updater), updaterSha256: digest(updater),
      updaterSignaturePresent: true, ...result };
    writeFileSync(join(bundle, 'native-smoke.json'), `${JSON.stringify(evidence, null, 2)}\n`);
    console.log(JSON.stringify({ target, result: 'passed', ...result }));
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}

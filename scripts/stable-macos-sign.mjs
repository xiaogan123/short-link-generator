import { createPrivateKey, randomBytes } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { certificateInfo, cleanSigningEnvironment, stableRequirement, verifyMacSigning } from './macos-signature.mjs';
import { signingToolEnvironment } from './macos-codesign.mjs';
import { verifyRcodesignTool } from './rcodesign-tool.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const shellQuote = value => `'${value.replace(/'/g, `'"'"'`)}'`;
const fail = (stage = 'configuration') => Object.assign(new Error(`Isolated macOS signing failed at ${stage}; no candidate is approved.`), { stage });

// Only the packaging process needs the updater signer. Inspection and native
// security tools use cleanSigningEnvironment without these private inputs.
export function cleanBuildEnvironment(env) {
  const clean = cleanSigningEnvironment(env);
  for (const name of ['TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD']) {
    if (env[name] !== undefined) clean[name] = env[name];
  }
  return clean;
}

function privateFile(path, cwd) {
  const actual = realpathSync(path);
  const repo = realpathSync(cwd);
  const stat = statSync(actual);
  if (!isAbsolute(path) || actual === repo || actual.startsWith(`${repo}${sep}`) || !stat.isFile() ||
      (stat.mode & 0o077) !== 0 || stat.size > 1024 * 1024) throw fail();
  return readFileSync(actual);
}

export function loadMaterial(env, cwd) {
  if (Boolean(env.SLG_MACOS_SIGNING_P12_PATH) === Boolean(env.SLG_MACOS_SIGNING_P12_BASE64)) throw fail();
  if ((env.SLG_MACOS_SIGNING_P12_PASSWORD !== undefined) === Boolean(env.SLG_MACOS_SIGNING_P12_PASSWORD_FILE)) throw fail();
  let p12;
  if (env.SLG_MACOS_SIGNING_P12_PATH) p12 = privateFile(env.SLG_MACOS_SIGNING_P12_PATH, cwd);
  else {
    const encoded = env.SLG_MACOS_SIGNING_P12_BASE64;
    if (encoded.length > 2 * 1024 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw fail();
    p12 = Buffer.from(encoded, 'base64');
    if (p12.toString('base64') !== encoded) throw fail();
  }
  const password = env.SLG_MACOS_SIGNING_P12_PASSWORD_FILE
    ? privateFile(env.SLG_MACOS_SIGNING_P12_PASSWORD_FILE, cwd).toString('utf8').replace(/\r?\n$/, '')
    : env.SLG_MACOS_SIGNING_P12_PASSWORD;
  if (!password || password.length > 4096 || /[\r\n\0]/.test(password)) { p12.fill(0); throw fail(); }
  return { p12, password };
}

// Captures all tool output. Neither tool errors nor command arguments may print secret material.
export function runCaptured(command, args, { env, input, timeout = 60_000, onChild } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    onChild?.(child);
    const chunks = [];
    let size = 0;
    let failed = false;
    const timer = setTimeout(() => { failed = true; child.kill('SIGKILL'); }, timeout);
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) { failed = true; child.kill('SIGKILL'); }
      else chunks.push(chunk);
    });
    child.stderr.resume();
    child.stdin.on('error', () => {});
    child.on('error', () => { failed = true; });
    child.on('close', code => {
      clearTimeout(timer);
      onChild?.(null);
      if (failed || code !== 0) { for (const chunk of chunks) chunk.fill(0); reject(fail()); }
      else { const output = Buffer.concat(chunks); for (const chunk of chunks) chunk.fill(0); resolveResult(output); }
    });
    child.stdin.end(input);
  });
}

export async function prepareMaterial(material, expectedPin, { run = runCaptured, openssl = '/usr/bin/openssl', env = {}, temp }) {
  const decodeEnv = { ...env, SLG_INTERNAL_P12_PASSWORD: material.password };
  let privatePem, exportPem;
  try {
    const certOutput = await run(openssl, ['pkcs12', '-passin', 'env:SLG_INTERNAL_P12_PASSWORD', '-nokeys'], { env: decodeEnv, input: material.p12 });
    const certificates = certOutput.toString('utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (certificates?.length !== 1) throw fail();
    const cert = new X509Certificate(certificates[0]);
    const info = certificateInfo(cert.raw, expectedPin);
    privatePem = await run(openssl, ['pkcs12', '-passin', 'env:SLG_INTERNAL_P12_PASSWORD', '-nocerts', '-nodes'], { env: decodeEnv, input: material.p12 });
    if ((privatePem.toString('utf8').match(/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/g) ?? []).length !== 1 ||
        !cert.checkPrivateKey(createPrivateKey(privatePem))) throw fail();
    // Omitted input options use stdin directly. Descriptor paths reopen Node's
    // socket-backed pipe on Linux; '-' is not portable to Apple's LibreSSL.
    exportPem = Buffer.concat([privatePem, Buffer.from(`\n${certificates[0]}\n`)]);
    const importPassword = randomBytes(32).toString('base64url');
    const wrapped = await run(openssl, ['pkcs12', '-export', '-passout', 'env:SLG_INTERNAL_IMPORT_PASSWORD'], {
      env: { ...env, SLG_INTERNAL_IMPORT_PASSWORD: importPassword }, input: exportPem,
    });
    const importPath = join(temp, 'import.p12');
    writeFileSync(importPath, wrapped, { mode: 0o600 });
    wrapped.fill(0);
    return { ...info, importPath, importPassword };
  } catch {
    throw new Error('macOS signing material, password, certificate pin, or private-key match is invalid.');
  } finally {
    exportPem?.fill(0);
    privatePem?.fill(0);
    material.p12.fill(0);
    delete decodeEnv.SLG_INTERNAL_P12_PASSWORD;
  }
}

async function runBuild(command, env, cwd, state) {
  return new Promise((resolveBuild, reject) => {
    const child = spawn(command[0], command.slice(1), { env, cwd, detached: true, stdio: 'inherit' });
    state.child = child;
    state.groupPid = child.pid;
    child.on('error', () => reject(fail()));
    child.on('exit', (code, signal) => { state.child = null; code === 0 && !signal ? resolveBuild() : reject(fail()); });
  });
}

export async function withStableSigning({ command, env = process.env, cwd = process.cwd(), platform = process.platform,
  arch = process.arch, run = runCaptured, build = runBuild, verify = verifyMacSigning, materialLoader = loadMaterial,
  materialPreparer = prepareMaterial, verifyTool = verifyRcodesignTool, tempRoot = tmpdir(), removeTemp = path => rmSync(path, { recursive: true, force: true }) }) {
  if (platform !== 'darwin' || !command?.length || !/^[a-f0-9]{64}$/.test(env.SLG_MACOS_CERT_SHA256 ?? '') ||
      !env.SLG_RCODESIGN_PATH || env.SLG_MACOS_OPENSSL !== undefined) throw fail();
  const targetIndex = command.indexOf('--target');
  if (!['arm64', 'x64'].includes(arch) || command.filter(value => value === '--target').length > 1 ||
      command.some(value => value.startsWith('--target=')) ||
      (targetIndex >= 0 && command[targetIndex + 1] !== ({ arm64: 'aarch64-apple-darwin', x64: 'x86_64-apple-darwin' })[arch])) throw fail();
  const temp = mkdtempSync(join(tempRoot, 'slg-macos-sign-'));
  const toolEnv = signingToolEnvironment({ ...env, TMPDIR: temp });
  const inventoryEnv = signingToolEnvironment(env);
  const state = { child: null, toolChild: null, interrupted: false };
  let killTimer;
  const stop = () => {
    state.interrupted = true;
    state.toolChild?.kill('SIGKILL');
    if (state.child?.pid) {
      const pid = state.child.pid;
      try { process.kill(-pid, 'SIGTERM'); } catch {}
      killTimer ??= setTimeout(() => { try { process.kill(-pid, 'SIGKILL'); } catch {} }, 5000);
    }
  };
  const check = () => { if (state.interrupted) throw fail('interrupted'); };
  const checkedRun = async (cmd, args, options = {}) => {
    check();
    const result = await run(cmd, args, { ...options, onChild: child => { state.toolChild = child; } });
    check(); return result;
  };
  const inventory = async () => ({
    searchList: (await run('/usr/bin/security', ['list-keychains', '-d', 'user'], { env: inventoryEnv })).toString(),
    defaultKeychain: (await run('/usr/bin/security', ['default-keychain', '-d', 'user'], { env: inventoryEnv })).toString(),
  });
  for (const name of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(name, stop);
  let before, result, tool, operationFailure, cleanupFailure;
  let stage = 'configuration';
  try {
    chmodSync(temp, 0o700);
    stage = 'core-limits';
    const limits = (await checkedRun('/bin/sh', ['-c', 'ulimit -S -c; ulimit -H -c'], { env: toolEnv })).toString().trim();
    if (limits !== '0\n0') throw fail();
    stage = 'signer-tool';
    tool = await verifyTool(env.SLG_RCODESIGN_PATH, { arch, platform,
      run: (cmd, args, options) => checkedRun(cmd, args, { ...options, env: toolEnv }) });
    check();
    const privateTool = join(realpathSync(temp), 'rcodesign');
    copyFileSync(tool.path, privateTool); chmodSync(privateTool, 0o500);
    const copiedTool = await verifyTool(privateTool, { arch, platform,
      run: (cmd, args, options) => checkedRun(cmd, args, { ...options, env: toolEnv }) });
    if (copiedTool.sha256 !== tool.sha256 || copiedTool.version !== tool.version || copiedTool.arch !== tool.arch) throw fail();
    tool = copiedTool;
    check();
    stage = 'searchlist'; before = await inventory(); check();
    stage = 'material';
    const prepared = await materialPreparer(materialLoader(env, cwd), env.SLG_MACOS_CERT_SHA256,
      { run: checkedRun, env: toolEnv, temp, openssl: '/usr/bin/openssl' });
    check();
    if (!prepared.importPassword || /[\r\n\0]/.test(prepared.importPassword)) throw fail();
    const passwordPath = join(temp, 'signing-password.txt');
    writeFileSync(passwordPath, prepared.importPassword, { mode: 0o600, flag: 'wx' });
    delete prepared.importPassword;
    stage = 'requirement';
    const requirementPath = join(temp, 'designated-requirement.bin');
    await checkedRun('/usr/bin/csreq', ['-r', `=${stableRequirement(prepared.certificateSha1)}`, '-b', requirementPath], { env: toolEnv });
    chmodSync(requirementPath, 0o600);
    const outputRoot = resolve(cwd, env.CARGO_TARGET_DIR || 'src-tauri/target');
    const home = join(temp, 'home'); const buildTemp = join(temp, 'build-temp');
    mkdirSync(home, { mode: 0o700 }); mkdirSync(buildTemp, { mode: 0o700 });
    const contextPath = join(temp, 'context.json');
    writeFileSync(contextPath, JSON.stringify({ schema: 1, outputRoot, materialRoot: temp, home, temp: buildTemp,
      certificateSha1: prepared.certificateSha1, certificateSha256: prepared.certificateSha256,
      p12Path: prepared.importPath, passwordPath, requirementPath, tool,
      entitlementsRoots: [realpathSync(cwd), realpathSync(buildTemp)] }), { mode: 0o600, flag: 'wx' });
    const bin = join(temp, 'bin'); mkdirSync(bin, { mode: 0o700 });
    // Tauri retains its updater inputs; the adapter starts with an empty environment.
    const shim = `#!/bin/sh\nexec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C HOME=${shellQuote(home)} TMPDIR=${shellQuote(buildTemp)} SLG_PRIVATE_SIGNING_CONTEXT=${shellQuote(contextPath)} ${shellQuote(process.execPath)} ${shellQuote(join(scriptDir, 'macos-codesign.mjs'))} "$@"\n`;
    writeFileSync(join(bin, 'codesign'), shim, { mode: 0o700, flag: 'wx' });
    check(); stage = 'build';
    await build(command, { ...cleanBuildEnvironment(env), APPLE_SIGNING_IDENTITY: prepared.certificateSha1,
      TMPDIR: buildTemp, SLG_PRIVATE_SIGNING_CONTEXT: contextPath,
      PATH: `${bin}:${cleanSigningEnvironment(env).PATH ?? '/usr/bin:/bin'}` }, cwd, state);
    check(); stage = 'verify';
    const targetAt = command.indexOf('--target');
    const target = targetAt < 0 ? '' : command[targetAt + 1];
    if (targetAt >= 0 && !['aarch64-apple-darwin', 'x86_64-apple-darwin'].includes(target)) throw fail();
    const bundle = join(outputRoot, target, 'release', 'bundle', 'macos');
    const apps = readdirSync(bundle).filter(name => name.endsWith('.app'));
    if (apps.length !== 1) throw fail();
    result = verify(join(bundle, apps[0]), env.SLG_MACOS_CERT_SHA256, (cmd, args, options) =>
      execFileSync(cmd, args, { ...options, env: toolEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000, killSignal: 'SIGKILL' }));
    check();
  } catch (error) { operationFailure = state.interrupted ? 'interrupted' : error.stage === 'interrupted' ? 'interrupted' : stage; }
  finally {
    if ((operationFailure || state.interrupted) && state.groupPid) {
      try { process.kill(-state.groupPid, 'SIGKILL'); } catch {}
    }
    try { removeTemp(temp); if (existsSync(temp)) throw fail(); }
    catch { cleanupFailure = 'cleanup'; }
    try {
      if (before && JSON.stringify(await inventory()) !== JSON.stringify(before)) cleanupFailure ??= 'searchlist';
    } catch { cleanupFailure ??= 'searchlist'; }
    clearTimeout(killTimer);
    for (const name of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.removeListener(name, stop);
  }
  if (operationFailure || cleanupFailure || state.interrupted) {
    const error = fail(operationFailure ?? cleanupFailure ?? 'interrupted');
    error.cleanupStage = cleanupFailure ?? null;
    throw error;
  }
  return { nativeSigning: result, backend: 'rcodesign', signerVersion: tool.version, signerSha256: tool.sha256,
    signerArch: tool.arch, temporarySigningFilesRemoved: true, searchListUnchanged: true,
    defaultKeychainUnchanged: true, keychainWrites: 0, trustWrites: 0 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const command = args[0] === '--' ? args.slice(1) : [];
  withStableSigning({ command }).then(result => console.log(JSON.stringify(result))).catch(error => {
    const stages = ['configuration', 'core-limits', 'signer-tool', 'material', 'requirement', 'build', 'verify', 'cleanup', 'searchlist', 'interrupted'];
    console.error(JSON.stringify({ ok: false, stage: stages.includes(error.stage) ? error.stage : 'cleanup',
      cleanupStage: stages.includes(error.cleanupStage) ? error.cleanupStage : null, candidateApproved: false }));
    process.exitCode = 1;
  });
}

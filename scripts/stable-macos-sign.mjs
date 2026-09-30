import { createPrivateKey, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { certificateInfo, cleanSigningEnvironment, verifyMacSigning } from './macos-signature.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const shellQuote = value => `'${value.replace(/'/g, `'"'"'`)}'`;
const fail = (stage = 'configuration') => Object.assign(new Error(`Isolated macOS signing failed at ${stage}; no candidate is approved.`), { stage });

// Share the same boundary with public-certificate inspection subprocesses.
export const cleanBuildEnvironment = cleanSigningEnvironment;

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
export function runCaptured(command, args, { env, input, timeout = 60_000 } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
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
      if (failed || code !== 0) reject(fail());
      else resolveResult(Buffer.concat(chunks));
    });
    child.stdin.end(input);
  });
}

export async function prepareMaterial(material, expectedPin, { run = runCaptured, openssl = '/usr/bin/openssl', env = {}, temp }) {
  const decodeEnv = { ...env, SLG_INTERNAL_P12_PASSWORD: material.password };
  let privatePem;
  try {
    const certOutput = await run(openssl, ['pkcs12', '-in', '/dev/stdin', '-passin', 'env:SLG_INTERNAL_P12_PASSWORD', '-nokeys'], { env: decodeEnv, input: material.p12 });
    const certificates = certOutput.toString('utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (certificates?.length !== 1) throw fail();
    const cert = new X509Certificate(certificates[0]);
    const info = certificateInfo(cert.raw, expectedPin);
    privatePem = await run(openssl, ['pkcs12', '-in', '/dev/stdin', '-passin', 'env:SLG_INTERNAL_P12_PASSWORD', '-nocerts', '-nodes'], { env: decodeEnv, input: material.p12 });
    if ((privatePem.toString('utf8').match(/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/g) ?? []).length !== 1 ||
        !cert.checkPrivateKey(createPrivateKey(privatePem))) throw fail();
    const certificatePath = join(temp, 'certificate.pem');
    writeFileSync(certificatePath, certificates[0], { mode: 0o600 });
    const importPassword = randomBytes(32).toString('base64url');
    const wrapped = await run(openssl, ['pkcs12', '-export', '-in', certificatePath, '-inkey', '/dev/stdin', '-passout', 'env:SLG_INTERNAL_IMPORT_PASSWORD'], {
      env: { ...env, SLG_INTERNAL_IMPORT_PASSWORD: importPassword }, input: privatePem,
    });
    const importPath = join(temp, 'import.p12');
    writeFileSync(importPath, wrapped, { mode: 0o600 });
    wrapped.fill(0);
    return { ...info, importPath, importPassword };
  } catch {
    throw new Error('macOS signing material, password, certificate pin, or private-key match is invalid.');
  } finally {
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
  run = runCaptured, build = runBuild, verify = verifyMacSigning, materialLoader = loadMaterial, tempRoot = tmpdir() }) {
  if (platform !== 'darwin' || !command?.length || !/^[a-f0-9]{64}$/.test(env.SLG_MACOS_CERT_SHA256 ?? '')) throw fail();
  const clean = cleanBuildEnvironment(env);
  const temp = mkdtempSync(join(tempRoot, 'slg-macos-sign-'));
  chmodSync(temp, 0o700);
  const keychain = join(temp, 'release-signing.keychain-db');
  const security = (args) => run('/usr/bin/security', args, { env: clean });
  const state = { child: null, interrupted: false };
  // A signal received during a tool invocation must stop the next key operation.
  // Cleanup deliberately uses security() directly so cancellation cannot prevent it.
  const signingSecurity = async args => {
    if (state.interrupted) throw fail('interrupted');
    const output = await security(args);
    if (state.interrupted) throw fail('interrupted');
    return output;
  };
  let killTimer;
  const stop = () => {
    state.interrupted = true;
    if (state.child?.pid) {
      const pid = state.child.pid;
      try { process.kill(-pid, 'SIGTERM'); } catch {}
      killTimer ??= setTimeout(() => { try { process.kill(-pid, 'SIGKILL'); } catch {} }, 5000);
    }
  };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  let beforeList;
  let beforeDefault;
  let result;
  let failure;
  let stage = 'material';
  let cleanupFailed = false;
  try {
    const material = materialLoader(env, cwd);
    const prepared = await prepareMaterial(material, env.SLG_MACOS_CERT_SHA256, { run, env: clean, temp,
      openssl: env.SLG_MACOS_OPENSSL ?? '/usr/bin/openssl' });
    stage = 'searchlist';
    beforeList = (await security(['list-keychains', '-d', 'user'])).toString();
    beforeDefault = (await security(['default-keychain', '-d', 'user'])).toString();
    if (state.interrupted) throw fail();
    // Only randomly generated, single-build passwords enter security's argv; never the long-term password.
    const keychainPassword = randomBytes(32).toString('base64url');
    stage = 'import';
    await signingSecurity(['create-keychain', '-p', keychainPassword, keychain]);
    await signingSecurity(['unlock-keychain', '-p', keychainPassword, keychain]);
    await signingSecurity(['import', prepared.importPath, '-k', keychain, '-P', prepared.importPassword, '-T', '/usr/bin/codesign']);
    rmSync(prepared.importPath);
    await signingSecurity(['set-key-partition-list', '-S', 'apple-tool:,apple:', '-s', '-k', keychainPassword, keychain]);
    stage = 'searchlist';
    if (beforeList !== (await security(['list-keychains', '-d', 'user'])).toString() ||
        beforeDefault !== (await security(['default-keychain', '-d', 'user'])).toString()) throw fail();
    const outputRoot = resolve(cwd, env.CARGO_TARGET_DIR || 'src-tauri/target');
    const contextPath = join(temp, 'context.json');
    writeFileSync(contextPath, JSON.stringify({ keychain, outputRoot, certificateSha1: prepared.certificateSha1 }), { mode: 0o600 });
    const bin = join(temp, 'bin'); mkdirSync(bin);
    writeFileSync(join(bin, 'codesign'), `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(join(scriptDir, 'macos-codesign.mjs'))} "$@"\n`, { mode: 0o700 });
    if (state.interrupted) throw fail();
    stage = 'build';
    await build(command, { ...clean, APPLE_SIGNING_IDENTITY: prepared.certificateSha1,
      SLG_PRIVATE_SIGNING_CONTEXT: contextPath, PATH: `${bin}${sep === '/' ? ':' : ';'}${clean.PATH ?? ''}` }, cwd, state);
    if (state.interrupted) throw fail();
    stage = 'verify';
    const targetAt = command.indexOf('--target');
    const target = targetAt < 0 ? '' : command[targetAt + 1];
    if (targetAt >= 0 && !['aarch64-apple-darwin', 'x86_64-apple-darwin'].includes(target)) throw fail();
    const bundle = join(outputRoot, target, 'release', 'bundle', 'macos');
    const apps = readdirSync(bundle).filter(name => name.endsWith('.app'));
    if (apps.length !== 1) throw fail();
    result = verify(join(bundle, apps[0]), env.SLG_MACOS_CERT_SHA256);
  } catch {
    failure = fail(state.interrupted ? 'interrupted' : stage);
  } finally {
    if ((failure || state.interrupted) && state.groupPid) {
      try { process.kill(-state.groupPid, 'SIGKILL'); } catch {}
    }
    try {
      if (existsSync(keychain)) {
        try { await security(['lock-keychain', keychain]); } catch {}
        await security(['delete-keychain', keychain]);
      }
    } catch { failure = fail('cleanup'); cleanupFailed = true; }
    try {
      if (beforeList !== undefined && (beforeList !== (await security(['list-keychains', '-d', 'user'])).toString() ||
          beforeDefault !== (await security(['default-keychain', '-d', 'user'])).toString())) failure = fail('searchlist');
    } catch { failure = fail('searchlist'); }
    try {
      if (!cleanupFailed) rmSync(temp, { recursive: true, force: true });
      else writeFileSync(join(temp, 'cleanup-required.json'), JSON.stringify({ stage: 'cleanup', encryptedTemporaryKeychainRetained: true }), { mode: 0o600 });
    } catch { failure = fail('cleanup'); }
    finally {
      clearTimeout(killTimer);
      process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
    }
  }
  if (failure || state.interrupted) throw failure || fail('interrupted');
  return { nativeSigning: result, isolatedKeychainRemoved: true, searchListUnchanged: true, defaultKeychainUnchanged: true };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const command = args[0] === '--' ? args.slice(1) : [];
  withStableSigning({ command }).then(result => console.log(JSON.stringify(result))).catch(error => {
    const stage = ['configuration','material','import','build','verify','cleanup','searchlist','interrupted'].includes(error.stage) ? error.stage : 'cleanup';
    console.error(JSON.stringify({ ok: false, stage, candidateApproved: false }));
    process.exitCode = 1;
  });
}

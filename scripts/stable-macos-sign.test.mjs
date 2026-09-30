import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { certificateInfo, hash, stableRequirement, validateMacSigningEvidence, validateRequirement, verifyMacSigning } from './macos-signature.mjs';
import { cleanBuildEnvironment, loadMaterial, prepareMaterial, runCaptured, withStableSigning } from './stable-macos-sign.mjs';
import { classifyCodesignError, executeSigning, readSigningContext, signingArguments, signingToolEnvironment } from './macos-codesign.mjs';

// All certificates/private keys below are throwaway synthetic fixtures outside the repository.
// No test creates/imports a real Keychain, invokes native signing, or reads user credentials.
const openssl = process.platform === 'darwin' && existsSync('/opt/homebrew/bin/openssl') ? '/opt/homebrew/bin/openssl' : 'openssl';
const supported = process.platform !== 'win32';
function fixture(fixtureOpenSSL = openssl) {
  const temp = mkdtempSync(join(tmpdir(), 'slg-signing-fixture-'));
  const key = join(temp, 'test-key.pem'); const cert = join(temp, 'test-cert.pem'); const p12 = join(temp, 'test.p12');
  const password = 'synthetic-fixture-only';
  const config = join(temp, 'fixture.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=codesign\n[dn]\nCN=Example Synthetic Signing\n[codesign]\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=codeSigning\nkeyUsage=critical,digitalSignature\n', { mode: 0o600 });
  const env = { ...process.env, FIXTURE_PASSWORD: password };
  execFileSync(fixtureOpenSSL, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-config', config], { env, stdio: 'pipe' });
  execFileSync(fixtureOpenSSL, ['pkcs12', '-export', '-inkey', key, '-in', cert, '-out', p12, '-passout', 'env:FIXTURE_PASSWORD'], { env, stdio: 'pipe' });
  const der = new X509Certificate(readFileSync(cert)).raw;
  const info = certificateInfo(der, hash(der));
  return { temp, password, der, info, p12: readFileSync(p12), cleanup: () => rmSync(temp, { recursive: true, force: true }) };
}
function evidence(info) {
  const requirement = stableRequirement(info.certificateSha1);
  return { identity: 'self-signed', identityVerified: true, signatureVerified: true, requirementVerified: true,
    certificateSelfSignatureVerified: true, notarization: 'not-notarized', identifier: 'org.shortlink.generator',
    ...info, designatedRequirement: requirement, designatedRequirementSha256: hash(requirement) };
}

test('stable DR rejects identifier-only, CN-only, cdhash, wrong cert and extra alternatives', () => {
  const sha1 = 'a'.repeat(40);
  assert.equal(validateRequirement(stableRequirement(sha1), sha1), stableRequirement(sha1));
  for (const requirement of ['identifier "org.shortlink.generator"', 'certificate leaf[subject.CN] = "Example"',
    `cdhash H"${sha1}"`, stableRequirement('b'.repeat(40)), `${stableRequirement(sha1)} or always`,
    stableRequirement(sha1).replace('generator"', 'generator'), 'identifier org.shortlink.generator and anchor trusted']) {
    assert.throws(() => validateRequirement(requirement, sha1));
  }
});

test('stable evidence binds the certificate, DR and actual verification results', () => {
  const info = { certificateSha1: 'a'.repeat(40), certificateSha256: 'b'.repeat(64) };
  const valid = evidence(info);
  validateMacSigningEvidence(valid, info.certificateSha256);
  for (const patch of [{ identity: 'ad-hoc' }, { identity: 'developer-id' }, { requirementVerified: false },
    { signatureVerified: false }, { certificateSelfSignatureVerified: false }, { certificateSha256: 'c'.repeat(64) },
    { designatedRequirement: 'identifier org.shortlink.generator' }, { designatedRequirementSha256: 'c'.repeat(64) },
    { notarization: 'verified' }, { identifier: 'example.other' }]) {
    assert.throws(() => validateMacSigningEvidence({ ...valid, ...patch }, info.certificateSha256));
  }
  assert.throws(() => validateMacSigningEvidence(valid, undefined));
});

test('native signing failures expose only fixed categories and known OSStatus values', () => {
  const secret = 'synthetic-sensitive-fixture-value';
  const result = classifyCodesignError({ stderr: Buffer.from(`${secret}: unable to build chain to self-signed root\nerrSecInternalComponent\n${secret}`) });
  assert.deepEqual(result, { categories: ['chain-untrusted', 'internal-security-error'],
    osStatuses: [{ symbol: 'errSecInternalComponent', code: -2070 }] });
  assert.equal(JSON.stringify(result).includes(secret), false);
  for (const [output, category] of [
    ['no identity found', 'identity-not-found'], ['OSStatus -25308', 'interaction-not-allowed'],
    ['errSecAuthFailed', 'authorization-failed'], ['resource fork, Finder information', 'bundle-format'],
    [secret, 'unclassified-native-error'],
  ]) assert.ok(classifyCodesignError({ stderr: output }).categories.includes(category));
  assert.deepEqual(classifyCodesignError({ stderr: 'arbitrary code -999999; long prefix -253080' }).osStatuses, []);
  assert.deepEqual(classifyCodesignError({ message: secret }).categories, ['unclassified-native-error']);
});

test('build receives only its required updater secrets and no macOS signing inputs', () => {
  const env = cleanBuildEnvironment({ PATH: '/usr/bin', APPLE_CERTIFICATE: 'secret', APPLE_ID: 'private',
    SLG_MACOS_SIGNING_P12_PASSWORD: 'secret', SLG_MACOS_SIGNING_P12_BASE64: 'secret', SLG_INTERNAL_TEST: 'secret',
    SLG_MACOS_CERT_SHA256: 'public', RUST_LOG: 'debug', TAURI_LOG_LEVEL: 'trace',
    TAURI_SIGNING_PRIVATE_KEY: 'updater-key', TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'updater-password',
    TAURI_SIGNING_UNEXPECTED: 'secret', SLG_RELEASE_PRIVATE_KEY: 'secret', SLG_PRIVATE_SIGNING_CONTEXT: 'stale' });
  assert.deepEqual(env, { PATH: '/usr/bin', SLG_MACOS_CERT_SHA256: 'public',
    TAURI_SIGNING_PRIVATE_KEY: 'updater-key', TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'updater-password' });
  assert.throws(() => loadMaterial({}, process.cwd()));
});

const fixtureEngines = process.platform === 'darwin' ? [...new Set(['/usr/bin/openssl', openssl])] : [openssl];
for (const fixtureOpenSSL of fixtureEngines) test(`PKCS12 fixture proves stdin roundtrip, password, certificate pin and private-key correspondence (${fixtureOpenSSL})`, { skip: !supported }, async () => {
  const f = fixture(fixtureOpenSSL);
  try {
    const prepared = await prepareMaterial({ p12: Buffer.from(f.p12), password: f.password }, f.info.certificateSha256,
      { openssl: fixtureOpenSSL, env: process.env, temp: f.temp });
    assert.equal(prepared.certificateSha1, f.info.certificateSha1);
    assert.notEqual(prepared.importPassword, f.password);
    assert.ok(existsSync(prepared.importPath));
    const decodeEnv = { ...process.env, SYNTHETIC_WRAP_PASSWORD: prepared.importPassword };
    const wrapped = readFileSync(prepared.importPath);
    const wrappedCert = await runCaptured(fixtureOpenSSL, ['pkcs12', '-passin', 'env:SYNTHETIC_WRAP_PASSWORD', '-nokeys'], { env: decodeEnv, input: wrapped });
    assert.deepEqual(new X509Certificate(wrappedCert).raw, f.der);
    const wrappedKey = await runCaptured(fixtureOpenSSL, ['pkcs12', '-passin', 'env:SYNTHETIC_WRAP_PASSWORD', '-nocerts', '-nodes'], { env: decodeEnv, input: wrapped });
    try { assert.ok(new X509Certificate(f.der).checkPrivateKey(createPrivateKey(wrappedKey))); }
    finally { wrappedKey.fill(0); wrapped.fill(0); }
    for (const [password, pin] of [['wrong-password', f.info.certificateSha256], [f.password, '0'.repeat(64)]]) {
      await assert.rejects(prepareMaterial({ p12: Buffer.from(f.p12), password }, pin, { openssl: fixtureOpenSSL, env: process.env, temp: f.temp }), /material/);
    }
    const wrongKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' });
    const mismatch = (command, args, options) => args.includes('-nocerts') ? Promise.resolve(Buffer.from(wrongKey)) : runCaptured(command, args, options);
    await assert.rejects(prepareMaterial({ p12: Buffer.from(f.p12), password: f.password }, f.info.certificateSha256,
      { openssl: fixtureOpenSSL, env: process.env, temp: f.temp, run: mismatch }), /material/);
    let failedExportInput;
    const exportFailure = (command, args, options) => {
      if (args.includes('-export')) { failedExportInput = options.input; return Promise.reject(new Error('synthetic-export-failure')); }
      return runCaptured(command, args, options);
    };
    await assert.rejects(prepareMaterial({ p12: Buffer.from(f.p12), password: f.password }, f.info.certificateSha256,
      { openssl: fixtureOpenSSL, env: process.env, temp: f.temp, run: exportFailure }), /material/);
    assert.ok(Buffer.isBuffer(failedExportInput) && failedExportInput.every(byte => byte === 0));
    assert.throws(() => certificateInfo(f.der, '0'.repeat(64)), /certificate/);
  } finally { f.cleanup(); }
});

test('artifact verifier reads actual certificate/DR and invokes strict native checks (mock OS commands)', { skip: !supported }, () => {
  const f = fixture();
  try {
    const calls = [];
    const run = (command, args) => {
      calls.push([command, args]);
      if (args.includes('--requirements')) return `designated => ${stableRequirement(f.info.certificateSha1)}\n`;
      const extract = args.find(arg => arg.startsWith('--extract-certificates='));
      if (extract) writeFileSync(`${extract.slice('--extract-certificates='.length)}0`, f.der);
      return '';
    };
    const result = verifyMacSigning('synthetic.app', f.info.certificateSha256, run);
    assert.deepEqual(result, evidence(f.info));
    assert.ok(calls.some(([, args]) => args.includes('--deep') && args.includes('--strict')));
    assert.ok(calls.some(([, args]) => args.includes('-R')));
    assert.ok(calls.some(([, args]) => args.length === 3 && args[1].startsWith('--extract-certificates=') && args[2] === 'synthetic.app'));
    assert.throws(() => verifyMacSigning('synthetic.app', f.info.certificateSha256, (command, args) =>
      args.includes('--requirements') ? 'designated => identifier org.shortlink.generator\n' : run(command, args)), /pin both/);
  } finally { f.cleanup(); }
});

test('public signature inspections strip inherited CI signing material from every child environment', { skip: !supported }, () => {
  const f = fixture();
  const names = ['SLG_MACOS_SIGNING_P12_PASSWORD', 'SLG_MACOS_SIGNING_P12_BASE64', 'SLG_INTERNAL_PASSWORD', 'APPLE_CERTIFICATE',
    'TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD', 'SLG_RELEASE_PRIVATE_KEY', 'SLG_PRIVATE_SIGNING_CONTEXT'];
  const previous = names.map(name => process.env[name]);
  try {
    for (const name of names) process.env[name] = 'synthetic-inherited-secret';
    let inspected = 0;
    verifyMacSigning('synthetic.app', f.info.certificateSha256, (command, args, options) => {
      inspected++;
      assert.ok(options?.env, 'inspection must not inherit process.env implicitly');
      for (const name of names) assert.equal(options.env[name], undefined);
      if (args.includes('--requirements')) return `designated => ${stableRequirement(f.info.certificateSha1)}\n`;
      const extract = args.find(arg => arg.startsWith('--extract-certificates='));
      if (extract) writeFileSync(`${extract.slice('--extract-certificates='.length)}0`, f.der);
      return '';
    });
    assert.equal(inspected, 4);
  } finally {
    names.forEach((name, i) => { if (previous[i] === undefined) delete process.env[name]; else process.env[name] = previous[i]; });
    f.cleanup();
  }
});

function shimFixture() {
  const temp = realpathSync(mkdtempSync(join(tmpdir(), 'slg-shim-fixture-')));
  chmodSync(temp, 0o700);
  const outputRoot = join(temp, 'output'); mkdirSync(outputRoot);
  const target = join(outputRoot, 'helper'); writeFileSync(target, Buffer.from('cffaedfe', 'hex'));
  const context = { schema: 1, outputRoot, materialRoot: temp, certificateSha1: 'a'.repeat(40),
    certificateSha256: 'b'.repeat(64), entitlementsRoots: [temp], tool: { path: join(temp, 'rcodesign'),
      sha256: 'c'.repeat(64), version: '0.29.0', arch: 'arm64' } };
  for (const name of ['p12Path', 'passwordPath', 'requirementPath']) {
    context[name] = join(temp, name); writeFileSync(context[name], 'synthetic', { mode: 0o600 });
  }
  for (const name of ['home', 'temp']) { context[name] = join(temp, name); mkdirSync(context[name], { mode: 0o700 }); }
  const path = join(temp, 'context.json'); writeFileSync(path, JSON.stringify(context), { mode: 0o600 });
  return { temp, target, context, path, cleanup: () => rmSync(temp, { recursive: true, force: true }) };
}

test('signing context requires private owned regular files within its temporary root', { skip: !supported }, () => {
  const f = shimFixture();
  try {
    assert.deepEqual(readSigningContext(f.path), f.context);
    chmodSync(f.path, 0o644); assert.throws(() => readSigningContext(f.path)); chmodSync(f.path, 0o600);
    chmodSync(f.context.passwordPath, 0o644); assert.throws(() => readSigningContext(f.path)); chmodSync(f.context.passwordPath, 0o600);
    const alias = join(f.temp, 'alias'); symlinkSync(f.context.p12Path, alias);
    writeFileSync(f.path, JSON.stringify({ ...f.context, p12Path: alias })); assert.throws(() => readSigningContext(f.path));
    writeFileSync(f.path, JSON.stringify({ ...f.context, p12Path: process.execPath })); assert.throws(() => readSigningContext(f.path));
  } finally { f.cleanup(); }
});

test('codesign shim maps only Tauri flags and rejects duplicates, overrides and escaping targets', { skip: !supported }, () => {
  const f = shimFixture();
  try {
    const base = ['--force', '-s', f.context.certificateSha1];
    const args = signingArguments([...base, '--options', 'runtime', f.target], f.context);
    assert.deepEqual(args, ['--config-file', '/dev/null', 'sign', '--timestamp-url', 'none', '--digest', 'sha256', '--shallow',
      '--p12-file', f.context.p12Path, '--p12-password-file', f.context.passwordPath, '--code-signature-flags', 'runtime', f.target]);
    for (const extra of ['--keychain', '--requirements', '--identifier', '--timestamp', '--deep', '--exclude', '--force']) {
      assert.throws(() => signingArguments([...base, extra, f.target], f.context));
    }
    for (const extra of [['-s', f.context.certificateSha1], ['--options', 'runtime', '--options', 'runtime'],
      ['--entitlements', f.context.passwordPath, '--entitlements', f.context.passwordPath]]) {
      assert.throws(() => signingArguments([...base, ...extra, f.target], f.context));
    }
    for (const bad of [['-s', f.context.certificateSha1, f.target], ['--force', '-s', '-', f.target],
      [...base, '--options', 'none', f.target], [...base, process.execPath], [...base, f.context.passwordPath]]) {
      assert.throws(() => signingArguments(bad, f.context));
    }
    const alias = join(f.context.outputRoot, 'alias'); symlinkSync(f.target, alias);
    assert.throws(() => signingArguments([...base, alias], f.context));
    const app = join(f.context.outputRoot, 'Example.app'); mkdirSync(app);
    const appArgs = signingArguments([...base, app], f.context, { readIdentifier: () => 'org.shortlink.generator' });
    assert.ok(appArgs.includes('--exclude')); assert.equal(appArgs[appArgs.indexOf('--exclude') + 1], '**');
    assert.equal(args.includes('--exclude'), false);
    assert.deepEqual(appArgs.slice(-5), ['--binary-identifier', 'org.shortlink.generator', '--code-requirements-file', f.context.requirementPath, app]);
    assert.throws(() => signingArguments([...base, app], f.context, { readIdentifier: () => 'org.other.app' }));
    const entitlements = join(f.temp, 'entitlements.plist'); writeFileSync(entitlements, '<plist/>');
    assert.ok(signingArguments([...base, '--entitlements', entitlements, f.target], f.context).includes('--entitlements-xml-file'));
    assert.throws(() => signingArguments([...base, '--entitlements', process.execPath, f.target], f.context));
  } finally { f.cleanup(); }
});

test('adapter validates core limits and pinned tool before contained signing with a five-variable environment', { skip: !supported }, async () => {
  const f = shimFixture();
  const contaminated = { HOME: f.context.home, TMPDIR: f.context.temp, RCODESIGN_P12_PASSWORD: 'secret', DYLD_INSERT_LIBRARIES: 'secret',
    NODE_OPTIONS: 'secret', NODE_PATH: 'secret', OPENSSL_CONF: 'secret', BASH_ENV: 'secret', ENV: 'secret',
    TAURI_SIGNING_PRIVATE_KEY: 'secret', SLG_MACOS_SIGNING_P12_PASSWORD: 'secret', SLG_PRIVATE_SIGNING_CONTEXT: 'secret' };
  const safe = signingToolEnvironment(contaminated);
  assert.deepEqual(Object.keys(safe).sort(), ['HOME', 'LANG', 'LC_ALL', 'PATH', 'TMPDIR']);
  try {
    for (const mode of ['success', 'core', 'tool', 'signer']) {
      const calls = [];
      const run = async (cmd, argv, options) => {
        assert.deepEqual(options.env, safe); calls.push(cmd);
        if (cmd === '/bin/sh') return Buffer.from(mode === 'core' ? '0\nunlimited\n' : '0\n0\n');
        assert.equal(cmd, '/usr/bin/sandbox-exec');
        assert.deepEqual(argv.slice(0, 3), ['-p', '(version 1)(allow default)(deny network*)', f.context.tool.path]);
        assert.ok(argv.includes('--shallow')); assert.ok(argv.includes('--timestamp-url')); assert.ok(argv.includes('none'));
        if (mode === 'signer') throw Object.assign(new Error('private-path-secret'), { stderr: Buffer.from('private-path-secret') });
        return Buffer.alloc(0);
      };
      const verifyTool = async () => { calls.push('tool-verify'); return { ...f.context.tool, sha256: mode === 'tool' ? '0'.repeat(64) : f.context.tool.sha256 }; };
      const promise = executeSigning(['--force', '-s', f.context.certificateSha1, f.target], f.context, { run, verifyTool });
      if (mode === 'success') { await promise; assert.deepEqual(calls, ['/bin/sh', 'tool-verify', '/usr/bin/sandbox-exec']); }
      else await assert.rejects(promise, error => {
        assert.equal(JSON.stringify(error).includes('private-path-secret'), false);
        return error.stage === ({ core: 'signing-input', tool: 'signer-tool', signer: 'rcodesign' })[mode];
      });
      if (mode === 'core' || mode === 'tool') assert.equal(calls.includes('/usr/bin/sandbox-exec'), false);
    }
  } finally { f.cleanup(); }
});

test('build wrapper signs without Keychain writes and cleans success, cancellation and every failure stage (mock OS)', { skip: !supported }, async () => {
  const temp = mkdtempSync(join(tmpdir(), 'slg-wrapper-fixture-'));
  const info = { certificateSha1: 'a'.repeat(40), certificateSha256: 'b'.repeat(64) };
  const sourceTool = join(temp, 'reviewed-tool'); writeFileSync(sourceTool, 'synthetic tool', { mode: 0o500 });
  try {
    for (const mode of ['success', 'core-failure', 'tool-failure', 'copy-mismatch', 'material-failure', 'requirement-failure',
      'build-failure', 'verify-failure', 'search-list-changed', 'default-changed', 'interrupted-during-tool',
      'interrupted-during-material', 'interrupted-during-requirement', 'interrupted-during-build', 'cleanup-failure', 'build-and-cleanup-failure']) {
      const parent = join(temp, mode); mkdirSync(parent);
      const output = join(parent, 'output'); mkdirSync(join(output, 'release/bundle/macos/Example.app'), { recursive: true });
      const calls = []; let loaded = 0, built = 0, inventoryCalls = 0, verifiedTools = 0;
      const run = async (command, args, options) => {
        assert.deepEqual(Object.keys(options.env).sort(), ['HOME', 'LANG', 'LC_ALL', 'PATH', 'TMPDIR']);
        calls.push([command, args]); assert.equal(args.includes('synthetic-secret-password'), false);
        if (command === '/bin/sh') return Buffer.from(mode === 'core-failure' ? '0\nunlimited\n' : '0\n0\n');
        if (command === '/usr/bin/csreq') {
          assert.equal(args[1], `=${stableRequirement(info.certificateSha1)}`);
          if (mode === 'requirement-failure') throw new Error('private failure');
          writeFileSync(args.at(-1), 'synthetic compiled DR', { mode: 0o600 });
          if (mode === 'interrupted-during-requirement') process.emit('SIGTERM');
          return Buffer.alloc(0);
        }
        assert.equal(command, '/usr/bin/security');
        assert.ok(['list-keychains', 'default-keychain'].includes(args[0])); assert.deepEqual(args.slice(1), ['-d', 'user']);
        inventoryCalls++;
        return Buffer.from(inventoryCalls > 2 && ((args[0] === 'list-keychains' && mode === 'search-list-changed') ||
          (args[0] === 'default-keychain' && mode === 'default-changed')) ? 'changed' : 'unchanged');
      };
      const verifyTool = async path => {
        verifiedTools++;
        if (mode === 'tool-failure') throw new Error('private path');
        if (mode === 'interrupted-during-tool') process.emit('SIGTERM');
        assert.equal(readFileSync(path, 'utf8'), 'synthetic tool');
        return { path, sha256: mode === 'copy-mismatch' && verifiedTools === 2 ? '0'.repeat(64) : 'c'.repeat(64), version: '0.29.0', arch: 'arm64' };
      };
      const materialPreparer = async (material, pin, options) => {
        assert.equal(options.openssl, '/usr/bin/openssl'); assert.equal(pin, info.certificateSha256);
        assert.equal(verifiedTools, 2); assert.equal(inventoryCalls, 2); material.p12.fill(0);
        const importPath = join(options.temp, 'import.p12'); writeFileSync(importPath, 'synthetic encrypted material', { mode: 0o600 });
        if (mode === 'material-failure') throw new Error('private failure');
        if (mode === 'interrupted-during-material') process.emit('SIGTERM');
        return { ...info, importPath, importPassword: 'synthetic-temporary-password' };
      };
      const build = async (command, env) => {
        built++;
        assert.equal(env.APPLE_SIGNING_IDENTITY, info.certificateSha1);
        assert.equal(env.TAURI_SIGNING_PRIVATE_KEY, 'synthetic-updater-key');
        assert.equal(env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD, 'synthetic-updater-password');
        for (const name of ['SLG_MACOS_SIGNING_P12_PASSWORD', 'SLG_RELEASE_PRIVATE_KEY', 'DYLD_INSERT_LIBRARIES', 'NODE_OPTIONS', 'RCODESIGN_P12_PASSWORD']) assert.equal(env[name], undefined);
        const context = readSigningContext(env.SLG_PRIVATE_SIGNING_CONTEXT);
        assert.notEqual(context.tool.path, sourceTool); assert.equal(context.certificateSha1, info.certificateSha1);
        const shim = readFileSync(join(env.PATH.split(':')[0], 'codesign'), 'utf8');
        assert.ok(shim.includes('exec /usr/bin/env -i ')); assert.equal(shim.includes('updater'), false); assert.equal(shim.includes('password'), false);
        if (mode === 'build-failure' || mode === 'build-and-cleanup-failure') throw new Error('private failure');
        if (mode === 'interrupted-during-build') process.emit('SIGTERM');
      };
      const promise = withStableSigning({ command: ['synthetic-build'], platform: 'darwin', arch: 'arm64', run, build,
        verify: () => { if (mode === 'verify-failure') throw new Error('private failure'); return evidence(info); }, verifyTool, materialPreparer,
        materialLoader: () => { loaded++; return { p12: Buffer.from('synthetic'), password: 'synthetic-secret-password' }; }, tempRoot: parent,
        removeTemp: path => { if (mode.includes('cleanup-failure')) throw new Error('private failure'); rmSync(path, { recursive: true, force: true }); },
        env: { PATH: process.env.PATH, CARGO_TARGET_DIR: output, SLG_RCODESIGN_PATH: sourceTool,
          TAURI_SIGNING_PRIVATE_KEY: 'synthetic-updater-key', TAURI_SIGNING_PRIVATE_KEY_PASSWORD: 'synthetic-updater-password',
          SLG_RELEASE_PRIVATE_KEY: 'synthetic-release-key', DYLD_INSERT_LIBRARIES: 'private', NODE_OPTIONS: 'private', RCODESIGN_P12_PASSWORD: 'private',
          SLG_MACOS_CERT_SHA256: info.certificateSha256, SLG_MACOS_SIGNING_P12_PASSWORD: 'synthetic-secret-password' },
      });
      if (mode === 'success') {
        const result = await promise;
        assert.equal(result.backend, 'rcodesign'); assert.equal(result.temporarySigningFilesRemoved, true);
        assert.equal(result.keychainWrites, 0); assert.equal(result.trustWrites, 0); assert.equal(result.searchListUnchanged, true);
      } else await assert.rejects(promise, error => {
        const stage = mode.startsWith('interrupted-') ? 'interrupted' : ({ 'core-failure': 'core-limits', 'tool-failure': 'signer-tool',
          'copy-mismatch': 'signer-tool', 'material-failure': 'material', 'requirement-failure': 'requirement', 'build-failure': 'build',
          'verify-failure': 'verify', 'search-list-changed': 'searchlist', 'default-changed': 'searchlist', 'cleanup-failure': 'cleanup',
          'build-and-cleanup-failure': 'build' })[mode];
        assert.equal(error.stage, stage);
        if (mode.includes('cleanup-failure')) assert.equal(error.cleanupStage, 'cleanup');
        return true;
      });
      if (['core-failure', 'tool-failure', 'copy-mismatch', 'interrupted-during-tool'].includes(mode)) assert.equal(loaded, 0);
      if (['interrupted-during-material', 'interrupted-during-requirement'].includes(mode)) assert.equal(built, 0);
      if (!mode.includes('cleanup-failure')) assert.deepEqual(readdirSync(parent), ['output']);
      assert.equal(calls.some(([cmd, args]) => cmd === '/usr/bin/security' && !['list-keychains', 'default-keychain'].includes(args[0])), false);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('wrapper rejects cross-architecture targets, duplicate targets and unreviewed OpenSSL before material reads', async () => {
  const env = { SLG_MACOS_CERT_SHA256: 'b'.repeat(64), SLG_RCODESIGN_PATH: '/synthetic/pre-acquired-tool' };
  for (const [command, patch] of [[['build', '--target', 'x86_64-apple-darwin'], {}],
    [['build', '--target=x86_64-apple-darwin'], {}],
    [['build', '--target', 'aarch64-apple-darwin', '--target', 'aarch64-apple-darwin'], {}],
    [['build'], { SLG_MACOS_OPENSSL: '/unreviewed/openssl' }]]) {
    await assert.rejects(withStableSigning({ command, platform: 'darwin', arch: 'arm64', env: { ...env, ...patch },
      materialLoader: () => { assert.fail('configuration must fail before material'); } }), error => error.stage === 'configuration');
  }
});

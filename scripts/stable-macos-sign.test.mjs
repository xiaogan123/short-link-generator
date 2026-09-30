import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { certificateInfo, hash, stableRequirement, validateMacSigningEvidence, validateRequirement, verifyMacSigning } from './macos-signature.mjs';
import { cleanBuildEnvironment, loadMaterial, prepareMaterial, runCaptured, withStableSigning } from './stable-macos-sign.mjs';
import { classifyCodesignError, signingArguments } from './macos-codesign.mjs';

// All certificates/private keys below are throwaway synthetic fixtures outside the repository.
// No test creates/imports a real Keychain, invokes native signing, or reads user credentials.
const openssl = process.platform === 'darwin' && existsSync('/opt/homebrew/bin/openssl') ? '/opt/homebrew/bin/openssl' : 'openssl';
const supported = process.platform !== 'win32';
function fixture() {
  const temp = mkdtempSync(join(tmpdir(), 'slg-signing-fixture-'));
  const key = join(temp, 'test-key.pem'); const cert = join(temp, 'test-cert.pem'); const p12 = join(temp, 'test.p12');
  const password = 'synthetic-fixture-only';
  const env = { ...process.env, FIXTURE_PASSWORD: password };
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-subj', '/CN=Example Synthetic Signing', '-days', '1', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'extendedKeyUsage=codeSigning', '-addext', 'keyUsage=critical,digitalSignature'], { env, stdio: 'pipe' });
  execFileSync(openssl, ['pkcs12', '-export', '-inkey', key, '-in', cert, '-out', p12, '-passout', 'env:FIXTURE_PASSWORD'], { env, stdio: 'pipe' });
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

test('secret-bearing build inputs are stripped from the child environment', () => {
  const env = cleanBuildEnvironment({ PATH: '/usr/bin', APPLE_CERTIFICATE: 'secret', APPLE_ID: 'private',
    SLG_MACOS_SIGNING_P12_PASSWORD: 'secret', SLG_MACOS_SIGNING_P12_BASE64: 'secret', SLG_INTERNAL_TEST: 'secret',
    SLG_MACOS_CERT_SHA256: 'public', RUST_LOG: 'debug', TAURI_LOG_LEVEL: 'trace' });
  assert.deepEqual(env, { PATH: '/usr/bin', SLG_MACOS_CERT_SHA256: 'public' });
  assert.throws(() => loadMaterial({}, process.cwd()));
});

test('PKCS12 fixture proves password, certificate pin and private-key correspondence', { skip: !supported }, async () => {
  const f = fixture();
  try {
    const prepared = await prepareMaterial({ p12: Buffer.from(f.p12), password: f.password }, f.info.certificateSha256,
      { openssl, env: process.env, temp: f.temp });
    assert.equal(prepared.certificateSha1, f.info.certificateSha1);
    assert.notEqual(prepared.importPassword, f.password);
    assert.ok(existsSync(prepared.importPath));
    for (const [password, pin] of [['wrong-password', f.info.certificateSha256], [f.password, '0'.repeat(64)]]) {
      await assert.rejects(prepareMaterial({ p12: Buffer.from(f.p12), password }, pin, { openssl, env: process.env, temp: f.temp }), /material/);
    }
    const wrongKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' });
    const mismatch = (command, args, options) => args.includes('-nocerts') ? Promise.resolve(Buffer.from(wrongKey)) : runCaptured(command, args, options);
    await assert.rejects(prepareMaterial({ p12: Buffer.from(f.p12), password: f.password }, f.info.certificateSha256,
      { openssl, env: process.env, temp: f.temp, run: mismatch }), /material/);
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
      if (args.includes('--extract-certificates')) writeFileSync(`${args[args.indexOf('--extract-certificates') + 1]}0`, f.der);
      return '';
    };
    const result = verifyMacSigning('synthetic.app', f.info.certificateSha256, run);
    assert.deepEqual(result, evidence(f.info));
    assert.ok(calls.some(([, args]) => args.includes('--deep') && args.includes('--strict')));
    assert.ok(calls.some(([, args]) => args.includes('-R')));
    assert.throws(() => verifyMacSigning('synthetic.app', f.info.certificateSha256, (command, args) =>
      args.includes('--requirements') ? 'designated => identifier org.shortlink.generator\n' : run(command, args)), /pin both/);
  } finally { f.cleanup(); }
});

test('public signature inspections strip inherited CI signing material from every child environment', { skip: !supported }, () => {
  const f = fixture();
  const names = ['SLG_MACOS_SIGNING_P12_PASSWORD', 'SLG_MACOS_SIGNING_P12_BASE64', 'SLG_INTERNAL_PASSWORD', 'APPLE_CERTIFICATE'];
  const previous = names.map(name => process.env[name]);
  try {
    for (const name of names) process.env[name] = 'synthetic-inherited-secret';
    let inspected = 0;
    verifyMacSigning('synthetic.app', f.info.certificateSha256, (command, args, options) => {
      inspected++;
      assert.ok(options?.env, 'inspection must not inherit process.env implicitly');
      for (const name of names) assert.equal(options.env[name], undefined);
      if (args.includes('--requirements')) return `designated => ${stableRequirement(f.info.certificateSha1)}\n`;
      if (args.includes('--extract-certificates')) writeFileSync(`${args[args.indexOf('--extract-certificates') + 1]}0`, f.der);
      return '';
    });
    assert.equal(inspected, 4);
  } finally {
    names.forEach((name, i) => { if (previous[i] === undefined) delete process.env[name]; else process.env[name] = previous[i]; });
    f.cleanup();
  }
});

test('codesign shim rejects overrides and targets outside the generated output', () => {
  const temp = mkdtempSync(join(tmpdir(), 'slg-shim-fixture-'));
  try {
    const target = join(temp, 'test-binary'); writeFileSync(target, 'synthetic');
    const context = { outputRoot: temp, keychain: join(temp, 'private.keychain-db'), certificateSha1: 'a'.repeat(40) };
    const args = signingArguments(['--force', '-s', context.certificateSha1, '--options', 'runtime', target], context);
    assert.ok(args.includes('--timestamp=none')); assert.ok(args.includes('--keychain'));
    for (const extra of ['--keychain', '--requirements', '--identifier', '--timestamp', '--deep']) {
      assert.throws(() => signingArguments(['--force', '-s', context.certificateSha1, extra, target], context));
    }
    assert.throws(() => signingArguments(['-s', '-', target], context));
    assert.throws(() => signingArguments(['-s', context.certificateSha1, process.execPath], context));
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('build wrapper isolates the keychain and cleans up success, build/import failure and changed search list (mock OS)', { skip: !supported }, async () => {
  const f = fixture();
  try {
    for (const mode of ['success', 'material-failure', 'build-failure', 'verify-failure', 'import-failure', 'search-list-changed', 'default-changed', 'interrupted', 'interrupted-during-create', 'interrupted-during-unlock', 'interrupted-during-import', 'cleanup-failure']) {
      const parent = join(f.temp, mode); mkdirSync(parent);
      const output = join(parent, 'output'); const apps = join(output, 'release/bundle/macos');
      mkdirSync(join(apps, 'Example.app'), { recursive: true });
      const commands = []; let created = false;
      const run = async (command, args, options) => {
        if (command !== '/usr/bin/security') return runCaptured(command, args, options);
        commands.push(args);
        assert.equal(args.includes(f.password), false, 'long-term password must not enter argv');
        assert.equal(options.env.SLG_MACOS_SIGNING_P12_PASSWORD, undefined);
        assert.equal(options.env.SLG_MACOS_SIGNING_P12_BASE64, undefined);
        if (args[0] === 'create-keychain') {
          created = true; writeFileSync(args.at(-1), 'synthetic keychain placeholder');
          if (mode === 'interrupted-during-create') process.emit('SIGTERM');
        }
        if (mode === 'interrupted-during-unlock' && args[0] === 'unlock-keychain') process.emit('SIGTERM');
        if (mode === 'interrupted-during-import' && args[0] === 'import') process.emit('SIGTERM');
        if (args[0] === 'import' && mode === 'import-failure') throw new Error('synthetic failure');
        if (args[0] === 'delete-keychain') {
          if (mode === 'cleanup-failure') throw new Error('synthetic cleanup failure');
          rmSync(args.at(-1));
        }
        return Buffer.from(created && ((args[0] === 'list-keychains' && mode === 'search-list-changed') ||
          (args[0] === 'default-keychain' && mode === 'default-changed')) ? 'concurrent change' : 'unchanged');
      };
      const build = async (command, env) => {
        assert.equal(env.APPLE_SIGNING_IDENTITY, f.info.certificateSha1);
        assert.equal(env.SLG_MACOS_SIGNING_P12_PASSWORD, undefined);
        assert.ok(readFileSync(env.SLG_PRIVATE_SIGNING_CONTEXT, 'utf8').includes(f.info.certificateSha1));
        if (mode === 'build-failure') throw new Error('synthetic build exit');
        if (mode === 'interrupted') process.emit('SIGTERM');
      };
      const promise = withStableSigning({ command: ['synthetic-build'], platform: 'darwin', run, build,
        verify: () => { if (mode === 'verify-failure') throw new Error('synthetic verification failure'); return evidence(f.info); }, tempRoot: parent,
        env: { PATH: process.env.PATH, CARGO_TARGET_DIR: output, SLG_MACOS_OPENSSL: openssl,
          SLG_MACOS_CERT_SHA256: f.info.certificateSha256, SLG_MACOS_SIGNING_P12_PASSWORD: f.password,
          SLG_MACOS_SIGNING_P12_BASE64: f.p12.toString('base64') },
        materialLoader: () => ({ p12: Buffer.from(f.p12), password: mode === 'material-failure' ? 'wrong-password' : f.password }),
      });
      if (mode === 'success') assert.equal((await promise).isolatedKeychainRemoved, true);
      else await assert.rejects(promise, error => error.stage === ({ 'material-failure': 'material', 'build-failure': 'build', 'verify-failure': 'verify', 'import-failure': 'import',
        'search-list-changed': 'searchlist', 'default-changed': 'searchlist', interrupted: 'interrupted', 'interrupted-during-create': 'interrupted',
        'interrupted-during-unlock': 'interrupted', 'interrupted-during-import': 'interrupted', 'cleanup-failure': 'cleanup' })[mode]);
      if (['interrupted-during-create', 'interrupted-during-unlock'].includes(mode)) {
        assert.equal(commands.some(args => args[0] === 'import'), false, 'cancelled wrapper must not import a private key after create-keychain returns');
      }
      if (mode === 'interrupted-during-import') assert.equal(commands.some(args => args[0] === 'set-key-partition-list'), false);
      if (mode === 'material-failure') assert.equal(commands.length, 0);
      else assert.ok(commands.some(args => args[0] === 'delete-keychain'));
      assert.equal(commands.some(args => args[0] === 'list-keychains' && args.includes('-s')), false);
      assert.equal(commands.some(args => args[0] === 'default-keychain' && args.includes('-s')), false);
      assert.equal(commands.some(args => args[0] === 'add-trusted-cert'), false);
      if (mode === 'cleanup-failure') {
        const leftover = readdirSync(parent).find(name => name.startsWith('slg-macos-sign-'));
        assert.ok(leftover);
        assert.ok(existsSync(join(parent, leftover, 'cleanup-required.json')));
      } else assert.deepEqual(readdirSync(parent), ['output']);
    }
  } finally { f.cleanup(); }
});

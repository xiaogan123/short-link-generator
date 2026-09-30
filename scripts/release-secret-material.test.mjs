import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { releaseSecretPatterns, containsReleaseSecret, macSigningSecretPatterns, macPrivateKeySecretPatterns, artifactInspectionEnvironment } from './release-secret-material.mjs';

const syntheticKey = generateKeyPairSync('rsa', { modulusLength: 3072 }).privateKey;
const syntheticEnv = () => ({ SLG_MACOS_SIGNING_P12_BASE64: Buffer.alloc(128, 173).toString('base64'),
  SLG_MACOS_SIGNING_P12_PASSWORD: 'synthetic-p12-password-only' });

test('decrypted RSA private-key exports and encodings are found without flagging public material', () => {
  let decoded, output, childEnv;
  const patterns = macPrivateKeySecretPatterns({ ...syntheticEnv(), DYLD_INSERT_LIBRARIES: 'forbidden',
    OPENSSL_CONF: 'forbidden', RCODESIGN_PASSWORD: 'forbidden', SLG_PRIVATE_SIGNING_CONTEXT: 'forbidden',
    SLG_RELEASE_PRIVATE_KEY: 'forbidden', TAURI_SIGNING_PRIVATE_KEY: 'forbidden' }, {
    platform: 'darwin', run(command, args, options) {
      assert.equal(command, '/usr/bin/openssl');
      assert.deepEqual(args, ['pkcs12', '-in', '/dev/stdin', '-passin', 'env:SLG_INTERNAL_P12_PASSWORD', '-nocerts', '-nodes']);
      assert.equal(args.includes(syntheticEnv().SLG_MACOS_SIGNING_P12_PASSWORD), false);
      assert.equal(options.timeout, 15000); assert.equal(options.maxBuffer, 1024 * 1024);
      assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
      childEnv = options.env; decoded = options.input;
      assert.equal(childEnv.OPENSSL_CONF, '/dev/null');
      assert.equal(childEnv.SLG_INTERNAL_P12_PASSWORD, syntheticEnv().SLG_MACOS_SIGNING_P12_PASSWORD);
      assert.equal(Object.values(childEnv).includes('forbidden'), false);
      output = Buffer.from(syntheticKey.export({ type: 'pkcs8', format: 'pem' }));
      return output;
    }
  });
  try {
    assert.equal(decoded.every(byte => byte === 0), true); assert.equal(output.every(byte => byte === 0), true);
    assert.equal(childEnv.SLG_INTERNAL_P12_PASSWORD, undefined);
    for (const type of ['pkcs1', 'pkcs8']) for (const format of ['der', 'pem']) {
      const value = Buffer.from(syntheticKey.export({ type, format }));
      const encoded = value.toString('base64');
      for (const candidate of [value, Buffer.from(encoded), Buffer.from(encoded, 'utf16le'),
        Buffer.from(value.toString('hex')), Buffer.from(value.toString('hex').toUpperCase(), 'utf16le'),
        Buffer.from(encoded.match(/.{1,64}/g).join('\r\n')),
        ...(format === 'pem' ? [Buffer.from(value.toString(), 'utf16le'), Buffer.from(value.toString().replace(/\n/g, '\r\n')),
          Buffer.from(JSON.stringify(value.toString()).slice(1, -1))] : [])]) {
        assert.equal(containsReleaseSecret(Buffer.concat([Buffer.from('prefix'), candidate, Buffer.from('suffix')]), patterns), true);
      }
      value.fill(0);
    }
    const publicKey = createPublicKey(syntheticKey);
    for (const format of ['pem', 'der']) assert.equal(containsReleaseSecret(publicKey.export({ type: 'spki', format }), patterns), false);
    assert.equal(containsReleaseSecret('ordinary archive header and release metadata', patterns), false);
  } finally { for (const pattern of patterns) pattern.fill(0); }
});

test('private-key inspection fails closed, scrubs buffers, and never exposes parser diagnostics', () => {
  assert.deepEqual(macPrivateKeySecretPatterns({}), []);
  assert.throws(() => macPrivateKeySecretPatterns(syntheticEnv(), { platform: 'linux' }), /macOS/);
  for (const mode of ['tool-error', 'malformed', 'multiple', 'mixed-types', 'wrong-type', 'oversized']) {
    let decoded, output, errorOutput, childEnv;
    assert.throws(() => macPrivateKeySecretPatterns(syntheticEnv(), { platform: 'darwin', run(_command, _args, options) {
      decoded = options.input; childEnv = options.env;
      if (mode === 'tool-error') {
        errorOutput = Buffer.from('SENSITIVE_DIAGNOSTIC');
        throw Object.assign(new Error('SENSITIVE_DIAGNOSTIC'), { stdout: errorOutput, stderr: errorOutput, output: [null, errorOutput] });
      }
      const pem = syntheticKey.export({ type: 'pkcs8', format: 'pem' });
      output = mode === 'multiple' ? Buffer.from(pem + pem) : mode === 'mixed-types'
        ? Buffer.from(pem + ['-----BEGIN EC ', 'PRIVATE KEY-----\nAA==\n-----END EC ', 'PRIVATE KEY-----\n'].join('')) : mode === 'wrong-type'
        ? Buffer.from(generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }))
        : mode === 'oversized' ? Buffer.alloc(1024 * 1024 + 1, 65) : Buffer.from('SENSITIVE_DIAGNOSTIC');
      return output;
    } }), error => error.message === 'macOS private-key inspection failed.' && error.cause === undefined && !error.stack.includes('SENSITIVE_DIAGNOSTIC'));
    assert.equal(decoded.every(byte => byte === 0), true);
    assert.equal(childEnv.SLG_INTERNAL_P12_PASSWORD, undefined);
    if (output) assert.equal(output.every(byte => byte === 0), true);
    if (errorOutput) assert.equal(errorOutput.every(byte => byte === 0), true);
  }
});

test('native synthetic PKCS12 roundtrip detects the actual decrypted key, not its public certificate', { skip: process.platform !== 'darwin' }, () => {
  const temp = mkdtempSync(join(tmpdir(), 'slg-public-certificate-test-'));
  const pem = Buffer.from(syntheticKey.export({ type: 'pkcs8', format: 'pem' }));
  const env = { PATH: '/usr/bin:/bin', OPENSSL_CONF: '/dev/null', SLG_TEST_P12_PASSWORD: 'synthetic-roundtrip-only' };
  const run = args => execFileSync('/usr/bin/openssl', args, { input: pem, env, stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 1024 * 1024 });
  let p12; let patterns = []; let encryptedPatterns = [];
  try {
    const config = join(temp, 'certificate.cnf');
    writeFileSync(config, '[req]\ndistinguished_name=subject\n[subject]\n', { mode: 0o600 });
    const certificate = run(['req', '-new', '-x509', '-key', '/dev/stdin', '-config', config, '-subj', '/CN=Public Synthetic Artifact Test', '-days', '1', '-sha256']);
    const certificatePath = join(temp, 'certificate.pem'); writeFileSync(certificatePath, certificate, { mode: 0o600 });
    p12 = run(['pkcs12', '-export', '-in', certificatePath, '-inkey', '/dev/stdin', '-passout', 'env:SLG_TEST_P12_PASSWORD']);
    const supplied = { SLG_MACOS_SIGNING_P12_BASE64: p12.toString('base64'), SLG_MACOS_SIGNING_P12_PASSWORD: env.SLG_TEST_P12_PASSWORD };
    encryptedPatterns = macSigningSecretPatterns(supplied);
    assert.equal(containsReleaseSecret(pem, encryptedPatterns), false); // Original coverage gap.
    patterns = macPrivateKeySecretPatterns(supplied);
    assert.equal(containsReleaseSecret(pem, patterns), true);
    assert.equal(containsReleaseSecret(syntheticKey.export({ type: 'pkcs1', format: 'der' }), patterns), true);
    assert.equal(containsReleaseSecret(certificate, patterns), false);
    assert.equal(containsReleaseSecret(new X509Certificate(certificate).raw, patterns), false);
    assert.throws(() => macPrivateKeySecretPatterns({ SLG_MACOS_SIGNING_P12_BASE64: p12.toString('base64'), SLG_MACOS_SIGNING_P12_PASSWORD: 'synthetic-wrong-password' }), /private-key inspection failed/);
  } finally { pem.fill(0); p12?.fill(0); for (const pattern of [...patterns, ...encryptedPatterns]) pattern.fill(0); rmSync(temp, { recursive: true, force: true }); }
});

test('release key is found in encoded, decoded, hex and UTF-16 representations', () => {
  const key = Buffer.from(Array.from({ length: 158 }, (_, index) => (index * 53 + 17) % 256));
  const body = key.toString('base64');
  const envelope = `untrusted comment: rsign encrypted secret key\n${body}\n`;
  const encoded = Buffer.from(envelope).toString('base64');
  const patterns = releaseSecretPatterns(`${encoded}\n`);
  for (const value of [Buffer.from(encoded), Buffer.from(envelope), Buffer.from(body), key,
    Buffer.from(key.toString('hex')), Buffer.from(key.toString('hex').toUpperCase()),
    Buffer.from(encoded, 'utf16le'), Buffer.from(body, 'utf16le')]) {
    assert.equal(containsReleaseSecret(Buffer.concat([Buffer.from('prefix'), value, Buffer.from('suffix')]), patterns), true);
  }
  assert.equal(containsReleaseSecret('untrusted comment: minisign public key\npublic signature', patterns), false);
  assert.equal(containsReleaseSecret('release metadata and normal executable bytes', patterns), false);
});

test('release key inspection rejects missing or malformed configured material without echoing it', () => {
  assert.deepEqual(releaseSecretPatterns(undefined), []);
  for (const value of ['', 'not a signing secret', Buffer.from('untrusted comment: public key\nYWJj\n').toString('base64')]) {
    assert.throws(() => releaseSecretPatterns(value), /signing-key|private key/);
  }
});

test('macOS encrypted container and password representations are detected without treating public signatures as secrets', () => {
  const p12 = Buffer.alloc(128, 173);
  const password = 'synthetic-fixture-"password\\only';
  const patterns = macSigningSecretPatterns({ SLG_MACOS_SIGNING_P12_BASE64: p12.toString('base64'), SLG_MACOS_SIGNING_P12_PASSWORD: password });
  for (const value of [p12, Buffer.from(p12.toString('base64')), Buffer.from(p12.toString('hex'), 'utf16le'),
    Buffer.from(p12.toString('hex').toUpperCase()), Buffer.from(p12.toString('base64').match(/.{1,64}/g).join('\n')),
    Buffer.from(p12.toString('base64').match(/.{1,76}/g).join('\r\n')),
    Buffer.from(JSON.stringify(password).slice(1, -1)),
    Buffer.from(password), Buffer.from(password, 'utf16le'), Buffer.from(Buffer.from(password).toString('base64'))]) {
    assert.equal(containsReleaseSecret(value, patterns), true);
  }
  assert.equal(containsReleaseSecret('public certificate and signed application', patterns), false);
});

test('artifact inspection rejects partial macOS inputs and strips all release secrets from extraction processes', () => {
  assert.deepEqual(macSigningSecretPatterns({}), []);
  for (const env of [{ SLG_MACOS_SIGNING_P12_BASE64: 'sensitive-invalid-value' },
    { SLG_MACOS_SIGNING_P12_PASSWORD: 'sensitive-invalid-value' },
    { SLG_MACOS_SIGNING_P12_BASE64: 'YWJj', SLG_MACOS_SIGNING_P12_PASSWORD: 'sensitive-invalid-value' }]) {
    assert.throws(() => macSigningSecretPatterns(env), error => !error.message.includes('sensitive-invalid-value'));
  }
  const clean = artifactInspectionEnvironment({ PATH: '/usr/bin', SLG_MACOS_CERT_SHA256: 'public-pin',
    SLG_RELEASE_PRIVATE_KEY: 'secret', SLG_MACOS_SIGNING_P12_PASSWORD: 'secret', SLG_MACOS_SIGNING_P12_BASE64: 'secret',
    SLG_INTERNAL_IMPORT_PASSWORD: 'secret', APPLE_CERTIFICATE: 'secret', TAURI_SIGNING_PRIVATE_KEY: 'secret',
    SLG_PRIVATE_SIGNING_CONTEXT: 'private-context', RCODESIGN_SIGN_SIGNER_P12_PASSWORD: 'secret',
    DYLD_INSERT_LIBRARIES: '/untrusted/library', NODE_OPTIONS: '--require=/untrusted/module', NODE_PATH: '/untrusted',
    OPENSSL_CONF: '/untrusted/config', OPENSSL_ENGINES: '/untrusted', OPENSSL_MODULES: '/untrusted',
    BASH_ENV: '/untrusted/startup', ENV: '/untrusted/startup' });
  assert.deepEqual(clean, { PATH: '/usr/bin', SLG_MACOS_CERT_SHA256: 'public-pin' });
});

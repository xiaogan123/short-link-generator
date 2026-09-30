import test from 'node:test';
import assert from 'node:assert/strict';
import { releaseSecretPatterns, containsReleaseSecret, macSigningSecretPatterns, artifactInspectionEnvironment } from './release-secret-material.mjs';

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
    SLG_INTERNAL_IMPORT_PASSWORD: 'secret', APPLE_CERTIFICATE: 'secret', TAURI_SIGNING_PRIVATE_KEY: 'secret' });
  assert.deepEqual(clean, { PATH: '/usr/bin', SLG_MACOS_CERT_SHA256: 'public-pin' });
});

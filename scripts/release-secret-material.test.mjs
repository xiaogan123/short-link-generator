import test from 'node:test';
import assert from 'node:assert/strict';
import { releaseSecretPatterns, containsReleaseSecret } from './release-secret-material.mjs';

test('release key is found in encoded, decoded, hex and UTF-16 representations', () => {
  const key = Buffer.from(Array.from({ length: 158 }, (_, index) => (index * 53 + 17) % 256));
  const body = key.toString('base64');
  const envelope = `untrusted comment: rsign encrypted secret key\n${body}\n`;
  const encoded = Buffer.from(envelope).toString('base64');
  const patterns = releaseSecretPatterns(`${encoded}\n`);
  for (const value of [Buffer.from(encoded), Buffer.from(envelope), Buffer.from(body), key,
    Buffer.from(key.toString('hex')), Buffer.from(encoded, 'utf16le'), Buffer.from(body, 'utf16le')]) {
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

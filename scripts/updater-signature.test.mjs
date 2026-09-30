import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash, generateKeyPairSync, randomBytes, sign,
} from 'node:crypto';
import { updaterPublicKeySha256, verifyUpdaterSignature } from './updater-signature.mjs';

const outer = text => Buffer.from(text, 'utf8').toString('base64');
const packet = encoded => Buffer.from(encoded, 'base64');
const encodePacket = bytes => bytes.toString('base64');

// Public interoperability vectors from minisign-verify 0.2.5, the crate used by
// the locked Tauri updater. Both signatures cover the bytes `test`.
const VECTOR_PUBLIC_KEY = outer(`untrusted comment: minisign public key E7620F1842B4E81F
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
`);
const VECTOR_PREHASHED_SIGNATURE = outer(`untrusted comment: signature from minisign secret key
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=
trusted comment: timestamp:1556193335\tfile:test
y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==
`);
const VECTOR_LEGACY_SIGNATURE = outer(`untrusted comment: signature from minisign secret key
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=
trusted comment: timestamp:1555779966\tfile:test
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==
`);

function generatedFixture(data, trustedComment = 'timestamp:1\tfile:update.bin\tversion:0.1.7') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const keyId = randomBytes(8);
  const publicPacket = Buffer.concat([Buffer.from('Ed'), keyId, rawPublicKey]);
  const digest = createHash('blake2b512').update(data).digest();
  const primary = sign(null, digest, privateKey);
  const signaturePacket = Buffer.concat([Buffer.from('ED'), keyId, primary]);
  const globalSignature = sign(
    null,
    Buffer.concat([primary, Buffer.from(trustedComment, 'utf8')]),
    privateKey,
  );
  const publicKeyEnvelope = outer(`untrusted comment: generated test key
${encodePacket(publicPacket)}
`);
  const signatureEnvelope = outer(`untrusted comment: generated test signature
${encodePacket(signaturePacket)}
trusted comment: ${trustedComment}
${encodePacket(globalSignature)}
`);
  return { publicKeyEnvelope, signatureEnvelope };
}

function mutateSignature(encoded, mutate) {
  const lines = Buffer.from(encoded, 'base64').toString('utf8').trimEnd().split('\n');
  mutate(lines);
  return outer(`${lines.join('\n')}\n`);
}

test('verifies the locked Tauri Minisign prehashed and legacy formats', () => {
  const data = Buffer.from('test');
  assert.equal(
    verifyUpdaterSignature(data, VECTOR_PREHASHED_SIGNATURE, VECTOR_PUBLIC_KEY, 'v0.1.7').algorithm,
    'ED',
  );
  assert.equal(
    verifyUpdaterSignature(data, VECTOR_LEGACY_SIGNATURE, VECTOR_PUBLIC_KEY).algorithm,
    'Ed',
  );
  assert.match(updaterPublicKeySha256(VECTOR_PUBLIC_KEY), /^[0-9a-f]{64}$/);
});

test('verifies a test-only generated key and both Minisign signature layers', () => {
  const data = Buffer.from('generated updater package');
  const fixture = generatedFixture(data);
  const result = verifyUpdaterSignature(
    data,
    fixture.signatureEnvelope,
    fixture.publicKeyEnvelope,
    'v0.1.7',
  );
  assert.equal(result.algorithm, 'ED');
  assert.equal(result.trustedComment, 'timestamp:1\tfile:update.bin\tversion:0.1.7');
  assert.equal(result.signedVersion, '0.1.7');
  assert.throws(
    () => verifyUpdaterSignature(data, fixture.signatureEnvelope, fixture.publicKeyEnvelope, '0.1.8'),
    /version 0\.1\.7 does not match 0\.1\.8/,
  );
  const invalidSemver = generatedFixture(
    data,
    'timestamp:1\tfile:update.bin\tversion:v0.1.7-alpha..1',
  );
  assert.throws(
    () => verifyUpdaterSignature(
      data,
      invalidSemver.signatureEnvelope,
      invalidSemver.publicKeyEnvelope,
      '0.1.7-alpha..1',
    ),
    /does not match/,
  );

  assert.throws(
    () => verifyUpdaterSignature(Buffer.from('replaced package'), fixture.signatureEnvelope, fixture.publicKeyEnvelope),
    /package signature verification failed/,
  );
  const wrongKey = generatedFixture(data).publicKeyEnvelope;
  assert.throws(
    () => verifyUpdaterSignature(data, fixture.signatureEnvelope, wrongKey),
    /key id does not match/,
  );

  const damagedPrimary = mutateSignature(fixture.signatureEnvelope, lines => {
    const bytes = packet(lines[1]); bytes[10] ^= 1; lines[1] = encodePacket(bytes);
  });
  assert.throws(
    () => verifyUpdaterSignature(data, damagedPrimary, fixture.publicKeyEnvelope),
    /package signature verification failed/,
  );

  const damagedComment = mutateSignature(fixture.signatureEnvelope, lines => {
    lines[2] = lines[2].replace('version:0.1.7', 'version:9.9.9');
  });
  assert.throws(
    () => verifyUpdaterSignature(data, damagedComment, fixture.publicKeyEnvelope),
    /trusted-comment signature verification failed/,
  );

  const damagedGlobal = mutateSignature(fixture.signatureEnvelope, lines => {
    const bytes = packet(lines[3]); bytes[0] ^= 1; lines[3] = encodePacket(bytes);
  });
  assert.throws(
    () => verifyUpdaterSignature(data, damagedGlobal, fixture.publicKeyEnvelope),
    /trusted-comment signature verification failed/,
  );
});

test('rejects malformed outer envelopes and extra unsigned lines', () => {
  assert.throws(
    () => verifyUpdaterSignature(Buffer.from('test'), 'NOT_A_SIGNATURE', VECTOR_PUBLIC_KEY),
    /canonical base64/,
  );
  const extraLine = outer(`${Buffer.from(VECTOR_PREHASHED_SIGNATURE, 'base64').toString('utf8')}unsigned\n`);
  assert.throws(
    () => verifyUpdaterSignature(Buffer.from('test'), extraLine, VECTOR_PUBLIC_KEY),
    /invalid Minisign layout/,
  );

  const publicLines = Buffer.from(VECTOR_PUBLIC_KEY, 'base64').toString('utf8').trimEnd().split('\n');
  const damagedPublicAlgorithm = packet(publicLines[1]);
  damagedPublicAlgorithm[0] |= 0x80;
  publicLines[1] = encodePacket(damagedPublicAlgorithm);
  const highBitPublicKey = outer(`${publicLines.join('\n')}\n`);
  assert.throws(
    () => updaterPublicKeySha256(highBitPublicKey),
    /unsupported Minisign algorithm/,
  );

  const highBitSignature = mutateSignature(VECTOR_PREHASHED_SIGNATURE, lines => {
    const bytes = packet(lines[1]); bytes[1] |= 0x80; lines[1] = encodePacket(bytes);
  });
  assert.throws(
    () => verifyUpdaterSignature(Buffer.from('test'), highBitSignature, VECTOR_PUBLIC_KEY),
    /unsupported Minisign algorithm/,
  );
});

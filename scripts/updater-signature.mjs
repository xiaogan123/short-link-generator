import {
  createHash, createPublicKey, timingSafeEqual, verify,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PUBLIC_KEY_PACKET_BYTES = 42;
const SIGNATURE_PACKET_BYTES = 74;
const ED25519_SIGNATURE_BYTES = 64;

function decodeBase64(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`${label} is not canonical base64.`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) throw new Error(`${label} is not canonical base64.`);
  return decoded;
}

function decodeTextEnvelope(value, label) {
  const bytes = decodeBase64(value, label);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} does not contain UTF-8 Minisign text.`);
  }
}

function exactLines(text, expected, label) {
  if (text.includes('\r') && !text.includes('\r\n')) {
    throw new Error(`${label} contains invalid line endings.`);
  }
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (lines.length !== expected || lines.some(line => line.length === 0)) {
    throw new Error(`${label} has an invalid Minisign layout.`);
  }
  return lines;
}

function supportedAlgorithm(packet, label) {
  if (packet[0] !== 0x45 || (packet[1] !== 0x64 && packet[1] !== 0x44)) {
    throw new Error(`${label} uses an unsupported Minisign algorithm.`);
  }
  return packet[1] === 0x44 ? 'ED' : 'Ed';
}

function parsePublicKey(encodedPublicKey) {
  const lines = exactLines(
    decodeTextEnvelope(encodedPublicKey, 'Updater public key'),
    2,
    'Updater public key',
  );
  if (!lines[0].startsWith('untrusted comment: ')) {
    throw new Error('Updater public key is missing its Minisign comment.');
  }
  const packet = decodeBase64(lines[1], 'Minisign public-key packet');
  if (packet.length !== PUBLIC_KEY_PACKET_BYTES) {
    throw new Error('Minisign public-key packet has an invalid length.');
  }
  supportedAlgorithm(packet, 'Updater public key');
  const rawKey = packet.subarray(10);
  return {
    keyId: packet.subarray(2, 10),
    key: createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]),
      format: 'der',
      type: 'spki',
    }),
  };
}

function parseSignature(encodedSignature) {
  const lines = exactLines(
    decodeTextEnvelope(encodedSignature, 'Updater signature'),
    4,
    'Updater signature',
  );
  if (!lines[0].startsWith('untrusted comment: ')) {
    throw new Error('Updater signature is missing its Minisign comment.');
  }
  if (!lines[2].startsWith('trusted comment: ')) {
    throw new Error('Updater signature is missing its trusted comment.');
  }
  const packet = decodeBase64(lines[1], 'Minisign signature packet');
  if (packet.length !== SIGNATURE_PACKET_BYTES) {
    throw new Error('Minisign signature packet has an invalid length.');
  }
  const globalSignature = decodeBase64(lines[3], 'Minisign global signature');
  if (globalSignature.length !== ED25519_SIGNATURE_BYTES) {
    throw new Error('Minisign global signature has an invalid length.');
  }
  return {
    algorithm: supportedAlgorithm(packet, 'Updater signature'),
    keyId: packet.subarray(2, 10),
    signature: packet.subarray(10),
    trustedComment: lines[2].slice('trusted comment: '.length),
    globalSignature,
  };
}

export function updaterPublicKeySha256(encodedPublicKey) {
  parsePublicKey(encodedPublicKey);
  return createHash('sha256').update(encodedPublicKey, 'utf8').digest('hex');
}

function signedVersion(trustedComment) {
  return trustedComment.split('\t').find(field => field.startsWith('version:'))?.slice('version:'.length);
}

function versionsMatch(signed, expected) {
  const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
  const parse = value => {
    const bare = value.replace(/^v+/, '');
    const match = semver.exec(bare);
    if (!match || match.slice(1, 4).some(number => BigInt(number) > 0xffff_ffff_ffff_ffffn)) return null;
    return bare;
  };
  const parsedSigned = parse(signed);
  const parsedExpected = parse(expected);
  if (parsedSigned !== null && parsedExpected !== null) return parsedSigned === parsedExpected;
  return signed === expected;
}

export function verifyUpdaterSignature(data, encodedSignature, encodedPublicKey, expectedVersion) {
  if (!Buffer.isBuffer(data)) throw new Error('Updater package must be supplied as bytes.');
  const publicKey = parsePublicKey(encodedPublicKey);
  const signature = parseSignature(encodedSignature);
  if (!timingSafeEqual(publicKey.keyId, signature.keyId)) {
    throw new Error('Updater signature key id does not match the configured public key.');
  }
  const signedData = signature.algorithm === 'ED'
    ? createHash('blake2b512').update(data).digest()
    : data;
  if (!verify(null, signedData, publicKey.key, signature.signature)) {
    throw new Error('Updater package signature verification failed.');
  }
  const globalData = Buffer.concat([
    signature.signature,
    Buffer.from(signature.trustedComment, 'utf8'),
  ]);
  if (!verify(null, globalData, publicKey.key, signature.globalSignature)) {
    throw new Error('Updater trusted-comment signature verification failed.');
  }
  const version = signedVersion(signature.trustedComment);
  if (version !== undefined && expectedVersion !== undefined && !versionsMatch(version, expectedVersion)) {
    throw new Error(`Updater signature version ${version} does not match ${expectedVersion}.`);
  }
  return {
    algorithm: signature.algorithm,
    trustedComment: signature.trustedComment,
    signedVersion: version,
  };
}

export function verifyUpdaterSignatureFile(
  packagePath,
  signaturePath,
  encodedPublicKey,
  expectedVersion,
) {
  const encodedSignature = readFileSync(signaturePath, 'utf8').trim();
  if (!encodedSignature) throw new Error('Updater signature file is empty.');
  return verifyUpdaterSignature(
    readFileSync(packagePath),
    encodedSignature,
    encodedPublicKey,
    expectedVersion,
  );
}

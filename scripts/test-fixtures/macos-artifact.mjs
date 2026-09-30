import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { stableRequirement, hash } from '../macos-signature.mjs';

export const CERT_PIN = 'd'.repeat(64);
const certificateSha1 = 'e'.repeat(40);
const designatedRequirement = stableRequirement(certificateSha1);
export const nativeSigning = { identity: 'self-signed', identityVerified: true, signatureVerified: true,
  requirementVerified: true, certificateSelfSignatureVerified: true, notarization: 'not-notarized',
  identifier: 'org.shortlink.generator', certificateSha256: CERT_PIN, certificateSha1,
  designatedRequirement, designatedRequirementSha256: hash(designatedRequirement) };

export function tarBytes(entries, { trailer = Buffer.alloc(1024) } = {}) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? ''); const header = Buffer.alloc(512);
    const set = (value, offset, length) => header.write(value, offset, length, 'utf8');
    set(entry.path, 0, 100);
    set((entry.mode ?? (entry.type === '5' ? 0o755 : entry.type === '2' ? 0o777 : 0o644)).toString(8).padStart(7, '0'), 100, 8);
    set('0000000', 108, 8); set('0000000', 116, 8);
    set(data.length.toString(8).padStart(11, '0'), 124, 12); set('00000000000', 136, 12);
    header.fill(32, 148, 156); set(entry.type ?? '0', 156, 1); set(entry.target ?? '', 157, 100);
    set('ustar\u000000', 257, 8); set(entry.prefix ?? '', 345, 155);
    set(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
    chunks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return Buffer.concat([...chunks, trailer]);
}
export const pack = entries => gzipSync(tarBytes(entries));
export const bundleEntries = () => [
  { path: 'Example.app/', type: '5' },
  { path: 'Example.app/Contents', type: '5' },
  { path: 'Example.app/Contents/Info.plist', data: 'synthetic-info' },
  { path: 'Example.app/Contents/MacOS', type: '5' },
  { path: 'Example.app/Contents/MacOS/short-link-generator', data: 'synthetic-executable', mode: 0o755 },
];
export function pax(values) {
  return Buffer.concat(Object.entries(values).map(([key, value]) => {
    const record = Buffer.from(` ${key}=${value}\n`);
    let length = record.length + 1;
    while (String(length).length + record.length !== length) length = String(length).length + record.length;
    return Buffer.concat([Buffer.from(String(length)), record]);
  }));
}

// Ephemeral test-only key: never accepts or reads a user's release credential.
export function testUpdaterSigner() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const id = Buffer.from('12345678');
  const packet = Buffer.concat([Buffer.from('Ed'), id, publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]);
  const encodedPublicKey = Buffer.from(`untrusted comment: generated test key\n${packet.toString('base64')}\n`).toString('base64');
  return { publicKey: encodedPublicKey, sign(data) {
    const signature = sign(null, createHash('blake2b512').update(data).digest(), privateKey);
    const trusted = 'timestamp:1\tfile:test';
    const global = sign(null, Buffer.concat([signature, Buffer.from(trusted)]), privateKey);
    const packet = Buffer.concat([Buffer.from('ED'), id, signature]);
    return Buffer.from(`untrusted comment: generated test signature\n${packet.toString('base64')}\ntrusted comment: ${trusted}\n${global.toString('base64')}\n`).toString('base64');
  } };
}
export function artifactEvidence(manifest, buildBundleCompared = true) {
  return { schema: 1, updaterBundleVerified: true, contentMatchVerified: true, modesMatchVerified: true,
    buildBundleCompared, bundleManifestSha256: manifest.sha256, entryCount: manifest.entryCount, fileCount: manifest.fileCount,
    updaterSigning: { ...nativeSigning }, ...(buildBundleCompared ? { buildSigning: { ...nativeSigning } } : {}) };
}

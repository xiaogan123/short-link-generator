import { createHash, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const MAC_IDENTIFIER = 'org.shortlink.generator';
export const hash = value => createHash('sha256').update(value).digest('hex');
const hex = (value, size) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${size}}$`).test(value);

export function cleanSigningEnvironment(env) {
  const clean = { ...env };
  for (const name of Object.keys(clean)) {
    if (name.startsWith('SLG_MACOS_SIGNING_') || name.startsWith('SLG_INTERNAL_') ||
        name.startsWith('TAURI_SIGNING_') || name.startsWith('APPLE_') ||
        name.startsWith('RCODESIGN_') || name.startsWith('DYLD_') ||
        name === 'SLG_RELEASE_PRIVATE_KEY' || name === 'SLG_PRIVATE_SIGNING_CONTEXT') delete clean[name];
  }
  for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'OPENSSL_CONF', 'OPENSSL_ENGINES', 'OPENSSL_MODULES', 'BASH_ENV', 'ENV']) delete clean[name];
  delete clean.RUST_LOG;
  delete clean.TAURI_LOG_LEVEL;
  return clean;
}

export function certificateInfo(der, expectedSha256) {
  if (!hex(expectedSha256, 64)) throw new Error('Expected macOS certificate SHA-256 is required.');
  const cert = new X509Certificate(der);
  if (hash(cert.raw) !== expectedSha256 || cert.subject !== cert.issuer || !cert.verify(cert.publicKey) ||
      cert.ca || !cert.keyUsage?.includes('1.3.6.1.5.5.7.3.3')) {
    throw new Error('macOS certificate does not match the pinned self-signed code-signing identity.');
  }
  return { certificateSha256: expectedSha256, certificateSha1: createHash('sha1').update(cert.raw).digest('hex') };
}

export function stableRequirement(sha1) {
  if (!hex(sha1, 40)) throw new Error('Invalid macOS certificate identity.');
  return `identifier "${MAC_IDENTIFIER}" and certificate leaf = H"${sha1}"`;
}

export function validateRequirement(value, sha1) {
  if (typeof value !== 'string' || !hex(sha1, 40)) throw new Error('Missing stable designated requirement.');
  const normalized = value.trim().replace(/\s+/g, ' ');
  const match = /^identifier (?:"org\.shortlink\.generator"|org\.shortlink\.generator) and (?:certificate (?:leaf|0)|anchor) = H"([0-9a-fA-F]{40})"$/.exec(normalized);
  if (!match || match[1].toLowerCase() !== sha1) throw new Error('Designated requirement must pin both identifier and exact certificate.');
  return normalized;
}

export function validateMacSigningEvidence(signing, expectedSha256) {
  if (!signing || signing.identity !== 'self-signed' || signing.identityVerified !== true ||
      signing.signatureVerified !== true || signing.requirementVerified !== true ||
      signing.certificateSelfSignatureVerified !== true || signing.notarization !== 'not-notarized' ||
      signing.identifier !== MAC_IDENTIFIER || !hex(expectedSha256, 64) || signing.certificateSha256 !== expectedSha256 ||
      !hex(signing.certificateSha1, 40)) throw new Error('Stable macOS signing evidence is incomplete or mismatched.');
  const requirement = validateRequirement(signing.designatedRequirement, signing.certificateSha1);
  if (signing.designatedRequirementSha256 !== hash(requirement)) throw new Error('Stable macOS designated requirement hash mismatch.');
}

export function verifyMacSigning(app, expectedSha256, run = (cmd, args, options) => {
  const result = execFileSync(cmd, args, { ...options, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 });
  return result;
}) {
  const temp = mkdtempSync(join(tmpdir(), 'slg-public-signature-'));
  // Verification only needs public data; never inherit CI P12/password inputs.
  const inspect = (cmd, args) => run(cmd, args, { env: cleanSigningEnvironment(process.env) });
  try {
    inspect('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]);
    // codesign displays requirements on stdout; diagnostic paths remain captured on stderr.
    const output = inspect('/usr/bin/codesign', ['--display', '--requirements', '-', app]);
    const match = /^\s*(?:#\s*)?designated => (.+)$/m.exec(output);
    if (!match) throw new Error('Missing designated requirement.');
    const prefix = join(temp, 'certificate-');
    // This option's prefix is optional; codesign requires '=' to bind it rather
    // than treating a separate argument as another object to inspect.
    inspect('/usr/bin/codesign', ['--display', `--extract-certificates=${prefix}`, app]);
    if (!existsSync(`${prefix}0`) || existsSync(`${prefix}1`)) throw new Error('Expected one self-signed certificate.');
    const info = certificateInfo(readFileSync(`${prefix}0`), expectedSha256);
    const requirement = validateRequirement(match[1], info.certificateSha1);
    inspect('/usr/bin/codesign', ['--verify', '--strict', '-R', `=${stableRequirement(info.certificateSha1)}`, app]);
    const evidence = { identity: 'self-signed', identityVerified: true, signatureVerified: true,
      requirementVerified: true, certificateSelfSignatureVerified: true, notarization: 'not-notarized',
      identifier: MAC_IDENTIFIER, ...info, designatedRequirement: requirement, designatedRequirementSha256: hash(requirement) };
    validateMacSigningEvidence(evidence, expectedSha256);
    return evidence;
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fail = () => new Error('Credential helper bundle bytes do not match the approved archive.');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const REQUIRED = new Set([
  'Contents/Info.plist',
  'Contents/MacOS/credential-helper',
  'Contents/_CodeSignature/CodeResources',
]);
export const REVIEWED_HELPER_INFO_SHA256 = '87c8fdacf498ebdcf98e1f99674aa1f3c172c0e9f0e5a46a731a5d8249f8805e';

export function helperPinForTarget(target, env) {
  const name = {
    'aarch64-apple-darwin': 'SLG_MACOS_HELPER_TREE_SHA256_ARM64',
    'x86_64-apple-darwin': 'SLG_MACOS_HELPER_TREE_SHA256_X64',
  }[target];
  const pin = name && env[name];
  if (!/^[a-f0-9]{64}$/.test(pin ?? '')) throw fail();
  return pin;
}

// Canonical, path-independent digest of an already signed .xpc directory.
// It proves only exact staged/packaged bytes; identity and signature approval
// must independently establish the expected digest before this is called.
export function helperTreeDigest(bundle) {
  if (basename(bundle) !== 'credential-helper.xpc') throw fail();
  const root = resolve(bundle);
  const entries = [];
  let totalBytes = 0;
  function visit(path, relative) {
    const stat = lstatSync(path);
    if (stat.mode & 0o7000) throw fail();
    if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) throw fail();
    if (stat.isDirectory()) {
      entries.push({ path: relative || '.', type: 'directory', mode: stat.mode & 0o777 });
      for (const name of readdirSync(path).sort()) {
        if (name === '.' || name === '..' || name.includes('/') || name.includes('\0')) throw fail();
        visit(join(path, name), relative ? `${relative}/${name}` : name);
      }
    } else if (stat.isFile()) {
      if (stat.size > 128 * 1024 * 1024) throw fail();
      totalBytes += stat.size;
      if (totalBytes > 256 * 1024 * 1024) throw fail();
      const bytes = readFileSync(path);
      if (bytes.length !== stat.size) throw fail();
      entries.push({ path: relative, type: 'file', mode: stat.mode & 0o777,
        size: stat.size, sha256: sha256(bytes) });
    } else throw fail();
  }
  visit(root, '');
  const observed = new Set(entries.filter(entry => entry.type === 'file').map(entry => entry.path));
  for (const required of REQUIRED) if (!observed.has(required)) throw fail();
  return sha256(Buffer.from(JSON.stringify(entries)));
}

export function verifyPackagedHelper(stage, packaged, approvedTreeSha256) {
  if (!/^[a-f0-9]{64}$/.test(approvedTreeSha256 ?? '')) throw fail();
  if (helperTreeDigest(stage) !== approvedTreeSha256 ||
      helperTreeDigest(packaged) !== approvedTreeSha256) throw fail();
  return { bytesPreserved: true, treeSha256: approvedTreeSha256 };
}

export function verifyEmbeddedHelper(app, approvedTreeSha256) {
  if (!/^[a-f0-9]{64}$/.test(approvedTreeSha256 ?? '')) throw fail();
  const helper = join(app, 'Contents', 'XPCServices', 'credential-helper.xpc');
  const infoSha256 = sha256(readFileSync(join(helper, 'Contents', 'Info.plist')));
  if (infoSha256 !== REVIEWED_HELPER_INFO_SHA256 ||
      helperTreeDigest(helper) !== approvedTreeSha256) throw fail();
  return { treeSha256: approvedTreeSha256, infoSha256 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 5) throw fail();
    console.log(JSON.stringify(verifyPackagedHelper(process.argv[2], process.argv[3], process.argv[4])));
  } catch {
    console.error(JSON.stringify({ ok: false, stage: 'credential-helper-bytes' }));
    process.exitCode = 1;
  }
}

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync,
  renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { readMacUpdater } from './macos-artifact.mjs';
import { verifyUpdaterSignatureFile } from './updater-signature.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TARGETS = new Set(['aarch64-apple-darwin', 'x86_64-apple-darwin']);
const MAX_EXPANDED = 512 * 1024 * 1024;
const MAX_COMPRESSED = 256 * 1024 * 1024;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => new Error('macOS updater owner normalization failed; candidate is not approved.');
const ascii = value => /^[\x20-\x7e]+$/.test(value);
const paddedLength = size => Math.ceil(size / 512) * 512;

function canonicalExpanded(bytes) {
  for (let offset = 0; offset < bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      if (!bytes.subarray(offset).every(byte => byte === 0)) throw fail();
      return;
    }
    const readOctal = (start, end) => {
      const value = header.toString('ascii', start, end).replace(/[\0 ]+$/g, '');
      if (!/^[0-7]+$/.test(value)) throw fail();
      return parseInt(value, 8);
    };
    if (readOctal(108, 116) !== 0 || readOctal(116, 124) !== 0 || readOctal(136, 148) !== 0 ||
        !header.subarray(265, 512).every(byte => byte === 0)) throw fail();
    const size = readOctal(124, 136);
    const padded = paddedLength(size);
    if (offset + 512 + padded > bytes.length ||
        !bytes.subarray(offset + 512 + size, offset + 512 + padded).every(byte => byte === 0)) throw fail();
    if (header[156] === 120) { // PAX x-header: only path and linkpath are allowed.
      const data = bytes.subarray(offset + 512, offset + 512 + size);
      const keys = new Set();
      for (let at = 0; at < data.length;) {
        const space = data.indexOf(32, at);
        if (space < at || space - at > 8) throw fail();
        const length = Number(data.toString('ascii', at, space));
        if (!Number.isSafeInteger(length) || length < 4 || at + length > data.length || data[at + length - 1] !== 10) throw fail();
        const equals = data.indexOf(61, space + 1);
        if (equals < 0 || equals >= at + length - 1) throw fail();
        const key = data.toString('ascii', space + 1, equals);
        if (!['path', 'linkpath'].includes(key) || keys.has(key)) throw fail();
        keys.add(key); at += length;
      }
    }
    offset += 512 + padded;
  }
  throw fail();
}

function octal(header, value, offset, width) {
  if (!Number.isSafeInteger(value) || value < 0 || value.toString(8).length > width - 1) throw fail();
  header.write(value.toString(8).padStart(width - 1, '0'), offset, width - 1, 'ascii');
  header[offset + width - 1] = 0;
}

function rawHeader({ name, type, mode, size = 0, target = '' }) {
  if (!ascii(name) || Buffer.byteLength(name) > 100 || target && (!ascii(target) || Buffer.byteLength(target) > 100)) throw fail();
  const header = Buffer.alloc(512);
  header.write(name, 0, 'ascii');
  octal(header, mode, 100, 8);
  octal(header, 0, 108, 8); // uid
  octal(header, 0, 116, 8); // gid
  octal(header, size, 124, 12);
  octal(header, 0, 136, 12); // mtime
  header.fill(32, 148, 156);
  header.write(type, 156, 1, 'ascii');
  if (target) header.write(target, 157, 'ascii');
  header.write('ustar\0', 257, 'latin1');
  header.write('00', 263, 'ascii');
  // uname, gname, dev numbers, prefix and residual header padding stay zero.
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  if (checksum.toString(8).length > 6) throw fail();
  header.write(checksum.toString(8).padStart(6, '0'), 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 32;
  return header;
}

function paxRecord(key, value) {
  const body = Buffer.from(` ${key}=${value}\n`, 'utf8');
  let length = body.length + 1;
  while (Buffer.byteLength(String(length)) + body.length !== length) {
    length = Buffer.byteLength(String(length)) + body.length;
  }
  return Buffer.concat([Buffer.from(String(length), 'ascii'), body]);
}

function append(chunks, header, data = Buffer.alloc(0)) {
  chunks.push(header);
  if (data.length) chunks.push(data);
  if (data.length % 512) chunks.push(Buffer.alloc(paddedLength(data.length) - data.length));
}

// Entries come only from readMacUpdater, which already validates paths, links,
// types, bounds, duplicate aliases, member padding and the complete graph.
export function encodeCanonicalMacUpdater(entries) {
  if (!Array.isArray(entries) || !entries.length || entries.length > 20_000) throw fail();
  const chunks = [];
  let expanded = 1024;
  for (const [index, entry] of entries.entries()) {
    const path = entry.path;
    const target = entry.type === 'symlink' ? entry.target : '';
    const pathInHeader = ascii(path) && Buffer.byteLength(path) <= 100;
    const targetInHeader = !target || ascii(target) && Buffer.byteLength(target) <= 100;
    const pax = [];
    if (!pathInHeader) pax.push(paxRecord('path', path));
    if (!targetInHeader) pax.push(paxRecord('linkpath', target));
    if (pax.length) {
      const payload = Buffer.concat(pax);
      if (payload.length > 64 * 1024) throw fail();
      append(chunks, rawHeader({ name: `PaxHeaders.${index}`, type: 'x', mode: 0o644, size: payload.length }), payload);
      expanded += 512 + paddedLength(payload.length);
    }
    const data = entry.type === 'file' ? entry.data : Buffer.alloc(0);
    if (entry.type === 'file' && !Buffer.isBuffer(data)) throw fail();
    const type = entry.type === 'directory' ? '5' : entry.type === 'symlink' ? '2' : entry.type === 'file' ? '0' : null;
    if (!type || !Number.isInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o777) throw fail();
    append(chunks, rawHeader({ name: pathInHeader ? path : `Entry.${index}`, type,
      mode: entry.mode, size: data.length, target: targetInHeader ? target : '' }), data);
    expanded += 512 + paddedLength(data.length);
    if (expanded > MAX_EXPANDED) throw fail();
  }
  chunks.push(Buffer.alloc(1024));
  const gzip = gzipSync(Buffer.concat(chunks, expanded), { level: 9 });
  if (gzip.length > MAX_COMPRESSED || gzip[0] !== 31 || gzip[1] !== 139 || gzip[2] !== 8 || gzip[3] !== 0) throw fail();
  gzip.fill(0, 4, 8); // gzip mtime
  gzip[9] = 255; // unknown OS, independent of the build host
  return gzip;
}

function regular(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.nlink !== 1) throw fail();
  return stat;
}

export function locateMacUpdater(bundle, target) {
  if (!TARGETS.has(target)) throw fail();
  const macos = join(bundle, 'macos');
  if (!lstatSync(bundle).isDirectory() || !lstatSync(macos).isDirectory()) throw fail();
  const inventory = readdirSync(macos);
  if (inventory.some(name => name.startsWith('.owner-normalize-'))) throw fail();
  const names = inventory.filter(name => name.endsWith('.app.tar.gz'));
  if (names.length !== 1 || names[0].includes('/') || names[0].includes('\\')) throw fail();
  const updater = join(macos, names[0]);
  const signature = `${updater}.sig`;
  regular(updater);
  if (regular(signature).size === 0) throw fail();
  return { updater, signature };
}

export function signerInvocation(archive, version, sourceEnv = process.env) {
  const key = sourceEnv.TAURI_SIGNING_PRIVATE_KEY;
  const password = sourceEnv.TAURI_SIGNING_PRIVATE_KEY_PASSWORD;
  if (!key || typeof key !== 'string') throw fail();
  const cli = join(ROOT, 'node_modules/@tauri-apps/cli/tauri.js');
  const env = { TAURI_SIGNING_PRIVATE_KEY: key };
  if (password !== undefined) env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD = password;
  return { executable: process.execPath,
    args: [cli, 'signer', 'sign', '--app-version', version, archive], env };
}

export function requireDisabledCoreDumps(run = spawnSync) {
  const result = run('/bin/sh', ['-c', 'ulimit -S -c; ulimit -H -c'], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
    stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 5_000, maxBuffer: 1024,
  });
  if (result.error || result.status !== 0 || result.stdout?.trim() !== '0\n0') throw fail();
}

export function signCanonicalUpdater(archive, version, sourceEnv = process.env,
  { coreRun = spawnSync, signerRun = spawnSync } = {}) {
  requireDisabledCoreDumps(coreRun);
  const command = signerInvocation(archive, version, sourceEnv);
  regular(command.args[0]);
  const result = signerRun(command.executable, command.args, {
    cwd: ROOT, env: command.env, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'buffer',
    timeout: 120_000, maxBuffer: 1024 * 1024,
  });
  result.stdout?.fill(0);
  result.stderr?.fill(0);
  if (result.error || result.status !== 0) throw fail();
  // Deliberately discard stdout/stderr: signer messages may reveal local paths.
  regular(`${archive}.sig`);
}

function sameManifest(a, b) {
  return a.sha256 === b.sha256 && a.entryCount === b.entryCount && a.fileCount === b.fileCount;
}

export function normalizeMacUpdater({ updater, signature, version, publicKey, sign = signCanonicalUpdater }) {
  regular(updater);
  if (regular(signature).size === 0 || signature !== `${updater}.sig` || !publicKey || !version) throw fail();
  if (verifyUpdaterSignatureFile(updater, signature, publicKey, version).signedVersion !== version) throw fail();
  const before = readMacUpdater(updater);
  const directory = dirname(updater);
  const temporary = mkdtempSync(join(directory, '.owner-normalize-'));
  chmodSync(temporary, 0o700);
  const staged = join(temporary, basename(updater));
  const stagedSignature = `${staged}.sig`;
  const previous = join(temporary, 'previous-updater');
  const previousSignature = join(temporary, 'previous-signature');
  let movedOriginalArchive = false;
  let movedOriginalSignature = false;
  let movedNewArchive = false;
  let movedNewSignature = false;
  let mayClean = true;
  try {
    const canonical = encodeCanonicalMacUpdater(before.entries);
    writeFileSync(staged, canonical, { flag: 'wx', mode: 0o600 });
    if (!sameManifest(before.manifest, readMacUpdater(staged, { inspectExpanded: canonicalExpanded }).manifest)) throw fail();
    sign(staged, version);
    if (regular(stagedSignature).size === 0) throw fail();
    if (verifyUpdaterSignatureFile(staged, stagedSignature, publicKey, version).signedVersion !== version) throw fail();
    renameSync(updater, previous); movedOriginalArchive = true;
    renameSync(signature, previousSignature); movedOriginalSignature = true;
    renameSync(staged, updater); movedNewArchive = true;
    renameSync(stagedSignature, signature); movedNewSignature = true;
    if (!sameManifest(before.manifest, readMacUpdater(updater, { inspectExpanded: canonicalExpanded }).manifest)) throw fail();
    if (verifyUpdaterSignatureFile(updater, signature, publicKey, version).signedVersion !== version) throw fail();
    return { updaterSha256: sha(readFileSync(updater)), signatureSha256: sha(readFileSync(signature)),
      manifestSha256: before.manifest.sha256, entryCount: before.manifest.entryCount };
  } catch {
    try {
      if (movedNewSignature && existsSync(signature)) rmSync(signature);
      if (movedNewArchive && existsSync(updater)) rmSync(updater);
      if (movedOriginalSignature) renameSync(previousSignature, signature);
      if (movedOriginalArchive) renameSync(previous, updater);
    } catch {
      mayClean = false; // preserve our backups if rollback cannot be confirmed
    }
    throw fail();
  } finally {
    if (mayClean) rmSync(temporary, { recursive: true, force: false });
  }
}

export function normalizeOptionalMacUpdater({ bundle, target, version, publicKey, sourceEnv = process.env,
  releaseRoot = ROOT, normalize = normalizeMacUpdater }) {
  const macos = join(bundle, 'macos');
  const names = readdirSync(macos);
  if (names.some(name => name.startsWith('.owner-normalize-'))) throw fail();
  const archives = names.filter(name => name.endsWith('.app.tar.gz'));
  const signatures = names.filter(name => name.endsWith('.app.tar.gz.sig'));
  if (!archives.length && !signatures.length) return { present: false };
  if (archives.length !== 1 || signatures.length !== 1 || !publicKey) throw fail();
  const paths = locateMacUpdater(bundle, target);
  return { present: true, ...normalize({ ...paths, version: version ?? releaseVersion(releaseRoot), publicKey,
    sign: (archive, signedVersion) => signCanonicalUpdater(archive, signedVersion, sourceEnv) }) };
}

export function releaseVersion(root = ROOT) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const tauri = JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8'));
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(pkg.version) || pkg.version !== tauri.version) throw fail();
  return pkg.version;
}

function main() {
  const [bundle, target, extra] = process.argv.slice(2);
  if (!bundle || !target || extra) throw fail();
  const version = releaseVersion(ROOT);
  const publicKey = process.env.SLG_UPDATER_PUBLIC_KEY;
  if (!publicKey) throw fail();
  const paths = locateMacUpdater(bundle, target);
  const result = normalizeMacUpdater({ ...paths, version, publicKey });
  console.log(JSON.stringify({ target, normalizedUpdater: true, ...result }));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); }
  catch { console.error('macOS updater owner normalization failed; candidate is not approved.'); process.exitCode = 1; }
}

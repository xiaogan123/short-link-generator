import { createHash } from 'node:crypto';
import { chmodSync, lchmodSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, posix, resolve, sep } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { validateMacSigningEvidence, verifyMacSigning } from './macos-signature.mjs';

// Fail closed beyond these bounds. Normal Tauri bundles are much smaller.
const MAX_COMPRESSED = 256 * 1024 * 1024;
const MAX_EXPANDED = 512 * 1024 * 1024;
const MAX_ENTRIES = 20_000;
const hash = data => createHash('sha256').update(data).digest('hex');
const invalid = () => new Error('Unsafe or unsupported macOS updater archive.');
const text = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const zero = bytes => bytes.every(byte => byte === 0);
const alias = path => path.normalize('NFD').toLowerCase();
const pathParts = path => {
  if (!path || Buffer.byteLength(path) > 4096 || /[\\:\x00-\x1f\x7f]/.test(path)) throw invalid();
  const parts = path.split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) throw invalid();
  return parts;
};
function field(bytes) {
  const end = bytes.indexOf(0);
  if (end >= 0 && !zero(bytes.subarray(end))) throw invalid();
  return text(end < 0 ? bytes : bytes.subarray(0, end));
}
function octal(bytes) {
  const value = bytes.toString('latin1').replace(/[\0 ]+$/g, '').replace(/^ +/, '');
  if (!/^[0-7]+$/.test(value)) throw invalid();
  const number = parseInt(value, 8);
  if (!Number.isSafeInteger(number)) throw invalid();
  return number;
}
function paxFields(bytes) {
  const result = {};
  for (let offset = 0; offset < bytes.length;) {
    const space = bytes.indexOf(32, offset);
    if (space < offset || space - offset > 8) throw invalid();
    const number = bytes.toString('latin1', offset, space);
    if (!/^[1-9][0-9]*$/.test(number)) throw invalid();
    const end = offset + Number(number);
    if (end > bytes.length || end <= space + 2 || bytes[end - 1] !== 10) throw invalid();
    const record = text(bytes.subarray(space + 1, end - 1));
    const equals = record.indexOf('=');
    if (equals <= 0) throw invalid();
    const key = record.slice(0, equals);
    // No sparse files, xattrs, ACLs, or vendor-specific extraction instructions.
    if (!['path', 'linkpath', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname'].includes(key) || Object.hasOwn(result, key)) throw invalid();
    result[key] = record.slice(equals + 1);
    offset = end;
  }
  return result;
}
function validateEntries(entries) {
  if (!entries.length || entries.length > MAX_ENTRIES) throw invalid();
  const root = entries[0].path.split('/')[0];
  if (!root.endsWith('.app')) throw invalid();
  const byPath = new Map(); const aliases = new Set();
  for (const entry of entries) {
    const parts = pathParts(entry.path);
    if (parts[0] !== root || aliases.has(alias(entry.path))) throw invalid();
    aliases.add(alias(entry.path)); byPath.set(entry.path, entry);
  }
  if (byPath.get(root)?.type !== 'directory') throw invalid();
  for (const entry of entries) {
    // Never create an archive member through a link, regardless of entry order.
    for (let parent = posix.dirname(entry.path); parent !== '.'; parent = posix.dirname(parent)) {
      if (byPath.get(parent)?.type !== 'directory') throw invalid();
    }
    if (entry.type === 'symlink') {
      const target = entry.target;
      if (!target || target.startsWith('/') || /[\\:\x00-\x1f\x7f]/.test(target) || Buffer.byteLength(target) > 4096) throw invalid();
      let pending = [...entry.path.split('/').slice(0, -1), ...target.split('/')];
      let current = []; let followed = 0;
      while (pending.length) {
        const part = pending.shift();
        if (part === '.' || part === '') continue;
        if (part === '..') { if (current.length <= 1) throw invalid(); current.pop(); continue; }
        current.push(part);
        if (current[0] !== root) throw invalid();
        const next = byPath.get(current.join('/'));
        if (!next) throw invalid();
        if (next.type === 'symlink') {
          if (++followed > 40) throw invalid();
          current.pop(); pending = [...next.target.split('/'), ...pending];
        } else if (pending.length && next.type !== 'directory') throw invalid();
      }
    }
  }
  return root;
}
function manifest(entries, root) {
  const records = entries.map(({ path, type, mode, data, target, size, sha256 }) => ({
    path: path === root ? '.' : path.slice(root.length + 1), type, mode,
    ...(type === 'file' ? { size: data?.length ?? size, sha256: data ? hash(data) : sha256 } : {}),
    ...(type === 'symlink' ? { target } : {}),
  })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { sha256: hash(JSON.stringify(records)), entryCount: records.length,
    fileCount: records.filter(entry => entry.type === 'file').length, entries: records };
}

export function readMacUpdater(archive, { inspectExpanded } = {}) {
  const stat = lstatSync(archive);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_COMPRESSED) throw invalid();
  let bytes;
  try { bytes = gunzipSync(readFileSync(archive), { maxOutputLength: MAX_EXPANDED }); }
  catch { throw invalid(); }
  if (bytes.length % 512) throw invalid();
  const entries = []; let pending = {}; let headers = 0; let ended = false;
  for (let offset = 0; offset < bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (zero(header)) {
      if (bytes.length - offset < 1024 || !zero(bytes.subarray(offset)) || Object.keys(pending).length) throw invalid();
      ended = true; break;
    }
    if (++headers > MAX_ENTRIES) throw invalid();
    const expected = octal(header.subarray(148, 156));
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (checksum !== expected) throw invalid();
    const magic = header.toString('latin1', 257, 265);
    if (!['ustar\u000000', 'ustar  \0'].includes(magic)) throw invalid();
    const type = header.toString('latin1', 156, 157);
    const extension = ['x', 'L', 'K'].includes(type);
    let size = octal(header.subarray(124, 136));
    if (!extension && pending.size !== undefined) {
      if (!/^(0|[1-9][0-9]*)$/.test(pending.size)) throw invalid();
      size = Number(pending.size);
    }
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_EXPANDED || offset + 512 + Math.ceil(size / 512) * 512 > bytes.length) throw invalid();
    const data = bytes.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (extension) {
      if (size > 64 * 1024) throw invalid();
      const extra = type === 'x' ? paxFields(data) : { [type === 'L' ? 'path' : 'linkpath']: field(data) };
      if (Object.keys(extra).some(key => Object.hasOwn(pending, key))) throw invalid();
      pending = { ...pending, ...extra }; continue;
    }
    if (!['0', '\0', '5', '2'].includes(type)) throw invalid();
    const prefix = magic === 'ustar\u000000' ? field(header.subarray(345, 500)) : '';
    // GNU sparse/extended layout is deliberately unsupported.
    if (magic === 'ustar  \0' && !zero(header.subarray(345))) throw invalid();
    const name = field(header.subarray(0, 100));
    let path = pending.path ?? (prefix ? `${prefix}/${name}` : name);
    if (type === '5' && path.endsWith('/')) path = path.slice(0, -1);
    const rawMode = octal(header.subarray(100, 108));
    const kind = type === '5' ? 'directory' : type === '2' ? 'symlink' : 'file';
    const typeMode = kind === 'directory' ? 0o040000 : kind === 'symlink' ? 0o120000 : 0o100000;
    if (rawMode & 0o7000 || (rawMode & ~0o777) !== 0 && (rawMode & ~0o777) !== typeMode) throw invalid();
    const mode = rawMode & 0o777;
    if (kind !== 'file' && size !== 0) throw invalid();
    const link = pending.linkpath ?? field(header.subarray(157, 257));
    if (kind !== 'symlink' && link) throw invalid();
    entries.push({ path, type: kind, mode, ...(kind === 'file' ? { data } : {}), ...(kind === 'symlink' ? { target: link } : {}) });
    pending = {};
  }
  if (!ended) throw invalid();
  const root = validateEntries(entries);
  // Inspect headers, ignored metadata and member padding as well as file data.
  // Callers must keep these bounded bytes private; never include them in evidence JSON.
  inspectExpanded?.(bytes);
  return { root, entries, manifest: manifest(entries, root) };
}

export function extractMacUpdater(archive, destination, options) {
  // Validate the entire graph before any writes; destination must be new and private.
  const parsed = readMacUpdater(archive, options);
  mkdirSync(destination, { mode: 0o700 });
  const directories = parsed.entries.filter(entry => entry.type === 'directory').sort((a, b) => a.path.split('/').length - b.path.split('/').length);
  for (const entry of directories) mkdirSync(join(destination, entry.path), { mode: 0o700 });
  for (const entry of parsed.entries.filter(entry => entry.type === 'file')) {
    const path = join(destination, entry.path);
    writeFileSync(path, entry.data, { flag: 'wx', mode: 0o600 }); chmodSync(path, entry.mode);
  }
  for (const entry of parsed.entries.filter(entry => entry.type === 'symlink')) {
    const path = join(destination, entry.path); symlinkSync(entry.target, path);
    // macOS applies umask to symlink modes, unlike Linux. Never chmod the target.
    if ((lstatSync(path).mode & 0o777) !== entry.mode) lchmodSync(path, entry.mode);
  }
  for (const entry of directories.reverse()) chmodSync(join(destination, entry.path), entry.mode);
  const app = join(destination, parsed.root);
  if (bundleManifest(app).sha256 !== parsed.manifest.sha256) throw new Error('Extracted macOS bundle differs from its archive manifest.');
  return { app, manifest: parsed.manifest };
}

export function bundleManifest(app) {
  if (!lstatSync(app).isDirectory()) throw invalid();
  const base = realpathSync(resolve(app)); const entries = []; let total = 0;
  function walk(path, name) {
    if (entries.length >= MAX_ENTRIES) throw invalid();
    const stat = lstatSync(path); const mode = stat.mode & 0o777;
    if (stat.mode & 0o7000) throw invalid();
    if (stat.isSymbolicLink()) entries.push({ path: name, type: 'symlink', mode, target: readlinkSync(path) });
    else if (stat.isDirectory()) {
      entries.push({ path: name, type: 'directory', mode });
      for (const child of readdirSync(path)) walk(join(path, child), `${name}/${child}`);
    } else if (stat.isFile() && stat.nlink === 1) {
      total += stat.size; if (total > MAX_EXPANDED) throw invalid();
      entries.push({ path: name, type: 'file', mode, size: stat.size, sha256: hash(readFileSync(path)) });
    } else throw invalid();
  }
  walk(base, 'Bundle.app'); validateEntries(entries);
  for (const entry of entries.filter(entry => entry.type === 'symlink')) {
    const actual = realpathSync(join(base, entry.path.slice('Bundle.app/'.length)));
    if (actual !== base && !actual.startsWith(`${base}${sep}`)) throw invalid();
  }
  return manifest(entries, 'Bundle.app');
}

export function validateMacArtifactEvidence(evidence, pin, updaterManifest, nativeSigning) {
  const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  if (!evidence || evidence.schema !== 1 || evidence.updaterBundleVerified !== true || evidence.contentMatchVerified !== true ||
      evidence.modesMatchVerified !== true || typeof evidence.buildBundleCompared !== 'boolean' || !hex(evidence.bundleManifestSha256) ||
      !Number.isInteger(evidence.entryCount) || evidence.entryCount < 1 || !Number.isInteger(evidence.fileCount) || evidence.fileCount < 1 ||
      evidence.fileCount > evidence.entryCount || evidence.entryCount > MAX_ENTRIES) throw new Error('macOS artifact comparison evidence is incomplete.');
  for (const signing of [nativeSigning, evidence.updaterSigning, ...(evidence.buildBundleCompared ? [evidence.buildSigning] : [])]) {
    validateMacSigningEvidence(signing, pin);
    if (signing.certificateSha1 !== nativeSigning.certificateSha1 || signing.designatedRequirementSha256 !== nativeSigning.designatedRequirementSha256) {
      throw new Error('macOS artifact signing identities or designated requirements differ.');
    }
  }
  if (!evidence.buildBundleCompared && evidence.buildSigning !== undefined) throw new Error('Unexpected macOS build signing evidence.');
  if (updaterManifest && (evidence.bundleManifestSha256 !== updaterManifest.sha256 || evidence.entryCount !== updaterManifest.entryCount || evidence.fileCount !== updaterManifest.fileCount)) {
    throw new Error('macOS updater bundle does not match its native comparison evidence.');
  }
}

export function verifyMacArtifactSet({ updater, installedApp, builtApp, destination, pin, verify = verifyMacSigning }) {
  const extracted = extractMacUpdater(updater, destination);
  const installed = bundleManifest(installedApp);
  if (extracted.manifest.sha256 !== installed.sha256) throw new Error('DMG and updater bundle content or modes differ.');
  const nativeSigning = verify(installedApp, pin);
  const updaterSigning = verify(extracted.app, pin);
  let buildSigning;
  if (builtApp) {
    if (bundleManifest(builtApp).sha256 !== installed.sha256) throw new Error('Build and packaged bundle content or modes differ.');
    buildSigning = verify(builtApp, pin);
  }
  const macArtifacts = { schema: 1, updaterBundleVerified: true, contentMatchVerified: true, modesMatchVerified: true,
    buildBundleCompared: Boolean(builtApp), bundleManifestSha256: installed.sha256, entryCount: installed.entryCount, fileCount: installed.fileCount,
    updaterSigning, ...(buildSigning ? { buildSigning } : {}) };
  validateMacArtifactEvidence(macArtifacts, pin, extracted.manifest, nativeSigning);
  return { nativeSigning, macArtifacts };
}

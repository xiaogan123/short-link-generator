import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { certificateInfo, cleanSigningEnvironment } from './macos-signature.mjs';
import { helperTreeDigest, REVIEWED_HELPER_INFO_SHA256 } from './macos-credential-helper-bytes.mjs';
import { requireMacOS11BuildVersion } from './macos-build-version.mjs';
import { assertAllowedHelperAttributeNames, helperAttributePaths } from './macos-helper-attributes.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const approvalPath = resolve(scriptDir, '../src-tauri/native/credential-helper-approval.json');
const clientCoreManifestPath = resolve(scriptDir, '../src-tauri/native/credential-core/SOURCE-MANIFEST.sha256');
const checkedInArchiveRoot = resolve(scriptDir, '../src-tauri/native/credential-helper-archives');
const stageRoot = resolve(scriptDir, '../_private/credential-helper-stage');
const APPROVAL_MANIFEST_SHA256 = '9ef6fe4298caf0e5f15a9c5502ba3d8677f9526a8e8c4d4da4bcc724bf1282b1';
const CLIENT_CORE_MANIFEST_SHA256 = '4d674ca38c1d3719764fbd3ed2dd73b492495d0b9ef0b5b06f88921366d6606f';
const CLIENT_CORE_REVIEW_MANIFEST_SHA256 = '6fd49df68520ee95ff3f007e082b2b60a0c56fd24b7c205529c9dea0593f86eb';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex64 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const fail = () => new Error('Frozen credential helper archive is not approved for staging.');
const targetArch = { 'aarch64-apple-darwin': 'arm64', 'x86_64-apple-darwin': 'x86_64' };

export function loadPinnedApproval(path = approvalPath) {
  const bytes = readFileSync(path);
  if (sha256(bytes) !== APPROVAL_MANIFEST_SHA256) throw fail();
  return JSON.parse(bytes.toString('utf8'));
}

export function approvedArchiveRecord(approval, target) {
  if (!Object.hasOwn(targetArch, target) || approval?.schema !== 1 || approval.state !== 'APPROVED' ||
      approval.mainBundleIdentifier !== 'org.shortlink.generator' ||
      approval.helperBundleIdentifier !== 'org.shortlink.generator.credential-helper' ||
      approval.joinExistingSession !== true || approval.minimumSystemVersion !== '11.0' ||
      approval.embeddedClientCoreManifestSha256 !== CLIENT_CORE_MANIFEST_SHA256 ||
      approval.embeddedClientCoreReviewManifestSha256 !== CLIENT_CORE_REVIEW_MANIFEST_SHA256 ||
      approval.helperInfoSha256 !== REVIEWED_HELPER_INFO_SHA256) throw fail();
  const record = approval.archives?.[target];
  if (record?.architecture !== targetArch[target] ||
      !['archiveSha256', 'treeSha256', 'signerCertificateSha256', 'helperSourceManifestSha256']
        .every(name => hex64(record[name])) ||
      !/^[a-f0-9]{40}$/.test(record.cdhash ?? '') ||
      !/^\d+\.\d+\.\d+$/.test(record.helperVersion ?? '')) throw fail();
  return record;
}

function runReadOnly(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    env: cleanSigningEnvironment(process.env), timeout: 30_000, maxBuffer: 1024 * 1024 });
  if (result.error || result.signal || result.status !== 0) throw fail();
  return `${result.stdout}${result.stderr}`;
}

// Read-only inspection of an already signed helper. Never calls codesign -s.
export function inspectSignedHelper(bundle, record, run = runReadOnly) {
  const binary = join(bundle, 'Contents', 'MacOS', 'credential-helper');
  const info = join(bundle, 'Contents', 'Info.plist');
  if (sha256(readFileSync(info)) !== REVIEWED_HELPER_INFO_SHA256) throw fail();
  const identifier = run('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleIdentifier', info]).trim();
  const executable = run('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable', info]).trim();
  const version = run('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleShortVersionString', info]).trim();
  const joinSession = run('/usr/libexec/PlistBuddy', ['-c', 'Print :XPCService:JoinExistingSession', info]).trim();
  if (identifier !== 'org.shortlink.generator.credential-helper' || executable !== 'credential-helper' ||
      version !== record.helperVersion || joinSession !== 'true') throw fail();
  const arch = run('/usr/bin/xcrun', ['lipo', '-archs', binary]).trim();
  const loadCommands = run('/usr/bin/xcrun', ['otool', '-l', binary]);
  if (arch !== record.architecture) throw fail();
  requireMacOS11BuildVersion(loadCommands);
  for (const path of helperAttributePaths(bundle)) {
    assertAllowedHelperAttributeNames(run('/usr/bin/xattr', [path]));
  }
  run('/usr/bin/codesign', ['--verify', '--strict', bundle]);
  const display = run('/usr/bin/codesign', ['--display', '--verbose=4', bundle]);
  const displayedIdentifier = /(?:^|\n)Identifier=([^\r\n]+)/.exec(display)?.[1];
  const displayedCdhash = /(?:^|\n)CDHash=([a-fA-F0-9]{40})(?:\r?\n|$)/.exec(display)?.[1]?.toLowerCase();
  if (displayedIdentifier !== identifier || displayedCdhash !== record.cdhash) throw fail();
  const temp = mkdtempSync(join(tmpdir(), 'slg-helper-public-certificate-'));
  try {
    const prefix = join(temp, 'certificate-');
    run('/usr/bin/codesign', ['--display', `--extract-certificates=${prefix}`, bundle]);
    if (!existsSync(`${prefix}0`) || existsSync(`${prefix}1`)) throw fail();
    const certificate = certificateInfo(readFileSync(`${prefix}0`), record.signerCertificateSha256);
    const requirement = `identifier "${identifier}" and certificate leaf = H"${certificate.certificateSha1}"`;
    run('/usr/bin/codesign', ['--verify', '--strict', '-R', `=${requirement}`, bundle]);
  } finally { rmSync(temp, { recursive: true, force: true }); }
  return { signatureVerified: true, identifier, certificateSha256: record.signerCertificateSha256,
    cdhash: record.cdhash, architecture: arch, helperVersion: version, joinExistingSession: true };
}

function ensurePrivateDirectory(path) {
  if (!existsSync(path)) mkdirSync(path, { mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() ||
      (stat.mode & 0o077) !== 0) throw fail();
}

function pathPresent(path) {
  try { lstatSync(path); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

function extractPinnedArchive(archive, destination) {
  const result = spawnSync('/usr/bin/ditto', ['-x', '-k', archive, destination], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    env: cleanSigningEnvironment(process.env), timeout: 60_000, maxBuffer: 1024 * 1024,
  });
  if (result.error || result.signal || result.status !== 0) throw fail();
}

// Test injection is confined to this library entrypoint; the CLI below always
// loads the pinned approval file and performs real read-only signature checks.
export function stageFrozenHelper({ target, archive, extractedBundle, platform = process.platform,
  approval = loadPinnedApproval(), inspect = inspectSignedHelper, output = stageRoot } = {}) {
  if (platform !== 'darwin' || !isAbsolute(archive ?? '') || !isAbsolute(extractedBundle ?? '') ||
      basename(extractedBundle) !== 'credential-helper.xpc') throw fail();
  const record = approvedArchiveRecord(approval, target);
  if (sha256(readFileSync(clientCoreManifestPath)) !== CLIENT_CORE_MANIFEST_SHA256) throw fail();
  const archiveStat = lstatSync(archive);
  if (!archiveStat.isFile() || archiveStat.isSymbolicLink() || archiveStat.nlink !== 1 ||
      archiveStat.size < 1 || archiveStat.size > 128 * 1024 * 1024 ||
      sha256(readFileSync(archive)) !== record.archiveSha256) throw fail();
  if (helperTreeDigest(extractedBundle) !== record.treeSha256 ||
      sha256(readFileSync(join(extractedBundle, 'Contents', 'Info.plist'))) !== REVIEWED_HELPER_INFO_SHA256) throw fail();
  const identity = inspect(extractedBundle, record);
  if (identity?.signatureVerified !== true || identity.identifier !== approval.helperBundleIdentifier ||
      identity.certificateSha256 !== record.signerCertificateSha256 || identity.cdhash !== record.cdhash ||
      identity.architecture !== record.architecture || identity.helperVersion !== record.helperVersion ||
      identity.joinExistingSession !== true) throw fail();
  ensurePrivateDirectory(dirname(output));
  ensurePrivateDirectory(output);
  const destination = join(output, 'credential-helper.xpc');
  if (pathPresent(destination)) throw fail();
  const incoming = mkdtempSync(join(output, '.incoming-'));
  try {
    const copy = join(incoming, 'credential-helper.xpc');
    cpSync(extractedBundle, copy, { recursive: true, errorOnExist: true, force: false });
    if (helperTreeDigest(copy) !== record.treeSha256) throw fail();
    renameSync(copy, destination);
    if (helperTreeDigest(destination) !== record.treeSha256) throw fail();
  } catch {
    // If publication succeeded, retain the exact failed stage for inspection;
    // no automatic overwrite or retry can silently replace it.
    throw fail();
  } finally { rmSync(incoming, { recursive: true, force: true }); }
  return { staged: true, target, archiveSha256: record.archiveSha256,
    treeSha256: record.treeSha256, signerCertificateSha256: record.signerCertificateSha256,
    cdhash: record.cdhash, helperSourceManifestSha256: record.helperSourceManifestSha256,
    helperVersion: record.helperVersion };
}

// The production CLI has no path argument: its only input is the exact target
// archive committed alongside the pinned approval. Tests inject inert archives
// and an extractor; the CLI always uses macOS ditto and real identity checks.
export function stageCheckedInFrozenHelper({ target, platform = process.platform,
  approval = loadPinnedApproval(), archiveRoot = checkedInArchiveRoot, output = stageRoot,
  extract = extractPinnedArchive, inspect = inspectSignedHelper } = {}) {
  const record = approvedArchiveRecord(approval, target);
  if (platform !== 'darwin' || !isAbsolute(archiveRoot) || !isAbsolute(output)) throw fail();
  if (sha256(readFileSync(clientCoreManifestPath)) !== CLIENT_CORE_MANIFEST_SHA256) throw fail();
  const rootStat = lstatSync(archiveRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw fail();
  const archive = join(archiveRoot, `${target}.zip`);
  const stat = lstatSync(archive);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
      stat.size < 1 || stat.size > 128 * 1024 * 1024) throw fail();
  const archiveBytes = readFileSync(archive);
  if (archiveBytes.length !== stat.size || sha256(archiveBytes) !== record.archiveSha256) throw fail();
  ensurePrivateDirectory(dirname(output));
  ensurePrivateDirectory(output);
  if (pathPresent(join(output, 'credential-helper.xpc'))) throw fail();
  const work = mkdtempSync(join(output, '.archive-extract-'));
  try {
    // Extract the hashed bytes, never a path that can change after validation.
    const safeArchive = join(work, 'approved.zip');
    writeFileSync(safeArchive, archiveBytes, { flag: 'wx', mode: 0o600 });
    const extracted = join(work, 'extracted');
    mkdirSync(extracted, { mode: 0o700 });
    extract(safeArchive, extracted);
    ensurePrivateDirectory(extracted);
    const entries = readdirSync(extracted);
    if (entries.length !== 1 || entries[0] !== 'credential-helper.xpc' ||
        readdirSync(work).sort().join(',') !== 'approved.zip,extracted') throw fail();
    const bundle = join(extracted, 'credential-helper.xpc');
    const bundleStat = lstatSync(bundle);
    if (!bundleStat.isDirectory() || bundleStat.isSymbolicLink() ||
        helperTreeDigest(bundle) !== record.treeSha256) throw fail();
    return stageFrozenHelper({ target, archive: safeArchive, extractedBundle: bundle,
      platform, approval, inspect, output });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) throw fail();
    console.log(JSON.stringify(stageCheckedInFrozenHelper({ target: process.argv[2] })));
  } catch {
    console.error(JSON.stringify({ ok: false, stage: 'frozen-helper-stage' }));
    process.exitCode = 1;
  }
}

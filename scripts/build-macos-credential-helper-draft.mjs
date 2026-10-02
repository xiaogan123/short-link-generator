import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireMacOS11BuildVersion } from './macos-build-version.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const sourceRoot = resolve(scriptDir, '../src-tauri/native/credential-core');
const outputRoot = resolve(scriptDir, '../src-tauri/target/credential-helper-unlaunched');
const REVIEWED_MANIFEST_SHA256 = 'b26d8a06b948cc0d240a062b90f3ca274d3c10a87030e7a2f2efb4e7579d0443';
const SOURCE_FILES = [
  'identity.c', 'policy.c', 'entitlements.c', 'credential_policy.c',
  'credential_protocol.c', 'xpc_credential.c', 'credential_native.c', 'helper.c',
  'credential_location.c', 'operation_guard.c',
];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => new Error('Unlaunched credential helper draft build failed.');

export function verifyReviewedCore(root = sourceRoot) {
  const manifest = readFileSync(join(root, 'SOURCE-MANIFEST.sha256'));
  if (sha256(manifest) !== REVIEWED_MANIFEST_SHA256) throw fail();
  const listed = new Set();
  for (const line of manifest.toString('utf8').trimEnd().split('\n')) {
    const match = /^([a-f0-9]{64})  (helper-Info\.plist|src\/[^/]+)$/.exec(line);
    if (!match || listed.has(match[2])) throw fail();
    listed.add(match[2]);
    const path = join(root, match[2]);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || sha256(readFileSync(path)) !== match[1]) throw fail();
  }
  const observed = new Set(['helper-Info.plist', ...readdirSync(join(root, 'src')).map(name => `src/${name}`)]);
  if (listed.size !== observed.size || [...listed].some(name => !observed.has(name))) throw fail();
  return REVIEWED_MANIFEST_SHA256;
}

export function helperCompileArgs(root, binary, arch) {
  if (!['arm64', 'x86_64'].includes(arch)) throw fail();
  return ['--sdk', 'macosx', 'clang', '-std=c11', '-g0', '-fblocks', '-Wall', '-Wextra', '-Werror',
    '-Wpedantic', '-Wno-deprecated-declarations', '-mmacosx-version-min=11.0',
    '-arch', arch, '-I', join(root, 'src'),
    ...SOURCE_FILES.map(name => join(root, 'src', name)),
    '-framework', 'Security', '-framework', 'CoreFoundation', '-o', binary];
}

export function buildUnlaunchedHelper({ platform = process.platform, arch = process.arch,
  core = sourceRoot, output = outputRoot, run = execFileSync } = {}) {
  if (platform !== 'darwin' || !['arm64', 'x64'].includes(arch)) throw fail();
  verifyReviewedCore(core);
  const clangArch = arch === 'arm64' ? 'arm64' : 'x86_64';
  const target = arch === 'arm64' ? 'aarch64-apple-darwin' : 'x86_64-apple-darwin';
  mkdirSync(output, { recursive: true, mode: 0o700 });
  const work = mkdtempSync(join(output, `${target}-`));
  const contents = join(work, 'credential-helper.xpc', 'Contents');
  const binary = join(contents, 'MacOS', 'credential-helper');
  const env = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' };
  try {
    mkdirSync(join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
    copyFileSync(join(core, 'helper-Info.plist'), join(contents, 'Info.plist'));
    run('/usr/bin/xcrun', helperCompileArgs(core, binary, clangArch),
      { env, stdio: 'pipe', timeout: 120_000, maxBuffer: 1024 * 1024 });
    const builtArch = run('/usr/bin/xcrun', ['lipo', '-archs', binary],
      { env, stdio: 'pipe', encoding: 'utf8', timeout: 10_000 }).trim();
    const loadCommands = run('/usr/bin/xcrun', ['otool', '-l', binary],
      { env, stdio: 'pipe', encoding: 'utf8', timeout: 10_000 });
    if (builtArch !== clangArch) throw fail();
    requireMacOS11BuildVersion(loadCommands);
    run('/usr/bin/plutil', ['-lint', join(contents, 'Info.plist')],
      { env, stdio: 'pipe', timeout: 10_000 });
    return { unsigned: true, unlaunched: true, target,
      coreManifestSha256: REVIEWED_MANIFEST_SHA256,
      helperBinarySha256: sha256(readFileSync(binary)),
      helperInfoSha256: sha256(readFileSync(join(contents, 'Info.plist'))) };
  } catch {
    rmSync(work, { recursive: true, force: true });
    throw fail();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw fail();
    console.log(JSON.stringify(buildUnlaunchedHelper()));
  } catch {
    console.error(JSON.stringify({ ok: false, stage: 'unlaunched-helper-build' }));
    process.exitCode = 1;
  }
}

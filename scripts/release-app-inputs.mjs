import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const requiredInputs = new Set([
  'index.html', 'package.json', 'package-lock.json', 'vite.config.ts', 'tsconfig.json',
  'LICENSE', 'THIRD-PARTY-NOTICES.md',
]);
const releaseOnlyFiles = new Set([
  'AGENTS.md', 'README.md', 'design-qa.md', 'release-config.json',
  'release-assets.json', 'latest.json', 'SHA256SUMS', 'tsconfig.tsbuildinfo',
  'scripts/artifact-check.mjs', 'scripts/native-smoke.mjs', 'scripts/publish-draft.mjs',
  'scripts/release-app-inputs.mjs', 'scripts/release-config.mjs',
  'scripts/release-manifest.mjs', 'scripts/release-selective.test.mjs',
  'scripts/release-secret-material.mjs', 'scripts/release-secret-material.test.mjs',
  'scripts/updater-signature.mjs', 'scripts/updater-signature.test.mjs',
  'scripts/macos-updater-owner-normalize.mjs', 'scripts/macos-updater-owner-normalize.test.mjs',
  'scripts/stable-macos-sign.mjs', 'scripts/stable-macos-sign.test.mjs',
  'scripts/macos-dmg-owner-stage.mjs', 'scripts/macos-dmg-owner-stage.test.mjs',
  'scripts/normalize-macos-dmg-owners.py', 'tests/test_normalize_macos_dmg_owners.py',
  'scripts/release.test.mjs',
]);
const releaseOnlyPrefixes = [
  '.github/', '.githooks/', 'docs/', 'probe/',
  'node_modules/', 'dist/', 'target/', 'coverage/', 'src-tauri/target/',
  'candidates/', 'release-assets/',
];
export const isAppInput = path => !releaseOnlyFiles.has(path) &&
  !releaseOnlyPrefixes.some(prefix => path.startsWith(prefix));
const git = (args, cwd) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 8 * 1024 * 1024 });

export function appInputManifest(sha, cwd = '.') {
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error('Application input commit must be a full SHA.');
  if (git(['rev-parse', '--verify', `${sha}^{commit}`], cwd).trim() !== sha) throw new Error('Application input commit is unavailable.');
  const tree = execFileSync('git', ['ls-tree', '-rz', '--full-tree', sha], { cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  const entries = tree.split('\0').filter(Boolean).map(record => {
    const match = /^(\d{6}) (blob) ([0-9a-f]{40})\t(.+)$/.exec(record);
    if (!match) throw new Error('Unexpected Git tree entry.');
    return { mode: match[1], object: match[3], path: match[4] };
  }).filter(entry => isAppInput(entry.path)).sort((a, b) => a.path.localeCompare(b.path, 'en'));
  for (const required of requiredInputs) {
    if (!entries.some(entry => entry.path === required)) throw new Error(`Missing required application input: ${required}`);
  }
  if (!entries.some(entry => entry.path.startsWith('src/')) ||
      !entries.some(entry => entry.path.startsWith('src-tauri/')) ||
      !entries.some(entry => entry.path === 'edge/worker.mjs')) {
    throw new Error('Application input tree is incomplete.');
  }
  const serialized = entries.map(entry => `${entry.mode} ${entry.object}\t${entry.path}\n`).join('');
  return { sha256: createHash('sha256').update(serialized).digest('hex'), fileCount: entries.length, paths: entries.map(entry => entry.path) };
}

export function assertCleanAppInputs(cwd = '.') {
  if (readdirSync(cwd).some(name => /^\.env(?:\.|$)/.test(name))) {
    throw new Error('Local Vite environment files prevent application input equivalence.');
  }
  const dirty = git(['status', '--porcelain=v1', '-z', '--untracked-files=all'], cwd).split('\0').filter(Boolean);
  for (let index = 0; index < dirty.length; index++) {
    const record = dirty[index];
    if (isAppInput(record.slice(3))) throw new Error('Application inputs contain tracked or untracked local changes.');
    if (/[RC]/.test(record.slice(0, 2)) && isAppInput(dirty[++index] ?? '')) {
      throw new Error('Application inputs contain renamed local changes.');
    }
  }
  const ignored = git(['ls-files', '--others', '--ignored', '--exclude-standard', '--directory', '-z'], cwd);
  if (ignored.split('\0').filter(Boolean).some(path => isAppInput(path))) {
    throw new Error('Ignored files inside application inputs prevent local build reuse.');
  }
}

export function matchingAppInputs(buildSha, reviewedSha, cwd = '.') {
  assertCleanAppInputs(cwd);
  const built = appInputManifest(buildSha, cwd);
  const reviewed = appInputManifest(reviewedSha, cwd);
  if (built.sha256 !== reviewed.sha256 || built.fileCount !== reviewed.fileCount) {
    throw new Error('Application inputs changed between the local build and reviewed release.');
  }
  return { sha256: reviewed.sha256, fileCount: reviewed.fileCount };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [buildSha, reviewedSha] = process.argv.slice(2);
  try {
    console.log(JSON.stringify(matchingAppInputs(buildSha, reviewedSha), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

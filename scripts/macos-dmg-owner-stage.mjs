import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync,
  renameSync, rmSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { certificateInfo } from './macos-signature.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'normalize-macos-dmg-owners.py');
const TARGETS = new Set(['aarch64-apple-darwin', 'x86_64-apple-darwin']);
const fail = () => new Error('macOS DMG owner normalization failed; candidate is not approved.');
const sha = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

function regular(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.nlink !== 1) throw fail();
  return stat;
}

function evidenceMatches(receipt, input, output) {
  const tree = receipt?.sourceTree;
  if (!receipt || !hex(receipt.inputDmgSha256) || !hex(receipt.outputDmgSha256) ||
      !hex(receipt.inputRawSha256) || !hex(receipt.normalizedRawSha256) ||
      receipt.inputDmgSha256 !== sha(input) || receipt.outputDmgSha256 !== sha(output) ||
      !Number.isInteger(receipt.catalogObjects) || receipt.catalogObjects < 1 ||
      !Number.isInteger(receipt.noncanonicalObjectsBefore) || receipt.noncanonicalObjectsBefore < 0 ||
      receipt.noncanonicalObjectsBefore > receipt.catalogObjects ||
      receipt.allOwnersZeroAfter !== true || receipt.onlyCatalogOwnerGroupFieldsChanged !== true ||
      receipt.allFileForksPreserved !== true ||
      receipt.roundtripRawExact !== true || receipt.hdiutilVerified !== true || receipt.outputSigned !== false ||
      !tree || !Number.isInteger(tree.entries) || tree.entries < 1 ||
      !Number.isInteger(tree.files) || tree.files < 1 || tree.files > tree.entries ||
      !Number.isInteger(tree.links) || tree.links < 0 || tree.links > tree.entries ||
      !hex(tree.manifestSha256)) throw fail();
  return { catalogObjects: receipt.catalogObjects, noncanonicalObjectsBefore: receipt.noncanonicalObjectsBefore,
    sourceTreeSha256: tree.manifestSha256 };
}

async function pinnedDmgSignature(dmg, certPin, prefix, run, env) {
  await run('/usr/bin/codesign', ['--verify', '--strict', dmg], { env, timeout: 60_000 });
  await run('/usr/bin/codesign', ['--display', `--extract-certificates=${prefix}`, dmg], { env, timeout: 60_000 });
  if (!existsSync(`${prefix}0`) || existsSync(`${prefix}1`)) throw fail();
  certificateInfo(readFileSync(`${prefix}0`), certPin);
}

// This stage runs only inside withStableSigning's live, pinned P12 context.
// The only new codesign target is a fresh DMG; it never targets the app/helper.
export async function normalizeOptionalMacDmg({ bundle, app, target, certificateSha1, certificateSha256,
  shim, run, env, script = SCRIPT, verifySignature = pinnedDmgSignature }) {
  const directory = join(bundle, 'dmg');
  let directoryStat;
  try { directoryStat = lstatSync(directory); }
  catch (error) { if (error.code === 'ENOENT') return { present: false }; throw fail(); }
  if (!directoryStat.isDirectory()) throw fail();
  const names = readdirSync(directory);
  const images = names.filter(name => name.endsWith('.dmg'));
  if (!images.length) return { present: false };
  if (!TARGETS.has(target) || images.length !== 1 ||
      names.some(name => name.startsWith('.owner-normalize-')) ||
      !/^[a-f0-9]{40}$/.test(certificateSha1 ?? '') || !hex(certificateSha256) ||
      !lstatSync(app).isDirectory() || typeof run !== 'function') throw fail();
  const original = join(directory, images[0]);
  regular(original);
  regular(script);
  const temporary = mkdtempSync(join(directory, '.owner-normalize-'));
  chmodSync(temporary, 0o700);
  const staged = join(temporary, 'normalized.dmg');
  const evidencePath = join(temporary, 'owner-evidence.json');
  const previous = join(temporary, 'previous.dmg');
  let movedOriginal = false;
  let movedNew = false;
  let mayClean = true;
  try {
    await verifySignature(original, certificateSha256, join(temporary, 'before-cert-'), run, env);
    await run('/usr/bin/python3', ['-I', '-S', '-B', script, original, staged, app, '--evidence', evidencePath],
      { env, timeout: 300_000 });
    regular(staged);
    regular(evidencePath);
    const facts = evidenceMatches(JSON.parse(readFileSync(evidencePath, 'utf8')), original, staged);
    await run(shim, ['--force', '-s', certificateSha1, staged], { env, timeout: 120_000 });
    await verifySignature(staged, certificateSha256, join(temporary, 'after-cert-'), run, env);
    renameSync(original, previous); movedOriginal = true;
    renameSync(staged, original); movedNew = true;
    await verifySignature(original, certificateSha256, join(temporary, 'final-cert-'), run, env);
    return { present: true, ...facts, dmgSha256: sha(original), name: basename(original) };
  } catch {
    try {
      if (movedNew && existsSync(original)) rmSync(original);
      if (movedOriginal) renameSync(previous, original);
    } catch { mayClean = false; }
    throw fail();
  } finally {
    if (mayClean) rmSync(temporary, { recursive: true, force: false });
  }
}

import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync, lstatSync, openSync, readSync, closeSync } from 'node:fs';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { MAC_IDENTIFIER } from './macos-signature.mjs';
import { verifyRcodesignTool } from './rcodesign-tool.mjs';

// Return fixed labels only. Native output may contain local paths, signer names,
// or other sensitive context and must never be copied into diagnostics.
export function classifyCodesignError(error) {
  const output = [error?.stderr, error?.stdout].map(value =>
    typeof value === 'string' || Buffer.isBuffer(value) ? value.toString().slice(0, 65_536) : '').join('\n');
  const categories = new Set();
  const osStatuses = [];
  for (const [pattern, category] of [
    [/unable to build chain to self-signed root|CSSMERR_TP_NOT_TRUSTED/i, 'chain-untrusted'],
    [/no identity found|specified item could not be found in the keychain|identity.*not found/i, 'identity-not-found'],
    [/user interaction is not allowed/i, 'interaction-not-allowed'],
    [/resource fork|Finder information|bundle format.*(?:invalid|unrecognized)/i, 'bundle-format'],
  ]) if (pattern.test(output)) categories.add(category);
  for (const [symbol, code, category] of [
    ['errSecInternalComponent', -2070, 'internal-security-error'],
    ['errSecInteractionNotAllowed', -25308, 'interaction-not-allowed'],
    ['errSecAuthFailed', -25293, 'authorization-failed'],
    ['errSecItemNotFound', -25300, 'identity-not-found'],
    ['errSecNotAvailable', -25291, 'keychain-unavailable'],
    ['errSecDecode', -26275, 'material-decode-error'],
  ]) {
    if (new RegExp(`\\b${symbol}\\b|(?:^|[^\\d])${code}(?!\\d)`).test(output)) {
      categories.add(category); osStatuses.push({ symbol, code });
    }
  }
  if (!categories.size) categories.add('unclassified-native-error');
  return { categories: [...categories], osStatuses };
}

export function signingToolEnvironment(env = {}) {
  return { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: env.HOME || homedir(), TMPDIR: env.TMPDIR || tmpdir(), LANG: 'C', LC_ALL: 'C' };
}
const contained = (path, root) => path.startsWith(`${root}${sep}`);
const inputFailure = () => new Error('Invalid isolated signing input.');
function fileMagic(path) {
  const descriptor = openSync(path, 'r'); const header = Buffer.alloc(4);
  try { return readSync(descriptor, header, 0, 4, 0) === 4 ? header.toString('hex') : ''; }
  finally { closeSync(descriptor); }
}

export function readSigningContext(path) {
  if (!isAbsolute(path ?? '')) throw inputFailure();
  const st = lstatSync(path); const root = realpathSync(dirname(path)); const parent = lstatSync(root);
  if (!st.isFile() || st.isSymbolicLink() || st.size > 65_536 || (st.mode & 0o077) ||
      st.uid !== process.getuid() || !parent.isDirectory() || (parent.mode & 0o077) || parent.uid !== process.getuid()) throw inputFailure();
  const context = JSON.parse(readFileSync(path, 'utf8'));
  if (context.schema !== 1 || realpathSync(context.materialRoot) !== root ||
      !/^[a-f0-9]{40}$/.test(context.certificateSha1 ?? '') || !/^[a-f0-9]{64}$/.test(context.certificateSha256 ?? '') ||
      !Array.isArray(context.entitlementsRoots) || !context.entitlementsRoots.length) throw inputFailure();
  for (const name of ['p12Path', 'passwordPath', 'requirementPath']) {
    const file = context[name]; const fileStat = lstatSync(file);
    if (!isAbsolute(file) || !contained(realpathSync(file), root) || !fileStat.isFile() || fileStat.isSymbolicLink() ||
        fileStat.uid !== process.getuid() || (fileStat.mode & 0o077) || fileStat.size < 1 || fileStat.size > 2 * 1024 * 1024) throw inputFailure();
  }
  for (const name of ['home', 'temp']) {
    const value = realpathSync(context[name]); const stat = lstatSync(value);
    if (!contained(value, root) || !stat.isDirectory() || (stat.mode & 0o077) || stat.uid !== process.getuid()) throw inputFailure();
  }
  return context;
}

export function signingArguments(args, context, { readIdentifier = app => execFileSync('/usr/libexec/PlistBuddy',
  ['-c', 'Print :CFBundleIdentifier', resolve(app, 'Contents/Info.plist')], {
    env: signingToolEnvironment(), encoding: 'utf8', stdio: 'pipe', timeout: 10_000, killSignal: 'SIGKILL',
  }).trim() } = {}) {
  const seen = new Set(); let identity, target, runtime = false, entitlements;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (['--force', '-s', '--options', '--entitlements'].includes(arg)) {
      if (seen.has(arg)) throw inputFailure(); seen.add(arg);
      if (arg === '--force') continue;
      const value = args[++i];
      if (!value || value.startsWith('-')) throw inputFailure();
      if (arg === '-s') identity = value;
      else if (arg === '--options') { if (value !== 'runtime') throw inputFailure(); runtime = true; }
      else entitlements = value;
    } else if (!arg.startsWith('-') && i === args.length - 1 && !target) target = arg;
    else throw inputFailure();
  }
  if (!seen.has('--force') || identity !== context.certificateSha1 || !target) throw inputFailure();
  const actual = realpathSync(target); const allowed = realpathSync(context.outputRoot); const stat = lstatSync(target);
  if (!contained(actual, allowed) || stat.isSymbolicLink()) throw inputFailure();
  const bundle = stat.isDirectory() && (actual.endsWith('.app') || actual.endsWith('.framework'));
  const dmg = stat.isFile() && actual.endsWith('.dmg');
  const magic = stat.isFile() && !dmg ? fileMagic(actual) : '';
  if (!bundle && !dmg && !['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'].includes(magic)) throw inputFailure();
  const result = ['--config-file', '/dev/null', 'sign', '--timestamp-url', 'none', '--digest', 'sha256', '--shallow',
    '--p12-file', context.p12Path, '--p12-password-file', context.passwordPath];
  // In 0.29.0, shallow alone still re-signs Mach-O files matching nested resource
  // rules. Exclusions preserve their signatures while the parent seals them.
  if (bundle) result.push('--exclude', '**');
  if (runtime) result.push('--code-signature-flags', 'runtime');
  if (entitlements) {
    const path = realpathSync(entitlements); const entStat = lstatSync(entitlements);
    if (!entStat.isFile() || entStat.isSymbolicLink() || entStat.size > 1024 * 1024 ||
        !context.entitlementsRoots.some(root => contained(path, realpathSync(root)))) throw inputFailure();
    result.push('--entitlements-xml-file', path);
  }
  if (actual.endsWith('.app')) {
    if (readIdentifier(actual) !== MAC_IDENTIFIER) throw inputFailure();
    result.push('--binary-identifier', MAC_IDENTIFIER, '--code-requirements-file', context.requirementPath);
  }
  return [...result, actual];
}

export async function executeSigning(args, context, { verifyTool = verifyRcodesignTool,
  run = (cmd, argv, options) => execFileSync(cmd, argv, { ...options, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000,
    killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024 }) } = {}) {
  const env = signingToolEnvironment({ HOME: context.home, TMPDIR: context.temp });
  let stage = 'signing-input';
  try {
    const argv = signingArguments(args, context);
    if ((await run('/bin/sh', ['-c', 'ulimit -S -c; ulimit -H -c'], { env })).toString().trim() !== '0\n0') throw inputFailure();
    stage = 'signer-tool';
    const tool = await verifyTool(context.tool.path, { run: (cmd, argv, options) => run(cmd, argv, { ...options, env }) });
    if (tool.sha256 !== context.tool.sha256 || tool.arch !== context.tool.arch || tool.version !== context.tool.version) throw inputFailure();
    stage = 'rcodesign';
    await run('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)(deny network*)', tool.path, ...argv], { env });
  } catch (error) {
    const safe = Object.assign(new Error('Isolated signing adapter failed.'), { stage });
    if (stage === 'rcodesign') safe.diagnostic = classifyCodesignError(error);
    throw safe;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let context;
  try { context = readSigningContext(process.env.SLG_PRIVATE_SIGNING_CONTEXT); }
  catch { console.error(JSON.stringify({ ok: false, stage: 'signing-input' })); process.exitCode = 1; }
  if (context) executeSigning(process.argv.slice(2), context).catch(error => {
    console.error(JSON.stringify({ ok: false, stage: error.stage ?? 'signing-input', ...(error.diagnostic ?? {}) }));
    process.exitCode = 1;
  });
}

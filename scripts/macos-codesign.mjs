import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanSigningEnvironment, MAC_IDENTIFIER, stableRequirement } from './macos-signature.mjs';

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

export function signingArguments(args, context) {
  // Tauri 2.12 passes only these options. Unknown options must not override our identity or DR.
  const forwarded = [];
  let identity;
  let target;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--force') forwarded.push(arg);
    else if (arg === '-s') identity = args[++i];
    else if (arg === '--options' && args[i + 1] === 'runtime') { forwarded.push(arg, args[++i]); }
    else if (arg === '--entitlements' && args[i + 1]) { forwarded.push(arg, args[++i]); }
    else if (!arg.startsWith('-') && i === args.length - 1) target = arg;
    else throw new Error('Unexpected native signing option.');
  }
  if (identity !== context.certificateSha1 || !target) throw new Error('Unexpected native signing identity.');
  const actual = realpathSync(target);
  const allowed = realpathSync(context.outputRoot);
  if (!actual.startsWith(`${allowed}${sep}`)) throw new Error('Signing target is outside the build output.');
  const result = [...forwarded, '-s', identity, '--keychain', context.keychain, '--timestamp=none'];
  if (target.endsWith('.app')) {
    const identifier = execFileSync('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleIdentifier', resolve(target, 'Contents/Info.plist')], {
      env: cleanSigningEnvironment(process.env), encoding: 'utf8', stdio: 'pipe',
    }).trim();
    if (identifier !== MAC_IDENTIFIER) throw new Error('Unexpected application identifier.');
    result.push('--identifier', MAC_IDENTIFIER, '--requirements', `=designated => ${stableRequirement(identity)}`);
  }
  return [...result, target];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let stage = 'signing-input';
  try {
    const context = JSON.parse(readFileSync(process.env.SLG_PRIVATE_SIGNING_CONTEXT, 'utf8'));
    const args = signingArguments(process.argv.slice(2), context);
    stage = 'native-codesign';
    execFileSync('/usr/bin/codesign', args, { env: cleanSigningEnvironment(process.env), stdio: 'pipe', timeout: 120_000 });
  } catch (error) {
    console.error(JSON.stringify({ ok: false, stage,
      ...(stage === 'native-codesign' ? classifyCodesignError(error) : {}) }));
    process.exitCode = 1;
  }
}

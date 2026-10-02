import { lstatSync, opendirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const MAX_NODES = 512;
const invalid = () => new Error('Credential helper has unsupported extended attributes or bundle entries.');

// Pure inventory shared by synchronous staging and the asynchronous signing
// recipe. The caller lists xattr *names* once per returned path; no values.
export function helperAttributePaths(bundle) {
  if (typeof bundle !== 'string' || basename(bundle) !== 'credential-helper.xpc') throw invalid();
  const paths = [];
  function visit(path) {
    if (paths.length >= MAX_NODES) throw invalid();
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || (stat.mode & 0o7000) ||
        (!stat.isDirectory() && !stat.isFile()) ||
        (stat.isFile() && (stat.nlink !== 1 || stat.size > 128 * 1024 * 1024))) throw invalid();
    paths.push(path);
    if (stat.isDirectory()) {
      const names = [];
      const directory = opendirSync(path);
      try {
        for (let entry = directory.readSync(); entry; entry = directory.readSync()) {
          if (names.length + paths.length >= MAX_NODES || entry.name === '.' ||
              entry.name === '..' || /[\\/\x00-\x1f\x7f]/.test(entry.name)) throw invalid();
          names.push(entry.name);
        }
      } finally { directory.closeSync(); }
      for (const name of names.sort()) {
        visit(join(path, name));
      }
    }
  }
  visit(resolve(bundle));
  return paths;
}

// `/usr/bin/xattr <path>` emits one name per line. Never use `-l` or read EA
// contents; macOS-managed provenance may persist even after xattr -d succeeds.
export function assertAllowedHelperAttributeNames(output) {
  if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > 4096 ||
      /[\x00-\x09\x0b-\x1f\x7f]/.test(output)) throw invalid();
  if (output === '') return false;
  if (!output.endsWith('\n')) throw invalid();
  const names = output.slice(0, -1).split('\n');
  if (names.length !== 1 || names[0] !== 'com.apple.provenance') throw invalid();
  return true;
}

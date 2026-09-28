#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, lstatSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const builtins = [
  ['home-directory', /(?:\/Users\/|\/home\/)[a-zA-Z0-9][^\s/"'<>]+\//g],
  ['windows-home', /[A-Z]:\\Users\\[^\\\s"']+\\/gi],
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ['cloud-credential', /(?:Bearer\s+)[A-Za-z0-9_-]{32,}/g],
  ['environment-secret', /(?:CLOUDFLARE_API_TOKEN|SELFTEST_KEY)\s*=\s*["']?[A-Za-z0-9_-]{32,}/g],
];
export function inspect(data, words = []) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const texts = [buf.toString('utf8'), buf.toString('utf16le')];
  const hits = new Set();
  for (const source of texts) {
    for (const [label, pattern] of builtins) { pattern.lastIndex = 0; if (pattern.test(source)) hits.add(label); }
    const lower = source.toLocaleLowerCase('en-US');
    words.forEach((word, index) => { if (lower.includes(word.toLocaleLowerCase('en-US'))) hits.add(`private-term-${index + 1}`); });
  }
  return [...hits];
}
export function loadWords(path, required = true) {
  if (!existsSync(path)) { if (required) throw new Error('Private denylist is missing. Create it outside the repository before pushing.'); return []; }
  const words = readFileSync(path, 'utf8').split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith('#'));
  if (required && words.length === 0) throw new Error('Private denylist is empty. Fill it outside the repository before pushing.');
  return words;
}
function git(args, cwd, encoding = 'utf8') {
  const r = spawnSync('git', args, { cwd, encoding, maxBuffer: 256 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`Git inspection failed (${args[0]}). No push was approved.`);
  return r.stdout;
}
export function scanRepository({ cwd = process.cwd(), words = [], refs = [], workingTree = false, checkIdentity = false }) {
  const failures = []; let files = 0; let commits = 0;
  const check = (label, buffer) => { const hits = inspect(buffer, words); if (hits.length) failures.push({ location: label, rules: hits }); };
  if (workingTree) {
    const paths = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd).split('\0').filter(Boolean);
    for (const path of new Set(paths)) {
      check('filename', path);
      // readFile follows symlinks; inspect the link itself instead, never external data.
      const absolute = resolve(cwd, path);
      try { if (lstatSync(absolute).isSymbolicLink()) { failures.push({location:'symlink',rules:['symlink-review-required']}); continue; } } catch { continue; }
      if (!existsSync(absolute)) continue;
      check(`file #${++files}`, readFileSync(absolute));
    }
  }
  const seenBlobs = new Set();
  if (refs.length) {
    const revisions = git(['rev-list', ...refs], cwd).trim().split('\n').filter(Boolean);
    const configured = spawnSync('git', ['config', 'user.email'], {cwd,encoding:'utf8'});
    const expected = checkIdentity ? (configured.stdout?.trim() || (revisions.length ? git(['show','-s','--format=%ae',revisions[0]],cwd).trim() : '')) : '';
    if (checkIdentity && !/^\d+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$/.test(expected)) throw new Error('Configure a verified GitHub noreply commit identity first.');
    for (const revision of revisions) {
      commits++;
      const metadata = git(['show', '-s', '--format=%B%x00%an%x00%ae%x00%cn%x00%ce', revision], cwd);
      check(`commit ${revision.slice(0, 12)}`, metadata);
      if (checkIdentity) {
        const [,an,ae,cn,ce] = metadata.trimEnd().split('\0');
        if ([an,ae,cn,ce].some(v => v !== expected)) failures.push({location:`commit ${revision.slice(0,12)}`,rules:['commit-identity']});
      }
      const tree = git(['ls-tree', '-rz', '--full-tree', revision], cwd).split('\0').filter(Boolean);
      for (const entry of tree) {
        const tab = entry.indexOf('\t'); const [mode,type,hash] = entry.slice(0,tab).split(' '); const name = entry.slice(tab+1);
        check('history filename',name);
        if (mode === '160000') { failures.push({location:'submodule',rules:['submodule-review-required']}); continue; }
        if (type !== 'blob' || seenBlobs.has(hash)) continue;
        seenBlobs.add(hash); files++;
        check(`blob ${hash.slice(0,12)}`,git(['cat-file','blob',hash],cwd,null));
      }
    }
  }
  return {files,commits,failures};
}
export function main(args = process.argv.slice(2)) {
  try {
    const publicOnly = args.includes('--public');
    const words = loadWords(resolve(homedir(),'.config/short-link-generator/denylist.txt'),!publicOnly);
    const refs = [];
    if (args.includes('--pre-push')) {
      const input = readFileSync(0,'utf8');
      for (const line of input.trim().split('\n').filter(Boolean)) {
        const [,localSha] = line.trim().split(/\s+/);
        if (!/^[0-9a-f]{40,64}$/.test(localSha ?? '')) throw new Error('Invalid push input.');
        if (!/^0+$/.test(localSha)) refs.push(localSha);
      }
    } else if (args.includes('--history')) refs.push('--all');
    const result = scanRepository({words,refs,workingTree:args.includes('--working-tree'),checkIdentity:!publicOnly});
    console.log(JSON.stringify({...result,privateDenylist:publicOnly?'not-enforced':'enforced'},null,2));
    return result.failures.length ? 1 : 0;
  } catch (error) { console.error(error.message); return 2; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exitCode = main();

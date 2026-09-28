import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { inspect, loadWords, scanRepository } from './privacy-check.mjs';

test('private terms are case-insensitive and never echoed', () => {
  assert.deepEqual(inspect('alpha PRIVATE-EXAMPLE omega',['private-example']),['private-term-1']);
});
test('binary UTF-16 text is inspected', () => {
  assert.deepEqual(inspect(Buffer.from('Private-Example','utf16le'),['private-example']),['private-term-1']);
});
test('credential and home path detector', () => {
  assert.ok(inspect('Bearer ' + 'a'.repeat(40)).includes('cloud-credential'));
  assert.ok(inspect('/Us' + 'ers/' + 'person/file').includes('home-directory'));
  assert.deepEqual(inspect('https://example.com/go/read'),[]);
});
test('missing and empty private list fail closed', () => {
  const dir=mkdtempSync(join(tmpdir(),'privacy-fixture-')); try {
    const path=join(dir,'denylist'); assert.throws(()=>loadWords(path));
    writeFileSync(path,'# instructions\n'); assert.throws(()=>loadWords(path));
  } finally {rmSync(dir,{recursive:true,force:true});}
});
test('scans deleted historical blobs and commit messages', () => {
  const dir=mkdtempSync(join(tmpdir(),'privacy-fixture-'));
  const git=(...args)=>execFileSync('git',args,{cwd:dir,stdio:'pipe'});
  try {
    git('init','-q');git('config','user.name','Example');git('config','user.email','example@example.org');
    writeFileSync(join(dir,'file.txt'),'old private-example');git('add','.');git('commit','-qm','first');
    writeFileSync(join(dir,'file.txt'),'clean');git('add','.');git('commit','-qm','private-message');
    const scan=scanRepository({cwd:dir,words:['private-example','private-message'],refs:['HEAD']});
    assert.equal(scan.commits,2);assert.equal(scan.failures.length,2);
    assert.ok(scan.failures.some(x=>x.location.startsWith('blob')));
    assert.ok(scan.failures.some(x=>x.location.startsWith('commit')));
  } finally {rmSync(dir,{recursive:true,force:true});}
});

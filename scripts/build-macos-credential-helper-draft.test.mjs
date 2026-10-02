import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { buildUnlaunchedHelper, helperCompileArgs, verifyReviewedCore } from './build-macos-credential-helper-draft.mjs';
import { VALID_MACOS_11_LOAD_COMMANDS } from './test-fixtures/macos-build-version.mjs';

const reviewed = resolve(import.meta.dirname, '../src-tauri/native/credential-core');
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'helper-build-mock-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const core = join(root, 'core');
  cpSync(reviewed, core, { recursive: true });
  return { root, core, output: join(root, 'out') };
}

test('reviewed source manifest and fixed compiler flags are pinned', t => {
  const { core } = fixture(t);
  assert.equal(verifyReviewedCore(core), 'b26d8a06b948cc0d240a062b90f3ca274d3c10a87030e7a2f2efb4e7579d0443');
  const args = helperCompileArgs(core, '/tmp/inert-output', 'arm64');
  assert.ok(args.includes('-fblocks'));
  assert.ok(args.includes('-g0'));
  assert.ok(args.includes('-mmacosx-version-min=11.0'));
  assert.ok(args.includes('Security'));
  assert.ok(args.includes('CoreFoundation'));
  assert.equal(args.filter(arg => arg.endsWith('.c')).length, 10);
  assert.throws(() => helperCompileArgs(core, '/tmp/inert-output', 'i386'));
});

test('source tamper fails before any compiler invocation', t => {
  const { core, output } = fixture(t);
  writeFileSync(join(core, 'src', 'pins.h'), `${readFileSync(join(core, 'src', 'pins.h'))}\n`);
  let calls = 0;
  assert.throws(() => buildUnlaunchedHelper({ platform: 'darwin', arch: 'arm64', core, output,
    run: () => { calls++; } }));
  assert.equal(calls, 0);
});

test('pure command mock assembles an unlaunched bundle; wrong arch removes its output', t => {
  const { core, output } = fixture(t);
  const calls = [];
  const run = (_tool, args) => {
    calls.push(args);
    if (args.includes('clang')) {
      writeFileSync(args[args.indexOf('-o') + 1], Buffer.from([0xcf, 0xfa, 0xed, 0xfe]));
      return Buffer.alloc(0);
    }
    if (args[0] === 'lipo') return 'arm64\n';
    if (args[0] === 'otool') return VALID_MACOS_11_LOAD_COMMANDS;
    return Buffer.alloc(0);
  };
  const result = buildUnlaunchedHelper({ platform: 'darwin', arch: 'arm64', core, output, run });
  assert.equal(result.unsigned, true);
  assert.equal(result.unlaunched, true);
  assert.equal(result.target, 'aarch64-apple-darwin');
  assert.equal(calls.length, 4);
  assert.equal(readdirSync(output).length, 1);
  const failure = join(output, 'failure');
  assert.throws(() => buildUnlaunchedHelper({ platform: 'darwin', arch: 'arm64', core, output: failure,
    run: (_tool, args) => {
      if (args.includes('clang')) {
        writeFileSync(args[args.indexOf('-o') + 1], 'inert');
        return Buffer.alloc(0);
      }
      if (args[0] === 'lipo') return 'x86_64\n';
      return Buffer.alloc(0);
    } }));
  assert.deepEqual(readdirSync(failure), []);
});

test('real build caller stops before plist inspection on invalid build-version output', t => {
  const { core, root } = fixture(t);
  for (const [name, loadCommands] of [
    ['patch', VALID_MACOS_11_LOAD_COMMANDS.replace('minos 11.0\n', 'minos 11.0.1\n')],
    ['platform', VALID_MACOS_11_LOAD_COMMANDS.replace('platform 1\n', 'platform 2\n')],
    ['cross-block', VALID_MACOS_11_LOAD_COMMANDS.replace('minos 11.0\n', 'minos 10.15\n')
      .replace('cmdsize 72\n', 'cmdsize 72\n minos 11.0\n')],
  ]) {
    const output = join(root, name);
    const calls = [];
    assert.throws(() => buildUnlaunchedHelper({ platform: 'darwin', arch: 'arm64', core, output,
      run: (_tool, args) => {
        calls.push(args[0]);
        if (args.includes('clang')) {
          writeFileSync(args[args.indexOf('-o') + 1], Buffer.from([0xcf, 0xfa, 0xed, 0xfe]));
          return Buffer.alloc(0);
        }
        if (args[0] === 'lipo') return 'arm64\n';
        if (args[0] === 'otool') return loadCommands;
        throw new Error('unexpected command');
      } }));
    assert.deepEqual(calls, ['--sdk', 'lipo', 'otool'], name);
    assert.deepEqual(readdirSync(output), [], name);
  }
});

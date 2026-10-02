import test from 'node:test';
import assert from 'node:assert/strict';
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertAllowedHelperAttributeNames, helperAttributePaths } from './macos-helper-attributes.mjs';

function fixture(t) {
  const parent = mkdtempSync(join(tmpdir(), 'helper-attributes-mock-'));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const bundle = join(parent, 'credential-helper.xpc');
  mkdirSync(join(bundle, 'Contents', 'Resources', 'nested'), { recursive: true });
  writeFileSync(join(bundle, 'Contents', 'Resources', 'nested', 'inert.txt'), 'inert');
  return { parent, bundle };
}

test('only a single plain-line OS-managed provenance name is allowed', () => {
  assert.equal(assertAllowedHelperAttributeNames(''), false);
  assert.equal(assertAllowedHelperAttributeNames('com.apple.provenance\n'), true);
  for (const output of ['com.apple.provenance', 'com.apple.quarantine\n',
    'user.example\n', 'com.apple.provenance\ncom.apple.quarantine\n',
    'com.apple.provenance\ncom.apple.provenance\n', '\n',
    'com.apple.provenance\r\n', 'com.apple.provenance\tvalue\n',
    'com.apple.provenance\nvalue', null]) {
    assert.throws(() => assertAllowedHelperAttributeNames(output));
  }
});

test('inventory includes every nested file and directory without following links', t => {
  const { bundle } = fixture(t);
  const paths = helperAttributePaths(bundle);
  assert.equal(paths.length, 5);
  assert.ok(paths.some(path => path.endsWith('/nested/inert.txt')));
  assert.ok(paths.every(path => path.startsWith(bundle)));
  symlinkSync('/tmp', join(bundle, 'Contents', 'linked'));
  assert.throws(() => helperAttributePaths(bundle));
});

test('hard links, special entries and wrong bundle names fail closed', t => {
  const { parent, bundle } = fixture(t);
  const file = join(bundle, 'Contents', 'Resources', 'nested', 'inert.txt');
  linkSync(file, join(parent, 'alias.txt'));
  assert.throws(() => helperAttributePaths(bundle));
  assert.throws(() => helperAttributePaths(parent));
});

test('node inventory is bounded before any xattr invocation', t => {
  const { bundle } = fixture(t);
  const extra = join(bundle, 'Contents', 'Resources', 'many');
  mkdirSync(extra);
  for (let index = 0; index < 512; index++) {
    writeFileSync(join(extra, `item-${index}`), 'x');
  }
  assert.throws(() => helperAttributePaths(bundle));
});

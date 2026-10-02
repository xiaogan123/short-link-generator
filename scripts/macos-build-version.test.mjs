import test from 'node:test';
import assert from 'node:assert/strict';
import { requireMacOS11BuildVersion } from './macos-build-version.mjs';
import { VALID_MACOS_11_LOAD_COMMANDS as valid } from './test-fixtures/macos-build-version.mjs';

test('accepts one bounded macOS platform 1 LC_BUILD_VERSION with the full 11.0.0 tuple', () => {
  assert.deepEqual(requireMacOS11BuildVersion(valid),
    { platform: 'macos', minimumSystemVersion: '11.0.0' });
  assert.deepEqual(requireMacOS11BuildVersion(valid.replace('minos 11.0\n', 'minos 11.0.0\n')),
    { platform: 'macos', minimumSystemVersion: '11.0.0' });
});

test('rejects 11.0.1, foreign platform, duplicate, malformed and cross-command values', () => {
  const cases = [
    valid.replace('minos 11.0\n', 'minos 11.0.1\n'),
    valid.replace('platform 1\n', 'platform 2\n'),
    valid.replace('minos 11.0\n', 'minos 10.15\n'),
    valid.replace('minos 11.0\n', 'minos 11.0extra\n'),
    valid.replace('minos 11.0\n', 'minos 11.0\n minos 11.0\n'),
    valid.replace('cmdsize 32\n platform', 'cmdsize 40\n platform'),
    valid.replace('ntools 1\n', 'ntools 0\n'),
    valid.replace('platform 1\n    minos 11.0\n', 'platform 1\n') + ' minos 11.0\n',
    valid.replace('minos 11.0\n', 'minos 12.0\n').replace('cmdsize 72\n', 'cmdsize 72\n minos 11.0\n'),
    `${valid}Load command 3\n cmd LC_BUILD_VERSION\n cmdsize 24\n platform 1\n minos 11.0\n sdk 26.5\n ntools 0\n`,
    valid.replace('cmd LC_SEGMENT_64', 'cmd LC_VERSION_MIN_MACOSX'),
    valid.replace('Load command 1', 'Load command 2'),
    valid.replace('cmd LC_BUILD_VERSION\n', 'cmd LC_BUILD_VERSION extra\n'),
    valid.replace('cmd LC_SEGMENT_64', 'cmd LC_BUILD_VERSION extra'),
    valid.replace('platform 1\n', 'platform 1\n platform 1\n'),
  ];
  for (const output of cases) assert.throws(() => requireMacOS11BuildVersion(output));
});

test('rejects absent or oversized command output', () => {
  for (const output of ['', null, 1, 'Load command 0\n cmd LC_SEGMENT_64\n',
    `${valid}\0`, `${valid}${'x'.repeat(1024 * 1024)}`]) {
    assert.throws(() => requireMacOS11BuildVersion(output));
  }
});

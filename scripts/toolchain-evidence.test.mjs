import test from 'node:test';
import assert from 'node:assert/strict';
import { collectToolchainEvidence, validateToolchainEvidence } from './toolchain-evidence.mjs';

const fixture = { node: '24.10.0', npm: '11.6.0',
  rustc: 'rustc 1.90.0 (123456789 2025-09-18)', cargo: 'cargo 1.90.0 (abcdef123 2025-09-18)' };

test('toolchain evidence records exact versions with no paths or inherited signing secrets', () => {
  for (const platform of ['darwin', 'win32']) {
    const calls = [];
    const result = collectToolchainEvidence({ platform, nodeVersion: fixture.node,
      env: { PATH: '/usr/bin', SLG_RELEASE_PRIVATE_KEY: 'synthetic-secret', NODE_OPTIONS: '--inspect' },
      run: (command, args, options) => {
        calls.push([command, args]);
        assert.equal(options.env.SLG_RELEASE_PRIVATE_KEY, undefined);
        assert.equal(options.env.NODE_OPTIONS, undefined);
        return fixture[command === 'cmd.exe' ? 'npm' : command] + '\n';
      } });
    assert.deepEqual(result, fixture);
    assert.deepEqual(calls[0], platform === 'win32'
      ? ['cmd.exe', ['/d', '/s', '/c', 'npm --version']] : ['npm', ['--version']]);
  }
});

test('toolchain evidence rejects missing versions, diagnostics and extra environment data', () => {
  for (const value of [undefined, { ...fixture, npm: undefined },
    { ...fixture, npm: '11.6.0\nsynthetic-path' }, { ...fixture, cwd: 'private' },
    { ...fixture, rustc: 'unknown' }]) assert.throws(() => validateToolchainEvidence(value));
  assert.throws(() => collectToolchainEvidence({ run: () => { throw Error('synthetic-private-message'); } }),
    error => error.message === 'Could not collect exact toolchain versions.');
  assert.deepEqual(validateToolchainEvidence({ ...fixture, node: '26.1.2', npm: '12.0.1' }),
    { ...fixture, node: '26.1.2', npm: '12.0.1' });
});

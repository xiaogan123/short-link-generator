import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { observeWindowsWindow } from './windows-window-observer.mjs';
import { nativeGuiSpawnOptions } from './native-smoke.mjs';

function observerFixture(outcome, code) {
  const calls = [];
  const spawnProcess = (command, args, options) => {
    calls.push({ command, args, options });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => { child.killed = true; };
    if (outcome !== null) {
      queueMicrotask(() => {
        child.stdout.write(`${outcome}\n`);
        child.emit('close', code);
      });
    }
    calls.child = child;
    return child;
  };
  return { spawnProcess, calls };
}

test('one pwsh observer accepts only a real-window marker from the requested PID', async () => {
  const fixture = observerFixture('WINDOW', 0);
  assert.deepEqual(await observeWindowsWindow(1234, fixture), { windowObserved: true });
  assert.equal(fixture.calls.length, 1);
  assert.equal(fixture.calls[0].command, 'pwsh.exe');
  assert.deepEqual(fixture.calls[0].args.slice(-4), ['-TargetPid', '1234', '-PollSeconds', '25']);
  assert.equal(fixture.calls[0].options.windowsHide, true);
});

test('the GUI under test is not launched with its window hidden', () => {
  assert.equal(nativeGuiSpawnOptions('.', {}).windowsHide, false);
});

test('an exited process or a live process without a window fails', async () => {
  await assert.rejects(observeWindowsWindow(1234, observerFixture('EXITED', 20)), /exited before showing/);
  await assert.rejects(observeWindowsWindow(1234, observerFixture('NO_WINDOW', 21)), /showed no native window/);
  await assert.rejects(observeWindowsWindow(1234, observerFixture('WINDOW', 1)), /failed \(exit code 1\)/);
});

test('an observer that stalls is killed at one total deadline', async () => {
  const fixture = observerFixture(null, null);
  await assert.rejects(observeWindowsWindow(1234, { ...fixture, timeoutMs: 10 }), /total limit/);
  assert.equal(fixture.calls.length, 1);
  assert.equal(fixture.calls.child.killed, true);
});

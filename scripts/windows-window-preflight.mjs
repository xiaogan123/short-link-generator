import { resolve } from 'node:path';
import { observeStartup } from './native-smoke.mjs';

if (process.platform !== 'win32' || process.arch !== 'x64' ||
    process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted' ||
    process.env.RUNNER_OS !== 'Windows' || process.env.RUNNER_ARCH !== 'X64' ||
    resolve(process.env.GITHUB_WORKSPACE ?? '') !== resolve('.')) {
  throw new Error('Window preflight runs only on the Windows x64 GitHub-hosted runner.');
}

const notepad = await observeStartup('notepad.exe', process.cwd(), process.env, true);
if (!notepad.processAlive || !notepad.windowObserved) throw new Error('Notepad window was not observed.');

let exitedProcessRejected = false;
try {
  await observeStartup(process.execPath, process.cwd(), process.env, true, ['-e', 'process.exit(0)']);
} catch (error) {
  if (!/exited/.test(error.message)) throw error;
  exitedProcessRejected = true;
}
if (!exitedProcessRejected) throw new Error('A quick-exit process was incorrectly accepted.');
console.log(JSON.stringify({ host: 'win32-x64', notepadWindowObserved: true, exitedProcessRejected: true }));

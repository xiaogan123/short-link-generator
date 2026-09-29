import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./windows-window-observer.ps1', import.meta.url));
const POLL_SECONDS = 25;
const TOTAL_TIMEOUT_MS = 45_000;

export function observeWindowsWindow(pid, { spawnProcess = spawn, timeoutMs = TOTAL_TIMEOUT_MS } = {}) {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error('Window observer requires a positive process ID.');
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnProcess('pwsh.exe', [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', script,
        '-TargetPid', String(pid), '-PollSeconds', String(POLL_SECONDS),
      ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch {
      reject(new Error('Could not start the Windows window observer.'));
      return;
    }
    let stdout = '';
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve({ windowObserved: true });
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(new Error('Windows window observer exceeded its 45-second total limit.'));
    }, timeoutMs);
    child.stdout.on('data', data => { stdout = (stdout + data.toString()).slice(-256); });
    child.stderr.on('data', () => {}); // Diagnostics may include runner paths; never echo them.
    child.on('error', () => finish(new Error('Could not run pwsh for native window inspection.')));
    child.on('close', code => {
      const outcome = stdout.trim();
      if (code === 0 && outcome === 'WINDOW') finish(null);
      else if (outcome === 'EXITED') finish(new Error('Installed application exited before showing a window.'));
      else if (outcome === 'NO_WINDOW') finish(new Error('Installed application stayed alive but showed no native window.'));
      else finish(new Error(`Windows window observer failed (exit code ${code ?? 'unknown'}).`));
    });
  });
}

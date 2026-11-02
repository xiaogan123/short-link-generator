import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const VERSION = '(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)(?:-(?:alpha|beta|rc|nightly)(?:[.-][0-9]+)?)?';
const allowedEnvironment = new Set(['PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'SYSTEMROOT', 'WINDIR', 'PATHEXT', 'RUSTUP_HOME', 'CARGO_HOME', 'TMPDIR', 'TEMP', 'TMP']);
const versionEnvironment = env => Object.fromEntries([
  ...Object.entries(env).filter(([name]) => allowedEnvironment.has(name.toUpperCase())),
  ['LANG', 'C'], ['LC_ALL', 'C'],
]);
const capture = (command, args, options) => execFileSync(command, args, {
  ...options, encoding: 'utf8', timeout: 15_000, maxBuffer: 4096, stdio: ['ignore', 'pipe', 'pipe'],
});

export function validateToolchainEvidence(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'cargo,node,npm,rustc') {
    throw new Error('Toolchain version evidence is incomplete.');
  }
  for (const name of ['node', 'npm', 'rustc', 'cargo']) {
    const pattern = name === 'node' || name === 'npm'
      ? new RegExp(`^${VERSION}$`)
      : new RegExp(`^${name} ${VERSION} \\([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\\)$`);
    if (typeof value[name] !== 'string' || value[name].length > 120 || !pattern.test(value[name])) {
      throw new Error(`Invalid ${name} version evidence.`);
    }
  }
  return value;
}

export function collectToolchainEvidence({ run = capture, platform = process.platform,
  nodeVersion = process.versions.node, env = process.env } = {}) {
  const options = { env: versionEnvironment(env) };
  try {
    // Windows npm is a command shim; this fixed command contains no user input.
    const npm = platform === 'win32'
      ? run('cmd.exe', ['/d', '/s', '/c', 'npm --version'], options)
      : run('npm', ['--version'], options);
    return validateToolchainEvidence({ node: nodeVersion, npm: String(npm).trim(),
      rustc: String(run('rustc', ['--version'], options)).trim(),
      cargo: String(run('cargo', ['--version'], options)).trim() });
  } catch {
    // Raw subprocess diagnostics can contain machine paths or configuration.
    throw new Error('Could not collect exact toolchain versions.');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { console.log(JSON.stringify(collectToolchainEvidence(), null, 2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}

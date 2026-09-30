import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { appendFileSync, chmodSync, lstatSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const RCODESIGN_VERSION = '0.29.0';
export const RCODESIGN_PINS = Object.freeze({
  arm64: Object.freeze({ target: 'aarch64-apple-darwin', archive: 'd1a532150adaf90048260d76359261aa716abafc45c53c5dc18845029184334a', binary: '6c4623db45f1d89af439a2ce42fd65798ef56aaaa3e4ced48879be05f750aacb' }),
  x64: Object.freeze({ target: 'x86_64-apple-darwin', archive: '14ef11bedd51a8d95eafd767939ae96d5900e5a61511bef75bb21db6e7c74140', binary: '21588902f0698182c21b14d9623c424eb32595f675ace5b31dc1c3f3b0223ec1' }),
});
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const failure = () => new Error('Pinned macOS signing tool verification failed.');
const zero = bytes => bytes.every(byte => byte === 0);
const environment = () => ({ PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: homedir(), LANG: 'C', LC_ALL: 'C' });
const capture = (command, args, { env, timeout = 30000 } = {}) => new Promise((done, reject) => {
  execFile(command, args, { env, timeout, maxBuffer: 1024 * 1024, encoding: 'buffer' }, (error, stdout) => error ? reject(failure()) : done(stdout));
});

function nativePin(arch, platform) {
  if (platform !== 'darwin' || !Object.hasOwn(RCODESIGN_PINS, arch)) throw failure();
  return RCODESIGN_PINS[arch];
}

function textField(bytes) {
  const at = bytes.indexOf(0);
  const text = at < 0 ? bytes : bytes.subarray(0, at);
  if ((at >= 0 && !zero(bytes.subarray(at))) || text.some(byte => byte < 32 || byte > 126)) throw failure();
  return text.toString('ascii');
}
function octal(bytes) {
  const text = bytes.toString('ascii').replace(/[\0 ]+$/g, '').replace(/^ +/, '');
  if (!/^[0-7]+$/.test(text)) throw failure();
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) throw failure();
  return value;
}

// Parse only the three regular members in the reviewed upstream archives. Never
// invoke a generic extractor on an archive or permit archive-controlled paths.
export function extractSignerArchive(archive, { arch = process.arch, pins = RCODESIGN_PINS } = {}) {
  const pin = Object.hasOwn(pins, arch) ? pins[arch] : null;
  if (!pin || !Buffer.isBuffer(archive) || archive.length > 40 * 1024 * 1024 || hash(archive) !== pin.archive) throw failure();
  let expanded;
  try { expanded = gunzipSync(archive, { maxOutputLength: 40 * 1024 * 1024 }); } catch { throw failure(); }
  if (expanded.length % 512) throw failure();
  const root = `apple-codesign-${RCODESIGN_VERSION}-${pin.target}`;
  const wanted = new Map([[`${root}/`, '5'], [`${root}/COPYING`, '0'], [`${root}/rcodesign`, '0']]);
  const members = new Map();
  let offset = 0, terminated = false;
  while (offset + 512 <= expanded.length) {
    const header = expanded.subarray(offset, offset + 512);
    if (zero(header)) {
      if (expanded.length - offset < 1024 || !zero(expanded.subarray(offset))) throw failure();
      terminated = true; break;
    }
    const checksum = octal(header.subarray(148, 156));
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
    if (sum !== checksum || header.subarray(257, 265).toString('binary') !== 'ustar  \0') throw failure();
    const name = textField(header.subarray(0, 100));
    const kind = String.fromCharCode(header[156]);
    const size = octal(header.subarray(124, 136));
    const mode = octal(header.subarray(100, 108));
    if (wanted.get(name) !== kind || members.has(name) || !zero(header.subarray(157, 257)) ||
        !zero(header.subarray(345)) || (mode & ~0o777) || (kind === '5' && size !== 0) || size > 35 * 1024 * 1024) throw failure();
    const end = offset + 512 + size;
    const next = offset + 512 + Math.ceil(size / 512) * 512;
    if (next > expanded.length || !zero(expanded.subarray(end, next))) throw failure();
    members.set(name, expanded.subarray(offset + 512, end));
    offset = next;
  }
  const binary = members.get(`${root}/rcodesign`);
  const license = members.get(`${root}/COPYING`);
  if (!terminated || members.size !== 3 || !binary?.length || !license?.length || hash(binary) !== pin.binary) throw failure();
  return { binary, license };
}

export async function verifyRcodesignTool(path, { arch = process.arch, platform = process.platform, run = capture } = {}) {
  const pin = nativePin(arch, platform);
  try {
    if (typeof path !== 'string' || !isAbsolute(path) || /[\r\n\0]/.test(path)) throw failure();
    const actual = realpathSync(path), stat = lstatSync(path);
    if (actual !== path || !stat.isFile() || stat.isSymbolicLink() || stat.size > 35 * 1024 * 1024 ||
        (stat.mode & 0o022) || hash(readFileSync(actual)) !== pin.binary) throw failure();
    const env = environment();
    const nativeArch = (await run('/usr/bin/lipo', ['-archs', actual], { env, timeout: 30000 })).toString().trim();
    if (nativeArch !== (arch === 'arm64' ? 'arm64' : 'x86_64')) throw failure();
    await run('/usr/bin/codesign', ['--verify', '--strict', '-R', '=anchor apple generic and certificate leaf[subject.OU] = "MK22MZP987"', actual], { env, timeout: 30000 });
    if (hash(readFileSync(actual)) !== pin.binary) throw failure();
    return { path: actual, sha256: pin.binary, version: RCODESIGN_VERSION, arch };
  } catch { throw failure(); }
}

async function download(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!response.ok || !response.body || Number(response.headers.get('content-length') || 0) > 40 * 1024 * 1024) throw failure();
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 40 * 1024 * 1024) { await response.body.cancel().catch(() => {}); throw failure(); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function installRcodesignTool({ arch = process.arch, platform = process.platform,
  tempRoot = tmpdir(), fetchArchive = download, verify = verifyRcodesignTool } = {}) {
  const pin = nativePin(arch, platform);
  const name = `apple-codesign-${RCODESIGN_VERSION}-${pin.target}.tar.gz`;
  const archive = await fetchArchive(`https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign/${RCODESIGN_VERSION}/${name}`);
  const { binary, license } = extractSignerArchive(archive, { arch });
  const root = mkdtempSync(join(realpathSync(tempRoot), 'slg-signing-tool-')); chmodSync(root, 0o700);
  try {
    const path = join(root, 'rcodesign');
    writeFileSync(path, binary, { flag: 'wx', mode: 0o500 });
    writeFileSync(join(root, 'COPYING'), license, { flag: 'wx', mode: 0o400 });
    return await verify(path, { arch, platform });
  } catch { rmSync(root, { recursive: true, force: true }); throw failure(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== '--install' || !process.env.GITHUB_ENV ||
        Object.entries(process.env).some(([key, value]) => value && /^(?:SLG_MACOS_SIGNING_|TAURI_SIGNING_|SLG_RELEASE_PRIVATE_KEY)/.test(key))) throw failure();
    const result = await installRcodesignTool({ tempRoot: process.env.RUNNER_TEMP || tmpdir() });
    appendFileSync(process.env.GITHUB_ENV, `SLG_RCODESIGN_PATH=${result.path}\n`);
    console.log(JSON.stringify({ verified: true, version: result.version, arch: result.arch, sha256: result.sha256 }));
  } catch { console.error('Unable to prepare the pinned macOS signing tool.'); process.exitCode = 1; }
}

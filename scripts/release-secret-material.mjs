// Keep signing-key comparisons in memory. Never print or persist these patterns.
import { createPrivateKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';

function decodeBase64(value) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid signing-key material for artifact inspection.');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
    decoded.fill(0);
    throw new Error('Invalid signing-key material for artifact inspection.');
  }
  return decoded;
}

function textPatterns(strings) {
  return [...new Set(strings)].flatMap(item => [Buffer.from(item), Buffer.from(item, 'utf16le')]);
}

function wrappedBase64(value) {
  return [value, ...[64, 76].flatMap(width => {
    const lines = value.match(new RegExp(`.{1,${width}}`, 'g'));
    return [lines.join('\n'), lines.join('\r\n')];
  })];
}

export function releaseSecretPatterns(value) {
  if (value === undefined) return [];
  const encoded = value.trim();
  const envelope = decodeBase64(encoded);
  const text = envelope.toString('utf8');
  const lines = text.trim().split(/\r?\n/);
  if (!/^untrusted comment: .*secret key/.test(lines[0] ?? '') || lines.length !== 2) {
    throw new Error('Expected a minisign private key for artifact inspection.');
  }
  const key = decodeBase64(lines[1]);
  if (key.length < 64) throw new Error('Signing-key material is incomplete.');
  const strings = [...wrappedBase64(encoded), text, ...wrappedBase64(lines[1]),
    envelope.toString('hex'), envelope.toString('hex').toUpperCase(), key.toString('hex'), key.toString('hex').toUpperCase()];
  return [envelope, key, ...textPatterns(strings)];
}

export function containsReleaseSecret(data, patterns) {
  const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return patterns.some(pattern => bytes.includes(pattern));
}

// These patterns cover the encrypted signing container and its password. They
// intentionally do not decrypt a private key or inspect public certificate data.
export function macSigningSecretPatterns(env) {
  const encoded = env.SLG_MACOS_SIGNING_P12_BASE64;
  const password = env.SLG_MACOS_SIGNING_P12_PASSWORD;
  if (encoded === undefined && password === undefined) return [];
  if (typeof encoded !== 'string' || encoded.length > 2 * 1024 * 1024 ||
      typeof password !== 'string' || password.length < 1 || password.length > 4096 || /[\r\n\0]/.test(password)) {
    throw new Error('macOS signing material is incomplete for artifact inspection.');
  }
  const container = decodeBase64(encoded);
  if (container.length < 64) throw new Error('macOS signing container is incomplete for artifact inspection.');
  const passwordBytes = Buffer.from(password);
  const strings = [...wrappedBase64(encoded), container.toString('hex'), container.toString('hex').toUpperCase(),
    password, JSON.stringify(password).slice(1, -1), ...wrappedBase64(passwordBytes.toString('base64')),
    passwordBytes.toString('hex'), passwordBytes.toString('hex').toUpperCase()];
  return [container, ...textPatterns(strings)];
}

// Public certificates must remain publishable. Extract only one private RSA key,
// then compare its complete private encodings, never public certificate bytes.
// The caller must wipe returned buffers after scanning. JavaScript strings and
// crypto runtime allocations cannot be guaranteed to be fully erased.
export function macPrivateKeySecretPatterns(env, { platform = process.platform, run = execFileSync } = {}) {
  const encoded = env.SLG_MACOS_SIGNING_P12_BASE64;
  const password = env.SLG_MACOS_SIGNING_P12_PASSWORD;
  if (encoded === undefined && password === undefined) return [];
  if (platform !== 'darwin') throw new Error('macOS private-key inspection requires macOS.');
  let container, output;
  const patterns = [];
  // No inherited configuration, loader overrides, release inputs or tool context.
  const childEnv = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' };
  try {
    if (typeof encoded !== 'string' || encoded.length > 2 * 1024 * 1024 ||
        typeof password !== 'string' || password.length < 1 || password.length > 4096 || /[\r\n\0]/.test(password)) throw new Error();
    container = decodeBase64(encoded);
    if (container.length < 64) throw new Error();
    childEnv.SLG_INTERNAL_P12_PASSWORD = password;
    output = run('/usr/bin/openssl', ['pkcs12', '-in', '/dev/stdin', '-passin', 'env:SLG_INTERNAL_P12_PASSWORD', '-nocerts', '-nodes'], {
      input: container, env: childEnv, stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 1024 * 1024,
    });
    if (!Buffer.isBuffer(output) || output.length > 1024 * 1024) throw new Error();
    const text = output.toString('utf8');
    const pem = text.match(/-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----/g);
    if (pem?.length !== 1 || (text.match(/-----BEGIN [^-]*PRIVATE KEY-----/g) ?? []).length !== 1) throw new Error();
    const key = createPrivateKey(output);
    if (key.asymmetricKeyType !== 'rsa') throw new Error();
    for (const type of ['pkcs1', 'pkcs8']) for (const format of ['der', 'pem']) {
      const exported = key.export({ type, format });
      const bytes = Buffer.isBuffer(exported) ? exported : Buffer.from(exported);
      patterns.push(bytes);
      const strings = [...wrappedBase64(bytes.toString('base64')), bytes.toString('hex'), bytes.toString('hex').toUpperCase()];
      if (format === 'pem') {
        const pemText = bytes.toString('utf8');
        strings.push(pemText, pemText.replace(/\n/g, '\r\n'), JSON.stringify(pemText).slice(1, -1));
      }
      patterns.push(...textPatterns(strings));
    }
    return patterns;
  } catch (error) {
    for (const bytes of [error?.stdout, error?.stderr, ...(Array.isArray(error?.output) ? error.output : []), ...patterns]) {
      if (Buffer.isBuffer(bytes)) bytes.fill(0);
    }
    // Do not attach the original error: native parser diagnostics can contain data.
    throw new Error('macOS private-key inspection failed.');
  } finally {
    container?.fill(0);
    if (Buffer.isBuffer(output)) output.fill(0);
    delete childEnv.SLG_INTERNAL_P12_PASSWORD;
  }
}

export function artifactInspectionEnvironment(env) {
  const clean = { ...env };
  for (const name of Object.keys(clean)) {
    if (name.startsWith('SLG_MACOS_SIGNING_') || name.startsWith('SLG_INTERNAL_') ||
        name.startsWith('TAURI_SIGNING_') || name.startsWith('APPLE_') || name.startsWith('RCODESIGN_') || name.startsWith('DYLD_') ||
        name === 'SLG_RELEASE_PRIVATE_KEY' || name === 'SLG_PRIVATE_SIGNING_CONTEXT') delete clean[name];
  }
  for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'OPENSSL_CONF', 'OPENSSL_ENGINES', 'OPENSSL_MODULES', 'BASH_ENV', 'ENV']) delete clean[name];
  return clean;
}

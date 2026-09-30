// Keep signing-key comparisons in memory. Never print or persist these patterns.
function decodeBase64(value) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid signing-key material for artifact inspection.');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
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

export function artifactInspectionEnvironment(env) {
  const clean = { ...env };
  for (const name of Object.keys(clean)) {
    if (name.startsWith('SLG_MACOS_SIGNING_') || name.startsWith('SLG_INTERNAL_') ||
        name.startsWith('TAURI_SIGNING_') || name.startsWith('APPLE_') || name === 'SLG_RELEASE_PRIVATE_KEY') delete clean[name];
  }
  return clean;
}

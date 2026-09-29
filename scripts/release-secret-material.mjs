// Keep signing-key comparisons in memory. Never print or persist these patterns.
function decodeBase64(value) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid signing-key material for artifact inspection.');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
    throw new Error('Invalid signing-key material for artifact inspection.');
  }
  return decoded;
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
  const strings = [encoded, text, lines[1], envelope.toString('hex'), key.toString('hex')];
  return [envelope, key, ...strings.flatMap(item => [Buffer.from(item), Buffer.from(item, 'utf16le')])];
}

export function containsReleaseSecret(data, patterns) {
  const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return patterns.some(pattern => bytes.includes(pattern));
}

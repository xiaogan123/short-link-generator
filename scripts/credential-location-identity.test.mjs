import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const source = readFileSync(fileURLToPath(new URL(
  '../src-tauri/native/credential-core/src/credential_location.c', import.meta.url,
)), 'utf8');
const resolver = source.slice(source.indexOf('static bool identity_for_path'),
  source.indexOf('OSStatus product_location_resolve'));
const hashBlock = resolver.slice(resolver.indexOf('static const char domain'));

const u64 = value => {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(value));
  return encoded;
};

function identity({ path, owner, device }) {
  const pathBytes = Buffer.from(path, 'utf8');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from('shortlink-keychain-user-default-v2\0'),
    u64(pathBytes.length), pathBytes, u64(owner), u64(device),
  ])).digest('hex');
}

test('logical User-default identity survives inode rollover but rejects path, owner and device changes', () => {
  const original = { path: '/synthetic/user-default.keychain-db',
    owner: 501, device: 17, inode: 29 };
  assert.equal(identity(original), identity({ ...original, inode: 31 }));
  for (const changed of [
    { ...original, path: '/synthetic/other.keychain-db' },
    { ...original, owner: 502 },
    { ...original, device: 18 },
  ]) assert.notEqual(identity(original), identity(changed));
  assert.match(hashBlock, /shortlink-keychain-user-default-v2/);
  assert.match(hashBlock, /CC_SHA256_Update\(&hash, canonical,/);
  assert.match(hashBlock, /before\.st_uid/);
  assert.match(hashBlock, /before\.st_dev/);
  assert.doesNotMatch(hashBlock, /hash_u64\([^\n]*st_ino/);
});

test('one resolver snapshot still rejects links, ownership drift and device or inode races', () => {
  for (const requirement of [
    /lstat\(path, &before\)/,
    /S_ISREG\(before\.st_mode\)/,
    /before\.st_uid != user/,
    /before\.st_nlink != 1/,
    /realpath\(path, canonical\)/,
    /strcmp\(path, canonical\) != 0/,
    /stat\(path, &after\)/,
    /S_ISREG\(after\.st_mode\)/,
    /after\.st_uid != user/,
    /after\.st_nlink != 1/,
    /after\.st_dev != before\.st_dev/,
    /after\.st_ino != before\.st_ino/,
  ]) assert.match(resolver, requirement);
  assert.match(source, /copy_default\(kSecPreferencesDomainUser, &ref\)/);
  assert.match(source, /\*selected = ref;/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_ITERATIONS,
  IV_BYTES,
  SALT_BYTES,
  decryptJSON,
  deriveKey,
  encryptJSON,
  fromBase64,
  randomBytes,
  toBase64,
} from '../src/core/crypto.js';

// Real vaults use 600k iterations; tests use the cheapest value that still
// exercises the same code path.
const FAST = 1000;

test('base64 round-trips arbitrary bytes', () => {
  const bytes = randomBytes(64);
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  assert.deepEqual(fromBase64(toBase64(new Uint8Array([0, 255, 128]))), new Uint8Array([0, 255, 128]));
});

test('randomBytes returns the requested length and varies between calls', () => {
  assert.equal(randomBytes(SALT_BYTES).length, SALT_BYTES);
  assert.notDeepEqual(randomBytes(32), randomBytes(32));
});

test('encrypt/decrypt round-trips a nested value', async () => {
  const key = await deriveKey('correct horse battery staple', randomBytes(SALT_BYTES), FAST);
  const value = { items: [{ title: 'GitHub', password: 'hunter2' }], count: 1, ok: true };

  const envelope = await encryptJSON(key, value);
  assert.deepEqual(await decryptJSON(key, envelope), value);
});

test('ciphertext leaks neither the plaintext nor a repeated IV', async () => {
  const key = await deriveKey('master', randomBytes(SALT_BYTES), FAST);
  const first = await encryptJSON(key, { password: 'hunter2' });
  const second = await encryptJSON(key, { password: 'hunter2' });

  assert.equal(fromBase64(first.iv).length, IV_BYTES);
  assert.notEqual(first.iv, second.iv, 'IV must be fresh per encryption');
  assert.notEqual(first.data, second.data, 'identical plaintext must not produce identical ciphertext');
  assert.ok(!atob(first.data).includes('hunter2'));
});

test('a wrong master password fails to decrypt', async () => {
  const salt = randomBytes(SALT_BYTES);
  const envelope = await encryptJSON(await deriveKey('right', salt, FAST), { secret: 1 });
  const wrongKey = await deriveKey('wrong', salt, FAST);

  await assert.rejects(() => decryptJSON(wrongKey, envelope), /wrong master password or corrupted vault/);
});

test('tampered ciphertext is rejected by the GCM tag', async () => {
  const key = await deriveKey('master', randomBytes(SALT_BYTES), FAST);
  const envelope = await encryptJSON(key, { admin: false });

  const bytes = fromBase64(envelope.data);
  bytes[0] ^= 0xff;

  await assert.rejects(() => decryptJSON(key, { ...envelope, data: toBase64(bytes) }), /decryption failed/);
});

test('associated data is authenticated', async () => {
  const key = await deriveKey('master', randomBytes(SALT_BYTES), FAST);
  const envelope = await encryptJSON(key, { secret: 1 }, 'header-v1');

  assert.deepEqual(await decryptJSON(key, envelope, 'header-v1'), { secret: 1 });
  await assert.rejects(() => decryptJSON(key, envelope, 'header-v2'), /decryption failed/);
});

test('the same password with a different salt yields a different key', async () => {
  const a = await encryptJSON(await deriveKey('master', randomBytes(SALT_BYTES), FAST), { x: 1 });
  const keyB = await deriveKey('master', randomBytes(SALT_BYTES), FAST);

  await assert.rejects(() => decryptJSON(keyB, a), /decryption failed/);
});

test('deriveKey rejects unusable inputs', async () => {
  await assert.rejects(() => deriveKey('', randomBytes(SALT_BYTES), FAST), /non-empty/);
  await assert.rejects(() => deriveKey('master', randomBytes(4), FAST), /at least 16 bytes/);
  await assert.rejects(() => deriveKey('master', randomBytes(SALT_BYTES), 0), /positive integer/);
});

test('the default iteration count meets the OWASP floor', () => {
  assert.ok(DEFAULT_ITERATIONS >= 600_000, `expected >=600000, got ${DEFAULT_ITERATIONS}`);
});

/**
 * Cryptographic primitives for the vault.
 *
 * Runs unchanged in Node (>=20) and in the browser: both expose the same
 * WebCrypto API on `globalThis.crypto`. The master password never leaves the
 * client, and the key derived from it is never persisted.
 */

const subtle = globalThis.crypto.subtle;

export const KDF_NAME = 'PBKDF2-SHA256';
export const CIPHER_NAME = 'AES-256-GCM';

/** OWASP 2023 recommendation for PBKDF2-HMAC-SHA256. */
export const DEFAULT_ITERATIONS = 600_000;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
const KEY_BITS = 256;

export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Stretch the master password into a 256 bit AES key.
 *
 * The key is created as non-extractable so that a scripting bug (or an XSS
 * payload) cannot read the raw key material back out of the browser.
 */
export async function deriveKey(masterPassword, salt, iterations = DEFAULT_ITERATIONS) {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new Error('master password must be a non-empty string');
  }
  if (!(salt instanceof Uint8Array) || salt.length < SALT_BYTES) {
    throw new Error(`salt must be at least ${SALT_BYTES} bytes`);
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error('iterations must be a positive integer');
  }

  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypt a JSON-serialisable value. `aad` is bound into the GCM tag so that
 * the envelope header (version, KDF parameters) cannot be tampered with.
 */
export async function encryptJSON(key, value, aad = '') {
  const iv = randomBytes(IV_BYTES);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = new TextEncoder().encode(aad);

  const ciphertext = new Uint8Array(await subtle.encrypt(params, key, plaintext));
  return { iv: toBase64(iv), data: toBase64(ciphertext) };
}

export async function decryptJSON(key, { iv, data }, aad = '') {
  const params = { name: 'AES-GCM', iv: fromBase64(iv) };
  if (aad) params.additionalData = new TextEncoder().encode(aad);

  let plaintext;
  try {
    plaintext = await subtle.decrypt(params, key, fromBase64(data));
  } catch {
    // AES-GCM refuses to tell us whether the key was wrong or the ciphertext
    // was modified; both mean the same thing to the caller.
    throw new Error('decryption failed: wrong master password or corrupted vault');
  }
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/**
 * Encrypted-envelope persistence.
 *
 * The server side of keyward is deliberately dumb: it reads and writes one
 * opaque blob and has no way to decrypt it. Everything here is about not
 * losing that blob.
 */
import { readFile, rename, writeFile, mkdir, copyFile, access } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { ENVELOPE_FORMAT, VAULT_VERSION } from '../core/vault.js';

export const DEFAULT_VAULT_PATH =
  process.env.KEYWARD_VAULT ?? path.join(homedir(), '.keyward', 'vault.json');

/** Reject anything that is not a sealed envelope -- in particular, plaintext. */
export function assertSealed(envelope) {
  if (!envelope || typeof envelope !== 'object') throw new Error('body must be a JSON object');
  if (envelope.format !== ENVELOPE_FORMAT) throw new Error('not a keyward vault envelope');
  if (!Number.isInteger(envelope.version) || envelope.version > VAULT_VERSION) {
    throw new Error('unsupported envelope version');
  }
  if (typeof envelope.iv !== 'string' || typeof envelope.data !== 'string') {
    throw new Error('envelope is missing ciphertext');
  }
  if (!envelope.kdf || typeof envelope.kdf.salt !== 'string') throw new Error('envelope is missing KDF parameters');
  // A guard rail, not a security boundary: if a client bug ever tried to save
  // a decrypted vault, refuse it loudly instead of writing secrets to disk.
  if ('items' in envelope) throw new Error('refusing to store a vault that is not encrypted');
}

export async function vaultExists(vaultPath = DEFAULT_VAULT_PATH) {
  try {
    await access(vaultPath);
    return true;
  } catch {
    return false;
  }
}

export async function readVaultFile(vaultPath = DEFAULT_VAULT_PATH) {
  try {
    return JSON.parse(await readFile(vaultPath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) throw new Error(`vault file at ${vaultPath} is not valid JSON`);
    throw error;
  }
}

/**
 * Write atomically: a crash mid-save must leave either the old vault or the
 * new one, never a truncated file. The previous version is kept as .bak.
 */
export async function writeVaultFile(envelope, vaultPath = DEFAULT_VAULT_PATH) {
  assertSealed(envelope);

  const directory = path.dirname(vaultPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });

  if (await vaultExists(vaultPath)) {
    await copyFile(vaultPath, `${vaultPath}.bak`);
  }

  const temporary = `${vaultPath}.tmp`;
  await writeFile(temporary, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, vaultPath);

  return vaultPath;
}

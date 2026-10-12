/**
 * Encrypted-envelope persistence.
 *
 * The server side of keyward is deliberately dumb: it reads and writes one
 * opaque blob and has no way to decrypt it. Everything here is about not
 * losing that blob.
 */
import { readFile, rename, writeFile, mkdir, mkdtemp, rm, access } from 'node:fs/promises';
import { createHash } from 'node:crypto';
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
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export async function readVaultFile(vaultPath = DEFAULT_VAULT_PATH) {
  try {
    const envelope = JSON.parse(await readFile(vaultPath, 'utf8'));
    assertSealed(envelope);
    return envelope;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) throw new Error(`vault file at ${vaultPath} is not valid JSON`);
    throw error;
  }
}

/** A content revision is independent of disk whitespace, not an authentication token. */
export function vaultRevision(envelope) {
  return envelope === null ? null : createHash('sha256').update(JSON.stringify(envelope)).digest('hex');
}

export class VaultConflictError extends Error {
  constructor() {
    super('The vault changed in another tab. Copy your unsaved edits before locking and unlocking to load the latest vault.');
    this.name = 'VaultConflictError';
  }
}

// One process owns the vault. Compare and publish under the same queue, including
// when separate server instances in that process use the same resolved path.
const writes = new Map();

/** Publish atomically, keeping the previous encrypted envelope as a private backup. */
export async function writeVaultFile(envelope, vaultPath = DEFAULT_VAULT_PATH, { expectedRevision } = {}) {
  assertSealed(envelope);
  vaultPath = path.resolve(vaultPath);
  // Snapshot the caller's envelope before waiting behind an earlier write.
  const contents = `${JSON.stringify(envelope, null, 2)}\n`;
  const revision = vaultRevision(envelope);
  const previous = writes.get(vaultPath) ?? Promise.resolve();
  // The previous caller still receives its rejection; only unblock the queue.
  const operation = previous.catch(() => {}).then(async () => {
    const current = await readVaultFile(vaultPath);
    const currentRevision = vaultRevision(current);
    // A lost response can be retried with the identical encrypted envelope.
    if (expectedRevision !== undefined && currentRevision === revision) return vaultPath;
    if (expectedRevision !== undefined && currentRevision !== expectedRevision) throw new VaultConflictError();

    const directory = path.dirname(vaultPath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = await mkdtemp(path.join(directory, '.keyward-'));
    try {
      const next = path.join(temporary, 'vault');
      await writeFile(next, contents, { mode: 0o600, flag: 'wx' });
      if (current !== null) {
        const backup = path.join(temporary, 'backup');
        await writeFile(backup, `${JSON.stringify(current, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
        await rename(backup, `${vaultPath}.bak`);
      }
      await rename(next, vaultPath);
      return vaultPath;
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
  writes.set(vaultPath, operation);

  try {
    return await operation;
  } finally {
    if (writes.get(vaultPath) === operation) writes.delete(vaultPath);
  }
}

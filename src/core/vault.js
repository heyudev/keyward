/**
 * Vault model and on-disk envelope format.
 *
 * A vault only ever leaves this module as an encrypted envelope. The plaintext
 * shape is:
 *
 *   { version, createdAt, updatedAt, items: [ Item, ... ] }
 *
 * Mutations are non-destructive: each helper returns a fresh vault so the UI
 * can swap state atomically and never render a half-updated list.
 */
import {
  CIPHER_NAME,
  DEFAULT_ITERATIONS,
  KDF_NAME,
  SALT_BYTES,
  decryptJSON,
  deriveKey,
  encryptJSON,
  fromBase64,
  randomBytes,
  toBase64,
} from './crypto.js';

export const VAULT_VERSION = 1;
export const ENVELOPE_FORMAT = 'keyward.vault';
export const ITEM_TYPES = ['login', 'note'];

const nowIso = () => new Date().toISOString();
const newId = () => globalThis.crypto.randomUUID();

export function createVault() {
  const timestamp = nowIso();
  return { version: VAULT_VERSION, createdAt: timestamp, updatedAt: timestamp, items: [] };
}

function normalizeDraft(draft) {
  const type = draft.type ?? 'login';
  if (!ITEM_TYPES.includes(type)) throw new Error(`unknown item type: ${type}`);

  const title = (draft.title ?? '').trim();
  if (!title) throw new Error('title is required');

  return {
    type,
    title,
    username: (draft.username ?? '').trim(),
    password: draft.password ?? '',
    url: (draft.url ?? '').trim(),
    notes: draft.notes ?? '',
    tags: (draft.tags ?? []).map((tag) => String(tag).trim().toLowerCase()).filter(Boolean),
    favorite: Boolean(draft.favorite),
  };
}

export function getItem(vault, id) {
  return vault.items.find((item) => item.id === id);
}

export function addItem(vault, draft) {
  const timestamp = nowIso();
  const item = {
    id: newId(),
    ...normalizeDraft(draft),
    createdAt: timestamp,
    updatedAt: timestamp,
    passwordUpdatedAt: draft.password ? timestamp : null,
  };
  return { vault: { ...vault, updatedAt: timestamp, items: [...vault.items, item] }, item };
}

export function updateItem(vault, id, patch) {
  const existing = getItem(vault, id);
  if (!existing) throw new Error(`no item with id ${id}`);

  const timestamp = nowIso();
  const merged = normalizeDraft({ ...existing, ...patch });
  const passwordChanged = merged.password !== existing.password;

  const item = {
    ...existing,
    ...merged,
    updatedAt: timestamp,
    // Tracking this separately is what lets the UI flag stale credentials.
    passwordUpdatedAt: passwordChanged ? timestamp : existing.passwordUpdatedAt,
  };

  return {
    vault: {
      ...vault,
      updatedAt: timestamp,
      items: vault.items.map((candidate) => (candidate.id === id ? item : candidate)),
    },
    item,
  };
}

export function deleteItem(vault, id) {
  if (!getItem(vault, id)) throw new Error(`no item with id ${id}`);
  return {
    ...vault,
    updatedAt: nowIso(),
    items: vault.items.filter((item) => item.id !== id),
  };
}

/**
 * Filter items by a free-text query. All whitespace-separated terms must match
 * (AND), each against any searchable field. Passwords are never searched --
 * typing a password fragment into the search box must not confirm a guess.
 */
export function searchItems(items, query) {
  const terms = String(query ?? '').toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [...items];

  return items.filter((item) => {
    const haystack = [item.title, item.username, item.url, item.notes, ...(item.tags ?? [])]
      .join('\n')
      .toLowerCase();
    return terms.every((term) => haystack.includes(term));
  });
}

export function sortItems(items) {
  return [...items].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return a.title.localeCompare(b.title, undefined, { sensitivity: 'base' });
  });
}

/** Reused passwords are the single most common real-world vault weakness. */
export function findReusedPasswords(items) {
  const byPassword = new Map();
  for (const item of items) {
    if (!item.password) continue;
    if (!byPassword.has(item.password)) byPassword.set(item.password, []);
    byPassword.get(item.password).push(item.id);
  }
  return new Set([...byPassword.values()].filter((ids) => ids.length > 1).flat());
}

/** Header fields are authenticated as AAD so KDF parameters cannot be downgraded. */
function envelopeAad(header) {
  return JSON.stringify([header.format, header.version, header.kdf.name, header.kdf.iterations, header.kdf.salt]);
}

/**
 * An unlocked session: the derived key plus the KDF parameters needed to write
 * the envelope header back out.
 *
 * The key is non-extractable and the master password is never stored, so an
 * unlocked client holds no material that can be read back out of memory by
 * script. Locking is therefore just dropping this object.
 */
export async function createSession(masterPassword, { iterations = DEFAULT_ITERATIONS } = {}) {
  const salt = randomBytes(SALT_BYTES);
  return { key: await deriveKey(masterPassword, salt, iterations), salt: toBase64(salt), iterations };
}

export async function sealWithSession(session, vault) {
  const header = {
    format: ENVELOPE_FORMAT,
    version: VAULT_VERSION,
    kdf: { name: KDF_NAME, iterations: session.iterations, salt: session.salt },
    cipher: CIPHER_NAME,
  };
  const { iv, data } = await encryptJSON(session.key, vault, envelopeAad(header));
  return { ...header, iv, data, updatedAt: nowIso() };
}

export async function openSession(envelope, masterPassword) {
  if (!envelope || envelope.format !== ENVELOPE_FORMAT) {
    throw new Error('not a keyward vault file');
  }
  if (!Number.isInteger(envelope.version) || envelope.version > VAULT_VERSION) {
    throw new Error(`vault was written by a newer version (${envelope.version}); please update keyward`);
  }
  if (envelope.kdf?.name !== KDF_NAME || envelope.cipher !== CIPHER_NAME) {
    throw new Error('unsupported KDF or cipher');
  }

  const { salt, iterations } = envelope.kdf;
  const key = await deriveKey(masterPassword, fromBase64(salt), iterations);
  const vault = await decryptJSON(key, envelope, envelopeAad(envelope));

  return { session: { key, salt, iterations }, vault: { ...createVault(), ...vault, version: VAULT_VERSION } };
}

/** Convenience wrappers for one-shot use (import/export, tests, scripts). */
export async function sealVault(vault, masterPassword, { iterations = DEFAULT_ITERATIONS } = {}) {
  return sealWithSession(await createSession(masterPassword, { iterations }), vault);
}

export async function openVault(envelope, masterPassword) {
  return (await openSession(envelope, masterPassword)).vault;
}

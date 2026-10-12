import { openSession } from '../core/vault.js';
import { loginMatches } from './matching.js';

export const IDLE_LOCK_MS = 5 * 60 * 1000;

/** No CryptoKey, master password, or plaintext is written to extension storage. */
export function createPopupSession({ open = openSession } = {}) {
  let vault = null;
  let generation = 0;
  return {
    async unlock(envelope, password) {
      const attempt = ++generation;
      vault = null;
      const opened = await open(envelope, password);
      if (attempt !== generation) throw new Error('sessionCancelled');
      if (!opened.vault || !Array.isArray(opened.vault.items)) throw new Error('invalidVault');
      vault = opened.vault;
    },
    lock() {
      generation++;
      vault = null;
    },
    get unlocked() { return vault !== null; },
    matches(pageUrl) {
      return (vault?.items ?? []).filter((item) => loginMatches(item, pageUrl))
        .map(({ id, title, username }) => ({ id, title, username }));
    },
    credentials(id, pageUrl) {
      const item = vault?.items.find((candidate) => candidate.id === id);
      if (!loginMatches(item, pageUrl)) throw new Error('accountUnavailable');
      return { username: item.username, password: item.password };
    },
  };
}

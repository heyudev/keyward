/** Commit plaintext changes only after their encrypted snapshot is saved. */
import { sealWithSession } from './vault.js';

export function createPersistence({ vault, session, revision, saveEnvelope, seal = sealWithSession }) {
  let closed = false;
  let tail = Promise.resolve();
  const assertOpen = () => {
    if (closed) throw new Error('Vault is locked.');
  };

  return {
    save(mutate) {
      const operation = tail.then(async () => {
        assertOpen();
        const next = mutate(vault);
        const envelope = await seal(session, next);
        assertOpen();
        const savedRevision = await saveEnvelope(envelope, revision);
        assertOpen();
        vault = next;
        revision = savedRevision;
        return vault;
      });
      // A failed write must not poison subsequent explicit retries.
      tail = operation.catch(() => {});
      return operation;
    },
    close() {
      closed = true;
      vault = null;
      session = null;
    },
  };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { createPersistence } from '../src/core/persistence.js';
import { addItem, createSession, createVault, openVault } from '../src/core/vault.js';

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test('failed saves do not commit plaintext or advance the revision; explicit retry works', async () => {
  const vault = createVault();
  const revisions = [];
  let fail = true;
  const persistence = createPersistence({
    vault, session: {}, revision: 'original', seal: async (_, next) => next,
    saveEnvelope: async (_, revision) => {
      revisions.push(revision);
      if (fail) throw new Error('disk full');
      return 'saved';
    },
  });
  const add = (current) => addItem(current, { title: 'Account' }).vault;
  await assert.rejects(persistence.save(add), /disk full/);
  fail = false;
  const saved = await persistence.save(add);
  assert.equal(saved.items.length, 1);
  assert.equal(vault.items.length, 0);
  assert.deepEqual(revisions, ['original', 'original']);
});

test('queued mutations use the last confirmed vault and revision', async () => {
  const gate = deferred();
  const revisions = [];
  const persistence = createPersistence({
    vault: createVault(), session: {}, revision: null, seal: async (_, next) => next,
    saveEnvelope: async (_, revision) => {
      revisions.push(revision);
      if (revisions.length === 1) await gate.promise;
      return `revision-${revisions.length}`;
    },
  });
  const first = persistence.save((vault) => addItem(vault, { title: 'First' }).vault);
  const second = persistence.save((vault) => addItem(vault, { title: 'Second' }).vault);
  gate.resolve();
  assert.equal((await first).items.length, 1);
  assert.deepEqual((await second).items.map((item) => item.title), ['First', 'Second']);
  assert.deepEqual(revisions, [null, 'revision-1']);
});

test('locking during encryption cancels the network write and queued mutations', async () => {
  const entered = deferred();
  const gate = deferred();
  let writes = 0;
  const persistence = createPersistence({
    vault: createVault(), session: {}, revision: null,
    seal: async () => { entered.resolve(); await gate.promise; return {}; },
    saveEnvelope: async () => { writes++; return 'saved'; },
  });
  const first = persistence.save((vault) => vault);
  const second = persistence.save((vault) => vault);
  const rejected = Promise.all([assert.rejects(first, /locked/), assert.rejects(second, /locked/)]);
  await entered.promise;
  persistence.close();
  gate.resolve();
  await rejected;
  assert.equal(writes, 0);
});

test('a response arriving after locking cannot publish plaintext', async () => {
  const entered = deferred();
  const gate = deferred();
  const persistence = createPersistence({
    vault: createVault(), session: {}, revision: null, seal: async () => ({}),
    saveEnvelope: async () => { entered.resolve(); await gate.promise; return 'saved'; },
  });
  const save = persistence.save((vault) => vault);
  const rejected = assert.rejects(save, /locked/);
  await entered.promise;
  persistence.close();
  gate.resolve();
  await rejected;
  await assert.rejects(persistence.save((vault) => vault), /locked/);
});

test('persistence sends encrypted data with the existing vault format', async () => {
  const session = await createSession('master', { iterations: 1000 });
  let envelope;
  const persistence = createPersistence({
    vault: createVault(), session, revision: null,
    saveEnvelope: async (sealed, revision) => {
      assert.equal(revision, null);
      assert.equal('items' in sealed, false);
      envelope = sealed;
      return 'saved';
    },
  });
  const saved = await persistence.save((vault) => addItem(vault, { title: 'Account', password: 'secret' }).vault);
  assert.deepEqual(await openVault(envelope, 'master'), saved);
});

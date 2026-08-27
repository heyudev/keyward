import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ENVELOPE_FORMAT,
  VAULT_VERSION,
  addItem,
  createVault,
  deleteItem,
  findReusedPasswords,
  getItem,
  openVault,
  searchItems,
  sealVault,
  sortItems,
  updateItem,
} from '../src/core/vault.js';

const FAST = { iterations: 1000 };

function vaultWith(...drafts) {
  return drafts.reduce((vault, draft) => addItem(vault, draft).vault, createVault());
}

test('a new vault starts empty and versioned', () => {
  const vault = createVault();
  assert.equal(vault.version, VAULT_VERSION);
  assert.deepEqual(vault.items, []);
  assert.ok(Date.parse(vault.createdAt) > 0);
});

test('addItem stores a normalised item and leaves the input vault untouched', () => {
  const before = createVault();
  const { vault, item } = addItem(before, {
    title: '  GitHub  ',
    username: ' me@example.com ',
    password: 'hunter2',
    tags: [' Work ', 'DEV', ''],
  });

  assert.equal(before.items.length, 0, 'addItem must not mutate its argument');
  assert.equal(vault.items.length, 1);
  assert.equal(item.title, 'GitHub');
  assert.equal(item.username, 'me@example.com');
  assert.deepEqual(item.tags, ['work', 'dev']);
  assert.equal(item.type, 'login');
  assert.ok(item.id);
  assert.ok(item.passwordUpdatedAt);
});

test('addItem validates the draft', () => {
  assert.throws(() => addItem(createVault(), { title: '   ' }), /title is required/);
  assert.throws(() => addItem(createVault(), { title: 'X', type: 'crypto-wallet' }), /unknown item type/);
});

test('items get distinct ids', () => {
  const vault = vaultWith({ title: 'A' }, { title: 'B' }, { title: 'C' });
  assert.equal(new Set(vault.items.map((item) => item.id)).size, 3);
});

test('updateItem patches fields and bumps passwordUpdatedAt only on change', async () => {
  const seeded = addItem(createVault(), { title: 'Bank', password: 'old' });
  const id = seeded.item.id;

  const renamed = updateItem(seeded.vault, id, { title: 'Bank of Earth' });
  assert.equal(renamed.item.title, 'Bank of Earth');
  assert.equal(renamed.item.password, 'old', 'unpatched fields survive');
  assert.equal(renamed.item.passwordUpdatedAt, seeded.item.passwordUpdatedAt);
  assert.equal(seeded.vault.items[0].title, 'Bank', 'updateItem must not mutate its argument');

  await new Promise((resolve) => setTimeout(resolve, 2));
  const rotated = updateItem(renamed.vault, id, { password: 'new' });
  assert.equal(rotated.item.password, 'new');
  assert.notEqual(rotated.item.passwordUpdatedAt, seeded.item.passwordUpdatedAt);
  assert.equal(rotated.item.createdAt, seeded.item.createdAt, 'createdAt is immutable');
});

test('updateItem and deleteItem reject unknown ids', () => {
  const vault = vaultWith({ title: 'A' });
  assert.throws(() => updateItem(vault, 'nope', { title: 'B' }), /no item with id/);
  assert.throws(() => deleteItem(vault, 'nope'), /no item with id/);
});

test('deleteItem removes only the target', () => {
  const vault = vaultWith({ title: 'A' }, { title: 'B' });
  const remaining = deleteItem(vault, vault.items[0].id);

  assert.deepEqual(remaining.items.map((item) => item.title), ['B']);
  assert.equal(vault.items.length, 2, 'deleteItem must not mutate its argument');
});

test('search matches across fields and requires every term', () => {
  const vault = vaultWith(
    { title: 'GitHub', username: 'octo@example.com', url: 'github.com', tags: ['work'] },
    { title: 'Gmail', username: 'me@gmail.com', tags: ['personal'] },
    { title: 'Bank', notes: 'checking account', tags: ['work', 'finance'] },
  );
  const titles = (query) => searchItems(vault.items, query).map((item) => item.title);

  assert.deepEqual(titles(''), ['GitHub', 'Gmail', 'Bank'], 'empty query returns everything');
  assert.deepEqual(titles('git'), ['GitHub']);
  assert.deepEqual(titles('GITHUB'), ['GitHub'], 'search is case-insensitive');
  assert.deepEqual(titles('example.com'), ['GitHub'], 'usernames are searchable');
  assert.deepEqual(titles('checking'), ['Bank'], 'notes are searchable');
  assert.deepEqual(titles('work'), ['GitHub', 'Bank'], 'tags are searchable');
  assert.deepEqual(titles('work finance'), ['Bank'], 'terms combine with AND');
  assert.deepEqual(titles('work nonsense'), []);
});

test('search never matches on passwords', () => {
  const vault = vaultWith({ title: 'Bank', password: 'sup3rs3cret' });
  assert.deepEqual(searchItems(vault.items, 'sup3rs3cret'), []);
});

test('sortItems puts favourites first, then alphabetical', () => {
  const vault = vaultWith(
    { title: 'zeta' },
    { title: 'Alpha' },
    { title: 'middle', favorite: true },
  );
  assert.deepEqual(sortItems(vault.items).map((item) => item.title), ['middle', 'Alpha', 'zeta']);
});

test('reused passwords are detected, unique and empty ones are not', () => {
  const vault = vaultWith(
    { title: 'A', password: 'same' },
    { title: 'B', password: 'same' },
    { title: 'C', password: 'unique' },
    { title: 'D', password: '' },
  );
  const reused = findReusedPasswords(vault.items);
  const [a, b, c, d] = vault.items.map((item) => item.id);

  assert.deepEqual([...reused].sort(), [a, b].sort());
  assert.ok(!reused.has(c) && !reused.has(d));
});

test('seal/open round-trips the whole vault', async () => {
  const vault = vaultWith(
    { title: 'GitHub', username: 'octo', password: 'hunter2', tags: ['work'] },
    { title: 'Recovery codes', type: 'note', notes: 'line one\nline two' },
  );

  const envelope = await sealVault(vault, 'master passphrase', FAST);
  const reopened = await openVault(envelope, 'master passphrase');

  assert.deepEqual(reopened.items, vault.items);
  assert.equal(reopened.version, VAULT_VERSION);
});

test('the envelope carries no plaintext', async () => {
  const vault = vaultWith({ title: 'GitHub', username: 'octo', password: 'hunter2' });
  const serialized = JSON.stringify(await sealVault(vault, 'master', FAST));

  for (const secret of ['GitHub', 'octo', 'hunter2', 'master']) {
    assert.ok(!serialized.includes(secret), `envelope leaked ${secret}`);
  }
});

test('the envelope header is self-describing', async () => {
  const envelope = await sealVault(createVault(), 'master', FAST);
  assert.equal(envelope.format, ENVELOPE_FORMAT);
  assert.equal(envelope.version, VAULT_VERSION);
  assert.equal(envelope.kdf.name, 'PBKDF2-SHA256');
  assert.equal(envelope.kdf.iterations, 1000);
  assert.equal(envelope.cipher, 'AES-256-GCM');
  assert.ok(envelope.iv && envelope.data && envelope.updatedAt);
});

test('sealing twice produces different ciphertext for the same vault', async () => {
  const vault = vaultWith({ title: 'GitHub', password: 'hunter2' });
  const first = await sealVault(vault, 'master', FAST);
  const second = await sealVault(vault, 'master', FAST);

  assert.notEqual(first.kdf.salt, second.kdf.salt);
  assert.notEqual(first.data, second.data);
  // Both must still open -- a fresh salt is what makes a master password change work.
  assert.deepEqual((await openVault(second, 'master')).items, vault.items);
});

test('opening with the wrong master password fails', async () => {
  const envelope = await sealVault(vaultWith({ title: 'A' }), 'right', FAST);
  await assert.rejects(() => openVault(envelope, 'wrong'), /wrong master password or corrupted vault/);
});

test('a downgraded iteration count is rejected', async () => {
  const envelope = await sealVault(vaultWith({ title: 'A' }), 'master', FAST);
  const downgraded = { ...envelope, kdf: { ...envelope.kdf, iterations: 1 } };

  await assert.rejects(() => openVault(downgraded, 'master'), /decryption failed/);
});

test('openVault rejects foreign or future files', async () => {
  await assert.rejects(() => openVault(null, 'master'), /not a keyward vault/);
  await assert.rejects(() => openVault({ format: 'keepass' }, 'master'), /not a keyward vault/);

  const envelope = await sealVault(createVault(), 'master', FAST);
  await assert.rejects(() => openVault({ ...envelope, version: 99 }, 'master'), /newer version/);
  await assert.rejects(() => openVault({ ...envelope, cipher: 'DES' }, 'master'), /unsupported KDF or cipher/);
});

test('an item survives edits across a seal/open cycle', async () => {
  const seeded = addItem(createVault(), { title: 'Mail', password: 'first' });
  const edited = updateItem(seeded.vault, seeded.item.id, { password: 'second', tags: ['email'] });

  const reopened = await openVault(await sealVault(edited.vault, 'master', FAST), 'master');
  const item = getItem(reopened, seeded.item.id);

  assert.equal(item.password, 'second');
  assert.deepEqual(item.tags, ['email']);
});

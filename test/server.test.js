import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server/server.js';
import { assertSealed, readVaultFile, writeVaultFile } from '../src/server/storage.js';
import { createVault, sealVault } from '../src/core/vault.js';

const FAST = { iterations: 1000 };

async function tempVaultPath() {
  return path.join(await mkdtemp(path.join(tmpdir(), 'keyward-')), 'vault.json');
}

/** Start the server on an ephemeral port and hand back a fetch bound to it. */
async function withServer(run) {
  const vaultPath = await tempVaultPath();
  const server = createServer({ vaultPath });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    await run({ base, vaultPath, call: (url, init) => fetch(`${base}${url}`, init) });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const sealed = () => sealVault(createVault(), 'master', FAST);

const put = (call, body, headers = {}) =>
  call('/api/vault', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

// ------------------------------------------------------------------ storage ---

test('assertSealed accepts an envelope and rejects everything else', async () => {
  assertSealed(await sealed());

  assert.throws(() => assertSealed(null), /JSON object/);
  assert.throws(() => assertSealed({ format: 'keepass' }), /not a keyward vault envelope/);
  assert.throws(() => assertSealed({ format: 'keyward.vault', version: 1 }), /missing ciphertext/);
});

test('assertSealed refuses a plaintext vault', async () => {
  const plaintext = { ...(await sealed()), items: [{ title: 'GitHub', password: 'hunter2' }] };
  assert.throws(() => assertSealed(plaintext), /refusing to store a vault that is not encrypted/);
});

test('readVaultFile returns null when there is no vault yet', async () => {
  assert.equal(await readVaultFile(await tempVaultPath()), null);
});

test('readVaultFile reports a corrupted file clearly', async () => {
  const vaultPath = await tempVaultPath();
  await writeFile(vaultPath, '{ not json');
  await assert.rejects(() => readVaultFile(vaultPath), /not valid JSON/);
});

test('writeVaultFile round-trips and keeps the previous version as .bak', async () => {
  const vaultPath = await tempVaultPath();
  const first = await sealed();
  const second = await sealed();

  await writeVaultFile(first, vaultPath);
  assert.deepEqual(await readVaultFile(vaultPath), first);

  await writeVaultFile(second, vaultPath);
  assert.deepEqual(await readVaultFile(vaultPath), second);
  assert.deepEqual(JSON.parse(await readFile(`${vaultPath}.bak`, 'utf8')), first, 'previous vault must survive as .bak');
});

// --------------------------------------------------------------------- api ---

test('GET /api/vault reports an absent vault', async () => {
  await withServer(async ({ call }) => {
    const response = await call('/api/vault');
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { exists: false, envelope: null });
  });
});

test('PUT then GET returns the same envelope', async () => {
  await withServer(async ({ call }) => {
    const envelope = await sealed();

    const saved = await put(call, envelope);
    assert.equal(saved.status, 200);
    assert.equal((await saved.json()).ok, true);

    const loaded = await (await call('/api/vault')).json();
    assert.equal(loaded.exists, true);
    assert.deepEqual(loaded.envelope, envelope);
  });
});

test('the API refuses plaintext and malformed bodies', async () => {
  await withServer(async ({ call, vaultPath }) => {
    const plaintext = { ...(await sealed()), items: [{ title: 'GitHub', password: 'hunter2' }] };

    const rejected = await put(call, plaintext);
    assert.equal(rejected.status, 400);
    assert.match((await rejected.json()).error, /not encrypted/);

    assert.equal((await put(call, 'not json at all')).status, 400);
    assert.equal((await put(call, { format: 'keepass' })).status, 400);

    assert.equal(await readVaultFile(vaultPath), null, 'nothing may be written when validation fails');
  });
});

test('cross-origin writes are refused', async () => {
  await withServer(async ({ call, vaultPath }) => {
    const response = await put(call, await sealed(), { Origin: 'https://evil.example' });

    assert.equal(response.status, 403);
    assert.equal(await readVaultFile(vaultPath), null);
  });
});

test('same-origin writes are allowed', async () => {
  await withServer(async ({ base, call }) => {
    assert.equal((await put(call, await sealed(), { Origin: base })).status, 200);
  });
});

test('unsupported methods are rejected', async () => {
  await withServer(async ({ call }) => {
    const response = await call('/api/vault', { method: 'DELETE' });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('allow'), 'GET, PUT');
  });
});

// ------------------------------------------------------------ static files ---

test('the client and its core modules are served', async () => {
  await withServer(async ({ call }) => {
    const page = await call('/');
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    assert.match(await page.text(), /<title>Keyward<\/title>/);

    for (const asset of ['/app.js', '/styles.css', '/core/vault.js', '/core/crypto.js', '/core/generator.js']) {
      assert.equal((await call(asset)).status, 200, `${asset} should be served`);
    }
  });
});

test('responses carry a restrictive CSP', async () => {
  await withServer(async ({ call }) => {
    const csp = (await call('/')).headers.get('content-security-policy');

    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /connect-src 'self'/);
    assert.doesNotMatch(csp, /unsafe-inline/, 'inline scripts must stay forbidden');
  });
});

test('path traversal cannot escape the served roots', async () => {
  await withServer(async ({ base }) => {
    for (const attack of ['/../package.json', '/core/../../package.json', '/..%2fpackage.json']) {
      const response = await fetch(`${base}${attack}`);
      assert.ok(response.status === 403 || response.status === 404, `${attack} returned ${response.status}`);
      assert.doesNotMatch(await response.text(), /"name": "keyward"/, `${attack} leaked a file`);
    }
  });
});

test('unknown paths 404', async () => {
  await withServer(async ({ call }) => {
    assert.equal((await call('/nope.js')).status, 404);
  });
});

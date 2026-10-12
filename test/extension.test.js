import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createVault, addItem, sealVault } from '../src/core/vault.js';
import { websiteOrigin, loginMatches } from '../src/extension/matching.js';
import { createPopupSession } from '../src/extension/session.js';
import { serviceOrigin, readEnvelope } from '../src/extension/service.js';
import { fillAccount } from '../src/extension/controller.js';

const login = { id: 'account', type: 'login', title: 'Account', username: 'user', password: 'secret', url: 'example.com' };

test('website matching canonicalizes origins and requires HTTPS except loopback', () => {
  assert.equal(websiteOrigin('Example.com/login', { stored: true }), 'https://example.com');
  assert.equal(websiteOrigin('example.com:8443/login', { stored: true }), 'https://example.com:8443');
  assert.equal(websiteOrigin('https://example.com:443/login'), 'https://example.com');
  assert.equal(websiteOrigin('http://127.0.0.1:8787/login'), 'http://127.0.0.1:8787');
  assert.equal(websiteOrigin('http://localhost:8080'), 'http://localhost:8080');
  assert.equal(websiteOrigin('http://[::1]:8080'), 'http://[::1]:8080');
  for (const url of [undefined, '', 'example.com', 'http://example.com', 'https://example.com@evil.test', 'https://user:pass@example.com', 'javascript:alert(1)', 'chrome://settings', 'file:///tmp/login', '//example.com', 'https://example.com:99999']) {
    assert.equal(websiteOrigin(url), null, String(url));
  }
});

test('matching never includes subdomains, lookalikes, wrong ports, notes or empty passwords', () => {
  assert.ok(loginMatches(login, 'https://example.com/login'));
  for (const url of ['https://evil-example.com', 'https://example.com.evil.test', 'https://login.example.com', 'https://example.com:8443', 'http://example.com']) {
    assert.equal(loginMatches(login, url), false, url);
  }
  for (const patch of [{ type: 'note' }, { password: '' }, { url: '' }, { username: null }, { id: null }, { title: null }]) {
    assert.equal(loginMatches({ ...login, ...patch }, 'https://example.com'), false);
  }
  assert.equal(loginMatches(null, 'https://example.com'), false);
});

test('internationalized domains match only their canonical punycode origin', () => {
  const item = { ...login, url: 'https://bücher.example' };
  assert.ok(loginMatches(item, 'https://xn--bcher-kva.example/login'));
  assert.equal(loginMatches(item, 'https://bucher.example'), false);
});

test('popup unlocks real ciphertext, exposes only matching summaries and forgets items on lock', async () => {
  const vault = addItem(createVault(), { title: 'Account', username: 'user', password: 'secret', url: 'example.com' }).vault;
  const envelope = await sealVault(vault, 'master', { iterations: 1000 });
  const session = createPopupSession();
  await assert.rejects(session.unlock(envelope, 'wrong'), /decryption failed/);
  assert.equal(session.unlocked, false);
  await session.unlock(envelope, 'master');
  const [summary] = session.matches('https://example.com');
  assert.deepEqual(Object.keys(summary).sort(), ['id', 'title', 'username']);
  assert.deepEqual(session.credentials(summary.id, 'https://example.com'), { username: 'user', password: 'secret' });
  assert.throws(() => session.credentials(summary.id, 'https://evil.test'), /accountUnavailable/);
  session.lock();
  assert.equal(session.unlocked, false);
  assert.deepEqual(session.matches('https://example.com'), []);
  assert.throws(() => session.credentials(summary.id, 'https://example.com'), /accountUnavailable/);
});

test('locking discards a late unlock result', async () => {
  let resolve;
  const session = createPopupSession({ open: () => new Promise((done) => { resolve = done; }) });
  const unlocking = session.unlock({}, 'master');
  const rejected = assert.rejects(unlocking, /sessionCancelled/);
  session.lock();
  resolve({ vault: { items: [login] } });
  await rejected;
  assert.equal(session.unlocked, false);
});

test('malformed decrypted vaults cannot become unlocked', async () => {
  const session = createPopupSession({ open: async () => ({ vault: { items: null } }) });
  await assert.rejects(session.unlock({}, 'master'), /invalidVault/);
  assert.equal(session.unlocked, false);
});

test('the local service setting cannot select a remote URL or invalid port', () => {
  assert.equal(serviceOrigin(), 'http://127.0.0.1:8787');
  assert.equal(serviceOrigin('01234'), 'http://127.0.0.1:1234');
  for (const port of [0, 65536, '', '8787/path', 'https://evil.test', '8787@evil.test', ' 8787', '1e3', -1]) {
    assert.throws(() => serviceOrigin(port), /invalidPort/);
  }
});

test('local reads make one credential-free GET, refuse redirects and return only ciphertext', async () => {
  const envelope = await sealVault(createVault(), 'master', { iterations: 1000 });
  let calls = 0;
  const actual = await readEnvelope('1234', { fetchImpl: async (url, options) => {
    calls++;
    assert.equal(url, 'http://127.0.0.1:1234/api/vault');
    assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    return Response.json({ exists: true, envelope });
  } });
  assert.deepEqual(actual, envelope);
  assert.equal(calls, 1);
});

test('local reads distinguish missing vaults, invalid responses and service failures', async () => {
  for (const [response, reason] of [
    [Response.json({ exists: false, envelope: null }), 'noVault'],
    [Response.json({ exists: true, envelope: {} }), 'invalidResponse'],
    [Response.json({ envelope: { format: 'keyward.vault' } }), 'invalidResponse'],
    [new Response('<html>not a vault</html>', { headers: { 'Content-Type': 'text/html' } }), 'invalidResponse'],
    [Response.json({}, { status: 500 }), 'serverReadFailed'],
  ]) {
    await assert.rejects(readEnvelope(8787, { fetchImpl: async () => response }), new RegExp(reason));
  }
});

test('local reads are cancellable and have a finite timeout', async () => {
  const fetchImpl = (_, { signal }) => new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new DOMException('Aborted', 'AbortError'));
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
  });
  await assert.rejects(readEnvelope(8787, { fetchImpl, timeoutMs: 1 }), /connectionTimedOut/);
  const controller = new AbortController();
  const reading = readEnvelope(8787, { fetchImpl, signal: controller.signal });
  const rejected = assert.rejects(reading, /sessionCancelled/);
  controller.abort();
  await rejected;
});

test('real loopback fetch refuses a redirect instead of contacting its destination', async (t) => {
  let destinationCalls = 0;
  const server = http.createServer((request, response) => {
    if (request.url === '/api/vault') response.writeHead(302, { Location: '/destination' }).end();
    else { destinationCalls++; response.end('not a vault'); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(readEnvelope(server.address().port), /serverUnavailable/);
  assert.equal(destinationCalls, 0);
});

function browserFixture({ url = 'https://example.com', documentOrigin = 'https://example.com', documentId = 'original', onProbe, outcome = { ok: true } } = {}) {
  const calls = [];
  const browser = {
    tabs: { query: async () => [{ id: 7, url }] },
    scripting: { executeScript: async (options) => {
      calls.push(options);
      if (calls.length === 1) {
        onProbe?.();
        return [{ frameId: 0, documentId, result: { origin: documentOrigin } }];
      }
      return [{ frameId: 0, documentId, result: outcome }];
    } },
  };
  return { browser, calls };
}

test('filling obtains credentials after probing and targets the exact document in isolation', async () => {
  const { browser, calls } = browserFixture();
  await fillAccount({ browser, tabId: 7, pageUrl: 'https://example.com/login', getCredentials: () => {
    assert.equal(calls.length, 1);
    assert.equal('args' in calls[0], false);
    return { username: 'user', password: 'secret' };
  } });
  assert.deepEqual(calls[1].target, { tabId: 7, documentIds: ['original'] });
  assert.equal(calls[1].world, 'ISOLATED');
  assert.deepEqual(calls[1].args, ['https://example.com', { username: 'user', password: 'secret' }]);
});

test('navigation or a missing document prevents any credential retrieval', async () => {
  for (const options of [{ url: 'https://evil.test' }, { documentOrigin: 'https://evil.test' }, { documentId: null }]) {
    const { browser, calls } = browserFixture(options);
    await assert.rejects(fillAccount({ browser, tabId: 7, pageUrl: 'https://example.com', getCredentials: () => assert.fail('credentials must not be retrieved') }), /pageChanged/);
    assert.ok(calls.length <= 1);
  }
});

test('locking during the page probe prevents credential retrieval', async () => {
  let current = true;
  const { browser, calls } = browserFixture({ onProbe: () => { current = false; } });
  await assert.rejects(fillAccount({ browser, tabId: 7, pageUrl: 'https://example.com', isCurrent: () => current, getCredentials: () => assert.fail('locked') }), /pageChanged/);
  assert.equal(calls.length, 1);
});

test('injection failure reports the reason without retrying or returning credentials', async () => {
  const { browser, calls } = browserFixture({ outcome: { ok: false, reason: 'ambiguousForm' } });
  await assert.rejects(fillAccount({ browser, tabId: 7, pageUrl: 'https://example.com', getCredentials: () => ({ username: 'user', password: 'secret' }) }), /ambiguousForm/);
  assert.equal(calls.length, 2);
});

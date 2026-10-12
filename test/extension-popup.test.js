import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { addItem, createVault, sealVault } from '../src/core/vault.js';

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.textContent = '';
    this.dataset = {};
  }
  set innerHTML(_) { assert.fail('UI must not parse HTML strings'); }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  querySelectorAll(selector) { return this.children.flatMap((node) => [...(node.tagName === selector.toUpperCase() ? [node] : []), ...node.querySelectorAll(selector)]); }
  focus() { this.focused = true; }
  async emit(name) { return this.listeners.get(name)?.({ preventDefault() {} }); }
}

let importId = 0;
async function popup(t, { password = 'master', fetchImpl, storedPort } = {}) {
  const html = await readFile(new URL('../src/extension/popup.html', import.meta.url), 'utf8');
  const messages = JSON.parse(await readFile(new URL('../src/extension/_locales/en/messages.json', import.meta.url)));
  const elements = new Map();
  for (const [, tag, attrs, id] of html.matchAll(/<([\w-]+)([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    const element = new Element(tag);
    element.hidden = /\bhidden\b/.test(attrs);
    element.disabled = /\bdisabled\b/.test(attrs);
    element.value = attrs.match(/\bvalue="([^"]*)"/)?.[1] ?? '';
    elements.set(id, element);
  }
  const localized = [...html.matchAll(/data-i18n="([^"]+)"/g)].map(([, key]) => {
    const element = new Element();
    element.dataset.i18n = key;
    return element;
  });
  const window = new Element();
  const document = new Element();
  document.documentElement = {};
  document.getElementById = (id) => { assert.ok(elements.has(id), id); return elements.get(id); };
  document.createElement = (tag) => new Element(tag);
  document.querySelectorAll = () => localized;
  const values = new Map(storedPort ? [['keyward.port', storedPort]] : []);
  const writes = [];
  const scripts = [];
  const vault = addItem(createVault(), { title: '<b>Account</b>', username: 'user', password: 'saved-secret', url: 'example.com' }).vault;
  const envelope = await sealVault(vault, password, { iterations: 1000 });
  const globals = {
    window, document,
    chrome: {
      i18n: { getMessage: (key) => {
        assert.match(key, /^[a-zA-Z][a-zA-Z0-9]*$/, 'only message identifiers reach the API');
        return messages[key]?.message ?? '';
      }, getUILanguage: () => 'en' },
      tabs: { query: async () => [{ id: 7, url: 'https://example.com/login' }], create: async () => {} },
      scripting: { executeScript: async (options) => {
        scripts.push(options);
        return [{ frameId: 0, documentId: 'document', result: options.args ? { ok: true } : { origin: 'https://example.com' } }];
      } },
    },
    localStorage: { getItem: (key) => values.get(key), setItem: (key, value) => { writes.push([key, value]); values.set(key, value); } },
    navigator: { clipboard: { writeText: async () => {} } },
    fetch: fetchImpl ?? (async () => Response.json({ exists: true, envelope })),
  };
  const original = new Map(Object.keys(globals).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  for (const [key, value] of Object.entries(globals)) Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  t.after(async () => {
    await window.emit('pagehide');
    for (const [key, descriptor] of original) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  });
  const module = await import(`../src/extension/popup.js?test=${++importId}`);
  await module.ready;
  return { $: (id) => elements.get(id), writes, scripts, envelope };
}

test('popup integrates unlock, account selection, filling, generation and DOM cleanup', async (t) => {
  const { $, writes, scripts } = await popup(t);
  $('master').value = 'master';
  await $('unlock-form').emit('submit');
  assert.equal($('master').value, '');
  assert.equal($('unlock-form').hidden, true);
  assert.equal($('accounts').hidden, false);
  const [row] = $('items').children;
  assert.equal(row.children[0].children[0].textContent, '<b>Account</b>');
  assert.equal(JSON.stringify(row).includes('saved-secret'), false);
  await row.children[1].emit('click');
  assert.equal(scripts.length, 2);
  assert.equal(scripts[1].args[1].password, 'saved-secret');
  await $('generate').emit('click');
  assert.equal($('generated').textContent.length, 20);
  assert.deepEqual(writes, [['keyward.port', '8787']]);
  await $('lock').emit('click');
  assert.equal($('accounts').hidden, true);
  assert.equal($('unlock-form').hidden, false);
  assert.deepEqual($('items').children, []);
  assert.equal($('generated').textContent, '');
  assert.equal($('copy').disabled, true);
});

test('a wrong master password leaves the popup locked with no plaintext', async (t) => {
  const { $, writes } = await popup(t);
  $('master').value = 'wrong';
  await $('unlock-form').emit('submit');
  assert.equal($('unlock-form').hidden, false);
  assert.equal($('accounts').hidden, true);
  assert.equal($('master').value, '');
  assert.equal($('error').hidden, false);
  assert.deepEqual($('items').children, []);
  assert.deepEqual(writes, []);
});

test('locking while a read is pending cannot resurrect the popup on completion', async (t) => {
  let resolve;
  const { $, envelope } = await popup(t, { fetchImpl: () => new Promise((done) => { resolve = done; }) });
  $('master').value = 'master';
  const pending = $('unlock-form').emit('submit');
  await $('lock').emit('click');
  resolve(Response.json({ exists: true, envelope }));
  await pending;
  assert.equal($('accounts').hidden, true);
  assert.equal($('unlock').disabled, false);
  assert.deepEqual($('items').children, []);
});

test('invalid saved connection settings recover to the loopback default', async (t) => {
  const { $ } = await popup(t, { storedPort: 'https://evil.test' });
  assert.equal(String($('port').value), '8787');
});

test('invalid generator options clear any prior value rather than copying stale output', async (t) => {
  const { $ } = await popup(t);
  $('master').value = 'master';
  await $('unlock-form').emit('submit');
  await $('generate').emit('click');
  assert.equal($('generated').textContent.length, 20);
  $('length').value = '0';
  await $('generate').emit('click');
  assert.equal($('generated').textContent, '');
  assert.equal($('copy').disabled, true);
  assert.equal($('error').hidden, false);
});

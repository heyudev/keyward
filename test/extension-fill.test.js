import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { fillLogin } from '../src/extension/fill.js';

/** Model only the DOM surface used by the serialized function, not a browser. */
function fixture({ origin = 'https://example.com', inputs = [], frame = false } = {}) {
  class Input {
    constructor(patch = {}) {
      Object.assign(this, { type: 'text', isConnected: true, disabled: false, readOnly: false, hidden: false, autocomplete: '', form: null, parentElement: null }, patch);
      this.events = [];
      this._value = '';
    }
    get value() { return this._value; }
    set value(value) { this._value = value; }
    getClientRects() { return this.hidden ? [] : [{}]; }
    getBoundingClientRect() { return this.rect ?? { top: 10, left: 10, bottom: 40, right: 110, width: 100, height: 30 }; }
    dispatchEvent(event) { this.events.push(event.type); this.onEvent?.(event); }
  }
  const fields = inputs.map((patch) => new Input(patch));
  const window = { HTMLInputElement: Input, innerWidth: 800, innerHeight: 600,
    getComputedStyle: (input) => ({ visibility: input.visibility ?? 'visible', opacity: input.opacity ?? '1', display: input.display ?? 'block' }) };
  window.top = frame ? {} : window;
  const context = vm.createContext({ window, document: { querySelectorAll: () => fields }, location: { origin, href: `${origin}/login` }, URL, Event });
  const run = (credentials = { username: 'user', password: 'secret' }) => {
    context.credentials = credentials;
    return JSON.parse(JSON.stringify(vm.runInContext(`(${fillLogin.toString()})('https://example.com', credentials)`, context)));
  };
  return { run, fields };
}

test('native input setters emit input/change without submitting or returning secrets', () => {
  const form = { action: 'https://example.com/session', submit: () => assert.fail('must not submit') };
  const { run, fields } = fixture({ inputs: [{ form, autocomplete: 'username' }, { form, type: 'password' }] });
  // A framework's own setter is bypassed by the native prototype setter.
  Object.defineProperty(fields[1], 'value', { set: () => assert.fail('own setter') });
  assert.deepEqual(run(), { ok: true });
  assert.equal(fields[0]._value, 'user');
  assert.equal(fields[1]._value, 'secret');
  assert.deepEqual(fields.map((field) => field.events), [['input', 'change'], ['input', 'change']]);
});

test('different origins and subframes cannot receive credentials', () => {
  for (const options of [{ origin: 'https://evil.test' }, { frame: true }]) {
    const { run, fields } = fixture({ ...options, inputs: [{}, { type: 'password' }] });
    assert.equal(run().reason, 'pageChanged');
    assert.ok(fields.every((field) => field.value === ''));
  }
});

test('hidden, disabled, readonly, transparent and offscreen password fields are ignored', () => {
  for (const patch of [
    { hidden: true }, { disabled: true }, { readOnly: true }, { isConnected: false },
    { visibility: 'hidden' }, { opacity: '0' }, { parentElement: { opacity: '0' } },
    { rect: { top: -1000, left: -1000, bottom: -970, right: -900, width: 100, height: 30 } },
  ]) {
    const { run, fields } = fixture({ inputs: [{}, { type: 'password', ...patch }] });
    assert.equal(run().reason, 'noLoginForm');
    assert.ok(fields.every((field) => field.value === ''));
  }
});

test('signup and multiple visible login password fields are not filled', () => {
  for (const [inputs, reason] of [
    [[{}, { type: 'password', autocomplete: 'section-signup new-password' }], 'noLoginForm'],
    [[{}, { type: 'password' }, { type: 'password' }], 'ambiguousForm'],
  ]) {
    const { run, fields } = fixture({ inputs });
    assert.equal(run().reason, reason);
    assert.ok(fields.every((field) => field.value === ''));
  }
});

test('a cross-origin form action fails before writing either field', () => {
  for (const action of ['https://evil.test/session', 'https://example.com.evil.test', 'https://example.com:8443', 'javascript:submit()']) {
    const form = { action };
    const { run, fields } = fixture({ inputs: [{ form }, { form, type: 'password' }] });
    assert.equal(run().reason, 'unsafeForm');
    assert.ok(fields.every((field) => field.value === ''));
  }
});

test('explicit username and email fields take precedence over other text fields', () => {
  for (const patch of [{ autocomplete: 'section-login username' }, { type: 'email' }]) {
    const { run, fields } = fixture({ inputs: [{}, patch, { type: 'password' }] });
    assert.deepEqual(run(), { ok: true });
    assert.equal(fields[0].value, '');
    assert.equal(fields[1].value, 'user');
  }
});

test('ambiguous username fields and fields in another form cannot receive credentials', () => {
  const unrelated = { action: 'https://example.com' };
  for (const inputs of [[{}, {}, { type: 'password' }], [{ form: unrelated }, { type: 'password' }]]) {
    const { run, fields } = fixture({ inputs });
    assert.equal(run().reason, 'ambiguousUsername');
    assert.ok(fields.every((field) => field.value === ''));
  }
});

test('password-only records can fill a unique login field without a username', () => {
  const { run, fields } = fixture({ inputs: [{ type: 'password' }] });
  assert.deepEqual(run({ username: '', password: 'secret' }), { ok: true });
  assert.equal(fields[0].value, 'secret');
});

test('a synchronous form change after username input prevents password delivery', () => {
  const form = { action: 'https://example.com/session' };
  const { run, fields } = fixture({ inputs: [{ form }, { form, type: 'password' }] });
  fields[0].onEvent = () => { form.action = 'https://evil.test'; };
  assert.equal(run().reason, 'unsafeForm');
  assert.equal(fields[1].value, '');
});

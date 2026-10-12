import { generatePassword, estimateStrength } from '../core/generator.js';
import { createPopupSession, IDLE_LOCK_MS } from './session.js';
import { websiteOrigin } from './matching.js';
import { readEnvelope, serviceOrigin, DEFAULT_PORT } from './service.js';
import { fillAccount } from './controller.js';

const $ = (id) => document.getElementById(id);
const message = (key) => chrome.i18n.getMessage(key) || key;
const session = createPopupSession();
let tab;
let epoch = 0;
let request;
let idle;
let generated = '';

function notice(key, { error = false } = {}) {
  $('error').hidden = !error;
  $('status').hidden = error || !key;
  $('error').textContent = error ? message(key) : '';
  $('status').textContent = !error && key ? message(key) : '';
}

function failureKey(error, fallback) {
  const key = error?.message;
  return typeof key === 'string' && /^[a-zA-Z][a-zA-Z0-9]*$/.test(key) && chrome.i18n.getMessage(key) ? key : fallback;
}

function lock() {
  epoch++;
  request?.abort();
  request = null;
  session.lock();
  clearTimeout(idle);
  generated = '';
  $('master').value = '';
  $('items').replaceChildren();
  $('generated').textContent = '';
  $('strength').textContent = '';
  $('accounts').hidden = true;
  $('unlock-form').hidden = false;
  $('unlock').disabled = false;
  $('unlock').textContent = message('unlock');
  $('port').disabled = false;
  $('lock').hidden = true;
  $('copy').disabled = true;
  notice('');
}

function resetIdle() {
  clearTimeout(idle);
  idle = setTimeout(() => { lock(); notice('sessionExpired'); }, IDLE_LOCK_MS);
}

function renderAccounts() {
  $('items').replaceChildren();
  const accounts = session.matches(tab?.url);
  $('empty').hidden = accounts.length !== 0;
  for (const account of accounts) {
    const row = document.createElement('li');
    const text = document.createElement('div');
    text.className = 'account';
    const title = document.createElement('strong');
    title.textContent = account.title;
    const username = document.createElement('span');
    username.className = 'muted';
    username.textContent = account.username;
    text.append(title, username);
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = message('fill');
    button.addEventListener('click', async () => {
      const attempt = epoch;
      for (const node of $('items').querySelectorAll('button')) node.disabled = true;
      try {
        await fillAccount({
          browser: chrome, tabId: tab.id, pageUrl: tab.url,
          getCredentials: () => session.credentials(account.id, tab.url),
          isCurrent: () => epoch === attempt && session.unlocked,
        });
        if (attempt === epoch) notice('filled');
      } catch (error) {
        if (attempt === epoch) notice(failureKey(error, 'fillFailed'), { error: true });
      } finally {
        if (attempt === epoch) for (const node of $('items').querySelectorAll('button')) node.disabled = false;
      }
    });
    row.append(text, button);
    $('items').append(row);
  }
}

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if ($('unlock').disabled) return;
  const attempt = ++epoch;
  request = new AbortController();
  $('unlock').disabled = true;
  $('unlock').textContent = message('unlocking');
  $('port').disabled = true;
  $('lock').hidden = false;
  notice('');
  resetIdle();
  let password = $('master').value;
  $('master').value = '';
  try {
    const port = $('port').value;
    const envelope = await readEnvelope(port, { signal: request.signal });
    if (attempt !== epoch) return;
    await session.unlock(envelope, password);
    if (attempt !== epoch) return;
    try { localStorage.setItem('keyward.port', String(Number(port))); } catch { /* Port persistence is optional. */ }
    $('unlock-form').hidden = true;
    $('accounts').hidden = false;
    renderAccounts();
    resetIdle();
  } catch (error) {
    if (attempt !== epoch) return;
    lock();
    notice(failureKey(error, 'unlockFailed'), { error: true });
  } finally {
    password = '';
    if (attempt === epoch) {
      request = null;
      $('unlock').disabled = false;
      $('unlock').textContent = message('unlock');
    }
  }
});

$('lock').addEventListener('click', lock);
$('manage').addEventListener('click', async () => {
  try { await chrome.tabs.create({ url: serviceOrigin($('port').value) }); }
  catch { notice('invalidPort', { error: true }); }
});
$('generate').addEventListener('click', () => {
  if (!session.unlocked) return;
  try {
    generated = generatePassword({ length: Number($('length').value) });
    $('generated').textContent = generated;
    $('strength').textContent = `${estimateStrength(generated).bits} bits`;
    $('copy').disabled = false;
  } catch {
    generated = '';
    $('generated').textContent = '';
    $('strength').textContent = '';
    $('copy').disabled = true;
    notice('invalidLength', { error: true });
  }
});
$('copy').addEventListener('click', async () => {
  if (!session.unlocked || !generated) return;
  const attempt = epoch;
  try {
    await navigator.clipboard.writeText(generated);
    if (attempt === epoch) notice('copied');
  } catch { if (attempt === epoch) notice('clipboardBlocked', { error: true }); }
});
for (const event of ['keydown', 'pointerdown']) document.addEventListener(event, () => { if (session.unlocked) resetIdle(); }, { passive: true });
window.addEventListener('pagehide', lock);

async function boot() {
  document.documentElement.lang = chrome.i18n.getUILanguage();
  for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = message(node.dataset.i18n);
  try {
    const port = localStorage.getItem('keyward.port') || DEFAULT_PORT;
    serviceOrigin(port);
    $('port').value = port;
  } catch { $('port').value = DEFAULT_PORT; }
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    $('site').textContent = websiteOrigin(tab?.url) || message('unsupportedSite');
  } catch { $('site').textContent = message('unsupportedSite'); }
  $('master').focus();
}

export const ready = boot();

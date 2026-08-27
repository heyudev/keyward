/**
 * Keyward web client.
 *
 * Holds the only copy of the decrypted vault, in memory, for as long as it is
 * unlocked. Everything sent to the server is already sealed. Locking simply
 * drops the derived key and the plaintext vault.
 */
import {
  addItem,
  createSession,
  createVault,
  deleteItem,
  findReusedPasswords,
  getItem,
  openSession,
  sealWithSession,
  searchItems,
  sortItems,
  updateItem,
} from '/core/vault.js';
import {
  estimateStrength,
  generatePassphrase,
  generatePassword,
} from '/core/generator.js';
import { planUnlock } from '/core/unlock.js';

const IDLE_LOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 20 * 1000;

const $ = (id) => document.getElementById(id);

/** Build an element. Text always goes through textContent -- never innerHTML. */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'value') node.value = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child == null) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function icon(pathData) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', pathData);
  svg.append(path);
  return svg;
}

const ICONS = {
  copy: 'M9 9V6.5A1.5 1.5 0 0 1 10.5 5h7A1.5 1.5 0 0 1 19 6.5v7a1.5 1.5 0 0 1-1.5 1.5H15M6.5 9h7A1.5 1.5 0 0 1 15 10.5v7A1.5 1.5 0 0 1 13.5 19h-7A1.5 1.5 0 0 1 5 17.5v-7A1.5 1.5 0 0 1 6.5 9Z',
  eye: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Zm9.5 2.6a2.6 2.6 0 1 0 0-5.2 2.6 2.6 0 0 0 0 5.2Z',
  eyeOff: 'M4 4l16 16M9.9 5.9A8.6 8.6 0 0 1 12 5.7c6 0 9.5 6.3 9.5 6.3a16 16 0 0 1-3.3 4M6.5 8.1A15.7 15.7 0 0 0 2.5 12s3.5 6.3 9.5 6.3a8.9 8.9 0 0 0 3.4-.66M9.9 9.9a2.6 2.6 0 0 0 3.7 3.7',
  open: 'M14 4.5h5.5V10M19 5l-8 8M18 14v4.5A1.5 1.5 0 0 1 16.5 20h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10',
};

// ------------------------------------------------------------------ state ---

const state = {
  session: null,       // { key, salt, iterations } -- present only while unlocked
  vault: null,         // decrypted vault -- present only while unlocked
  selectedId: null,
  editing: null,       // { id: string|null, draft } while the editor is open
  query: '',
  revealed: new Set(), // item ids whose password is currently shown
  generator: { mode: 'password', value: '' },
};

let idleTimer = null;
let clipboardTimer = null;
let toastTimer = null;

// -------------------------------------------------------------- utilities ---

function avatarColor(text) {
  let hash = 0;
  for (const char of text) hash = (hash * 31 + char.charCodeAt(0)) % 360;
  return `hsl(${hash}, 48%, 46%)`;
}

function initials(title) {
  const words = title.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return '?';
  return words.length === 1 ? words[0].slice(0, 2) : words[0][0] + words[1][0];
}

function relativeTime(iso) {
  if (!iso) return 'never';
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (days < 1) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 30) return `${days} days ago`;
  if (days < 365) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

function showToast(message) {
  const toast = $('toast');
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 2600);
}

function paintStrength(bar, label, password) {
  const { bits, label: name, score } = estimateStrength(password);
  bar.dataset.score = String(score);
  bar.style.width = `${password ? Math.max(6, Math.min(100, (bits / 128) * 100)) : 0}%`;
  label.textContent = password ? `${name} · ${bits} bits` : '';
}

/**
 * Write to the clipboard, falling back to the legacy selection-based copy when
 * the async API is refused (an insecure context, or a denied permission).
 */
async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch { /* try the fallback below */ }

  // The value is in the DOM only for the duration of the copy command.
  const holder = el('textarea', { class: 'offscreen', readonly: true, 'aria-hidden': 'true' });
  holder.value = text;
  document.body.append(holder);
  holder.select();

  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch { copied = false; }
  holder.remove();

  return copied;
}

/**
 * Copy to the clipboard and wipe it after a delay, so a password does not sit
 * in the paste buffer for the rest of the session.
 */
async function copyValue(label, value) {
  if (!value) return;

  if (!(await writeClipboard(value))) {
    showToast('Clipboard blocked by the browser');
    return;
  }

  showToast(`${label} copied · clears in ${CLIPBOARD_CLEAR_MS / 1000}s`);
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(() => writeClipboard(''), CLIPBOARD_CLEAR_MS);
}

// ----------------------------------------------------------- server access ---

async function loadEnvelope() {
  const response = await fetch('/api/vault');
  if (!response.ok) throw new Error(`could not read vault (HTTP ${response.status})`);
  return response.json();
}

function setSaveState(text, kind = '') {
  const node = $('save-state');
  node.textContent = text;
  node.dataset.state = kind;
}

async function persist() {
  setSaveState('Saving…');
  try {
    const envelope = await sealWithSession(state.session, state.vault);
    const response = await fetch('/api/vault', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    if (!response.ok) {
      const { error } = await response.json().catch(() => ({}));
      throw new Error(error ?? `HTTP ${response.status}`);
    }
    setSaveState('Saved');
    setTimeout(() => { if ($('save-state').textContent === 'Saved') setSaveState(''); }, 2000);
  } catch (error) {
    setSaveState(`Not saved: ${error.message}`, 'error');
    showToast('Could not save the vault');
  }
}

// -------------------------------------------------------------- lock state ---

/** Switch the lock screen between "create a vault" and "unlock a vault". */
function setLockScreenMode(creating) {
  $('lock-subtitle').textContent = creating
    ? 'Choose a master password. It encrypts everything in this vault.'
    : 'Enter your master password to unlock.';
  $('confirm-field').hidden = !creating;
  $('lock-strength').hidden = !creating;
  $('unlock-button').textContent = creating ? 'Create vault' : 'Unlock';
  $('master-password').autocomplete = creating ? 'new-password' : 'current-password';
  paintStrength($('lock-strength-bar'), $('lock-strength-label'), '');
}

function lock() {
  state.session = null;
  state.vault = null;
  state.selectedId = null;
  state.editing = null;
  state.query = '';
  state.revealed.clear();
  clearTimeout(idleTimer);

  $('app').hidden = true;
  $('lock-screen').hidden = false;
  $('search').value = '';
  $('master-password').value = '';
  $('master-password-confirm').value = '';
  $('lock-error').hidden = true;
  setSaveState('');
  // A vault necessarily exists by the time we can lock one.
  setLockScreenMode(false);
  $('master-password').focus();
}

function resetIdleTimer() {
  if (!state.session) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    lock();
    showToast('Vault locked after 5 minutes of inactivity');
  }, IDLE_LOCK_MS);
}

async function unlock(event) {
  event.preventDefault();

  const button = $('unlock-button');
  const error = $('lock-error');
  const password = $('master-password').value;

  const fail = (message) => {
    error.textContent = message;
    error.hidden = false;
  };

  error.hidden = true;

  // Ask the server what actually exists rather than trusting the form's mode:
  // a stale "create" screen must never overwrite a real vault.
  let stored;
  try {
    stored = await loadEnvelope();
  } catch (problem) {
    return fail(`Cannot reach the keyward server: ${problem.message}`);
  }

  const plan = planUnlock({
    vaultExists: stored.exists,
    formInCreateMode: !$('confirm-field').hidden,
    password,
    confirmation: $('master-password-confirm').value,
  });

  if (plan.action === 'switch-to-create') {
    setLockScreenMode(true);
    return fail(plan.message);
  }
  if (plan.action === 'reject') return fail(plan.message);
  if (plan.repairForm) setLockScreenMode(false);

  const creating = plan.action === 'create';

  // Key derivation is deliberately slow; tell the user why the UI paused.
  button.disabled = true;
  button.textContent = creating ? 'Creating vault…' : 'Unlocking…';
  await new Promise((resolve) => setTimeout(resolve, 16));

  try {
    if (creating) {
      state.session = await createSession(password);
      state.vault = createVault();
      await persist();
    } else {
      const opened = await openSession(stored.envelope, password);
      state.session = opened.session;
      state.vault = opened.vault;
    }
  } catch (problem) {
    button.disabled = false;
    button.textContent = creating ? 'Create vault' : 'Unlock';
    return fail(/wrong master password/.test(problem.message) ? 'Wrong master password.' : problem.message);
  }

  $('master-password').value = '';
  $('master-password-confirm').value = '';
  button.disabled = false;
  button.textContent = 'Unlock';

  $('lock-screen').hidden = true;
  $('app').hidden = false;
  render();
  resetIdleTimer();
  $('search').focus();
}

// ------------------------------------------------------------------ render ---

function visibleItems() {
  return sortItems(searchItems(state.vault.items, state.query));
}

function render() {
  if (!state.vault) return;
  renderList();
  renderDetail();
}

function renderList() {
  const list = $('item-list');
  const items = visibleItems();
  const reused = findReusedPasswords(state.vault.items);

  list.replaceChildren();
  $('item-count').textContent = state.query
    ? `${items.length} of ${state.vault.items.length}`
    : `${state.vault.items.length} item${state.vault.items.length === 1 ? '' : 's'}`;

  if (items.length === 0) {
    list.append(el('li', {}, el('p', {
      class: 'empty-state',
      text: state.vault.items.length === 0
        ? 'Your vault is empty. Add your first login to get started.'
        : 'No items match that search.',
    })));
    return;
  }

  for (const item of items) {
    const avatar = el('div', { class: 'item-avatar', text: initials(item.title) });
    avatar.style.backgroundColor = avatarColor(item.title);

    const flags = el('div', { class: 'item-flags' },
      item.favorite ? el('span', { class: 'item-flag', dataset: { kind: 'favorite' }, text: '★', title: 'Favourite' }) : null,
      reused.has(item.id) ? el('span', { class: 'item-flag', dataset: { kind: 'reused' }, text: '⚠', title: 'Password reused' }) : null,
    );

    list.append(el('li', {},
      el('button', {
        class: `item${item.id === state.selectedId ? ' is-selected' : ''}`,
        type: 'button',
        onClick: () => { state.selectedId = item.id; state.editing = null; render(); },
      },
        avatar,
        el('div', { class: 'item-body' },
          el('div', { class: 'item-title', text: item.title }),
          el('div', { class: 'item-subtitle', text: item.username || item.url || (item.type === 'note' ? 'Secure note' : 'No username') }),
        ),
        flags,
      ),
    ));
  }
}

function detailRow(label, value, { secret = false, itemId = null, href = null, copyAs = null } = {}) {
  const revealed = secret && state.revealed.has(itemId);
  const classes = ['row-value'];
  if (!value) classes.push('is-empty');
  else if (secret) classes.push(revealed ? 'is-secret' : 'is-masked');

  const display = value ? (secret && !revealed ? '•'.repeat(Math.min(value.length, 24)) : value) : '—';
  const valueNode = href && value
    ? el('div', { class: classes.join(' ') }, el('a', { href, target: '_blank', rel: 'noreferrer noopener', text: display }))
    : el('div', { class: classes.join(' '), text: display });

  const actions = el('div', { class: 'row-actions' });
  if (value && secret) {
    actions.append(el('button', {
      class: 'icon-button',
      type: 'button',
      title: revealed ? 'Hide' : 'Reveal',
      'aria-label': revealed ? 'Hide password' : 'Reveal password',
      onClick: () => {
        state.revealed.has(itemId) ? state.revealed.delete(itemId) : state.revealed.add(itemId);
        renderDetail();
      },
    }, icon(revealed ? ICONS.eyeOff : ICONS.eye)));
  }
  if (value) {
    actions.append(el('button', {
      class: 'icon-button',
      type: 'button',
      title: `Copy ${label.toLowerCase()}`,
      'aria-label': `Copy ${label.toLowerCase()}`,
      onClick: () => copyValue(copyAs ?? label, value),
    }, icon(ICONS.copy)));
  }
  if (href && value) {
    actions.append(el('a', {
      class: 'icon-button', href, target: '_blank', rel: 'noreferrer noopener', title: 'Open in a new tab',
    }, icon(ICONS.open)));
  }

  return el('div', { class: 'row' }, el('div', { class: 'row-label', text: label }), valueNode, actions);
}

function normalizeUrl(url) {
  if (!url) return null;
  return /^https?:\/\//i.test(url) ? url : `https://${url}`;
}

function renderDetail() {
  const detail = $('detail');
  detail.replaceChildren();

  if (state.editing) return detail.append(renderEditor());

  const item = state.selectedId ? getItem(state.vault, state.selectedId) : null;
  if (!item) {
    return detail.append(el('div', { class: 'detail-placeholder' },
      el('p', { text: state.vault.items.length === 0 ? 'Create an item to see it here.' : 'Select an item to view its details.' })));
  }

  const avatar = el('div', { class: 'detail-avatar', text: initials(item.title) });
  avatar.style.backgroundColor = avatarColor(item.title);

  const strength = item.password ? estimateStrength(item.password) : null;
  const reused = findReusedPasswords(state.vault.items).has(item.id);

  const rows = [];
  if (item.type === 'login') {
    rows.push(detailRow('Username', item.username, { copyAs: 'Username' }));
    rows.push(detailRow('Password', item.password, { secret: true, itemId: item.id, copyAs: 'Password' }));
    rows.push(detailRow('Website', item.url, { href: normalizeUrl(item.url), copyAs: 'Website' }));
  }

  detail.append(el('div', { class: 'detail-inner' },
    el('header', { class: 'detail-head' },
      avatar,
      el('div', { class: 'detail-heading' },
        el('h2', { class: 'detail-title', text: item.title }),
        el('div', {
          class: 'detail-meta',
          text: item.type === 'note'
            ? `Secure note · updated ${relativeTime(item.updatedAt)}`
            : `Password changed ${relativeTime(item.passwordUpdatedAt)}${strength ? ` · ${strength.label}` : ''}`,
        }),
      ),
      el('div', { class: 'detail-actions' },
        el('button', {
          class: 'button button-ghost button-small',
          type: 'button',
          title: item.favorite ? 'Remove from favourites' : 'Add to favourites',
          onClick: async () => {
            const result = updateItem(state.vault, item.id, { favorite: !item.favorite });
            state.vault = result.vault;
            render();
            await persist();
          },
        }, item.favorite ? '★' : '☆'),
        el('button', {
          class: 'button button-small',
          type: 'button',
          onClick: () => { state.editing = { id: item.id, draft: { ...item } }; renderDetail(); },
        }, 'Edit'),
      ),
    ),

    reused ? el('div', { class: 'banner' }, el('span', { text: '⚠' }),
      el('span', { text: 'This password is used by another item. Reused passwords turn one breach into several.' })) : null,

    rows.length ? el('section', { class: 'card' }, ...rows) : null,

    item.notes ? el('section', { class: 'card' },
      el('div', { class: 'row' },
        el('div', { class: 'row-label', text: 'Notes' }),
        el('div', { class: 'row-value' }),
        el('div', { class: 'row-actions' },
          el('button', { class: 'icon-button', type: 'button', title: 'Copy notes', onClick: () => copyValue('Notes', item.notes) }, icon(ICONS.copy)))),
      el('pre', { class: 'notes-body', text: item.notes }),
    ) : null,

    item.tags?.length ? el('section', { class: 'card' },
      el('div', { class: 'row' },
        el('div', { class: 'row-label', text: 'Tags' }),
        el('div', { class: 'row-value tag-row' }, ...item.tags.map((tag) => el('span', { class: 'tag', text: tag }))),
      ),
    ) : null,
  ));
}

// ------------------------------------------------------------------ editor ---

function renderEditor() {
  const { id, draft } = state.editing;
  const isNew = id === null;
  const form = el('form', { class: 'editor', autocomplete: 'off' });
  const error = el('p', { class: 'error-text', hidden: true });

  const field = (label, key, { type = 'text', placeholder = '' } = {}) => {
    const input = el('input', { class: 'input', type, value: draft[key] ?? '', placeholder, spellcheck: 'false', autocomplete: 'off' });
    input.addEventListener('input', () => { draft[key] = input.value; });
    return { input, node: el('label', { class: 'field' }, el('span', { class: 'field-label', text: label }), input) };
  };

  const title = field('Title', 'title', { placeholder: 'GitHub' });
  form.append(el('h2', { class: 'editor-title', text: isNew ? 'New item' : 'Edit item' }), error, title.node);

  if (draft.type === 'login') {
    form.append(field('Username', 'username', { placeholder: 'you@example.com' }).node);

    // Password field: free text, with a reveal toggle, a generator and a live meter.
    const passwordInput = el('input', { class: 'input', type: 'password', value: draft.password ?? '', autocomplete: 'new-password', spellcheck: 'false' });
    const bar = el('div', { class: 'strength-bar' });
    const meterLabel = el('span', { class: 'strength-label' });
    const sync = () => { draft.password = passwordInput.value; paintStrength(bar, meterLabel, passwordInput.value); };
    passwordInput.addEventListener('input', sync);

    form.append(el('label', { class: 'field' },
      el('span', { class: 'field-label', text: 'Password' }),
      el('div', { class: 'password-field' },
        passwordInput,
        el('button', {
          class: 'button', type: 'button', title: 'Reveal password',
          onClick: () => { passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password'; },
        }, icon(ICONS.eye)),
        el('button', {
          class: 'button', type: 'button', title: 'Generate a password',
          onClick: () => { passwordInput.value = generatePassword(); passwordInput.type = 'text'; sync(); },
        }, 'Generate'),
      ),
      el('div', { class: 'strength' }, el('div', { class: 'strength-track' }, bar), meterLabel),
    ));
    sync();

    form.append(field('Website', 'url', { placeholder: 'github.com' }).node);
  }

  const notes = el('textarea', { class: 'input', spellcheck: 'false' });
  notes.value = draft.notes ?? '';
  notes.addEventListener('input', () => { draft.notes = notes.value; });
  form.append(el('label', { class: 'field' }, el('span', { class: 'field-label', text: 'Notes' }), notes));

  const tags = el('input', { class: 'input', type: 'text', value: (draft.tags ?? []).join(', '), placeholder: 'work, email', spellcheck: 'false' });
  tags.addEventListener('input', () => { draft.tags = tags.value.split(',').map((tag) => tag.trim()).filter(Boolean); });
  form.append(el('label', { class: 'field' }, el('span', { class: 'field-label', text: 'Tags' }), tags));

  form.append(el('div', { class: 'editor-actions' },
    el('button', { class: 'button button-primary', type: 'submit' }, isNew ? 'Create item' : 'Save changes'),
    el('button', { class: 'button', type: 'button', onClick: () => { state.editing = null; renderDetail(); } }, 'Cancel'),
    el('div', { class: 'spacer' }),
    isNew ? null : el('button', {
      class: 'button button-danger', type: 'button',
      onClick: async () => {
        if (!confirm(`Delete "${draft.title}"? This cannot be undone.`)) return;
        state.vault = deleteItem(state.vault, id);
        state.editing = null;
        state.selectedId = null;
        render();
        await persist();
        showToast('Item deleted');
      },
    }, 'Delete'),
  ));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const result = isNew ? addItem(state.vault, draft) : updateItem(state.vault, id, draft);
      state.vault = result.vault;
      state.selectedId = result.item.id;
      state.editing = null;
      render();
      await persist();
    } catch (problem) {
      error.textContent = problem.message;
      error.hidden = false;
    }
  });

  return form;
}

// --------------------------------------------------------------- generator ---

function generatorOptions() {
  return {
    length: Number($('opt-length').value),
    lowercase: $('opt-lowercase').checked,
    uppercase: $('opt-uppercase').checked,
    digits: $('opt-digits').checked,
    symbols: $('opt-symbols').checked,
    excludeAmbiguous: $('opt-ambiguous').checked,
  };
}

function regenerate() {
  try {
    state.generator.value = state.generator.mode === 'password'
      ? generatePassword(generatorOptions())
      : generatePassphrase({
        words: Number($('opt-words').value),
        capitalize: $('opt-capitalize').checked,
        includeNumber: $('opt-number').checked,
      });
  } catch (error) {
    state.generator.value = '';
    showToast(error.message);
  }
  $('generated').textContent = state.generator.value;
  paintStrength($('generated-strength-bar'), $('generated-strength-label'), state.generator.value);
}

function openGenerator() {
  $('generator-overlay').hidden = false;
  regenerate();
}

// ------------------------------------------------------------------- wiring ---

function bindEvents() {
  $('unlock-form').addEventListener('submit', unlock);
  $('lock-button').addEventListener('click', lock);
  $('generator-button').addEventListener('click', openGenerator);
  $('generator-close').addEventListener('click', () => { $('generator-overlay').hidden = true; });
  $('generator-overlay').addEventListener('click', (event) => {
    if (event.target === $('generator-overlay')) $('generator-overlay').hidden = true;
  });
  $('regenerate').addEventListener('click', regenerate);
  $('copy-generated').addEventListener('click', () => copyValue('Password', state.generator.value));

  $('search').addEventListener('input', (event) => { state.query = event.target.value; renderList(); });

  $('new-item-button').addEventListener('click', () => {
    state.editing = { id: null, draft: { type: 'login', title: '', username: '', password: '', url: '', notes: '', tags: [] } };
    state.selectedId = null;
    render();
    document.querySelector('.editor .input')?.focus();
  });

  // Master password strength meter, shown only while creating a vault.
  $('master-password').addEventListener('input', (event) => {
    if ($('lock-strength').hidden) return;
    paintStrength($('lock-strength-bar'), $('lock-strength-label'), event.target.value);
  });

  for (const segment of document.querySelectorAll('.segment')) {
    segment.addEventListener('click', () => {
      for (const other of document.querySelectorAll('.segment')) other.classList.toggle('is-active', other === segment);
      state.generator.mode = segment.dataset.mode;
      $('password-options').hidden = segment.dataset.mode !== 'password';
      $('passphrase-options').hidden = segment.dataset.mode !== 'passphrase';
      regenerate();
    });
  }

  for (const id of ['opt-length', 'opt-lowercase', 'opt-uppercase', 'opt-digits', 'opt-symbols', 'opt-ambiguous', 'opt-words', 'opt-capitalize', 'opt-number']) {
    $(id).addEventListener('input', () => {
      $('opt-length-value').textContent = $('opt-length').value;
      $('opt-words-value').textContent = $('opt-words').value;
      regenerate();
    });
  }

  for (const event of ['mousemove', 'keydown', 'click', 'scroll']) {
    document.addEventListener(event, resetIdleTimer, { passive: true });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !$('generator-overlay').hidden) return void ($('generator-overlay').hidden = true);
    if (!state.session) return;

    if (event.key === 'l' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      return lock();
    }
    // "/" focuses search, the way it does in most list-driven apps.
    if (event.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
      event.preventDefault();
      $('search').focus();
    }
  });
}

async function boot() {
  bindEvents();

  try {
    const { exists } = await loadEnvelope();
    setLockScreenMode(!exists);
  } catch (error) {
    $('lock-error').textContent = `Cannot reach the keyward server: ${error.message}`;
    $('lock-error').hidden = false;
  }

  $('master-password').focus();
}

boot();

# Keyward

[简体中文](README.zh-CN.md) | **English**

[![tests](https://github.com/heyudev/keyward/actions/workflows/test.yml/badge.svg)](https://github.com/heyudev/keyward/actions/workflows/test.yml)

A locally hosted password manager with an encrypted vault, login records, and a password generator.

Your data stays on your machine. There are no accounts, synchronization, or cloud storage. Your master password stays in the browser and is never persisted or sent to the server.

The name comes from *ward*: an obstruction inside a lock that prevents an incorrect key from turning.

## Quick start

Requires Node.js 20 or later. There are no dependencies to install.

From your local checkout:

```bash
cd keyward && npm start
```

Open http://127.0.0.1:8787. On your first visit, choose a master password to create the vault. On subsequent visits, enter it to unlock.

Run the tests:

```bash
cd keyward && npm test
```

## Features

- **Vault:** one master password unlocks everything. Lock manually with Ctrl/Cmd+L, or let the vault lock automatically after five minutes of inactivity.
- **Items:** create, view, edit, and delete logins and secure notes. Logins include a title, username, password, website, notes, and tags. Mark items as favorites.
- **Search:** filter by title, username, website, notes, and tags. Every search term must match. Passwords are excluded from search so a query cannot confirm a password guess.
- **Password generator:** generate random passwords with configurable length, character classes, and exclusion of ambiguous characters, or word-based passphrases such as `Hood-Cook-Hour48-Lamp`. Includes a strength estimate.
- **Password reuse warnings:** the list and detail view flag passwords shared by multiple items.
- **Clipboard:** copy a username or password with one click. Keyward attempts to clear the clipboard after 20 seconds.
- **Save protection:** item changes are committed only after a successful save. A failed save leaves the editing form available for retry. Stale tabs cannot overwrite changes saved by another tab.
- **Chrome extension:** unlock a popup, select an account matching the current website, and click to fill it. Includes a generator and English/Simplified Chinese UI. Requires the local service; available as a development build, pending real-browser verification and store publication.

## Chrome extension

```bash
npm run build:extension
```

Load `dist/chrome` through **Load unpacked** at `chrome://extensions`. Keep `npm start` running. Chrome 106 or later is required; closing the popup locks its vault. See the [installation and packaging guide](docs/chrome-extension.md) and [privacy policy](PRIVACY.md).

## Security model

**Encryption happens in the browser. The server stores only encrypted envelopes.**

The master password is used with PBKDF2-SHA256 and 600,000 iterations to derive a 256-bit key for AES-256-GCM encryption. The key is non-extractable. The master password fields are cleared after a successful unlock. Locking clears session state and plaintext from the interface, and prevents unfinished asynchronous saves from displaying content again.

The server handles an encrypted envelope and has no decryption key. It rejects request bodies that do not have the expected envelope structure, including envelopes with a top-level plaintext `items` field. This validation is a guard against client bugs, not proof that arbitrary submitted data is encrypted.

Additional protections:

- The envelope header, including its version, KDF parameters, and salt, is authenticated as AES-GCM additional authenticated data. Tampering with those parameters causes decryption to fail.
- Each save uses a fresh initialization vector, so encrypting the same content again produces different ciphertext.
- The server binds to the loopback address by default. Writes check the host and port in the Origin header.
- The Content Security Policy (CSP) disallows inline scripts and external connections. DOM text is constructed with `textContent`, without concatenating HTML strings.

**There is no password recovery.** If you lose your master password, the vault cannot be unlocked.

## Storage and backups

The default vault path is `~/.keyward/vault.json`, with file permissions `0600`. Set `KEYWARD_VAULT` to change the path, or `PORT` to change the listening port.

Writes are atomic: Keyward writes to a separate temporary file before renaming it into place, so a partial file is never published as the vault. Before each save, the previous version is kept as `vault.json.bak`. Both the vault and its backup have permissions `0600`. Writes to the same path run sequentially within the server process. Only one server process should manage a given vault file.

If another tab has changed the vault, copy your unsaved edits before locking and unlocking to load the latest version, then apply your edits again. Keyward does not automatically merge or overwrite conflicting changes. After upgrading the server, refresh older open pages before saving, and preserve any unsaved edits first.

To back up the vault, copy the encrypted file to your backup location.

## Code layout

```text
src/core/         Shared encryption and data logic for the browser and Node
  crypto.js       Key derivation and AES-GCM encryption/decryption
  vault.js        Vault model, item operations, search, and encrypted envelopes
  generator.js    Password/passphrase generation and strength estimation
  unlock.js       Pure decision logic for creating or unlocking a vault
  persistence.js  Save confirmation, mutation ordering, and locking during saves
src/server/       Local HTTP server: static assets and encrypted vault storage
src/web/          Browser interface
src/extension/    Manifest V3 popup and user-triggered login filling
scripts/          Syntax checks and dependency-free extension packaging
test/             Automated tests
```

The code in `src/core` does not access the DOM or filesystem. The browser imports it directly, and Node tests the same implementation.

The decision to create or unlock a vault lives in `unlock.js` because an incorrect decision could overwrite existing data with an empty vault. The rule is **use the vault on disk as the source of truth, rather than the form's current mode**, with regression tests covering that behavior.

## Testing and manual verification

Automated tests cover encryption/decryption, tampering and downgrade detection, item operations, search, generator distribution, atomic storage, request checks, and path traversal protection. They also cover concurrent creation, stale-tab protection, retry after a failed save, backup permissions, and asynchronous saves during locking. The CI workflow is configured to run the same suite on Node 20, 22, and 24.

The original version was manually checked in a browser for creation, unlocking, locking and unlocking again, item operations, search, the generator, and clipboard copying. Browser interactions have not yet been rechecked after the save-protection changes. The five-minute automatic lock and delete confirmation dialog also still need manual verification. Scope, compatibility, and rollback details are recorded in the [vault save review (Chinese)](docs/save-safety.md).

## Not implemented

Multiple vaults, synchronization between devices, time-based one-time passwords (TOTP), attachments, password history, import/export, and breach detection are outside the current scope. The extension does not automatically capture credentials, submit forms, or fill iframe logins.

Changing the master password requires re-encrypting the entire vault; the interface does not yet provide this operation.

## License

MIT. See [LICENSE](LICENSE).

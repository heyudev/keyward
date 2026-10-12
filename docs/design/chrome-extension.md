# Chrome extension design

## Scope

Provide an optional Manifest V3 client for selecting a login and filling the current website after an explicit click. Keep the existing Node service, encrypted vault format, and web editor. The extension reads `/api/vault`; it does not create, modify, or save items. Automatic submission, automatic credential capture, iframe filling, and browser synchronization are outside this version.

## Verified dependencies

- `src/server/server.js:createServer` serves the encrypted envelope through GET `/api/vault`. PUT uses an Origin check and revision conditions. No additional server access or CORS exception is needed for a read-only client.
- `src/core/vault.js:openSession` and `src/core/crypto.js` already run in a browser with WebCrypto. The existing generator is in `src/core/generator.js`.
- `src/web/app.js` uses a five-minute inactivity lock. The extension keeps this limit and also locks when its popup closes.
- Chrome's [activeTab permission](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab) grants temporary page access following a user gesture. [scripting](https://developer.chrome.com/docs/extensions/reference/api/scripting) supports injection into a specific document ID from Chrome 106. Extension pages can read the loopback service with declared [host permissions](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests).

## Decisions

Use `activeTab` and `scripting`, plus host permission for `http://127.0.0.1/*`. The port setting selects only a numeric local port; users cannot configure a remote host. Host permission covers all ports on this loopback host, while the code calls only the configured service's `/api/vault`. Requests omit credentials, refuse redirects, make one request without retry, and are aborted on locking. The existing five-minute lock period is also the upper bound for reading the response, rather than introducing a separate service latency assumption. The browser owns connection pooling. WebCrypto key derivation cannot be cancelled, so late results must be discarded after locking.

Keep decrypted items only in the popup's memory. Persist only the local port, using extension-origin localStorage. Avoid a service worker and persistent unlock state: Chrome can terminate [extension service workers](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle), and persisting passwords or a reusable decryption key would change the security model. Closing the popup requires unlocking again. Generated passwords and clipboard content are not persisted by Keyward; clipboard copies are not automatically cleared after the popup closes.

Match the complete canonical origin, including scheme and non-default port, of each login's website. Bare website names mean HTTPS. Do not match parent domains, subdomains, substring lookalikes, or URLs containing embedded credentials. Allow HTTPS websites and HTTP loopback addresses for local development. Sites using HTTP elsewhere are unsupported.

Before sending credentials, recheck the active tab and probe its main frame. Capture the document ID and inject into that exact document. The injected function rechecks the origin and form action before writing. Only one visible, editable existing-password field is supported, excluding `autocomplete=new-password`. If a username is present, select an unambiguous field in the same form, preferring `autocomplete=username` and then email inputs. Ambiguous layouts fail without guessing. Fill through the native input setter and input/change events, never call form submission, and return only an outcome. A website can read credentials inserted into its own fields; the user-selected website is the intended recipient.

This stricter policy trades broader website compatibility for predictable credential delivery. A persistent background session or automatic filling would reduce clicks but require a separate session and permission review. The selected approach adds no server writes, no remote code, no analytics, no content-script message endpoint, and no externally accessible extension resources.

## Build, verification, and rollback

Package the existing core modules from source together with the extension. No second encryption implementation or remote script is used. Build a loadable directory and a ZIP for later store submission, with English and Simplified Chinese UI and documentation. GitHub CI checks JavaScript, tests, and packaging.

Test origin matching, malformed data, unlock failure, late unlock completion after locking, request cancellation, redirects, tab/document changes, form ambiguity, hidden fields, signup fields, off-origin form actions, and controlled-input events. Inspect the built manifest, resources, permissions, locales, and ZIP. Real Chrome/Edge installation and interactions remain a separate validation step; do not treat simulated DOM tests as browser verification.

Rollback by removing the extension and reverting its source, scripts, docs, and CI changes. The web client, server API, and disk format are unchanged, so no data migration is required. Store publication requires a reviewed listing, accessible privacy policy URL, screenshots, and developer-account access; producing a ZIP does not publish the extension.

# Chrome extension

**English** | [简体中文](chrome-extension.zh-CN.md)

The Keyward extension reads your locally hosted encrypted vault and fills a login after you select it. It requires Chrome 106 or later and the local Keyward Node service. The extension is not currently published in the Chrome Web Store.

## Installation

From the repository root, build the extension:

```bash
npm run build:extension
```

In Chrome, open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the generated `dist/chrome` directory. In Edge, the corresponding page is `edge://extensions`.

Start the local service:

```bash
npm start
```

Open http://127.0.0.1:8787 to create a vault or manage items. Keep the service running while using the extension. For a custom `PORT`, enter the same port under **Local connection** in the popup. The extension supports only `127.0.0.1`; it cannot connect to a remote Keyward server.

## Filling a login

1. Set the login item's website in the web vault, for example `https://example.com`.
2. Open that website's login page and click the Keyward extension icon.
3. Enter the master password and select **Fill** beside the intended account.
4. Check the filled form and submit it yourself. The extension never calls form submission.

Matching is exact by origin: scheme, hostname, and port. `example.com` in a saved item means `https://example.com`. A login for that origin does not match `login.example.com`, `example.com.evil.test`, or a different port. The popup shows the canonical origin, including punycode for internationalized domain names. Public HTTP sites are unsupported; HTTP loopback sites are allowed for local development.

The first version fills the main frame only. It requires one visible, editable login password field, excludes fields marked `autocomplete=new-password`, and refuses forms that submit to a different origin. Multiple candidate password or username fields may be rejected instead of guessed. Iframe logins, signup forms, and username-only steps are unsupported. Some websites using custom controls may require manual entry.

## Unlocking and copying

The popup unlocks independently of the web vault. Closing it, selecting **Lock**, or leaving it inactive for five minutes clears its session state. Reopening requires the master password again. Read requests are cancelled when locked; requests also have a five-minute upper limit. No background session or plaintext password storage is used.

The generator uses the existing Keyward generator, with lengths from 8 to 128. **Copy** writes the generated password to the system clipboard. Unlike the web client's delayed clearing attempt, extension copies are **not automatically cleared**.

See the [privacy policy](../PRIVACY.md) for data handling and permission details.

## Packaging and store publication

```bash
npm run check
npm test
npm run pack:extension
```

Packaging rebuilds the extension and produces `dist/keyward-chrome-0.1.0.zip`, with `manifest.json` at the archive root. The package includes shared core code, English and Simplified Chinese UI, icons, and the MIT license. No Node server, vault file, or secret is included. GitHub Actions is configured to build this ZIP and upload it as the `keyward-chrome` artifact.

The ZIP can be used for Chrome Web Store submission after browser verification. Publication also requires a developer account, screenshots, store listing text that explains the local-service requirement, an accessible privacy-policy URL, accurate data-use disclosures, and permission justifications. The current package is a development build; no store review or publication has been completed.

## Verification

Automated tests cover matching, decryption, locking, read cancellation, redirects, tab/document changes, form selection, controlled-input events, popup flows, locales, and packaging. Simulated DOM/API tests do not replace a real Chrome or Edge installation test.

Before store submission, verify installation, real popup rendering, connection to the local service, correct and incorrect passwords, filling on a disposable test website, locking/closing/reopening, clipboard behavior, and refusal of unsupported forms. Use synthetic credentials for these checks. Design decisions and rollback details are in the [extension design](design/chrome-extension.md).

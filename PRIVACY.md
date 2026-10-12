# Privacy policy

**English** | [简体中文](PRIVACY.zh-CN.md)

This policy describes the Keyward local web application and Chrome extension in this repository.

## Data handled

Keyward handles the master password, login titles, usernames, passwords, websites, notes, and tags that users enter into their vault. The Node service stores an AES-GCM encrypted vault and its previous encrypted backup on the user's machine. The master password is used for key derivation in the browser and is not sent to the Node service or persisted by Keyward.

The extension reads the encrypted vault from `http://127.0.0.1` on the configured port. It decrypts the vault in its popup and holds decrypted items in popup memory while unlocked. It clears session state on locking, closing the popup, or after five minutes of inactivity. The extension is read-only and does not modify the vault file.

The extension reads the active tab's URL to match its origin against saved login websites. When the user selects **Fill**, it inspects input fields and the form action in the main frame, and inserts only that selected login's username and password into matching website fields. The receiving website and its scripts can read those inserted values. Keyward does not collect browsing history or scan all open tabs.

## Storage and disclosure

The extension persists only the configured local service port in extension-origin localStorage. It does not persist the master password, decrypted vault, generated passwords, or a decryption key. It does not use browser synchronization, analytics, advertising, or remote code.

Keyward does not upload vault data or browsing activity to its developers or a cloud service. It sends the selected credentials to the website's form fields only after the user clicks **Fill**. It sends no vault or master password to that website. The local vault request contains no login credentials and refuses redirects.

Copying a password writes it to the operating system's clipboard, where it is available to other software with clipboard access. The web application attempts to clear copied values after 20 seconds. The extension does not automatically clear copied values. Users can overwrite the clipboard themselves.

## Extension permissions

- `activeTab`: access the current tab following the user's invocation, to match its origin and fill the selected login.
- `scripting`: inspect and fill the selected tab's main frame after a click; no continuously running content script is installed.
- `http://127.0.0.1/*` host permission: read the encrypted local vault. Chrome grants this host permission for all ports; Keyward's code uses only the configured service port and `/api/vault` endpoint.

## Limited use

Information obtained through Chrome APIs is used only to provide Keyward's described password-management functions. It is not used for advertising, sold, or transferred for unrelated purposes. Keyward developers do not receive or read users' vaults or browsing activity. These practices follow the [Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq), including its Limited Use requirements.

## User controls

Users can edit and delete items through the web application, lock either client, remove the extension, or remove their local vault and backup files. Removing the extension removes its settings but does not delete the vault or backup managed by the Node service. Deleting a login from the current vault does not immediately remove it from the previous encrypted `.bak` file.

There is no master-password recovery. Users are responsible for keeping encrypted backups and retaining their master password.

## Questions and changes

For questions, use the [project issue tracker](https://github.com/heyudev/keyward/issues). Do not include passwords, vault files, or private account details in public issues. Changes to data handling must be reflected in this policy and any Chrome Web Store disclosures before release.

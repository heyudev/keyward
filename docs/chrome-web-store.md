# Chrome Web Store submission draft

## Listing

**Name:** Keyward

**English summary:** Unlock your local Keyward vault and fill a matching login when you click. Requires the local Keyward service.

**English description:**

Keyward is an open-source password manager that stores an encrypted vault on your own computer. This extension connects to the local Keyward service, decrypts the vault in its popup, and lets you choose a matching account to fill the current website.

- Fill only after selecting an account and clicking Fill.
- Match the website's exact origin, including scheme, hostname, and port.
- Generate and copy random passwords.
- Lock when the popup closes or after five minutes of inactivity.
- Use English or Simplified Chinese UI, according to the browser language.

Requires Chrome 106 or later, Node.js 20 or later, and the separately running local Keyward service. The extension does not create or edit vault entries; use the web interface to manage them. It supports the main frame of HTTPS sites and HTTP loopback sites. Iframe logins, signup forms, username-only steps, and ambiguous forms are unsupported. Clipboard copies are not automatically cleared.

Source code and local-service setup: https://github.com/heyudev/keyward

**简体中文摘要：** 解锁本机 Keyward 保险库，点击后填充与当前网站匹配的账号。需要启动本地 Keyward 服务。

**简体中文介绍：**

Keyward 是开源密码管理器，加密保险库存储在自己的电脑上。扩展连接本地 Keyward 服务，在弹窗中解密，然后由用户选择匹配的账号并填充当前网站。

- 选择账号并点击“填充”后才写入登录字段。
- 精确匹配网站来源，包括协议、主机名和端口。
- 生成并复制随机密码。
- 关闭弹窗或闲置五分钟后锁定。
- 根据浏览器语言提供英文或简体中文界面。

需要 Chrome 106 或更高版本、Node.js 20 或更高版本，以及单独启动的本地 Keyward 服务。扩展不创建或编辑条目，条目管理请使用网页界面。支持 HTTPS 网站及 HTTP 回环地址的主框架，不支持 iframe 登录、注册表单、仅输入用户名的分步页面及存在歧义的表单。复制到剪贴板的内容不会自动清除。

源码与本地服务安装说明：https://github.com/heyudev/keyward

## Single purpose and permissions

**Single purpose:** Fill a user-selected login from a locally hosted Keyward encrypted vault into a matching website, with a password generator as part of password management.

| Permission | Justification |
| --- | --- |
| `activeTab` | Read the invoked tab's URL for exact-origin matching and grant temporary access to the selected page. |
| `scripting` | Probe and fill that tab's main frame after an explicit user click. |
| `http://127.0.0.1/*` | Read the encrypted vault from the locally running Keyward service on the configured port. |

No broad website host permission, persistent content script, remote code, analytics, or browser synchronization is used.

## Data-use disclosure

The extension handles authentication information, a vault's user-provided content, the current tab's URL, and login form structure to deliver its visible functions. Local-only processing still counts as data handling under the [Chrome Web Store policy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq). Declare these uses accurately in the dashboard, including any category that its current definitions place them in; do not claim that no user data is handled.

The [English privacy policy](../PRIVACY.md) and [Chinese privacy policy](../PRIVACY.zh-CN.md) describe storage, intended website recipients, clipboard behavior, and Limited Use. Store dashboard disclosures must match these policies and the submitted code.

## Submission status

The source, localized text, permission explanations, privacy policies, icons, loadable build, and ZIP package are prepared. Submission remains pending:

- Real Chrome installation and end-to-end verification, with synthetic credentials.
- Screenshots captured from the actual extension after verification.
- A publicly accessible privacy-policy URL; the local file alone is insufficient.
- Developer-account access, dashboard disclosures, reviewer instructions, and submission.

No store listing, review, extension ID, or publication has been created. Do not advertise the development ZIP as an approved store release.

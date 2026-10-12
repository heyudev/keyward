/** Self-contained: Chrome serializes this function into an isolated world. */
export function fillLogin(expectedOrigin, credentials) {
  const fail = (reason) => ({ ok: false, reason });
  if (location.origin !== expectedOrigin || window.top !== window) return fail('pageChanged');
  const current = new URL(location.href);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(current.hostname);
  if (current.protocol !== 'https:' && !(current.protocol === 'http:' && loopback)) return fail('unsupportedSite');
  if (typeof credentials?.username !== 'string' || typeof credentials.password !== 'string' || !credentials.password) {
    return fail('accountUnavailable');
  }

  const visible = (input) => {
    if (!input.isConnected || input.disabled || input.readOnly || input.hidden || !input.getClientRects().length) return false;
    const rect = input.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0 || rect.bottom <= 0 || rect.right <= 0 || rect.top >= window.innerHeight || rect.left >= window.innerWidth) return false;
    for (let node = input; node; node = node.parentElement) {
      const style = window.getComputedStyle(node);
      if (['hidden', 'collapse'].includes(style.visibility) || style.opacity === '0' || style.display === 'none') return false;
    }
    return true;
  };
  const autocomplete = (input) => (input.autocomplete || '').toLowerCase().split(/\s+/).at(-1);
  const inputs = [...document.querySelectorAll('input')];
  const passwords = inputs.filter((input) => input.type === 'password' && visible(input) && autocomplete(input) !== 'new-password');
  if (passwords.length !== 1) return fail(passwords.length ? 'ambiguousForm' : 'noLoginForm');
  const password = passwords[0];

  const safeTarget = () => {
    if (location.origin !== expectedOrigin || password.type !== 'password' || !visible(password) || autocomplete(password) === 'new-password') return false;
    try {
      return new URL(password.form?.action || location.href, location.href).origin === expectedOrigin;
    } catch {
      return false;
    }
  };
  if (!safeTarget()) return fail('unsafeForm');

  let username;
  if (credentials.username) {
    const candidates = inputs.filter((input) => visible(input) && input.form === password.form &&
      ['text', 'email', 'tel'].includes(input.type) && !['new-password', 'one-time-code'].includes(autocomplete(input)));
    const explicit = candidates.filter((input) => autocomplete(input) === 'username');
    const email = candidates.filter((input) => input.type === 'email');
    const preferred = explicit.length ? explicit : email.length ? email : candidates;
    if (preferred.length !== 1) return fail('ambiguousUsername');
    username = preferred[0];
  }

  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  if (!setter) return fail('noLoginForm');
  const write = (input, value) => {
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (username) write(username, credentials.username);
  // Input listeners can remove fields or change the form action synchronously.
  if (!safeTarget()) return fail('unsafeForm');
  write(password, credentials.password);
  return { ok: true };
}

export function probePage() {
  return { origin: location.origin };
}

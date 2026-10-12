/** Exact-origin matching deliberately avoids suffix and substring matching. */
export function websiteOrigin(value, { stored = false } = {}) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const text = value.trim();
  try {
    if (text.startsWith('//')) return null;
    const url = new URL(stored && !text.includes('://') ? `https://${text}` : text);
    if (url.username || url.password) return null;
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

export function loginMatches(item, pageUrl) {
  const origin = websiteOrigin(pageUrl);
  return origin !== null && item?.type === 'login' &&
    typeof item.id === 'string' && typeof item.title === 'string' &&
    typeof item.username === 'string' && typeof item.password === 'string' &&
    item.password.length > 0 && websiteOrigin(item.url, { stored: true }) === origin;
}

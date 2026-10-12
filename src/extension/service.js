import { IDLE_LOCK_MS } from './session.js';

export const DEFAULT_PORT = 8787;

export function serviceOrigin(port = DEFAULT_PORT) {
  const text = String(port);
  if (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65535) throw new Error('invalidPort');
  return `http://127.0.0.1:${Number(text)}`;
}

/** Only a fixed loopback host and path are allowed. Never follow redirects. */
export async function readEnvelope(port, { signal, fetchImpl = globalThis.fetch, timeoutMs = IDLE_LOCK_MS } = {}) {
  const origin = serviceOrigin(port);
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) cancel();
  const timeout = setTimeout(cancel, timeoutMs);
  try {
    const response = await fetchImpl(`${origin}/api/vault`, {
      method: 'GET', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
    });
    if (!response.ok) throw new Error('serverReadFailed');
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) throw new Error('invalidResponse');
    const stored = await response.json();
    if (controller.signal.aborted) throw new Error('sessionCancelled');
    if (stored?.exists === false && stored.envelope === null) throw new Error('noVault');
    if (stored?.exists !== true || stored.envelope?.format !== 'keyward.vault') throw new Error('invalidResponse');
    return stored.envelope;
  } catch (error) {
    if (controller.signal.aborted) throw new Error(signal?.aborted ? 'sessionCancelled' : 'connectionTimedOut');
    if (error instanceof TypeError) throw new Error('serverUnavailable');
    throw error;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', cancel);
  }
}

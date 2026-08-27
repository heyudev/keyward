#!/usr/bin/env node
/**
 * Local-only HTTP server for keyward.
 *
 * Serves the web client and stores the encrypted vault. It binds to loopback
 * only, and by design it never sees the master password or any plaintext: all
 * crypto happens in the browser.
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_VAULT_PATH, readVaultFile, writeVaultFile } from './storage.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(here, '..', 'web');
const CORE_ROOT = path.resolve(here, '..', 'core');

const HOST = process.env.KEYWARD_HOST ?? '127.0.0.1';
const PORT = Number(process.env.PORT ?? 8787);
const MAX_BODY_BYTES = 8 * 1024 * 1024;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

const SECURITY_HEADERS = {
  // No inline scripts or styles, no outbound connections except to ourselves:
  // a vault decrypted in the tab cannot be exfiltrated by injected markup.
  'Content-Security-Policy': [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function send(response, status, body, headers = {}) {
  response.writeHead(status, { ...SECURITY_HEADERS, ...headers });
  response.end(body);
}

function sendJson(response, status, payload, headers = {}) {
  send(response, status, JSON.stringify(payload), {
    'Content-Type': 'application/json; charset=utf-8',
    ...headers,
  });
}

/** Map a URL path to a file, refusing anything that escapes the served roots. */
function resolveStatic(pathname) {
  const [root, relative] = pathname.startsWith('/core/')
    ? [CORE_ROOT, pathname.slice('/core/'.length)]
    : [WEB_ROOT, pathname === '/' ? 'index.html' : pathname.slice(1)];

  const resolved = path.resolve(root, relative);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) return null;
  return resolved;
}

async function readBody(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error('request body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Reject cross-origin writes. A page on another site can make the browser
 * issue a request to localhost; it must not be able to overwrite the vault.
 *
 * Compared against the request's own Host header rather than the configured
 * port, so this holds however the server was started.
 */
function originAllowed(request) {
  const origin = request.headers.origin;
  if (!origin) return true; // curl and friends send no Origin

  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

async function handleApi(request, response, vaultPath) {
  if (request.method === 'GET') {
    const envelope = await readVaultFile(vaultPath);
    return sendJson(response, 200, { exists: envelope !== null, envelope });
  }

  if (request.method === 'PUT') {
    if (!originAllowed(request)) return sendJson(response, 403, { error: 'cross-origin write refused' });

    let envelope;
    try {
      envelope = JSON.parse(await readBody(request));
    } catch (error) {
      return sendJson(response, 400, { error: `invalid request body: ${error.message}` });
    }

    try {
      await writeVaultFile(envelope, vaultPath);
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
    return sendJson(response, 200, { ok: true, savedAt: new Date().toISOString() });
  }

  return sendJson(response, 405, { error: 'method not allowed' }, { Allow: 'GET, PUT' });
}

export function createServer({ vaultPath = DEFAULT_VAULT_PATH } = {}) {
  return http.createServer(async (request, response) => {
    try {
      const { pathname } = new URL(request.url, `http://${request.headers.host ?? 'localhost'}`);

      if (pathname === '/api/vault') return await handleApi(request, response, vaultPath);
      if (request.method !== 'GET') return sendJson(response, 405, { error: 'method not allowed' });

      const file = resolveStatic(pathname);
      if (!file) return send(response, 403, 'forbidden', { 'Content-Type': 'text/plain' });

      try {
        const body = await readFile(file);
        const type = MIME_TYPES[path.extname(file)] ?? 'application/octet-stream';
        return send(response, 200, body, { 'Content-Type': type });
      } catch {
        return send(response, 404, 'not found', { 'Content-Type': 'text/plain' });
      }
    } catch (error) {
      return sendJson(response, 500, { error: error.message });
    }
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  createServer().listen(PORT, HOST, () => {
    console.log(`keyward      http://${HOST}:${PORT}`);
    console.log(`vault file   ${DEFAULT_VAULT_PATH}`);
    console.log('the server stores only encrypted data; the master password never leaves the browser');
  });
}

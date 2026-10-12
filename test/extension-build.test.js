import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inflateSync } from 'node:zlib';
import { buildExtension } from '../scripts/build-extension.js';
import { packageExtension } from '../scripts/package-extension.js';
import { crc32, zipFiles } from '../scripts/archive.js';

test('the build uses the existing crypto source and requests only the reviewed permissions', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'keyward-extension-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await buildExtension(directory);
  const manifest = JSON.parse(await readFile(path.join(directory, 'manifest.json')));
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.minimum_chrome_version, '106');
  assert.equal(manifest.default_locale, 'en');
  assert.deepEqual(manifest.permissions, ['activeTab', 'scripting']);
  assert.deepEqual(manifest.host_permissions, ['http://127.0.0.1/*']);
  for (const key of ['background', 'content_scripts', 'externally_connectable', 'web_accessible_resources']) assert.equal(key in manifest, false);
  assert.match(manifest.content_security_policy.extension_pages, /connect-src http:\/\/127\.0\.0\.1:\*/);
  assert.doesNotMatch(manifest.content_security_policy.extension_pages, /unsafe-eval|unsafe-inline|https:/);
  for (const file of ['crypto.js', 'vault.js', 'generator.js', 'wordlist.js']) {
    assert.deepEqual(await readFile(path.join(directory, 'src/core', file)), await readFile(new URL(`../src/core/${file}`, import.meta.url)));
  }
  await readFile(path.join(directory, manifest.action.default_popup));
  for (const icon of Object.values(manifest.icons)) await readFile(path.join(directory, icon));
  assert.deepEqual((await readdir(path.join(directory, 'src'))).sort(), ['core', 'extension']);
  const en = JSON.parse(await readFile(path.join(directory, '_locales/en/messages.json')));
  const zh = JSON.parse(await readFile(path.join(directory, '_locales/zh_CN/messages.json')));
  assert.deepEqual(Object.keys(en).sort(), Object.keys(zh).sort());
  const html = await readFile(path.join(directory, manifest.action.default_popup), 'utf8');
  for (const [, key] of html.matchAll(/data-i18n="([^"]+)"/g)) assert.ok(en[key]?.message && zh[key]?.message, key);

  // Inspect every stored ZIP entry and verify its CRC with no external tools.
  const archive = await packageExtension(directory);
  assert.deepEqual(await packageExtension(directory), archive, 'packaging is deterministic');
  const entries = new Map();
  let offset = 0;
  while (archive.readUInt32LE(offset) === 0x04034b50) {
    const size = archive.readUInt32LE(offset + 18);
    const nameSize = archive.readUInt16LE(offset + 26);
    const extraSize = archive.readUInt16LE(offset + 28);
    const start = offset + 30 + nameSize + extraSize;
    const name = archive.subarray(offset + 30, offset + 30 + nameSize).toString();
    const data = archive.subarray(start, start + size);
    assert.equal(crc32(data), archive.readUInt32LE(offset + 14), name);
    entries.set(name, data);
    offset = start + size;
  }
  assert.equal(archive.readUInt32LE(offset), 0x02014b50);
  assert.equal(archive.readUInt32LE(archive.length - 22), 0x06054b50);
  assert.equal(entries.size, archive.readUInt16LE(archive.length - 14));
  assert.deepEqual(JSON.parse(entries.get('manifest.json')), manifest);
  assert.ok(entries.has('LICENSE'));
  assert.equal([...entries.keys()].some((name) => /vault\.json|server\/|\.bak$/.test(name)), false);

  for (const [size, name] of Object.entries(manifest.icons)) {
    const png = entries.get(name);
    assert.equal(png.readUInt32BE(16), Number(size));
    assert.equal(png.readUInt32BE(20), Number(size));
    const dataSize = png.readUInt32BE(33);
    const decoded = inflateSync(png.subarray(41, 41 + dataSize));
    assert.equal(decoded.length, Number(size) * (Number(size) * 4 + 1));
  }
});

test('archives reject absolute paths and path traversal', () => {
  for (const name of ['/manifest.json', '../vault.json', 'src/../../vault.json']) {
    assert.throws(() => zipFiles([[name, Buffer.from('no')]]), /invalid archive path/);
  }
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});

import { copyFile, cp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lockIcon } from './icons.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const extensionDirectory = path.join(root, 'dist', 'chrome');

export async function buildExtension(output = extensionDirectory) {
  await rm(output, { recursive: true, force: true });
  await mkdir(path.join(output, 'src', 'extension'), { recursive: true });
  await mkdir(path.join(output, 'src', 'core'), { recursive: true });
  await mkdir(path.join(output, 'icons'), { recursive: true });
  await copyFile(path.join(root, 'src/extension/manifest.json'), path.join(output, 'manifest.json'));
  await copyFile(path.join(root, 'LICENSE'), path.join(output, 'LICENSE'));
  await cp(path.join(root, 'src/extension/_locales'), path.join(output, '_locales'), { recursive: true });
  for (const file of await readdir(path.join(root, 'src/extension'))) {
    if (/\.(js|html|css)$/.test(file)) await copyFile(path.join(root, 'src/extension', file), path.join(output, 'src/extension', file));
  }
  for (const file of ['crypto.js', 'vault.js', 'generator.js', 'wordlist.js']) {
    await copyFile(path.join(root, 'src/core', file), path.join(output, 'src/core', file));
  }
  for (const size of [16, 32, 48, 128]) await writeFile(path.join(output, `icons/${size}.png`), lockIcon(size));
  return output;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(`Extension built: ${await buildExtension()}`);
}

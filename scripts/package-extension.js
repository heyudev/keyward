import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildExtension } from './build-extension.js';
import { zipFiles } from './archive.js';

export async function packageExtension(directory) {
  const files = [];
  async function walk(relative = '') {
    for (const entry of (await readdir(path.join(directory, relative), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile()) files.push([name, await readFile(path.join(directory, name))]);
      else throw new Error('extension bundles must not contain symlinks');
    }
  }
  await walk();
  return zipFiles(files);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = await buildExtension();
  const manifest = JSON.parse(await readFile(path.join(directory, 'manifest.json'), 'utf8'));
  const archive = path.join(path.dirname(directory), `keyward-chrome-${manifest.version}.zip`);
  await writeFile(archive, await packageExtension(directory));
  console.log(`Extension packaged: ${archive}`);
}

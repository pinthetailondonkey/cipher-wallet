// The build gate for a plain-ESM library: every source file must parse AND
// resolve. A syntax error is caught here, not at runtime on a vendor's device.
import { readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = new URL('..', import.meta.url).pathname;
const src = join(root, 'src');

const files = (await readdir(src, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith('.js'))
  .map((entry) => join(src, entry.name))
  .sort();

if (files.length === 0) {
  console.error('build: no source files found');
  process.exit(1);
}

let failed = false;
for (const file of files) {
  try {
    await import(pathToFileURL(file).href);
    console.log(`ok   ${relative(root, file)}`);
  } catch (error) {
    failed = true;
    console.error(`FAIL ${relative(root, file)}: ${error.message}`);
  }
}

if (failed) process.exit(1);
console.log(`build: ${files.length} modules resolved`);

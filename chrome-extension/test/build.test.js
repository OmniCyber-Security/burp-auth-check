import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { build, checkVersion } from '../build.mjs';

/** Reads a zip back through its central directory, as Chrome's unzip would. */
function unzip(buffer) {
  const end = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = buffer.readUInt16LE(end + 10);
  let at = buffer.readUInt32LE(end + 16);
  const out = new Map();
  for (let i = 0; i < count; i++) {
    assert.equal(buffer.readUInt32LE(at), 0x02014b50);
    const size = buffer.readUInt32LE(at + 20);
    const nameLength = buffer.readUInt16LE(at + 28);
    const local = buffer.readUInt32LE(at + 42);
    const name = buffer.toString('utf8', at + 46, at + 46 + nameLength);
    const dataAt = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
    out.set(name, inflateRawSync(buffer.subarray(dataAt, dataAt + size)));
    at += 46 + nameLength;
  }
  return out;
}

const outDir = () => mkdtempSync(join(tmpdir(), 'acr-build-'));

test('the package holds the extension and nothing it does not need', () => {
  const { path } = build({ outDir: outDir() });
  const names = [...unzip(readFileSync(path)).keys()];
  for (const required of ['manifest.json', 'src/background.js', 'src/editor.html', 'src/popup.html',
    'src/lib/analyse.js', 'icons/icon128.png']) {
    assert.ok(names.includes(required), `${required} missing from ${names}`);
  }
  assert.ok(!names.some((n) => n.startsWith('test/') || n === 'build.mjs' || n === 'package.json'), names.join(', '));
});

test('every file the manifest and pages point at is in the package', () => {
  const entries = unzip(readFileSync(build({ outDir: outDir() }).path));
  const manifest = JSON.parse(entries.get('manifest.json'));
  const referenced = [manifest.background.service_worker, manifest.action.default_popup,
    ...Object.values(manifest.icons)];
  for (const page of ['src/popup.html', 'src/editor.html']) {
    for (const [, ref] of entries.get(page).toString().matchAll(/(?:src|href)="([^"]+)"/g)) referenced.push(`src/${ref}`);
  }
  for (const [name, data] of entries) {
    if (!name.endsWith('.js')) continue;
    const dir = name.slice(0, name.lastIndexOf('/') + 1);
    for (const [, ref] of data.toString().matchAll(/from '(\.[^']+)'/g)) {
      referenced.push(new URL(ref, `file:///${dir}`).pathname.slice(1));
    }
  }
  for (const ref of referenced) assert.ok(entries.has(ref), `${ref} is referenced but not packaged`);
});

test('the release version is stamped into the packaged manifest', () => {
  const { path, version } = build({ version: '2.7.1', outDir: outDir() });
  assert.equal(version, '2.7.1');
  assert.match(path, /auth-check-recorder-2\.7\.1\.zip$/);
  assert.equal(JSON.parse(unzip(readFileSync(path)).get('manifest.json')).version, '2.7.1');
});

test('the same source builds the same bytes', () => {
  const a = readFileSync(build({ version: '1.0.0', outDir: outDir() }).path);
  const b = readFileSync(build({ version: '1.0.0', outDir: outDir() }).path);
  assert.ok(a.equals(b));
});

test('a version Chrome would reject fails the build', () => {
  for (const bad of ['1.0.0-beta', 'v1.0.0', '1.0.0.0.0', '01.2', '70000']) {
    assert.throws(() => checkVersion(bad), /not a Chrome extension version/, bad);
  }
  for (const good of ['1', '1.2', '1.2.3', '1.2.3.4', '65535.0.0']) assert.equal(checkVersion(good), good);
});

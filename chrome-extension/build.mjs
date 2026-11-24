#!/usr/bin/env node
// Packages the extension as a zip for "Load unpacked".
//
//   node build.mjs                      -> dist/auth-check-recorder-<manifest version>.zip
//   node build.mjs --version 1.4.0      -> stamps 1.4.0 into the packaged manifest
//
// The release job passes the version it is about to tag, so the extension
// inside the zip says the same version as the release and the jar beside it.
// The manifest in the repository is only the fallback for local builds, the
// same arrangement as `version` in gradle.properties.
//
// No dependencies: the zip is written by hand (stored entries deflated with
// node:zlib), with fixed timestamps and sorted entries, so the same source
// always produces the same bytes.

import { readFileSync, readdirSync, statSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep, dirname } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
/** What ships. Tests, fixtures and tooling stay out. */
const INCLUDE = ['manifest.json', 'src', 'icons', 'README.md'];

export function files(root = ROOT) {
  const out = [];
  const walk = (path) => {
    if (statSync(path).isDirectory()) {
      for (const name of readdirSync(path)) walk(join(path, name));
    } else {
      out.push(relative(root, path).split(sep).join('/'));
    }
  };
  for (const entry of INCLUDE) walk(join(root, entry));
  return out.sort();
}

/** Chrome accepts one to four dot-separated integers, each at most 65535. */
export function checkVersion(version) {
  const parts = String(version).split('.');
  if (parts.length < 1 || parts.length > 4 || parts.some((p) => !/^(0|[1-9][0-9]{0,4})$/.test(p) || Number(p) > 65535)) {
    throw new Error(`'${version}' is not a Chrome extension version (1-4 dot-separated integers up to 65535)`);
  }
  return version;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** A zip of [name, Buffer] entries. Timestamps are fixed at 1980-01-01. */
export function zip(entries) {
  const DOS_TIME = 0;
  const DOS_DATE = (0 << 9) | (1 << 5) | 1;
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBytes = Buffer.from(name, 'utf8');
    const compressed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);          // version needed
    local.writeUInt16LE(0x0800, 6);      // UTF-8 names
    local.writeUInt16LE(8, 8);           // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBytes, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);    // made by: unix, 2.0
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38); // -rw-r--r--
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);

    offset += 30 + nameBytes.length + compressed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** @returns { path, version, files } of the zip written. */
export function build({ version, root = ROOT, outDir = join(root, 'dist') } = {}) {
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  const stamped = checkVersion(version ?? manifest.version);
  manifest.version = stamped;

  const names = files(root);
  const entries = names.map((name) => [name, name === 'manifest.json'
    ? Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)
    : readFileSync(join(root, name))]);

  mkdirSync(outDir, { recursive: true });
  const path = join(outDir, `auth-check-recorder-${stamped}.zip`);
  writeFileSync(path, zip(entries));
  return { path, version: stamped, files: names };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf('--version');
  const version = at > 0 ? process.argv[at + 1] : undefined;
  if (at > 0 && !version) {
    console.error('--version needs a value');
    process.exit(2);
  }
  try {
    const { path, files: names } = build({ version });
    console.log(`${relative(process.cwd(), path)} (${names.length} files)`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

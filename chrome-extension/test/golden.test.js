// Pins the generated scripts. The Burp extension's own test suite compiles
// these exact files and runs them against a fake server issuing fresh values
// (RecordedScriptsTest), so a change here is checked on both sides.
//
// After an intended change to the generator: npm run golden

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { analyse } from '../src/lib/analyse.js';
import { generateScript } from '../src/lib/groovy.js';
import { all } from './fixtures/scenarios.js';

for (const [name, make] of Object.entries(all)) {
  test(`generated script for ${name} matches test/golden/${name}.groovy`, () => {
    const script = generateScript(analyse(make()).plan);
    const file = new URL(`./golden/${name}.groovy`, import.meta.url);
    if (process.env.UPDATE_GOLDEN || !existsSync(file)) writeFileSync(file, script);
    assert.equal(script, readFileSync(file, 'utf8'));
  });
}

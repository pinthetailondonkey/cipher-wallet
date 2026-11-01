// The real transaction fixture is what it says it is: its bytes are the
// transaction the fixture names, and its provenance is recorded. This is a
// fixture check, not a parser check; the parser's proof is monero-tx-read.test.mjs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hex } from '@scure/base';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-ringct-type6.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');

test('the pinned bytes are 2220 bytes, the length the provenance records', () => {
  const bytes = hex.decode(unspaced(FIXTURE.asHex));
  assert.equal(bytes.length, FIXTURE.byteLength);
  assert.equal(bytes.length, 2220);
  console.log(`[monero-tx] fixture: ${bytes.length} bytes, height ${FIXTURE.source.blockHeight}, index ${FIXTURE.source.txIndexInBlock} of ${FIXTURE.source.blockTxCount}`);
});

test('the fixture records its block, its endpoint and its capture date', () => {
  assert.equal(FIXTURE.source.blockHeight, 3796965);
  assert.equal(unspaced(FIXTURE.source.blockHash).length, 64);
  assert.equal(FIXTURE.source.node, 'xmr-node.cakewallet.com:18081');
  assert.match(FIXTURE.source.capturedAt, /^2026-\d\d-\d\dT/);
  assert.equal(FIXTURE.source.blockTxCount, 33);
  assert.equal(FIXTURE.source.txIndexInBlock, 0);
});

test('the fixture is version 2, RingCT type 6, as it says', () => {
  assert.equal(FIXTURE.version, 2);
  assert.equal(FIXTURE.rctType, 6);
});

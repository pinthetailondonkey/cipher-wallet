// The walk's own mutation sweep: controls on blockWalk beyond the needle
// tests, per Zebra-1's call. The needle tests flip bytes inside each tx
// section; these controls attack the WALK's own inputs and assumptions:
//
//   1. a flipped byte in the BLOCK's hash list (the walk's other input) must
//      be refused by the slot it broke, with the bytes untouched
//   2. a flipped byte in the MINER tx id (the walk's tree-root input) must
//      be caught by the root check, not the slot check
//   3. a tx bytes array in the WRONG ORDER (a permutation of real txs) must
//      be refused at the first disagreeing slot
//   4. a DUPLICATED tx bytes array (the same tx twice) must be refused if
//      the list has more entries than the dup covers
//   5. a walk where every tx byte is intact but one tx's LENGTH claim in the
//      fixture disagrees is not the walk's business (the fixture records
//      byteLength; the walk reads the bytes) - so no control there; noted so
//      the reader knows the boundary
//
// Every refusal is named. Every control uses the REAL pinned block 3796965
// bytes, not synthetic ones.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const BLOCK_FIXTURE = read('monero-block-3796965.json');
const TXS_FIXTURE = read('monero-block-3796965-txs.json');
const BLOCK_BYTES = bytesOf(BLOCK_FIXTURE.block.blob);
const block = parseBlock(BLOCK_BYTES);
const TX_BYTES = TXS_FIXTURE.txs.map((t) => bytesOf(t.asHex));

test('control 1: a flipped hash-list entry refuses its own slot, bytes untouched', () => {
  const flip = (h) => {
    const chars = h.split('');
    const at = 10;
    chars[at] = chars[at] === 'a' ? 'b' : 'a';
    return chars.join('');
  };
  const mutated = { ...block, txHashes: block.txHashes.map((h, i) => (i === 5 ? flip(h) : h)) };
  assert.throws(
    () => walkBlockTxs(mutated, TX_BYTES),
    /bytes and list do not agree: hash-list index 5/,
    'the refusal names the exact slot whose list entry no longer matches the bytes',
  );
});

test('control 2: a flipped miner id is caught by the tree-root check, not a slot check', () => {
  // the miner id sits OUTSIDE the hash list: it enters the walk only through
  // the tree root. Flipping it must leave every slot agreeing and still fail
  // on the root, which proves the root check is load-bearing on its own.
  const flippedMiner = block.minerTxId.slice(0, 10) +
    (block.minerTxId[10] === 'a' ? 'b' : 'a') + block.minerTxId.slice(11);
  const mutated = { ...block, minerTxId: flippedMiner };
  assert.throws(
    () => walkBlockTxs(mutated, TX_BYTES),
    /the proven ids build tree root/,
    'the root check catches a miner-id lie the slot checks cannot see',
  );
});

test('control 3: a permuted tx bytes list is refused at the first disagreeing slot', () => {
  // swap txs 3 and 7 wholesale: bytes intact, order wrong
  const swapped = TX_BYTES.slice();
  const tmp = swapped[3];
  swapped[3] = swapped[7];
  swapped[7] = tmp;
  assert.throws(
    () => walkBlockTxs(block, swapped),
    /bytes and list do not agree: hash-list index 3/,
    'the first wrong slot is named, not the whole list',
  );
});

test('control 4: a duplicated tx array is refused by the count, then the slot', () => {
  // duplicating tx0 into slot 1 shortens the array by one (32 vs 33), so the
  // count check fires first and names the arithmetic lie. The per-slot lie is
  // already covered by control 1; this control proves the count gate catches
  // a duplication that hides one real transaction.
  const duplicated = [TX_BYTES[0], TX_BYTES[0], ...TX_BYTES.slice(2, TX_BYTES.length - 1)];
  assert.equal(duplicated.length, 32, 'the dup array is one short: a real tx was replaced by a copy');
  assert.throws(
    () => walkBlockTxs(block, duplicated),
    /the count and the list do not agree: the block lists 33 transactions, 32 were fetched/,
    'the count gate catches the hidden transaction',
  );
});

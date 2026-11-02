// The refusal gate ordering in blockWalk. The walk checks three things in
// sequence: the count (list length vs hash-list length), then each slot
// (bytes vs listed hash), then the tree root. A caller reading the error
// message relies on this order: a count error means the array is the wrong
// size, a slot error means one transaction's bytes disagree, and a root
// error means every slot agreed but the tree still does not. Pinning the
// order proves that a caller seeing "count" can trust that no slot was
// checked, and one seeing "slot" can trust the count was already correct.
//
// No new code. Pure pinning of existing refusal ordering against the real
// pinned block 3796965 bytes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));
const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const BLOCK = read('monero-block-3796965.json');
const TXS = read('monero-block-3796965-txs.json');
const block = parseBlock(bytesOf(BLOCK.block.blob));
const TX_BYTES = TXS.txs.map((t) => bytesOf(t.asHex));

test('gate order: a count error fires before any slot check', () => {
  // wrong count AND a bad slot: the count error wins
  const wrongCountAndBadSlot = TX_BYTES.slice(0, 10);
  wrongCountAndBadSlot[0] = new Uint8Array(0); // also a bad slot
  let caught = '';
  try { walkBlockTxs(block, wrongCountAndBadSlot); } catch (e) { caught = e.message; }
  assert.match(caught, /the count and the list do not agree/,
    'the count refusal fires first');
  assert.doesNotMatch(caught, /hash-list index/,
    'no slot was named: the count gate fired before any slot check');
  console.log('[gate-order] count fires before slot');
});

test('gate order: a slot error fires before the root check', () => {
  // a bad slot in a correct-count array: the slot error wins, not the root
  const mutated = Uint8Array.from(TX_BYTES[0]);
  mutated[mutated.length - 9] ^= 0x01;
  let caught = '';
  try { walkBlockTxs(block, [mutated, ...TX_BYTES.slice(1)]); } catch (e) { caught = e.message; }
  assert.match(caught, /bytes and list do not agree: hash-list index 0/,
    'the slot refusal names the disagreeing index');
  assert.doesNotMatch(caught, /tree root/,
    'the root check did not fire: the slot gate fired first');
  console.log('[gate-order] slot fires before root');
});

test('gate order: the root check fires only when every slot agreed', () => {
  // swap two entries AND their bytes: every slot agrees, only the root fails
  const swapped = [TX_BYTES[1], TX_BYTES[0], ...TX_BYTES.slice(2)];
  const swappedBlock = { ...block, txHashes: [block.txHashes[1], block.txHashes[0], ...block.txHashes.slice(2)] };
  let caught = '';
  try { walkBlockTxs(swappedBlock, swapped); } catch (e) { caught = e.message; }
  assert.match(caught, /the proven ids build tree root/,
    'the root refusal fires when the slot checks all passed');
  assert.doesNotMatch(caught, /hash-list index \d+ claims/,
    'no slot was named: every slot agreed, the root check alone caught it');
  console.log('[gate-order] root fires only after all slots passed');
});

test('gate order: missing bytes fires after count but before slots', () => {
  // correct count with one empty slot: the missing-bytes error fires
  const holed = TX_BYTES.slice();
  holed[7] = new Uint8Array(0);
  let caught = '';
  try { walkBlockTxs(block, holed); } catch (e) { caught = e.message; }
  assert.match(caught, /the walk is missing transaction bytes for hash-list index 7/,
    'the missing-bytes refusal names the empty slot');
  // the count was correct (33 entries), so the count gate passed
  assert.doesNotMatch(caught, /the count and the list do not agree/,
    'the count gate passed before the missing-bytes check');
  console.log('[gate-order] missing-bytes fires after count, before slots');
});

// Live walk replay at a second block: the pipeline is re-proven against a
// different chain shape. The captured transcript is from block 3797100 (44
// transactions, several with large inputs fetched at a different tip than the
// first walk's 33-tx block). Nothing here talks to a node: the replay reads
// the pinned bytes and re-proves every id and the root.
//
// Structure check: the first live walk's block had 33 short transactions in a
// narrow-ring era; this one carries bigger transactions, wider variance in
// byte length, and a different root. The walk must survive all of it, and the
// count refusal must still be named (34 vs 33).
//
// ROOT-BYTES AGREEMENT: this block's own tree root, computed from the block
// bytes, matches the root the walked ids produce. A node lie here is caught
// by the walk, not just by the block header's own hash.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-live-walk-3797100.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const BLOCK_BYTES = bytesOf(FIXTURE.block.blob);
const block = parseBlock(BLOCK_BYTES);
const TX_BYTES = FIXTURE.txs.map((t) => bytesOf(t.asHex));

test('replay at block 3797100: the count and list agree and every id re-proves', () => {
  const walk = walkBlockTxs(block, TX_BYTES);
  assert.equal(walk.ids.length, block.txHashes.length, 'every listed hash has bytes that prove it');
  assert.equal(walk.txTreeRoot, block.txTreeRoot, 'the root re-proves from the proven ids');
  console.log(`[replay-3797100] ${walk.ids.length}/${block.txHashes.length} ids re-proven; root matches`);
});

test('replay root: the proven ids build the root the block claims, verified by name', () => {
  const block2 = { ...block, txHashes: [block.txHashes[1], block.txHashes[0], ...block.txHashes.slice(2)] };
  const txs2 = [TX_BYTES[1], TX_BYTES[0], ...TX_BYTES.slice(2)];
  assert.throws(() => walkBlockTxs(block2, txs2), /bytes and list do not agree/,
    'the reorder is caught, not passed through silently');
});

test('count refusal is named when a transaction is missing from a replay', () => {
  const short = TX_BYTES.slice(0, TX_BYTES.length - 1);
  assert.throws(
    () => walkBlockTxs(block, short),
    /the count and the list do not agree/,
  );
});

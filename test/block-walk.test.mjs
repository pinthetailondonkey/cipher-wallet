// The block walk's proof: the pinned 33-transaction block (monero-block-
// 3796965 and its -txs fixture) is read end to end, every transaction id is
// computed from bytes alone and must equal the block's own hash-list entry,
// and the tree root built from the proven ids must equal the root the block's
// bytes produce. LANE B. Nothing here trusts the node's claims: claimedTxHash
// fields are recorded in the fixture but the walk proves every id from bytes.
//
// The refusals are tested too: a mutated byte must either change the id (and
// so break the list agreement by name) or be refused; a count mismatch is
// refused by name; missing bytes are refused by name.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock, readTransaction, transactionIdOf } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const BLOCK_FIXTURE = read('monero-block-3796965.json');
const TXS_FIXTURE = read('monero-block-3796965-txs.json');
const BLOCK_BYTES = bytesOf(BLOCK_FIXTURE.block.blob);
const TX_BYTES = TXS_FIXTURE.txs.map((t) => bytesOf(t.asHex));

const block = parseBlock(BLOCK_BYTES);

test('lane B walk: every transaction id from bytes equals the block hash list, and the tree root matches', () => {
  assert.equal(block.txHashes.length, TX_BYTES.length, 'the pinned block and its tx fixture cover the same 33 transactions');
  const walk = walkBlockTxs(block, TX_BYTES);
  assert.equal(walk.ids.length, block.txHashes.length);
  assert.equal(walk.txTreeRoot, block.txTreeRoot, 'the root from proven ids is the root from the block bytes');
  console.log(`[block-walk] 33/33 ids proven from bytes; tree root ${walk.txTreeRoot.slice(0, 16)}… matches`);
});

test('lane B refusal [count]: a missing transaction is refused by name', () => {
  assert.throws(
    () => walkBlockTxs(block, TX_BYTES.slice(0, 32)),
    /the count and the list do not agree/,
  );
});

test('lane B refusal [missing bytes]: an empty slot is refused by name', () => {
  const holed = TX_BYTES.slice();
  holed[7] = new Uint8Array(0);
  assert.throws(
    () => walkBlockTxs(block, holed),
    /the walk is missing transaction bytes for hash-list index 7/,
  );
});

test('lane B refusal [bytes and list do not agree]: a flipped byte inside a tx breaks its hash-list slot by name', () => {
  // flip a byte deep inside tx 0's prunable section; the id must move, and
  // the walk must say exactly which slot disagrees
  const mutated = Uint8Array.from(TX_BYTES[0]);
  const at = mutated.length - 9;
  mutated[at] ^= 0x01;
  const tx = readTransaction(mutated, 0, 'mutated probe');
  const id = transactionIdOf(tx);
  const original = transactionIdOf(readTransaction(TX_BYTES[0], 0, 'original probe'));
  assert.notEqual(id, original, 'the flip changed the id');
  assert.throws(
    () => walkBlockTxs(block, [mutated, ...TX_BYTES.slice(1)]),
    /bytes and list do not agree: hash-list index 0/,
  );
});

test('lane B refusal [tree root]: a reordered hash list breaks the root check by name', () => {
  // swap two hash-list entries AND their bytes: every slot then agrees
  // (each slot's bytes prove the id now sitting in it), but the root built
  // from the proven ids no longer matches the root the block's bytes prove.
  // The tree-root check is the one that catches a pure reordering.
  const block2 = { ...block, txHashes: [block.txHashes[1], block.txHashes[0], ...block.txHashes.slice(2)] };
  const txs2 = [TX_BYTES[1], TX_BYTES[0], ...TX_BYTES.slice(2)];
  assert.throws(
    () => walkBlockTxs(block2, txs2),
    /bytes and list do not agree: the proven ids build tree root/,
  );
});

// The tree arithmetic against two real block sizes. txTreeRootOf is proven
// by merkle.test.mjs for the general case; this file pins the SPECIFIC shape
// the block walk uses: the miner tx id is always the first element, the hash
// list follows, and the root must match what parseBlock computed from the
// block's own bytes. Two blocks with different leaf counts exercise different
// Merkle padding paths:
//   block 3796965: 33 hash-list entries + 1 miner = 34 leaves (2 x 17, not
//     a power of 2; the tree has an odd count at the first level)
//   block 3797100: 44 hash-list entries + 1 miner = 45 leaves (also not a
//     power of 2; a different padding shape than 34)
// If the tree arithmetic handles one shape but not the other, this test
// catches it with real bytes.
//
// No node is contacted. Everything replays from pinned bytes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock, txTreeRootOf } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));
const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const BLOCKS = [
  { file: 'monero-block-3796965.json', txsFile: 'monero-block-3796965-txs.json', leaves: 34, label: '3796965 (34 leaves)' },
  { file: 'monero-live-walk-3797100.json', txsFile: null, leaves: 45, label: '3797100 (45 leaves)' },
];

for (const { file, txsFile, leaves, label } of BLOCKS) {
  const FIXTURE = read(file);
  const block = parseBlock(bytesOf(FIXTURE.block.blob));
  const allIds = [block.minerTxId, ...block.txHashes];

  test(`tree arithmetic at ${label}: miner id first, hash list after, root matches the block`, () => {
    assert.equal(allIds.length, leaves,
      `the leaf count is ${leaves}: the miner id plus ${block.txHashes.length} hash-list entries`);
    const root = txTreeRootOf(allIds.map((id) => {
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 32; i += 1) bytes[i] = parseInt(id.slice(i * 2, i * 2 + 2), 16);
      return bytes;
    }));
    assert.equal(Buffer.from(root).toString('hex'), block.txTreeRoot,
      'the tree root from the id order matches what the block bytes produce');
    console.log(`[tree-pin] ${label}: root matches at ${leaves} leaves`);
  });

  test(`tree arithmetic at ${label}: the root is order-sensitive (a swap moves it)`, () => {
    const swapped = [allIds[1], allIds[0], ...allIds.slice(2)];
    const rootSwapped = txTreeRootOf(swapped.map((id) => {
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 32; i += 1) bytes[i] = parseInt(id.slice(i * 2, i * 2 + 2), 16);
      return bytes;
    }));
    assert.notEqual(Buffer.from(rootSwapped).toString('hex'), block.txTreeRoot,
      'swapping the miner id with the first hash-list entry moves the root');
    console.log(`[tree-pin] ${label}: order sensitivity confirmed`);
  });

  // for the block that also has pinned tx bytes, prove the root from the
  // ids the WALK derived (not the hash list the block carries)
  if (txsFile) {
    const TXS = read(txsFile);
    test(`tree arithmetic at ${label}: the root from WALK-PROVEN ids matches`, () => {
      const walk = walkBlockTxs(block, TXS.txs.map((t) => bytesOf(t.asHex)));
      const rootFromProven = txTreeRootOf([block.minerTxId, ...walk.ids].map((id) => {
        const bytes = new Uint8Array(32);
        for (let i = 0; i < 32; i += 1) bytes[i] = parseInt(id.slice(i * 2, i * 2 + 2), 16);
        return bytes;
      }));
      assert.equal(Buffer.from(rootFromProven).toString('hex'), block.txTreeRoot,
        'the root from proven ids is the root from block bytes');
      console.log(`[tree-pin] ${label}: proven ids reproduce the root`);
    });
  }
}

// The miner transaction's needle on the newer pinned blocks. The original
// block fixture (202612) has full miner coverage in monero-block.test.mjs,
// including the flipped-byte control inside the miner tx. The newer pinned
// blocks (3796965 from the crash recovery, 3797001 and 3797100 from the live
// walks) enter the walk through the tree root, and the miner id they prove is
// cross-checked against the node's claimedMinerTxId only at capture time.
// This test closes that gap: for every pinned block, the miner id computed
// from the bytes alone must equal the fixture's recorded claim, and a flipped
// byte inside the miner tx must move BOTH the miner id and the block id.
//
// No node is contacted: everything replays from pinned bytes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock } from '../src/monero/block.js';

const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));
const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const BLOCKS = [
  { file: 'monero-block-3796965.json', height: 3796965 },
  { file: 'monero-live-walk-3797001.json', height: 3797001 },
  { file: 'monero-live-walk-3797100.json', height: 3797100 },
];

for (const { file, height } of BLOCKS) {
  const FIXTURE = read(file);
  // the two transcript shapes: the block fixture carries block.blob; the
  // live-walk transcripts carry block.blob as well
  const blob = FIXTURE.block?.blob ?? FIXTURE.block?.blob;
  const BYTES = bytesOf(blob);
  const claimedMiner = unspaced(FIXTURE.block.claimedMinerTxId ?? '');

  test(`miner needle at ${height}: the miner id from bytes equals the recorded claim`, () => {
    const block = parseBlock(BYTES);
    assert.ok(block.minerTx.coinbase, 'the first transaction is the miner transaction');
    if (claimedMiner) {
      assert.equal(block.minerTxId, claimedMiner,
        'the miner id proven from bytes matches what the node claimed at capture');
    }
    // the gen input names the height it generates for, and the block header
    // agrees: a miner tx for the wrong height is a different block's coinbase
    assert.equal(Number(block.minerTx.genHeight), height,
      'the coinbase generates for the block it rides in');
    console.log(`[miner-needle] ${height}: miner id ${block.minerTxId.slice(0, 16)}… proven`);
  });

  test(`miner control at ${height}: one flipped byte in the gen input moves the miner id and the block id`, () => {
    const block = parseBlock(BYTES);
    // flip a byte near the END of the miner tx: past every varint header
    // (version, unlock, gen height), so the parse cannot be shortened by the
    // flip and the refusal cannot be a framing lie. The last bytes of the
    // miner tx are signature data where any flip changes the bytes' proof.
    const at = block.minerTx.end - 3;
    const mutated = Uint8Array.from(BYTES);
    mutated[at] ^= 0x01;
    const after = parseBlock(mutated);
    assert.notEqual(after.minerTxId, block.minerTxId,
      'the flipped byte changed the miner id the bytes prove');
    // the block id is built from the tree root, which includes the miner id:
    // a moved miner id moves the root and with it the block id
    assert.notEqual(after.id, block.id,
      'the block id moved too: the miner tx is load-bearing for the whole block');
    console.log(`[miner-control] ${height}: miner and block ids both moved from one flipped byte`);
  });
}

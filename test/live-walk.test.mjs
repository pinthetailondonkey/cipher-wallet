// The live walk's proof: the pinned transcript of one real end-to-end walk
// (scripts/fetch-monero-live-walk.mjs, block 3797001 over Tor) is replayed
// with NO node. The block bytes are re-parsed, every transaction id is
// recomputed from the pinned bytes, and the tree root is re-proven. The
// fixture's provenId fields are the capture's COMPUTED values - the replay
// must reproduce them, not read them. A node claim (claimedHash) is checked
// exactly once, against the proven id, to show the capture caught a lie
// would have been caught had the node told one.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-live-walk-3797001.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

test('live walk replay: the pinned block re-parses to its recorded proven id', () => {
  const bytes = bytesOf(FIXTURE.block.blob);
  const block = parseBlock(bytes);
  assert.equal(block.id, unspaced(FIXTURE.block.provenId), 'the replayed id is the id the live walk computed');
  assert.equal(block.txHashes.length, FIXTURE.block.txCount);
  console.log(`[live-walk-replay] block ${FIXTURE.block.provenId.slice(0, 16)}… re-proven from bytes alone`);
});

test('live walk replay: every transaction id re-proves from its pinned bytes', () => {
  const bytes = bytesOf(FIXTURE.block.blob);
  const block = parseBlock(bytes);
  const txBytes = FIXTURE.txs.map((t) => bytesOf(t.asHex));
  const walk = walkBlockTxs(block, txBytes);
  // the replay's proven ids must equal the capture's recorded proven ids -
  // the capture's ids were computed, not claimed, so this is reproduction
  assert.deepEqual(walk.ids, FIXTURE.txs.map((t) => unspaced(t.provenId)));
  assert.equal(walk.txTreeRoot, unspaced(FIXTURE.walk.txTreeRoot));
  assert.equal(walk.txTreeRoot, block.txTreeRoot);
  assert.equal(FIXTURE.walk.rootMatchesBlock, true, 'the live capture recorded a matching root');
  console.log(`[live-walk-replay] ${walk.ids.length}/${FIXTURE.block.txCount} ids re-proven; root matches`);
});

test('live walk replay: the node claim was checked once and agrees with the bytes', () => {
  // provenance honesty: the capture cross-checked the node's claimedHash
  // against the proven id. The replay asserts the recorded agreement.
  assert.equal(unspaced(FIXTURE.block.claimedHash), unspaced(FIXTURE.block.provenId),
    'the live capture recorded claimedHash == provenId; a node lie at capture time would have refused the walk');
});

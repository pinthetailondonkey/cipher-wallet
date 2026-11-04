// The node driver: fetch -> prove -> scan, over a stubbed node so this runs
// without network. The live half is proven separately; this proves the ORDER and
// the identity handoff, which are the two things a driver can get wrong.
//
// What a driver can get wrong, and is checked here:
//   1. Scanning the block a node SERVED without checking it is the block that was
//      ASKED for. Asking by hash must refuse a node that answers with another
//      block, before any pocket sees bytes.
//   2. Believing the node's transaction hash list. The walk proves each id; a
//      node that lists a tx it does not carry is refused at the fetch door, and
//      a node that lists a hash whose bytes disagree is refused at the walk.
//   3. Asking by height and trusting the height claim. The id is proven from the
//      bytes; the recorded claim is not what the proof uses.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { scanBlockFromNode } from '../src/monero/scanFromNode.js';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';

const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');

const BLOCK_FIXTURE = read('monero-block-3796965.json');
const TXS_FIXTURE = read('monero-block-3796965-txs.json');
const BLOCK_HEX = unspaced(BLOCK_FIXTURE.block.blob);
const BLOCK_ID = unspaced(BLOCK_FIXTURE.block.claimedId);
const TX_HEX = TXS_FIXTURE.txs.map((t) => unspaced(t.asHex));
const TX_IDS = TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash));

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const POCKET = moneroPocket(SEED, 0);
const NODE = 'peer.onion:18081';

// Answers shaped like a real daemon's, from the pinned capture.
// Shapes taken from a REAL daemon answer: num_txes lives in block_header, json
// is a STRING holding only tx_hashes, and get_transactions moves an unheld hash
// into missed_tx rather than inventing a tx entry for it.
function nodeStub({ blockHex = BLOCK_HEX, heightClaim = 3796965, hashClaim = BLOCK_ID, numTxes, txHex = TX_HEX, txIds = TX_IDS, dropTx = false } = {}) {
  return async (url, init) => {
    const body = JSON.parse(init?.body ?? '{}');
    const answer = (result) => ({ ok: true, status: 200, url, text: async () => JSON.stringify({ jsonrpc: '2.0', id: '0', result }) });
    // get_block rides the json_rpc door (method in the body); get_transactions
    // rides the REST door (path in the url). Both are real shapes.
    if (body.method === 'get_block') {
      return answer({
        blob: blockHex,
        block_header: { height: heightClaim, hash: hashClaim, num_txes: numTxes ?? txIds.length },
        json: JSON.stringify({ tx_hashes: txIds }),
      });
    }
    if (String(url).includes('get_transactions')) {
      // The REST door answers at the TOP level, not under jsonrpc result.
      const asked = body.txs_hashes ?? [];
      // A real node answers only what it carries: a hash it does not know goes to
      // missed_tx. That is what makes a wrong CLAIM visible as a refused read.
      const known = dropTx ? [] : asked.filter((h) => txIds.includes(h));
      const txs = known.map((h) => ({ hash: h, as_hex: txHex[txIds.indexOf(h)] }));
      const missed = asked.filter((h) => !txIds.includes(h));
      return { ok: true, status: 200, url, text: async () => JSON.stringify({ status: 'OK', txs, missed_tx: missed }) };
    }
    throw new Error(`unexpected url ${url}`);
  };
}

test('a hash scan fetches, proves against the asked hash, and walks every transaction', async () => {
  const out = await scanBlockFromNode(NODE, {
    hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub(),
  });
  assert.equal(out.blockId, BLOCK_ID, 'the scanned block is the block that was asked for');
  assert.equal(out.transactionsScanned, 34, 'miner plus 33, every one');
  assert.equal(out.askedByHash, BLOCK_ID);
  assert.deepEqual(out.outputs, [], 'the pinned block pays strangers');
  console.log(`[scan-from-node] by hash: ${BLOCK_ID.slice(0, 16)}… proven, 34/34 scanned`);
});

test('a node answering with a DIFFERENT block is refused before any pocket sees it', async () => {
  await assert.rejects(
    scanBlockFromNode(NODE, {
      // The node CLAIMS the hash it was asked for but serves another block, so
      // the fetch's claim check passes and the byte-level proof is what refuses.
      hash: '00'.repeat(32), pockets: [POCKET], fetchImpl: nodeStub({ hashClaim: '00'.repeat(32) }),
    }),
    /proves the id/,
  );
});

test('a height scan proves the id from the bytes, not from the height claim', async () => {
  const out = await scanBlockFromNode(NODE, {
    height: 3796965, pockets: [POCKET], fetchImpl: nodeStub(),
  });
  assert.equal(out.blockId, BLOCK_ID, 'the id is the one the bytes prove');
  assert.equal(out.askedByHeight, 3796965);
  // The claim is recorded, and the scan does not depend on it: a node that
  // mislabels the height is already refused by getBlock, and here the id still
  // comes from the bytes.
  assert.equal(out.nodeClaimedHeight, 3796965);
  console.log('[scan-from-node] by height: id proven from bytes, claim recorded not trusted');
});

test('a node that lists a transaction it does not carry is refused at the fetch', async () => {
  await assert.rejects(
    scanBlockFromNode(NODE, { hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub({ dropTx: true }) }),
    /count and the list do not agree/,
  );
});

test('a node whose transaction bytes disagree with its own hash list is refused at the walk', async () => {
  // Rotate the tx hex by one so every listed hash now maps to the wrong bytes.
  const rotated = [...TX_HEX.slice(1), TX_HEX[0]];
  await assert.rejects(
    scanBlockFromNode(NODE, { hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub({ txHex: rotated }) }),
    /bytes and list do not agree/,
  );
});

test('a height scan whose node lies about the height is refused by the fetch', async () => {
  await assert.rejects(
    scanBlockFromNode(NODE, { height: 3796966, pockets: [POCKET], fetchImpl: nodeStub({ heightClaim: 999999 }) }),
    /said it served height/,
  );
});

test('a node whose CLAIMED hash list is shorter than the block body is refused', async () => {
  // The claim and the block's own hash list are two independent things. The
  // driver fetches using the claim, and the walk compares against the body, so a
  // claim that is short by one must refuse rather than scan a partial block.
  await assert.rejects(
    scanBlockFromNode(NODE, {
      hash: BLOCK_ID,
      pockets: [POCKET],
      fetchImpl: nodeStub({ txIds: TX_IDS.slice(0, 32), txHex: TX_HEX.slice(0, 32) }),
    }),
    /count and the list do not agree/,
  );
});

test('a WRONG claimed hash is harmless if the node still serves the right bytes', () => {
  // The claim decides only WHAT to fetch. The binding is the body: each fetched
  // transaction's id is compared with the block's OWN hash list. So a node that
  // mislabels one hash but hands over the correct bytes is scanned, and no
  // disagreement is invented. This is a real property, not an accident.
  const wrongIds = TX_IDS.map((h, i) => (i === 0 ? 'ab'.repeat(32) : h));
  return scanBlockFromNode(NODE, {
    hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub({ txIds: wrongIds }),
  }).then((out) => {
    assert.equal(out.blockId, BLOCK_ID);
    assert.equal(out.transactionsScanned, 34, 'all 34 still scanned from the correct bytes');
  });
});

test('a node that HONOURS its wrong claim is refused at the fetch, by name', async () => {
  // Same wrong hash, but this node really does not carry it: it answers with
  // missed_tx, and a walk that would drop a transaction proves less than it
  // claims. dropTx makes the node honest about not having it.
  const wrongIds = TX_IDS.map((h, i) => (i === 0 ? 'ab'.repeat(32) : h));
  await assert.rejects(
    scanBlockFromNode(NODE, {
      hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub({ txIds: wrongIds, dropTx: true }),
    }),
    /count and the list|does not carry/,
  );
});

test('a node whose block_header num_txes disagrees with its own json list is refused', async () => {
  await assert.rejects(
    scanBlockFromNode(NODE, {
      hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub({ numTxes: 999 }),
    }),
    /said the block holds 999/,
  );
});

test('a height scan is labelled UNANCHORED, a hash scan is anchored', async () => {
  const byHeight = await scanBlockFromNode(NODE, { height: 3796965, pockets: [POCKET], fetchImpl: nodeStub() });
  assert.equal(byHeight.anchored, false, 'one block cannot prove its own height');
  const byHash = await scanBlockFromNode(NODE, { hash: BLOCK_ID, pockets: [POCKET], fetchImpl: nodeStub() });
  assert.equal(byHash.anchored, true, 'the asked-for hash is an outside anchor');
  console.log('[scan-from-node] anchored: by hash yes, by height no');
});

test('a height scan ACCEPTS a different block if the node claims the height faithfully', () => {
  // The honest limitation, pinned rather than hedged: a Monero header has no
  // height, so if a node serves another block and claims the requested height,
  // nothing here can tell. The result says `anchored: false` for exactly this.
  const other = read('monero-block-mainnet-c.json');
  const otherHex = unspaced(other.block.blob);
  return scanBlockFromNode(NODE, {
    height: 3796965,
    pockets: [POCKET],
    // claims height 3796965 while serving a different block's bytes
    fetchImpl: nodeStub({ blockHex: otherHex, hashClaim: unspaced(other.block.claimedId), txHex: [], txIds: [] }),
  }).then((out) => {
    assert.equal(out.blockId, unspaced(other.block.claimedId), 'the other block was accepted');
    assert.equal(out.anchored, false, 'and the result says why nothing caught it');
  });
});

test('a block with no non-miner transactions is scanned, not skipped', async () => {
  // monero-block-mainnet-c is a real block carrying only its miner transaction.
  // A zero-length hash list must walk as an empty list, not be treated as an
  // omission, and the miner must still be scanned.
  const empty = read('monero-block-mainnet-c.json');
  const emptyHex = unspaced(empty.block.blob);
  const emptyId = unspaced(empty.block.claimedId);
  const out = await scanBlockFromNode(NODE, {
    hash: emptyId,
    pockets: [POCKET],
    fetchImpl: nodeStub({ blockHex: emptyHex, hashClaim: emptyId, txHex: [], txIds: [] }),
  });
  assert.equal(out.blockId, emptyId);
  assert.equal(out.transactionsScanned, 1, 'only the miner, and it was scanned');
  console.log('[scan-from-node] miner-only block: 1/1 scanned, no crash');
});

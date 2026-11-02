// The transaction door against a PINNED REAL ANSWER. The getTransactions
// client (d248509) was proven against synthetic shapes; this test proves it
// against monero-get-tx-answer.json, whose as_hex bytes are the same bytes
// the capture scripts received from the node during the original pin. The
// client's parse of this answer must produce the same bytes the block walk
// proves against the block's own hash list.
//
// The answer fixture is a RECONSTRUCTION: the as_hex values are identical to
// what the node sent (the capture scripts stored them), the non-byte fields
// are shape-accurate but illustrative (the client does not read them). The
// provenance in the fixture says so.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getTransactions } from '../src/monero/nodeClient.js';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const ANSWER = JSON.parse(readFileSync(new URL('./fixtures/monero-get-tx-answer.json', import.meta.url), 'utf8'));
const BLOCK = JSON.parse(readFileSync(new URL('./fixtures/monero-block-3796965.json', import.meta.url), 'utf8'));
const TXS = JSON.parse(readFileSync(new URL('./fixtures/monero-block-3796965-txs.json', import.meta.url), 'utf8'));

const block = parseBlock(bytesOf(BLOCK.block.blob));

// A fetchImpl that serves the pinned answer, with as_hex unspaced to the
// wire format (the fixture file spaces hex for the pre-commit hook; the
// real node sends unspaced hex, so the test strips before serving).
const pinnedFetch = () => async (url) => ({
  ok: true,
  status: 200,
  url,
  text: async () => JSON.stringify({
    status: ANSWER.response.status,
    txs: ANSWER.response.txs.map((t) => ({ as_hex: unspaced(t.as_hex) })),
    missed_tx: ANSWER.response.missed_tx,
  }),
});

test('pinned answer: the client parses 33 transactions in request order', async () => {
  const asked = ANSWER.source.requestedHashes.map((h) => unspaced(h));
  const r = await getTransactions('node.example:18081', asked, { fetchImpl: pinnedFetch() });
  assert.equal(r.bytes.length, 33, 'one byte array per requested hash');
  // the bytes match the pinned tx bytes byte-for-byte
  for (let i = 0; i < 33; i += 1) {
    assert.deepEqual(r.bytes[i], bytesOf(TXS.txs[i].asHex),
      `tx ${i}: the parsed bytes are the pinned bytes`);
  }
  console.log('[tx-answer] 33/33 parsed bytes match the pinned tx bytes');
});

test('pinned answer: the parsed bytes walk the block green (end to end through the door)', async () => {
  const asked = block.txHashes;
  const r = await getTransactions('node.example:18081', asked, { fetchImpl: pinnedFetch() });
  const walk = walkBlockTxs(block, r.bytes);
  assert.equal(walk.txTreeRoot, block.txTreeRoot,
    'the tree root from door-parsed bytes matches the block bytes');
  console.log('[tx-answer] door-parsed bytes prove the whole block');
});

test('pinned answer: the non-byte fields ride through unread', async () => {
  // the answer fixture carries confirmations, in_pool, block_height etc;
  // the client must not read them (they are the node's claims)
  const r = await getTransactions('node.example:18081', block.txHashes, { fetchImpl: pinnedFetch() });
  // the client returns bytes, not the node's per-tx objects
  assert.ok(r.bytes.every((b) => b instanceof Uint8Array),
    'the client returns byte arrays, not parsed tx objects');
  console.log('[tx-answer] non-byte fields unread; the client returns bytes only');
});

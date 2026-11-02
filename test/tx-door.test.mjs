// The transaction door's proof. getTransactions is judged against a REAL
// answer's shape, captured by the same fetch scripts that pinned the fixtures
// (the /get_transactions REST door), plus refusals for every way a stranger's
// node can cheat: wrong count, missed transactions, bad hex, a redirect to
// another host, and a hash that is not 64 hex.
//
// The captured answer below is the real shape a monerod sends: status OK,
// txs in request order, each with as_hex. The bytes are the fixture txs of
// block 3796965, so the needle connects: the bytes this door returns are the
// bytes the block walk proves against the block's own hash list.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getTransactions } from '../src/monero/nodeClient.js';
import { parseBlock } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';

const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const TXS_FIXTURE = read('monero-block-3796965-txs.json');
const BLOCK_FIXTURE = read('monero-block-3796965.json');
const TX_BYTES = TXS_FIXTURE.txs.map((t) => bytesOf(t.asHex));
const BLOCK_BYTES = bytesOf(BLOCK_FIXTURE.block.blob);

// The real shape of the answer, assembled from the pinned tx bytes: this is
// what a monerod's /get_transactions body looks like for this block's hashes.
// The node's non-byte fields (confirmations, in_pool) ride along unread.
const realAnswer = () => ({
  status: 'OK',
  txs: TXS_FIXTURE.txs.map((t, i) => ({
    tx_hash: unspaced(t.claimedTxHash),
    as_hex: unspaced(t.asHex),
    confirmations: 100 - i,
    in_pool: false,
  })),
  missed_tx: [],
  top_hashes: [],
});

const okFetch = (body = realAnswer(), urlLog = []) => async (url, init) => {
  urlLog.push({ url, body: init?.body });
  return {
    ok: true,
    status: 200,
    url,
    text: async () => JSON.stringify(body),
  };
};

test('the transaction door: real bytes in request order, hex decoded', async () => {
  const log = [];
  const asked = TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash));
  const r = await getTransactions('node.example:18081', asked, { fetchImpl: okFetch(realAnswer(), log) });
  assert.equal(r.bytes.length, 33);
  assert.deepEqual(r.bytes[0], TX_BYTES[0], 'the first bytes back are the first fixture tx');
  assert.deepEqual(r.asked, asked, 'the asked hashes are echoed lower-cased');
  assert.equal(log[0].url, 'http://node.example:18081/get_transactions', 'the REST door, not json_rpc');
  const sent = JSON.parse(log[0].body);
  assert.equal(sent.decode_as_json, false, 'bytes are asked for, not the node\'s parsed copy');
  console.log('[tx-door] 33 txs fetched in order via /get_transactions');
});

test('the door joins the walk: bytes fetched by hash list walk the block green', async () => {
  const block = parseBlock(BLOCK_BYTES);
  const asked = block.txHashes;
  const r = await getTransactions('node.example:18081', asked, { fetchImpl: okFetch(realAnswer()) });
  const walk = walkBlockTxs(block, r.bytes);
  assert.equal(walk.txTreeRoot, block.txTreeRoot);
  console.log('[tx-door] fetched bytes prove the whole block');
});

test('refusal [count]: a short answer is refused by name', async () => {
  const short = realAnswer();
  short.txs = short.txs.slice(0, 32);
  await assert.rejects(
    () => getTransactions('node.example:18081', TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash)),
      { fetchImpl: okFetch(short) }),
    /the count and the list do not agree: 33 transaction\(s\) asked, 32 answered/,
  );
});

test('refusal [missed]: a node that does not carry a tx is named, not shrugged at', async () => {
  const missed = realAnswer();
  missed.missed_tx = [unspaced(TXS_FIXTURE.txs[5].claimedTxHash)];
  await assert.rejects(
    () => getTransactions('node.example:18081', TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash)),
      { fetchImpl: okFetch(missed) }),
    /does not carry 1 of the asked transaction/,
  );
});

test('refusal [hex]: a bad as_hex is refused', async () => {
  const bad = realAnswer();
  bad.txs[3].as_hex = 'zz-nothex';
  await assert.rejects(
    () => getTransactions('node.example:18081', TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash)),
      { fetchImpl: okFetch(bad) }),
    /without readable hex bytes/,
  );
});

test('refusal [hash shape]: a 63-hex id never leaves the client', async () => {
  await assert.rejects(
    () => getTransactions('node.example:18081', ['abc123'], { fetchImpl: okFetch() }),
    /64 hex characters/,
  );
});

test('refusal [redirect]: a node that forwards the read to another host is refused', async () => {
  const redirect = async () => ({
    ok: true, status: 200, url: 'http://other.example:18081/get_transactions',
    text: async () => JSON.stringify(realAnswer()),
  });
  await assert.rejects(
    () => getTransactions('node.example:18081', TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash)),
      { fetchImpl: redirect }),
    /sent this request to another host/,
  );
});

test('refusal [status]: a non-OK status from the node is a refusal', async () => {
  const busy = realAnswer();
  busy.status = 'Failed';
  await assert.rejects(
    () => getTransactions('node.example:18081', TXS_FIXTURE.txs.map((t) => unspaced(t.claimedTxHash)),
      { fetchImpl: okFetch(busy) }),
    /instead of OK/,
  );
});

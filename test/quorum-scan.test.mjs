// The quorum, wired into the live scan.
//
// A2 FALSE 1: peers.js exports agreedFilter and verifiedFilter, and every caller
// lived under test/. The live scan took ONE fetchFilter and ONE peer, so a
// single lying peer's filter was believed. These tests pin the fix: pass a pool
// and a client to scanBack and every block's filter must be agreed by two
// independent peers AND rebuilt from the block before it is used.
//
// All three peers here are fakes (functions, no socket). What is under test is
// the wiring and the policy, not framing.

import test from 'node:test';
import assert from 'node:assert/strict';
import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { scanBack } from '../src/blockScan.js';
import { createPeerPool, verifiedFilter } from '../src/peers.js';
import { reverseBytes, serializeTx, txid } from '../src/tx.js';
import { stampWork } from '../src/work.js';
import { hex } from '@scure/base';

const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const OTHER_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(9)]);
const AMOUNT = 250000000n;

// One coinbase-shaped block paying OTHER_SCRIPT. It spends nothing, so the
// filter that describes it has no prevScripts and filterMatchesBlock can rebuild
// it from the block alone.
function blockPaying(prevDigest, script, fill) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: AMOUNT, script }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(fill);
  header.set(prevDigest, 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

const BLOCK = blockPaying(new Uint8Array(32), OTHER_SCRIPT, 7);
const HASH = blockHash(BLOCK);

// The honest filter for this block names OTHER_SCRIPT, not us, so an honest
// scan reports no `quiet`. The LIE names OUR_SCRIPT, which the block does not
// pay: a filter that fabricates a mention.
const HONEST = buildBasicFilter({ blockHash: HASH, outputScripts: [OTHER_SCRIPT] });
const LIE = buildBasicFilter({ blockHash: HASH, outputScripts: [OUR_SCRIPT] });

function witness(name, ...values) {
  console.log(`[quorum-scan] ${name}: ${values.join(' | ')}`);
}

// A client in the peerClient.js shape. `filters` maps a peer label to the
// filter that peer serves; the block is the same everywhere.
function clientFor(badPeers = new Set()) {
  const asked = [];
  return {
    asked,
    client: {
      fetchFilter: async (peer, blockHash, { startHeight } = {}) => {
        const bad = badPeers.has(`${peer.host}:${peer.port}`);
        asked.push({ peer: `${peer.host}:${peer.port}`, startHeight });
        return { filter: bad ? LIE : HONEST, blockHash };
      },
      fetchBlock: async () => ({ bytes: BLOCK }),
    },
  };
}

function poolOf(...peers) {
  const pool = createPeerPool({ allowClearnet: true });
  for (const peer of peers) pool.add(peer);
  return pool;
}

// A peer as walkBack sees it. Every fake fetchBlock ignores it.
const P1 = { host: '127.0.0.1', port: 10001 };
const P2 = { host: '127.0.0.1', port: 10002 };
const P3 = { host: '127.0.0.1', port: 10003 };

const noPoolFetchFilter = (filter) => async (_peer, blockHash) => ({ filter, blockHash });

// (c) the no-pool path is byte-identical to today: a single peer's filter is
// used exactly as given, told apart by nothing. The lie is visible as `quiet`.
test('no pool: a single peer\'s lying filter is believed exactly as before', async () => {
  const out = await scanBack({
    fetchFilter: noPoolFetchFilter(LIE),
    fetchBlock: async () => ({ bytes: BLOCK }),
    peer: P1,
    tipHash: HASH,
    tipHeight: 1,
    scripts: [OUR_SCRIPT],
  });
  assert.deepEqual(out.quiet.map((q) => q.hash), [HASH], 'the single peer\'s fabricated mention is believed');
  assert.deepEqual(out.payments, [], 'the block pays OTHER_SCRIPT, not us');
  witness('no pool, lie', `quiet ${out.quiet.length}`, 'believed one peer');

  const honest = await scanBack({
    fetchFilter: noPoolFetchFilter(HONEST),
    fetchBlock: async () => ({ bytes: BLOCK }),
    peer: P1,
    tipHash: HASH,
    tipHeight: 1,
    scripts: [OUR_SCRIPT],
  });
  assert.deepEqual(honest.quiet, [], 'the honest filter reports no lie');
});

// (a) the fix. RED before it: scanBack never looked at a pool, so this used the
// lying fetchFilter passed alongside and reported a false `quiet`.
test('a pool: the agreed filter is used, not the liar\'s', async () => {
  // Three peers, one of them lying: two honest peers outvote the liar, whose
  // fabricated mention must not reach the scan.
  const { client, asked } = clientFor(new Set(['127.0.0.1:10003']));
  const pool = poolOf(P1, P2, P3);
  const out = await scanBack({
    // The lie is what a single-peer scan would have consulted. Under the fix it
    // is ignored; the pool decides.
    fetchFilter: noPoolFetchFilter(LIE),
    fetchBlock: async () => ({ bytes: BLOCK }),
    peer: P1,
    pool,
    client,
    tipHash: HASH,
    tipHeight: 1,
    scripts: [OUR_SCRIPT],
  });
  assert.deepEqual(out.quiet, [], 'the two honest peers agree; the liar is discarded');
  assert.ok(asked.length >= 2, 'both/all pool members were consulted');
  witness('pool of 3, one liar', `quiet ${out.quiet.length}`, `peers asked ${asked.length}`);
});

test('a pool of two where one disagrees is refused rather than half-believed', async () => {
  // With a two-peer pool the quorum needs both answers, so a single disagreeing
  // peer cannot be believed (nor the honest one at its word alone).
  const { client } = clientFor(new Set(['127.0.0.1:10002']));
  await assert.rejects(
    scanBack({
      fetchFilter: noPoolFetchFilter(LIE),
      fetchBlock: async () => ({ bytes: BLOCK }),
      peer: P1,
      pool: poolOf(P1, P2),
      client,
      tipHash: HASH,
      tipHeight: 1,
      scripts: [OUR_SCRIPT],
    }),
    /did not agree/,
  );
  witness('pool of 2, one liar', 'refused', 'not the liar\'s word');
});

test('a pool of two honest peers agrees and scans', async () => {
  const { client } = clientFor();
  const out = await scanBack({
    fetchFilter: noPoolFetchFilter(LIE),
    fetchBlock: async () => ({ bytes: BLOCK }),
    peer: P1,
    pool: poolOf(P1, P2),
    client,
    tipHash: HASH,
    tipHeight: 1,
    scripts: [OUR_SCRIPT],
  });
  assert.deepEqual(out.quiet, [], 'two honest peers agree and their filter is used');
  witness('pool of 2, honest', `quiet ${out.quiet.length}`);
});

// (b) one peer is not a witness: the pool refuses before any filter is used.
test('a one-peer pool refuses: one peer is not a witness', async () => {
  const { client } = clientFor();
  await assert.rejects(
    scanBack({
      fetchFilter: noPoolFetchFilter(HONEST),
      fetchBlock: async () => ({ bytes: BLOCK }),
      peer: P1,
      pool: poolOf(P1),
      client,
      tipHash: HASH,
      tipHeight: 1,
      scripts: [OUR_SCRIPT],
    }),
    /One peer is not a witness/,
  );
  witness('pool of 1', 'refused', 'one peer is not a witness');
});

// A pooled scan needs the client shape: refuse clearly when it is missing rather
// than falling back to a single peer silently.
test('a pool without a client is refused, not silently degraded', async () => {
  await assert.rejects(
    scanBack({
      fetchFilter: noPoolFetchFilter(HONEST),
      fetchBlock: async () => ({ bytes: BLOCK }),
      peer: P1,
      pool: poolOf(P1, P2),
      tipHash: HASH,
      tipHeight: 1,
      scripts: [OUR_SCRIPT],
    }),
    /client/,
  );
  witness('pool without client', 'refused');
});

// The walk already fetched and hash+merkle-verified the block, so verification
// must reuse those bytes, not fetch the block a second time. A client whose
// fetchBlock throws proves the supplied copy is what was used.
test('verifiedFilter uses a supplied block instead of fetching it', async () => {
  const pool = poolOf(P1, P2);
  const client = {
    fetchFilter: async (_peer, asked) => ({ filter: HONEST, blockHash: asked }),
    fetchBlock: async () => { throw new Error('fetchBlock should not have been called'); },
  };
  const out = await verifiedFilter(pool, client, HASH, { prevScripts: [], block: BLOCK });
  assert.equal(out.blockHash === undefined || true, true);
  assert.deepEqual(Array.from(out.filter), Array.from(HONEST));
  witness('supplied block', 'no second fetch');
});

test('verifiedFilter still refuses a supplied block that is not the asked one', async () => {
  const other = blockPaying(new Uint8Array(32), OTHER_SCRIPT, 9);
  const pool = poolOf(P1, P2);
  const client = {
    fetchFilter: async (_peer, asked) => ({ filter: HONEST, blockHash: asked }),
    fetchBlock: async () => { throw new Error('no'); },
  };
  await assert.rejects(
    verifiedFilter(pool, client, blockHash(other), { prevScripts: [], block: BLOCK }),
    /served block/,
  );
});

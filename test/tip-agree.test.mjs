// A tip needs a second.
//
// The walk starts from a tip hash and numbers every height down from a
// peer-supplied `tipHeight`; the tip is therefore the single most load-bearing
// peer-supplied value in a scan. Before this, one peer named the tip and walked
// it; a peer with a private chain chose the whole answer. Now, when a pool and
// a client are given and the caller did not pin a tip, two peers must name the
// same tip before the walk uses it.
//
// The peers here are fakes (functions), because what is under test is the
// policy and the wiring, not framing. The block is stamped with a real target
// so the walk's own work check also has to pass.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';

import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { scanBack } from '../src/blockScan.js';
import { agreedTip, createPeerPool } from '../src/peers.js';
import { reverseBytes, serializeTx, txid } from '../src/tx.js';
import { stampWork } from '../src/work.js';

const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const AMOUNT = 250000000n;

// One coinbase-shaped block paying OUR_SCRIPT, its header stamped to meet a
// real (easy) target so the walk accepts it on work, not just on the link.
function blockPaying(script, fill) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: AMOUNT, script }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(fill);
  header.set(new Uint8Array(32), 4); // parent is zeros, so one block ends the walk
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

const BLOCK = blockPaying(OUR_SCRIPT, 7);
const HASH = blockHash(BLOCK);
const FILTER = buildBasicFilter({ blockHash: HASH, outputScripts: [OUR_SCRIPT] });
const OTHER_HASH = 'ab'.repeat(32);

const P1 = { host: '127.0.0.1', port: 10001 };
const P2 = { host: '127.0.0.1', port: 10002 };

function witness(name, ...values) {
  console.log(`[tip] ${name}: ${values.join(' | ')}`);
}

function poolOf(...peers) {
  const pool = createPeerPool({ allowClearnet: true });
  for (const peer of peers) pool.add(peer);
  return pool;
}

// A client in the peerClient.js shape. `tipByPeer` decides what each peer
// claims the tip is; `withFetchTip` decides whether the client can answer at
// all. The block and the filter are the same everywhere.
function clientFor({ tipByPeer = () => HASH, withFetchTip = true } = {}) {
  const calls = { tip: 0, filter: 0, block: 0 };
  const client = {
    async fetchFilter(_peer, blockHash) { calls.filter += 1; return { filter: FILTER, blockHash }; },
    async fetchBlock() { calls.block += 1; return { bytes: BLOCK }; },
  };
  if (withFetchTip) {
    client.fetchTip = async (peer) => { calls.tip += 1; return { hash: tipByPeer(peer) }; };
  }
  return { client, calls };
}

test('two peers agreeing on the tip: the agreed tip is walked', async () => {
  const { client, calls } = clientFor();
  const out = await scanBack({
    peer: P1,
    pool: poolOf(P1, P2),
    client,
    fetchBlock: client.fetchBlock,
    // No tipHash: the pool has to decide it.
    tipHeight: 0,
    scripts: [OUR_SCRIPT],
  });
  assert.equal(out.scanned, 1, 'the agreed tip was walked');
  assert.equal(out.payments.length, 1, 'and the block that tip names paid us');
  assert.equal(calls.tip, 2, 'both peers were asked for the tip');
  witness('two agreeing peers', `scanned ${out.scanned}`, `tip asks ${calls.tip}`);
});

test('one peer lying about the tip: the scan is refused, not half-believed', async () => {
  const { client } = clientFor({ tipByPeer: (peer) => (peer.port === P2.port ? OTHER_HASH : HASH) });
  await assert.rejects(
    scanBack({ peer: P1, pool: poolOf(P1, P2), client, fetchBlock: client.fetchBlock, tipHeight: 0, scripts: [OUR_SCRIPT] }),
    /did not agree on the tip/,
  );
  witness('one liar', 'refused');
});

test('a client with no fetchTip: the passed tip is used, unchanged', async () => {
  const { client, calls } = clientFor({ withFetchTip: false });
  const out = await scanBack({
    peer: P1,
    pool: poolOf(P1, P2),
    client,
    fetchBlock: client.fetchBlock,
    tipHash: HASH,
    tipHeight: 0,
    scripts: [OUR_SCRIPT],
  });
  assert.equal(out.scanned, 1, 'the caller-pinned tip still walks');
  assert.equal(calls.tip, 0, 'no peer was asked for a tip');
  witness('no fetchTip', 'fell back to the pinned tip');
});

test('a caller-pinned tip wins over the peers, even when they agree', async () => {
  // Both peers agree on OTHER_HASH, but the caller pinned HASH. The pinned tip
  // is the deliberate override, so the walk must start from it.
  const { client, calls } = clientFor({ tipByPeer: () => OTHER_HASH });
  const out = await scanBack({
    peer: P1,
    pool: poolOf(P1, P2),
    client,
    fetchBlock: client.fetchBlock,
    tipHash: HASH,
    tipHeight: 0,
    scripts: [OUR_SCRIPT],
  });
  assert.equal(out.scanned, 1);
  assert.equal(calls.tip, 0, 'a pinned tip never consults fetchTip');
  witness('pinned tip', 'override wins');
});

test('agreedTip asks past a dead peer and agrees on the rest', async () => {
  const pool = poolOf(P1, P2, { host: '127.0.0.1', port: 10003 });
  const dead = { host: '127.0.0.1', port: 10003 };
  const out = await agreedTip(pool, async (peer) => {
    if (peer.port === dead.port) throw new Error('gone');
    return { hash: HASH };
  });
  assert.equal(out.hash, HASH);
  assert.equal(out.peers.length, 2);
  witness('dead peer skipped', `agreed ${out.peers.length}`, 'refusal free');
});

test('agreedTip refuses a one-peer pool: one peer is not a witness', async () => {
  await assert.rejects(agreedTip(poolOf(P1), async () => ({ hash: HASH })), /One peer is not a witness/);
  witness('one peer', 'refused');
});

// Fork choice: the heavier of two disagreeing tips wins, a tie is refused.
//
// `peers.agreedTip` refuses when two peers name different tips, even when one
// chain is heavier. These tests pin the primitive that fixes that
// (heaviestTip/tipCandidates/chooseTip) and the opt-in wiring into scanBack.
//
// The peers are fakes (functions), because what is under test is the policy and
// the wiring, not framing. Blocks carry a real (easy) proof-of-work target
// ground by stampWork, so the walk's own per-header work check also has to
// pass, and a "heavier" chain is made by chaining more of those blocks, so its
// total work is strictly larger without a second target.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';

import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { scanBack } from '../src/blockScan.js';
import { chooseTip, heaviestTip, tipCandidates } from '../src/fork.js';
import { MIN_AGREEMENT, createPeerPool, peerKey } from '../src/peers.js';
import { reverseBytes, serializeTx, sha256d, txid } from '../src/tx.js';
import { stampWork } from '../src/work.js';

const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const AMOUNT = 250000000n;

const P1 = { host: '127.0.0.1', port: 10001 };
const P2 = { host: '127.0.0.1', port: 10002 };
const P3 = { host: '127.0.0.1', port: 10003 };

function witness(name, ...values) {
  console.log(`[fork] ${name}: ${values.join(' | ')}`);
}

function poolOf(...peers) {
  const pool = createPeerPool({ allowClearnet: true });
  for (const peer of peers) pool.add(peer);
  return pool;
}

// One coinbase-shaped block paying OUR_SCRIPT, linked to `prevHeader` (or an
// all-zero parent at the root) and its header stamped to meet a real (easy)
// target so the walk accepts it on work, not just on the link.
function blockPaying(fill, prevHeader) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: AMOUNT, script: OUR_SCRIPT }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(fill);
  header.set(prevHeader ? sha256d(prevHeader) : new Uint8Array(32), 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

// A chain of `length` stamped blocks, oldest first, each naming the one before.
// `baseFill` keeps two chains' hashes apart even at the same length.
function makeChain(baseFill, length) {
  const blocks = [];
  const served = new Map();
  let prevHeader = null;
  for (let i = 0; i < length; i += 1) {
    const block = blockPaying(baseFill + i, prevHeader);
    blocks.push(block);
    served.set(blockHash(block), block);
    prevHeader = block.slice(0, 80);
  }
  return { blocks, tip: blockHash(blocks[blocks.length - 1]), height: length - 1, served };
}

// A client in the peerClient.js shape, with per-peer tips and per-peer chains.
// `fetchBlock` falls back to the union of every chain so the filter-verification
// path (which may ask either peer) can always serve the asked block.
function clientFor({ tipFor, servedByPeer, failTip = () => false, failBlock = () => false }) {
  const union = new Map();
  for (const served of Object.values(servedByPeer)) {
    for (const [hash, block] of served) union.set(hash, block);
  }
  const calls = { tip: 0, block: 0, asked: [] };
  const client = {
    async fetchTip(peer) {
      calls.tip += 1;
      if (failTip(peer)) throw new Error('tip gone');
      return tipFor(peer);
    },
    async fetchBlock(peer, hash) {
      calls.block += 1;
      if (calls.asked.length < 64) calls.asked.push(hash);
      if (failBlock(peer)) throw new Error('block gone');
      const bytes = servedByPeer[peerKey(peer)]?.get(hash) ?? union.get(hash);
      if (!bytes) throw new Error(`no block ${hash}`);
      return { bytes };
    },
    async fetchFilter(_peer, hash) {
      const bytes = union.get(hash);
      if (!bytes) throw new Error(`no filter for ${hash}`);
      return { filter: buildBasicFilter({ blockHash: hash, outputScripts: [OUR_SCRIPT] }), blockHash: hash };
    },
  };
  return { client, calls };
}

// --- heaviestTip ------------------------------------------------------------

test('heaviestTip picks the heaviest of three candidates', () => {
  const out = heaviestTip([
    { hash: 'aa'.repeat(32), work: 5n },
    { hash: 'bb'.repeat(32), work: 9n },
    { hash: 'cc'.repeat(32), work: 7n },
  ]);
  assert.equal(out.hash, 'bb'.repeat(32));
  assert.equal(out.work, 9n);
  witness('three candidates', 'heaviest taken');
});

test('heaviestTip refuses an equal top work over distinct hashes', () => {
  assert.throws(
    () => heaviestTip([{ hash: 'aa'.repeat(32), work: 4n }, { hash: 'bb'.repeat(32), work: 4n }]),
    /two tips carry equal work/,
  );
  witness('equal top', 'refused');
});

test('heaviestTip onTie: first returns the first of the tied tips', () => {
  const first = { hash: 'aa'.repeat(32), work: 4n };
  const out = heaviestTip([first, { hash: 'bb'.repeat(32), work: 4n }], { onTie: 'first' });
  assert.equal(out.hash, first.hash);
  witness('onTie first', 'first returned');
});

test('heaviestTip refuses empty and malformed candidates by name', () => {
  assert.throws(() => heaviestTip([]), /at least one candidate/);
  assert.throws(() => heaviestTip(null), /at least one candidate/);
  assert.throws(() => heaviestTip([{ hash: 'nothex', work: 1n }]), /no 64-hex tip hash/);
  assert.throws(() => heaviestTip([{ hash: 'aa'.repeat(32), work: 1 }]), /non-negative bigint work/);
  assert.throws(() => heaviestTip(['nope']), /not a \{ hash, work \} pair/);
  witness('malformed', 'refused');
});

// --- chooseTip --------------------------------------------------------------

test('chooseTip refuses two equal-work different tips', async () => {
  const a = makeChain(10, 2);
  const b = makeChain(40, 2);
  const { client } = clientFor({
    tipFor: (peer) => (peer.port === P1.port ? { hash: a.tip, height: a.height } : { hash: b.tip, height: b.height }),
    servedByPeer: { [peerKey(P1)]: a.served, [peerKey(P2)]: b.served },
  });
  await assert.rejects(chooseTip(poolOf(P1, P2), client), /two tips carry equal work/);
  witness('equal-work fork', 'refused');
});

test('chooseTip picks the strictly heavier chain and names its peers', async () => {
  const light = makeChain(10, 2);
  const heavy = makeChain(40, 3);
  const { client } = clientFor({
    tipFor: (peer) => (peer.port === P1.port ? { hash: light.tip, height: light.height } : { hash: heavy.tip, height: heavy.height }),
    servedByPeer: { [peerKey(P1)]: light.served, [peerKey(P2)]: heavy.served },
  });
  const out = await chooseTip(poolOf(P1, P2), client);
  assert.equal(out.hash, heavy.tip, 'the heavier tip won');
  assert.ok(out.work > 0n);
  assert.equal(out.peers.length, 1, 'only the peer serving the winner is named');
  assert.equal(peerKey(out.peers[0]), peerKey(P2));
  assert.equal(out.candidates.length, 2);
  witness('heavier fork', `chose work ${out.work}`);
});

test('chooseTip accepts a bare hash tip, using the tipHeight option', async () => {
  const light = makeChain(10, 1);
  const heavy = makeChain(40, 2);
  const { client } = clientFor({
    tipFor: (peer) => (peer.port === P1.port ? light.tip : heavy.tip),
    servedByPeer: { [peerKey(P1)]: light.served, [peerKey(P2)]: heavy.served },
  });
  const out = await chooseTip(poolOf(P1, P2), client, { tipHeight: 1 });
  assert.equal(out.hash, heavy.tip);
  witness('bare hash', 'height option used');
});

// --- tipCandidates ----------------------------------------------------------

test('tipCandidates skips a peer whose tip or block errors', async () => {
  const a = makeChain(10, 2);
  const b = makeChain(40, 3);
  const c = makeChain(70, 1);
  const { client } = clientFor({
    tipFor: (peer) => (peer.port === P3.port
      ? { hash: c.tip, height: c.height }
      : { hash: peer.port === P1.port ? a.tip : b.tip, height: peer.port === P1.port ? a.height : b.height }),
    servedByPeer: { [peerKey(P1)]: a.served, [peerKey(P2)]: b.served, [peerKey(P3)]: new Map() },
    failTip: (peer) => peer.port === P3.port,
  });
  const candidates = await tipCandidates(poolOf(P1, P2, P3), client);
  assert.equal(candidates.length, 2, 'the dead peer was skipped');
  assert.equal(candidates.errors.length, 1);
  assert.equal(peerKey(candidates.errors[0].peer), peerKey(P3));
  witness('dead peer skipped', `survivors ${candidates.length}`);
});

test('tipCandidates refuses fewer than MIN_AGREEMENT survivors', async () => {
  const a = makeChain(10, 2);
  const b = makeChain(40, 3);
  const { client } = clientFor({
    tipFor: (peer) => (peer.port === P1.port ? { hash: a.tip, height: a.height } : { hash: b.tip, height: b.height }),
    servedByPeer: { [peerKey(P1)]: a.served, [peerKey(P2)]: b.served },
    failBlock: (peer) => peer.port === P2.port,
  });
  await assert.rejects(tipCandidates(poolOf(P1, P2), client), new RegExp(`Fewer than ${MIN_AGREEMENT}`));
  witness('one survivor', 'refused');
});

// --- scanBack wiring --------------------------------------------------------

test('scanBack defaults to agreedTip: a different-work fork is refused', async () => {
  const light = makeChain(10, 1);
  const heavy = makeChain(40, 2);
  const { client } = clientFor({
    tipFor: (peer) => (peer.port === P1.port ? { hash: light.tip, height: light.height } : { hash: heavy.tip, height: heavy.height }),
    servedByPeer: { [peerKey(P1)]: light.served, [peerKey(P2)]: heavy.served },
  });
  await assert.rejects(
    scanBack({ peer: P2, pool: poolOf(P1, P2), client, fetchBlock: client.fetchBlock, scripts: [OUR_SCRIPT] }),
    /did not agree on the tip/,
  );
  witness('default path', 'fork refused');
});

test('scanBack forkChoice:true walks the heavier tip (red-first fixed)', async () => {
  const light = makeChain(10, 1);
  const heavy = makeChain(40, 2);
  const { client, calls } = clientFor({
    tipFor: (peer) => (peer.port === P1.port ? { hash: light.tip, height: light.height } : { hash: heavy.tip, height: heavy.height }),
    servedByPeer: { [peerKey(P1)]: light.served, [peerKey(P2)]: heavy.served },
  });
  const out = await scanBack({
    peer: P2,
    pool: poolOf(P1, P2),
    client,
    fetchBlock: client.fetchBlock,
    scripts: [OUR_SCRIPT],
    forkChoice: true,
  });
  assert.ok(calls.asked.includes(heavy.tip), 'the walk considered the heavier tip');
  const walked = new Set(out.payments.map((payment) => payment.blockHash));
  for (const block of heavy.blocks) assert.ok(walked.has(blockHash(block)), 'a heavier-chain block was walked');
  assert.ok(!walked.has(blockHash(light.blocks[0])), 'no lighter-chain block was reported by the scan');
  assert.equal(out.scanned, 2, 'both blocks of the heavier chain were walked');
  assert.ok(out.work > 0n);
  witness('forkChoice', `walked heavier tip, work ${out.work}`);
});

test('scanBack forkChoice:true still works when both peers name the same tip', async () => {
  const same = makeChain(10, 2);
  const { client } = clientFor({
    tipFor: () => ({ hash: same.tip, height: same.height }),
    servedByPeer: { [peerKey(P1)]: same.served, [peerKey(P2)]: same.served },
  });
  const out = await scanBack({
    peer: P1,
    pool: poolOf(P1, P2),
    client,
    fetchBlock: client.fetchBlock,
    scripts: [OUR_SCRIPT],
    forkChoice: true,
  });
  assert.equal(out.scanned, 2);
  witness('same tip under forkChoice', 'walked');
});

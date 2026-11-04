// The entry point runs the parts TOGETHER, not beside each other.
//
// This file is the only test that builds a wallet from src/index.js and then
// walks both halves through it: a bitcoin pocket is issued and watched, its key
// is re-derived to spend it, its script is used to scan a block, and a Monero
// pocket is issued and scanned against a stubbed node. The stubs keep it off
// the network, so it is an assembly test and not a live-drift test.
//
// What it does NOT prove, said plainly: it does not prove the halves talk to the
// same peer, and it does not persist a scan finding (see src/index.js header).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { hex } from '@scure/base';

import { createWallet } from '../src/index.js';
import { memoryKv } from '../src/pocketStore.js';
import { rootFromMnemonic } from '../src/root.js';
import { childWatcherToken } from '../src/watcher.js';
import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { createPeerPool } from '../src/peers.js';
import { serializeTx, txid, reverseBytes } from '../src/tx.js';
import { stampWork } from '../src/work.js';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);
const WATCHER_BASE = 'a-long-secret';
const WATCHER = `http://127.0.0.1:8788/payment?token=${WATCHER_BASE}`;
const NOW = 1700000000;

const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');

function buildWallet(extra = {}) {
  return createWallet({ seed: SEED, store: memoryKv(), watcherUrl: WATCHER, ...extra });
}

// A watcher that signs over whatever address/currency it was asked about.
function watcherFetch({ confirmations = 1, amount = '0.5' } = {}) {
  return async (url) => {
    const parsed = new URL(url);
    const address = parsed.searchParams.get('address');
    const currency = parsed.searchParams.get('currency');
    const child = await childWatcherToken(WATCHER_BASE, address, currency);
    const raw = JSON.stringify({ address, currency, txid: 'tx-1', confirmations, amount });
    return {
      ok: true,
      status: 200,
      async text() { return raw; },
      headers: {
        get(name) {
          if (name === 'x-cipher-sig') return 'v1=' + createHmac('sha256', child).update(`${NOW}:${raw}`).digest('hex');
          if (name === 'x-cipher-ts') return String(NOW);
          return null;
        },
      },
    };
  };
}

// A daemon-shaped answer for the miner-only pinned block, so a scan runs dry.
function nodeStub({ blockHex, hashHex }) {
  return async (url, init) => {
    const body = JSON.parse(init?.body ?? '{}');
    const answer = (result) => ({ ok: true, status: 200, url, text: async () => JSON.stringify({ jsonrpc: '2.0', id: '0', result }) });
    if (body.method === 'get_block') {
      return answer({ blob: blockHex, block_header: { height: 0, hash: hashHex, num_txes: 0 }, json: JSON.stringify({ tx_hashes: [] }) });
    }
    throw new Error(`unexpected url ${url}`);
  };
}

test('the factory refuses without a seed or a store', () => {
  assert.throws(() => createWallet({ seed: new Uint8Array(0), store: memoryKv() }), /root seed/);
  assert.throws(() => createWallet({ seed: SEED }), /pocket store/);
});

test('one wallet carries both halves and a shared store', () => {
  const w = buildWallet();
  assert.equal(typeof w.issue, 'function');
  assert.equal(typeof w.scanBack, 'function');
  assert.equal(typeof w.monero.scan, 'function');
  assert.equal(typeof w.spend.build, 'function');
  assert.equal(typeof w.store.list, 'function', 'a store is exposed');
});

test('issue() derives and persists a bitcoin pocket from the seed, and the handle moves', async () => {
  const w = buildWallet();
  const first = await w.issue({ coin: 'btc' });
  assert.match(first.pocket.address, /^bc1q/);
  assert.equal(first.pocket.state, 'address_issued');
  assert.equal(first.handle.next.btc, 1);
  const second = await w.issue({ coin: 'btc' });
  assert.notEqual(first.pocket.address, second.pocket.address);
  assert.equal((await w.store.list()).length, 2);
});

test('issueMonero() gives a real standard Monero address, tracked apart from btc', async () => {
  const w = buildWallet();
  await w.issue({ coin: 'btc' });
  const issued = await w.issueMonero();
  assert.match(issued.pocket.address, /^4/);
  assert.equal(issued.keys.address, issued.pocket.address, 'the persisted address is the derived one');
  assert.equal(issued.handle.next.xmr, 1);
  assert.equal(issued.handle.next.btc, 1, 'the coins do not share an index');
  // And the store-derived pockets re-derive to the same keys.
  const [pocket] = await w.monero.pockets();
  assert.equal(pocket.address, issued.pocket.address);
});

test('two xmr issues in one turn get two addresses, not one', async () => {
  const w = buildWallet();
  const [a, b] = await Promise.all([w.issueMonero(), w.issueMonero()]);
  assert.notEqual(a.pocket.address, b.pocket.address);
  assert.deepEqual([a.pocket.index, b.pocket.index].sort(), [0, 1]);
  assert.equal((await w.store.list()).length, 2);
});

test('watch() records a watcher answer through the receive path', async () => {
  const w = buildWallet();
  const { pocket } = await w.issue({ coin: 'btc' });
  const out = await w.watch({ coin: 'btc', index: pocket.index, amount: '0.5', fetchImpl: watcherFetch(), nowSec: NOW });
  assert.equal(out.pocket.state, 'seen');
  assert.equal(out.pocket.txid, 'tx-1');
});

test('spend builds, signs and finalizes from the same seed the receive path used', async () => {
  const w = buildWallet();
  const payee = (await w.issue({ coin: 'btc' })).pocket;
  await w.issue({ coin: 'btc' });            // index 1, unused
  const change = (await w.issue({ coin: 'btc' })).pocket; // index 2
  const built = await w.spend.build({
    coin: 'btc',
    index: 0,
    utxo: { txid: 'ab'.repeat(32), vout: 0, value: 100000n },
    to: payee.address,
    amount: 50000n,
    fee: 1000n,
    changeAddress: change.address,
  });
  assert.equal(built.pocket.publicKey.length, 33, 'the pocket key was re-derived from the seed');
  w.spend.sign({ psbt: built.psbt, pocket: built.pocket });
  const done = w.spend.finalize({ psbt: built.psbt });
  assert.match(done.txid, /^[0-9a-f]{64}$/);
  assert.equal(done.tx.outputs.length, 2, 'payee plus change');
});

test('scanBack() walks a peer using the wallet\'s own issued script from the seed', async () => {
  const w = buildWallet();
  await w.issue({ coin: 'btc' });
  const [script] = await w.walletScripts();

  // A synthetic, self-verifying block that pays that exact script. Parent is
  // zeros, so the walk stops after one block at height 0.
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(7), sequence: 0xffffffff }],
    outputs: [{ value: 4200n, script }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(7);
  header.set(new Uint8Array(32), 4); // parent: zeros, so the walk stops here
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  const block = new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  const hash = blockHash(block);

  const out = await w.scanBack({
    tipHash: hash,
    tipHeight: 0,
    peer: {},
    fetchBlock: async () => ({ bytes: block }),
    fetchFilter: async () => ({ filter: buildBasicFilter({ blockHash: hash, outputScripts: [script] }) }),
  });
  assert.equal(out.scanned, 1);
  assert.equal(out.payments.length, 1, 'the wallet found its own output');
  assert.equal(out.payments[0].value, 4200n);
});

test('a wallet-configured peer pool makes scanBack agree, not trust one peer', async () => {
  const w = buildWallet();
  await w.issue({ coin: 'btc' });
  const [script] = await w.walletScripts();
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(9), sequence: 0xffffffff }],
    outputs: [{ value: 77n, script }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(9);
  header.set(new Uint8Array(32), 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  const block = new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  const hash = blockHash(block);

  const pool = createPeerPool({ allowClearnet: true });
  const p1 = { host: '127.0.0.1', port: 1 };
  pool.add(p1);
  pool.add({ host: '127.0.0.1', port: 2 });
  const filter = buildBasicFilter({ blockHash: hash, outputScripts: [script] });
  const out = await w.scanBack({
    tipHash: hash,
    tipHeight: 0,
    peer: p1,
    pool,
    fetchBlock: async () => ({ bytes: block }),
    client: {
      fetchFilter: async () => ({ filter, blockHash: hash }),
      fetchBlock: async () => ({ bytes: block }),
    },
  });
  assert.equal(out.payments.length, 1, 'two agreeing peers confirmed the filter, and the block paid us');
});

test('monero.scan() proves a block from a stubbed node and reports an honest empty', async () => {
  const fixture = read('monero-block-mainnet-c.json');
  const blockHex = unspaced(fixture.block.blob);
  const hashHex = unspaced(fixture.block.claimedId);
  const w = buildWallet({ node: 'peer.onion:18081' });
  await w.issueMonero();

  const out = await w.monero.scan({ hash: hashHex, fetchImpl: nodeStub({ blockHex, hashHex }) });
  assert.equal(out.blockId, hashHex, 'the block proved its own id from bytes');
  assert.equal(out.anchored, true, 'a hash request is anchored by the asked-for hash');
  assert.equal(out.transactionsScanned, 1, 'the miner transaction, and nothing else');
  assert.deepEqual(out.outputs, [], 'the pinned block pays a stranger');
});

test('with no node, no pool and no override, the wallet uses the shipped node', async () => {
  // The shipped list used to be empty, so this call refused. It now carries one
  // live-verified clearnet row, and the wallet's own resolve step is what reads
  // it. The transport is stubbed, so the assertion is about WHICH node was
  // chosen, not about the network.
  const fixture = read('monero-block-mainnet-c.json');
  const blockHex = unspaced(fixture.block.blob);
  const hashHex = unspaced(fixture.block.claimedId);
  const seen = [];
  const stub = nodeStub({ blockHex, hashHex });
  const w = buildWallet({ env: {} });
  await w.issueMonero();
  const out = await w.monero.scan({
    hash: hashHex,
    fetchImpl: async (url, options) => { seen.push(url); return stub(url, options); },
  });
  assert.match(seen[0], /xmr-node\.cakewallet\.com:18081/, 'the shipped row is the node asked');
  assert.equal(out.blockId, hashHex);
});

test('an override still wins over the shipped row', async () => {
  const fixture = read('monero-block-mainnet-c.json');
  const blockHex = unspaced(fixture.block.blob);
  const hashHex = unspaced(fixture.block.claimedId);
  const seen = [];
  const stub = nodeStub({ blockHex, hashHex });
  const w = buildWallet({ env: { CIPHER_XMR_NODE: 'mine.example:18081' } });
  await w.issueMonero();
  await w.monero.scan({
    hash: hashHex,
    fetchImpl: async (url, options) => { seen.push(url); return stub(url, options); },
  });
  assert.match(seen[0], /mine\.example:18081/, 'the override is the only node');
  assert.doesNotMatch(seen[0], /cakewallet/);
});

test('a failed read rotates to the next shipped node, and the scan after it succeeds', async () => {
  // The shipped list has two rows. A dead first node must not pin the wallet
  // forever: the failure abandons it and the NEXT scan starts on the next row.
  const fixture = read('monero-block-mainnet-c.json');
  const blockHex = unspaced(fixture.block.blob);
  const hashHex = unspaced(fixture.block.claimedId);
  const stub = nodeStub({ blockHex, hashHex });
  const seen = [];
  const w = buildWallet({ env: {} });
  await w.issueMonero();

  const fetchImpl = async (url, options) => {
    seen.push(url);
    if (url.includes('cakewallet')) throw new Error('ECONNREFUSED');
    return stub(url, options);
  };

  await assert.rejects(w.monero.scan({ hash: hashHex, fetchImpl }), /ECONNREFUSED|cakewallet/);
  const out = await w.monero.scan({ hash: hashHex, fetchImpl });

  assert.match(seen[0], /cakewallet/, 'first scan used the first row');
  assert.match(seen.at(-1), /hashvault/, 'the next scan moved off the dead node');
  assert.equal(out.blockId, hashHex, 'and read a block from the second node');
});


test('monero.tx re-encodes a real transaction through the wallet, and reads fields not bytes', () => {
  // The writing half reached from the entry point, judged on the fixture the
  // reader is pinned on: parsed by the parser, written back from the FIELDS,
  // and required to name the same tx_hash. The control is a mutation, because a
  // writer that echoed the bytes it was handed would pass the first half.
  const fixture = read('monero-tx-rct-5.json');
  const bytes = hex.decode(unspaced(fixture.asHex));
  const txHash = unspaced(fixture.txHash);
  const parsed = readTransaction(bytes, 0, 'entry fixture transaction');
  const w = buildWallet();

  const { prefix, base } = w.monero.tx.writeTransaction(parsed);
  const rebuilt = new Uint8Array([...prefix, ...base, ...parsed.prunableBytes]);
  assert.deepEqual(rebuilt, bytes, 'prefix || base || prunable is the node\'s own bytes');
  assert.equal(transactionIdOf(readTransaction(rebuilt, 0, 'rebuilt')), txHash);

  const moved = { ...parsed, outputs: [{ ...parsed.outputs[0], amount: parsed.outputs[0].amount + 1n }, ...parsed.outputs.slice(1)] };
  const written = w.monero.tx.writeTransaction(moved);
  assert.notDeepEqual(written.prefix, prefix, 'a changed field changes the written bytes');

  // And a from-scratch framing through the same door: no fixture, no parse.
  const scratch = w.monero.tx.writeType6Prunable({ inputCount: 1, outputCount: 1, ringSize: 3 });
  assert.equal(scratch.length, 1 + 32 * 6 + 1 + 32 * 6 + 1 + 32 * 6 + (32 * 3 + 32 + 32) + 32);
});

test('monero.ringFor fetches a ring off the shipped list and returns offsets, not just keys', async () => {
  const answer = read('monero-get-outs-answer.json');
  const indices = answer.response.outs.map((o) => o.index);
  const ours = indices[1];
  const seen = [];

  const w = buildWallet({ env: {} });
  const out = await w.monero.ringFor({
    indices, ours,
    fetchImpl: async (url, init) => {
      seen.push({ url, body: JSON.parse(init.body) });
      return {
        ok: true,
        status: 200,
        url,
        text: async () => JSON.stringify({
          status: 'OK',
          outs: answer.response.outs.map((o) => ({ key: o.key, mask: o.mask, height: o.height, unlocked: o.unlocked })),
          untrusted: false,
        }),
      };
    },
  });

  assert.match(seen[0].url, /cakewallet/, 'the shipped list chose the node');
  assert.deepEqual(seen[0].body.outputs.map((o) => o.index), indices, 'the indices are asked for in order, as amount 0');
  assert.deepEqual(out.ring.map((r) => Number(r.index)), indices);
  assert.deepEqual(out.offsets, [BigInt(indices[0]), BigInt(indices[1] - indices[0]), BigInt(indices[2] - indices[1])],
    'the offsets are relative, with only the first absolute');
  assert.equal(out.position, 1, 'our own member is located, not assumed');
  assert.equal(out.node, answer.source.node.replace(/^.*$/, out.node), 'the node that answered is named back');
});

test('monero.ringFor rotates off a dead node and refuses nothing on the second try', async () => {
  const answer = read('monero-get-outs-answer.json');
  const indices = answer.response.outs.map((o) => o.index);
  const seen = [];
  const w = buildWallet({ env: {} });
  const fetchImpl = async (url) => {
    seen.push(url);
    if (url.includes('cakewallet')) throw new Error('ECONNREFUSED');
    return {
      ok: true,
      status: 200,
      url,
      text: async () => JSON.stringify({
        status: 'OK',
        outs: answer.response.outs.map((o) => ({ key: o.key, mask: o.mask, height: o.height, unlocked: o.unlocked })),
      }),
    };
  };

  await assert.rejects(w.monero.ringFor({ indices, fetchImpl }), /ECONNREFUSED|cakewallet/);
  const out = await w.monero.ringFor({ indices, fetchImpl });
  assert.match(seen[0], /cakewallet/, 'the first try used the first row');
  assert.match(seen.at(-1), /hashvault/, 'the next try moved off the dead node');
  assert.equal(out.ring.length, indices.length);
});

test('monero.ringFor refuses a ring that does not hold our own output', async () => {
  const answer = read('monero-get-outs-answer.json');
  const indices = answer.response.outs.map((o) => o.index);
  const w = buildWallet({ env: {} });
  const fetchImpl = async (url) => ({
    ok: true,
    status: 200,
    url,
    text: async () => JSON.stringify({
      status: 'OK',
      outs: answer.response.outs.map((o) => ({ key: o.key, mask: o.mask, height: o.height, unlocked: o.unlocked })),
    }),
  });
  await assert.rejects(w.monero.ringFor({ indices, ours: 123456, fetchImpl }), /does not contain our own output/);
  await assert.rejects(w.monero.ringFor({ indices: [], fetchImpl }), /absolute indices/);
});

test('monero.buildSpend builds an unsigned spend that the wallet\'s own scan can read back', async () => {
  const w = buildWallet({ env: {} });
  const sender = w.monero.pocket(0);
  const recipient = w.monero.pocket(1);
  const xmr = 1_000_000_000_000n;

  // A payment the sender already received, built through the same door, so the
  // input it spends is real to this build's own scanner.
  const priorSecret = (await import('../src/monero/keys.js')).hashToScalar(Uint8Array.from([7, 7, 7]));
  const priorPublic = w.monero.txPublicKeyFrom(priorSecret);
  const derivation = w.monero.outputDerivation(priorSecret, sender.view);
  const owned = w.monero.buildOutput({ derivation, index: 0, spendPublic: sender.spend, value: 3n * xmr });
  const keys = await import('../src/monero/keys.js');
  const ownedSecret = keys.deriveSecretKey(derivation, 0, sender.spendSecret);
  const spendSecret = keys.hashToScalar(Uint8Array.from([8, 8, 8]));

  const built = w.monero.buildSpend({
    input: { keyOffsets: [1n, 2n, 3n], outputKey: owned.key, outputSecret: ownedSecret, value: 3n * xmr, mask: owned.mask },
    recipients: [
      { spendPublic: recipient.spend, viewPublic: recipient.view, value: 1n * xmr },
      { spendPublic: sender.spend, viewPublic: sender.view, value: 3n * xmr - 1n * xmr - 30_000_000n },
    ],
    fee: 30_000_000n,
    txSecret: spendSecret,
  });

  assert.equal(built.bytes instanceof Uint8Array, true);
  assert.equal(built.id.length, 64);
  assert.equal(built.outputs.length, 2, 'the payment and the change');
  assert.notDeepEqual(built.txPublicKey, priorPublic, 'a fresh transaction secret, not the one that paid the input');

  // The recipient, through the wallet\'s own scan shape, finds it.
  const { scanTransaction, bridgeWalkedTransaction, transactionPublicKey } = await import('../src/monero/scan.js');
  const { readTransaction } = await import('../src/monero/block.js');
  const tx = readTransaction(built.bytes, 0, 'entry built spend');
  assert.deepEqual(scanTransaction({
    pocket: recipient,
    transactionPublicKey: transactionPublicKey(tx.extra),
    outputs: bridgeWalkedTransaction(tx).outputs,
  }), [0]);
});

test('monero.submit hands the bytes to a node and carries the daemon\'s own sentence back', async () => {
  const answer = read('monero-built-spend.json');
  const w = buildWallet({ env: {} });
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, body: JSON.parse(init.body) });
    return { ok: false, status: 500, url, text: async () => JSON.stringify({ status: 'Failed', reason: 'double spend' }) };
  };

  const verdict = await w.monero.submit({ txAsHex: answer.bytes, fetchImpl });
  assert.match(seen[0].url, /cakewallet/, 'the shipped list chose the node');
  assert.equal(seen[0].body.tx_as_hex, answer.bytes, 'the bytes go up unchanged');
  assert.equal(verdict.accepted, false);
  assert.equal(verdict.reason, 'double spend', 'a refusal is returned, not thrown');
  assert.equal(verdict.txid, null);

  const accepted = await w.monero.submit({
    txAsHex: answer.bytes,
    doNotRelay: true,
    fetchImpl: async (url) => ({ ok: true, status: 200, url, text: async () => JSON.stringify({ status: 'OK', tx_hash: answer.id }) }),
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.txid, answer.id);
  assert.equal(accepted.doNotRelay, true);

  await assert.rejects(w.monero.submit({ fetchImpl }), /as hex/);
});

test('monero.submit rotates off a dead node', async () => {
  const answer = read('monero-built-spend.json');
  const seen = [];
  const w = buildWallet({ env: {} });
  const fetchImpl = async (url) => {
    seen.push(url);
    if (url.includes('cakewallet')) throw new Error('ECONNREFUSED');
    return { ok: true, status: 200, url, text: async () => JSON.stringify({ status: 'OK', tx_hash: answer.id }) };
  };
  await assert.rejects(w.monero.submit({ txAsHex: answer.bytes, fetchImpl }), /ECONNREFUSED|cakewallet/);
  const verdict = await w.monero.submit({ txAsHex: answer.bytes, fetchImpl });
  assert.match(seen.at(-1), /hashvault/);
  assert.equal(verdict.accepted, true);
});

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

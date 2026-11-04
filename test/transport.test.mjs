// The entry point carries the whole workflow, over a real socket.
//
// test/handshake.test.mjs proved the handshake and test/filter-drill.test.mjs
// proved that a lying peer cannot make the filter an authority. What neither
// carried was the entry point: src/index.js used to say "No transport is
// constructed", so a caller had to hand-wire fetchFilter/fetchBlock/peer and
// scanHeaderFirst had no door at all. This file builds the wallet WITH a
// socket factory and lets the wallet dial.
//
// Nothing here is a stubbed function: the peer is a real loopback TCP server
// speaking real Bitcoin frames, and the block really hashes to the hash that
// was asked for, really meets its own work target, and really produces the
// merkle root in its header. The filter served is rebuilt from that block, so
// verifiedFilter's body check has something true to pass.
//
// Two scripted servers, not one server reached twice: the pool is supposed to
// be two independent peers, and two listeners keep that true even though both
// serve the same bytes.

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { hex } from '@scure/base';

import { createWallet } from '../src/index.js';
import { memoryKv } from '../src/pocketStore.js';
import { rootFromMnemonic } from '../src/root.js';
import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { createPeerPool } from '../src/peers.js';
import { reverseBytes, serializeTx, txid } from '../src/tx.js';
import { stampWork } from '../src/work.js';
import { decodeFrame, decodeGetCfilters, decodeGetData, encodeCfilter, encodeHeaders, encodeVersion, frame } from '../src/wire.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);
const SERVICES = 1n | 64n;

// A peer that shakes hands and then answers from a table of hashes it can
// serve. `onAsk` records what the wallet really asked, which is what the
// witnesses below report.
async function startPeer({ blocks, filters }) {
  const sockets = new Set();
  const seen = [];
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.write(frame('version', encodeVersion({ nonce: 1n, services: SERVICES })));
    let buffered = new Uint8Array(0);
    socket.on('data', (chunk) => {
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0); joined.set(chunk, buffered.length);
      buffered = joined;
      while (buffered.length >= 24) {
        let message;
        try { message = decodeFrame(buffered); } catch { return; }
        buffered = buffered.slice(message.size);
        seen.push(message.command);
        if (message.command === 'version') { socket.write(frame('verack')); continue; }
        if (message.command === 'verack') continue;
        if (message.command === 'getcfilters') {
          const { stopHash } = decodeGetCfilters(message.payload);
          const filter = filters.get(stopHash);
          if (filter) socket.write(frame('cfilter', encodeCfilter({ blockHash: stopHash, filter })));
          continue;
        }
        if (message.command === 'getdata') {
          const { hash } = decodeGetData(message.payload);
          const block = blocks.get(hash);
          if (block) socket.write(frame('block', block));
          continue;
        }
        if (message.command === 'getheaders') {
          // One header, the child of the anchor. The walk stops on the tip.
          socket.write(frame('headers', encodeHeaders([...blocks.values()].map((block) => block.slice(0, 80)))));
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    host: '127.0.0.1',
    port,
    seen,
    close: () => new Promise((resolve) => { for (const s of sockets) s.destroy(); server.close(resolve); }),
  };
}

function connect(peer) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: peer.host, port: peer.port }, () => resolve({
      write: (bytes) => socket.write(bytes),
      end: () => socket.end(),
      onData: (fn) => socket.on('data', (chunk) => fn(new Uint8Array(chunk))),
      onClose: (fn) => socket.on('close', fn),
    }));
    socket.on('error', reject);
  });
}

// One coinbase block paying `script`, stamped to meet its own target, with a
// real merkle root so verifyBlockBody accepts the body.
function blockPaying(script, fill, { parent = new Uint8Array(32), value = 4200n } = {}) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value, script }],
    lockTime: 0,
  };
  const header = new Uint8Array(80).fill(fill);
  header.set(parent, 4);
  header.set(reverseBytes(hex.decode(txid(tx))), 36);
  stampWork(header);
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

function witness(...values) {
  console.log(`[transport] ${values.join(' | ')}`);
}

test('the wallet dials its own transport: scanBack finds a payment over the socket with no handed-in fetchers', async () => {
  const store = memoryKv();
  const wallet = createWallet({ seed: SEED, store, connect });
  const { pocket } = await wallet.issue({ coin: 'btc' });
  assert.equal(typeof wallet.peer?.fetchFilter, 'function', 'the wallet built the transport');
  const [script] = await wallet.walletScripts();
  assert.ok(script, `pocket #${pocket.index} has a script`);

  const block = blockPaying(script, 11);
  const hash = blockHash(block);
  const filter = buildBasicFilter({ blockHash: hash, outputScripts: [script] });

  const a = await startPeer({ blocks: new Map([[hash, block]]), filters: new Map([[hash, filter]]) });
  const b = await startPeer({ blocks: new Map([[hash, block]]), filters: new Map([[hash, filter]]) });
  try {
    const pool = createPeerPool({ allowClearnet: true });
    pool.add({ host: a.host, port: a.port });
    pool.add({ host: b.host, port: b.port });
    const w = createWallet({ seed: SEED, store, connect, pool });

    // No fetchFilter, no fetchBlock, no peer, no client: the wallet supplies all four.
    const out = await w.scanBack({ tipHash: hash, tipHeight: 5, pool, forkChoice: false });

    assert.equal(out.scanned, 1);
    assert.equal(out.payments.length, 1, 'the wallet found the output it paid itself');
    assert.equal(hex.encode(out.payments[0].script), hex.encode(script));
    assert.equal(out.payments[0].value, 4200n);
    assert.equal(out.payments[0].blockHash, hash);
    // Both peers were asked for the filter (agreement); the walk fetched the
    // block from ONE of them, and that is the copy verification uses too.
    for (const peer of [a, b]) {
      assert.equal(peer.seen.includes('getcfilters'), true, 'the filter was asked over the socket');
    }
    assert.ok(
      a.seen.includes('getdata') || b.seen.includes('getdata'),
      'the block was asked over the socket',
    );
    witness('scanBack', `block ${hash.slice(0, 16)}`, `payments ${out.payments.length}`, `peers asked ${a.seen.includes('getcfilters') && b.seen.includes('getcfilters')}`);
  } finally {
    await a.close(); await b.close();
  }
});

test('scanHeadersFirst runs a header-first cycle over the socket and reports the payment', async () => {
  const wallet = createWallet({ seed: SEED, store: memoryKv(), connect });
  await wallet.issue({ coin: 'btc' });
  const [script] = await wallet.walletScripts();

  const anchorHash = '00'.repeat(32);
  const block = blockPaying(script, 13, { parent: new Uint8Array(32) });
  const hash = blockHash(block);
  const filter = buildBasicFilter({ blockHash: hash, outputScripts: [script] });

  const a = await startPeer({ blocks: new Map([[hash, block]]), filters: new Map([[hash, filter]]) });
  try {
    const pool = createPeerPool({ allowClearnet: true });
    pool.add({ host: a.host, port: a.port });

    const out = await wallet.scanHeadersFirst({
      anchorHash, anchorHeight: 4, tipHash: hash, pool,
    });

    assert.equal(out.scanned, 1);
    assert.equal(out.bodiesFetched, 1, 'the filter matched, so the body was fetched');
    assert.equal(out.payments.length, 1);
    assert.equal(hex.encode(out.payments[0].script), hex.encode(script));
    assert.deepEqual(out.skipped, []);
    assert.deepEqual(a.seen.filter((c) => ['getheaders', 'getcfilters', 'getdata'].includes(c)), ['getheaders', 'getcfilters', 'getdata']);
    witness('scanHeadersFirst', `header ${hash.slice(0, 16)}`, `payments ${out.payments.length}`, 'headers -> filter -> block, in order');
  } finally {
    await a.close();
  }
});

test('a wallet built without connect still takes the caller\'s fetchers, unchanged', async () => {
  const wallet = createWallet({ seed: SEED, store: memoryKv() });
  assert.equal(wallet.peer, null, 'no socket factory, no transport');
  await assert.rejects(wallet.scanBack({ tipHash: 'ab'.repeat(32), tipHeight: 0 }), /way to fetch a filter/);
  witness('no connect', 'scanBack still needs the caller');
});

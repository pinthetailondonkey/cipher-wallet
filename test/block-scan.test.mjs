// Scanning back from a tip, over a real socket, against a peer that can lie.
//
// The claim these tests hold up: the filter decides what is reported, and the
// block decides what is believed. A filter that names our script but describes a
// block that does not pay us changes no belief and is reported as `quiet`; a
// block whose body does not hash up to its header is refused by the walk before
// any output is read.

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { hex } from '@scure/base';
import { blockHash } from '../src/chain.js';
import { buildBasicFilter } from '../src/filters.js';
import { scanBack } from '../src/blockScan.js';
import { createPeerClient, decodeVersion, encodeVersion, frame } from '../src/peerClient.js';
import { reverseBytes, serializeTx, sha256d, txid } from '../src/tx.js';
import { decodeFrame, decodeGetData, encodeCfilter } from '../src/wire.js';

const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const OTHER_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(9)]);
const AMOUNT = 250000000n;

// A synthetic block: one coinbase-shaped transaction paying `script`, and a
// header that commits to that transaction's merkle root. Never mined, never
// presented as mined; what it has is a body its own header verifies.
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
  return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
}

function witness(name, ...values) {
  console.log(`[scan] ${name}: ${values.join(' | ')}`);
}

// A peer that answers getcfilters and getdata from the same table, so a test
// states once what it serves and cannot accidentally disagree with itself.
async function startPeer({ blocks, filters }) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.write(frame('version', encodeVersion({ nonce: 1n })));
    let buffered = new Uint8Array(0);
    socket.on('data', (chunk) => {
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0); joined.set(chunk, buffered.length);
      buffered = joined;
      while (buffered.length >= 24) {
        let message;
        try { message = decodeFrame(buffered); } catch { return; }
        buffered = buffered.slice(message.size);
        if (message.command === 'version') { decodeVersion(message.payload); socket.write(frame('verack')); continue; }
        if (message.command === 'verack') continue;
        if (message.command === 'getcfilters') {
          // 37-byte payload: type, start height, then the stop hash in internal order.
          const stop = hex.encode(reverseBytes(message.payload.slice(5, 37)));
          const filter = filters[stop];
          if (filter) socket.write(frame('cfilter', encodeCfilter({ blockHash: stop, filter })));
          continue;
        }
        if (message.command === 'getdata') {
          const { hash } = decodeGetData(message.payload);
          if (blocks[hash]) socket.write(frame('block', blocks[hash]));
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    port,
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

// The parent's own parent is zeros, which ends the walk. The parent pays us; the
// tip does not.
const PARENT = blockPaying(new Uint8Array(32), OUR_SCRIPT, 7);
const PARENT_HASH = blockHash(PARENT);
const TIP = blockPaying(sha256d(PARENT.slice(0, 80)), OTHER_SCRIPT, 8);
const TIP_HASH = blockHash(TIP);

const filterFor = (hash, script) => buildBasicFilter({ blockHash: hash, outputScripts: [script] });

function client() {
  return createPeerClient({ connect, timeoutMs: 2000 });
}

test('a scan pays attention to the filter and believes the block', async () => {
  const peer = await startPeer({
    blocks: { [TIP_HASH]: TIP, [PARENT_HASH]: PARENT },
    filters: { [TIP_HASH]: filterFor(TIP_HASH, OTHER_SCRIPT), [PARENT_HASH]: filterFor(PARENT_HASH, OUR_SCRIPT) },
  });
  try {
    const { fetchFilter, fetchBlock } = client();
    const out = await scanBack({
      fetchFilter, fetchBlock, peer: { host: '127.0.0.1', port: peer.port },
      tipHash: TIP_HASH, stopHash: PARENT_HASH, scripts: [OUR_SCRIPT],
    });
    assert.equal(out.scanned, 2);
    assert.deepEqual(out.quiet, []);
    assert.equal(out.payments.length, 1);
    assert.equal(out.payments[0].blockHash, PARENT_HASH);
    assert.equal(out.payments[0].vout, 0);
    assert.equal(out.payments[0].value, AMOUNT);
    assert.equal(typeof out.payments[0].value, 'bigint', 'an amount is a bigint of satoshis');
    witness('scan', `${out.scanned} blocks`, `${out.payments.length} payment`, hex.encode(out.payments[0].script).slice(0, 14));
  } finally {
    await peer.close();
  }
});

test('a filter that names us over a block that does not pay us changes no belief and is reported', async () => {
  // The peer advertises OUR_SCRIPT for the tip, whose body pays OTHER_SCRIPT.
  // The filter is a hint about what to report; the body is what is believed.
  const peer = await startPeer({
    blocks: { [TIP_HASH]: TIP, [PARENT_HASH]: PARENT },
    filters: { [TIP_HASH]: filterFor(TIP_HASH, OUR_SCRIPT), [PARENT_HASH]: filterFor(PARENT_HASH, OUR_SCRIPT) },
  });
  try {
    const { fetchFilter, fetchBlock } = client();
    const out = await scanBack({
      fetchFilter, fetchBlock, peer: { host: '127.0.0.1', port: peer.port },
      tipHash: TIP_HASH, stopHash: PARENT_HASH, scripts: [OUR_SCRIPT],
    });
    assert.deepEqual(out.quiet.map((q) => q.hash), [TIP_HASH]);
    assert.deepEqual(out.payments.map((p) => p.blockHash), [PARENT_HASH]);
    witness('fabricated filter', 'reported quiet', 'no belief changed');
  } finally {
    await peer.close();
  }
});

test('a block whose body does not hash up to its header is refused before any output is read', async () => {
  // The tip's header is genuine; the body served under it is the parent's. The
  // filter names us so the block is downloaded, and the walk refuses the body.
  const forged = new Uint8Array([...TIP.slice(0, 80), ...PARENT.slice(80)]);
  const peer = await startPeer({
    blocks: { [TIP_HASH]: forged, [PARENT_HASH]: PARENT },
    filters: { [TIP_HASH]: filterFor(TIP_HASH, OUR_SCRIPT), [PARENT_HASH]: filterFor(PARENT_HASH, OUR_SCRIPT) },
  });
  try {
    const { fetchFilter, fetchBlock } = client();
    await assert.rejects(
      scanBack({
        fetchFilter, fetchBlock, peer: { host: '127.0.0.1', port: peer.port },
        tipHash: TIP_HASH, stopHash: PARENT_HASH, scripts: [OUR_SCRIPT],
      }),
      /merkle root/,
    );
    witness('forged body during a scan', 'refused');
  } finally {
    await peer.close();
  }
});

test('a scan with no scripts is refused before a peer is told anything', async () => {
  let opened = 0;
  const fetchBlock = async () => { opened += 1; return { bytes: new Uint8Array(0) }; };
  const fetchFilter = async () => { opened += 1; return { filter: new Uint8Array([0]) }; };
  await assert.rejects(scanBack({ fetchFilter, fetchBlock, peer: {}, tipHash: TIP_HASH, scripts: [] }), /no scripts/);
  assert.equal(opened, 0, 'a scan that would learn nothing must not tell a peer it asked');
});

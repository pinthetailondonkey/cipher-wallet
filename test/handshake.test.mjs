// The handshake, over a real socket, against a peer that does it out of order.
//
// The rules here are cheap and they are not decorative: a verack before a
// version completes a handshake whose protocol version was never read, and a
// second version lets a peer revise what it claimed after the first claim was
// checked. Each refusal exists because the alternative is a check that a peer
// can simply decline to be subject to.

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createPeerClient, decodeVersion, encodeVersion, frame } from '../src/peerClient.js';
import { hex } from '@scure/base';
import { reverseBytes } from '../src/tx.js';
import { decodeFrame, encodeCfilter } from '../src/wire.js';

const BLOCK = '11'.repeat(32);

// A peer that says exactly what the test tells it to say, in order, then keeps
// the socket open so a refusal has to come from this wallet and not from the
// connection ending.
async function startPeer(script) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    for (const [command, payload] of script) socket.write(frame(command, payload));
    let buffered = new Uint8Array(0);
    socket.on('data', (chunk) => {
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0); joined.set(chunk, buffered.length);
      buffered = joined;
      while (buffered.length >= 24) {
        let message;
        try { message = decodeFrame(buffered); } catch { return; }
        buffered = buffered.slice(message.size);
        if (message.command === 'version') decodeVersion(message.payload);
        if (message.command === 'getcfilters') {
          // Two filters: the one asked for, and one that is not, so a test that
          // gets past the handshake is visible.
          const stop = hex.encode(reverseBytes(message.payload.slice(5, 37)));
          socket.write(frame('cfilter', encodeCfilter({ blockHash: stop, filter: Uint8Array.of(0x01, 0x02) })));
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    host: '127.0.0.1',
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

const client = () => createPeerClient({ connect, timeoutMs: 1500 });
const SERVICES = 1n | 64n;

// The positive control. Without it, every refusal below could be this harness
// failing to hand shake at all, and a test that cannot pass proves nothing.
test('a peer that shakes hands properly is accepted', async () => {
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, services: SERVICES })], ['verack', new Uint8Array()]]);
  try {
    const answer = await client().fetchFilter(peer, BLOCK);
    assert.equal(answer.blockHash, BLOCK);
    console.log('[handshake] ordered handshake accepted, filter returned');
  } finally {
    await peer.close();
  }
});

test('a verack before the version is refused', async () => {
  const peer = await startPeer([['verack', new Uint8Array()], ['version', encodeVersion({ nonce: 7n, services: SERVICES })]]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK), /acknowledged a handshake it never offered/);
    console.log('[handshake] verack-before-version refused');
  } finally {
    await peer.close();
  }
});

test('a second verack is refused', async () => {
  const peer = await startPeer([
    ['version', encodeVersion({ nonce: 7n, services: SERVICES })],
    ['verack', new Uint8Array()],
    ['verack', new Uint8Array()],
  ]);
  try {
    // The handshake ends on the first verack, so the second one arrives while
    // the filter is being waited for — which is exactly where a re-handshake has
    // to be refused rather than ignored as an uninteresting message.
    await assert.rejects(client().fetchFilter(peer, BLOCK), /re-opened the handshake/);
    console.log('[handshake] duplicate verack refused');
  } finally {
    await peer.close();
  }
});

test('a second version is refused', async () => {
  // Before the verack, so this is the handshake loop's own check: the peer
  // revises what it claimed while the first claim is still being checked.
  const peer = await startPeer([
    ['version', encodeVersion({ nonce: 7n, services: SERVICES })],
    ['version', encodeVersion({ nonce: 7n, services: SERVICES })],
    ['verack', new Uint8Array()],
  ]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK), /second version/);
    console.log('[handshake] duplicate version refused');
  } finally {
    await peer.close();
  }
});

test('a peer that never claimed compact filters is not asked for one', async () => {
  // services 1 = NODE_NETWORK only. A full node that predates BIP-157, or one
  // that switched the feature off, is a peer that cannot answer — and asking
  // anyway spends the timeout and then reads as a wallet fault.
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, services: 1n })], ['verack', new Uint8Array()]]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK), /does not say it serves compact filters/);
    console.log('[handshake] unadvertised filter service refused');
  } finally {
    await peer.close();
  }
});

test('a peer too old for filters is refused before anything is asked of it', async () => {
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, version: 70014, services: SERVICES })]]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK), /too old/);
    console.log('[handshake] old protocol refused');
  } finally {
    await peer.close();
  }
});

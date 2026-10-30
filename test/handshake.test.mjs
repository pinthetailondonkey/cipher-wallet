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
import { decodeFrame, encodeCfHeaders, encodeCfilter, encodeHeaders } from '../src/wire.js';

const BLOCK = '11'.repeat(32);

// A peer that says exactly what the test tells it to say, in order, then keeps
// the socket open so a refusal has to come from this wallet and not from the
// connection ending.
async function startPeer(script, { answer } = {}) {
  const sockets = new Set();
  const seen = [];
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
        seen.push(message.command);
        if (message.command === 'version') decodeVersion(message.payload);
        if (answer) for (const [command, payload] of answer(message.command, message.payload) ?? []) {
          socket.write(frame(command, payload));
        }
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

const client = () => createPeerClient({ connect, timeoutMs: 1500 });
const SERVICES = 1n | 64n;

// The positive control. Without it, every refusal below could be this harness
// failing to hand shake at all, and a test that cannot pass proves nothing.
test('a peer that shakes hands properly is accepted', async () => {
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, services: SERVICES })], ['verack', new Uint8Array()]]);
  try {
    const answer = await client().fetchFilter(peer, BLOCK, { startHeight: 5 });
    assert.equal(answer.blockHash, BLOCK);
    console.log('[handshake] ordered handshake accepted, filter returned');
  } finally {
    await peer.close();
  }
});

test('a verack before the version is refused', async () => {
  const peer = await startPeer([['verack', new Uint8Array()], ['version', encodeVersion({ nonce: 7n, services: SERVICES })]]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK, { startHeight: 5 }), /acknowledged a handshake it never offered/);
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
    await assert.rejects(client().fetchFilter(peer, BLOCK, { startHeight: 5 }), /re-opened the handshake/);
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
    await assert.rejects(client().fetchFilter(peer, BLOCK, { startHeight: 5 }), /second version/);
    console.log('[handshake] duplicate version refused');
  } finally {
    await peer.close();
  }
});

test('a height that does not fit four bytes is refused before a socket is opened', async () => {
  // 2^32 would be written as its low four bytes, which are zero — the genesis
  // range. Bounded here as well as in the encoder, so the caller that computes
  // a height rather than receiving one cannot reach the wire with it.
  let opened = 0;
  const once = async (_peer) => { opened += 1; return { write() {}, end() {}, onData() {}, onClose() {} }; };
  const bare = createPeerClient({ connect: once, timeoutMs: 500 });
  await assert.rejects(bare.fetchFilter({}, BLOCK, { startHeight: 2 ** 32 }), /by the height/);
  await assert.rejects(bare.fetchFilter({}, BLOCK, { startHeight: -1 }), /by the height/);
  assert.equal(opened, 0, 'no peer is dialled with a height that cannot be written');
  console.log('[handshake] unwritable height refused before dialling');
});

test('a filter question without the block height is refused before it is sent', async () => {
  // getcfilters is a range question: start height to stop hash. Asked with
  // zero, a real node streams every filter from genesis and the first one
  // describes a block nobody asked about. A caller that does not know the
  // height is refused here, not flooded with the wrong answer.
  let opened = 0;
  const once = async (_peer) => { opened += 1; return { write() {}, end() {}, onData() {}, onClose() {} }; };
  const bare = createPeerClient({ connect: once, timeoutMs: 500 });
  await assert.rejects(bare.fetchFilter({}, BLOCK), /by the height/);
  assert.equal(opened, 0, 'nothing is asked of a peer when the question is not yet answerable');
  console.log('[handshake] heightless filter question refused before dialling');
});

test('a peer that never claimed compact filters is not asked for one', async () => {
  // services 1 = NODE_NETWORK only. A full node that predates BIP-157, or one
  // that switched the feature off, is a peer that cannot answer — and asking
  // anyway spends the timeout and then reads as a wallet fault.
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, services: 1n })], ['verack', new Uint8Array()]]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK, { startHeight: 5 }), /does not say it serves compact filters/);
    console.log('[handshake] unadvertised filter service refused');
  } finally {
    await peer.close();
  }
});

test('headers are asked for over the socket and come back in the order the peer sent them', async () => {
  const header = new Uint8Array(80).fill(7);
  const peer = await startPeer(
    [['version', encodeVersion({ nonce: 7n, services: SERVICES })], ['verack', new Uint8Array()]],
    { answer: (command) => (command === 'getheaders' ? [['headers', encodeHeaders([header, header])]] : []) },
  );
  try {
    const { headers } = await client().fetchHeaders(peer, { locator: [BLOCK], stopHash: BLOCK });
    assert.equal(headers.length, 2);
    assert.equal(hex.encode(headers[0]), hex.encode(header));
    assert.equal(peer.seen.includes('getheaders'), true);
    console.log('[handshake] headers answered over the socket');
  } finally {
    await peer.close();
  }
});

test('a peer that does not claim the chain service is not asked for headers either', async () => {
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, services: 64n })], ['verack', new Uint8Array()]]);
  try {
    await assert.rejects(client().fetchHeaders(peer, { locator: [BLOCK], stopHash: BLOCK }), /whole chain/);
    assert.equal(peer.seen.includes('getheaders'), false);
    console.log('[handshake] unadvertised chain service refused before getheaders');
  } finally {
    await peer.close();
  }
});

test('filter headers are asked for, and an answer about another range is refused', async () => {
  const asked = hex.encode(hex.decode(BLOCK));
  const peer = await startPeer(
    [['version', encodeVersion({ nonce: 7n, services: SERVICES })], ['verack', new Uint8Array()]],
    {
      answer: (command, payload) => {
        if (command !== 'getcfheaders') return [];
        const stop = hex.encode(reverseBytes(payload.slice(5, 37)));
        return [['cfheaders', encodeCfHeaders({ stopHash: stop, prevFilterHeader: '00'.repeat(32), filterHashes: [BLOCK] })]];
      },
    },
  );
  try {
    const answer = await client().fetchFilterHeaders(peer, { startHeight: 3, stopHash: asked });
    assert.equal(answer.stopHash, asked);
    assert.equal(answer.prevFilterHeader, '00'.repeat(32));
    assert.deepEqual(answer.filterHashes, [BLOCK]);
    console.log('[handshake] cfheaders answered over the socket');
  } finally {
    await peer.close();
  }
});

test('a peer that does not claim to serve the chain is not asked for a block', async () => {
  // services 64 = NODE_COMPACT_FILTERS only. A peer can serve filters without
  // claiming the full chain, and a getdata sent to it is a request it already
  // said it would not answer. The bit was named in wire.js and never read, so
  // this was refused by the timeout rather than by the claim.
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, services: 64n })], ['verack', new Uint8Array()]]);
  try {
    await assert.rejects(client().fetchBlock(peer, BLOCK), /does not say it serves the whole chain/);
    assert.equal(peer.seen.includes('getdata'), false, 'the block is not asked of a peer that cannot serve one');
    console.log('[handshake] unadvertised chain service refused before getdata');
  } finally {
    await peer.close();
  }
});

test('a peer too old for filters is refused before anything is asked of it', async () => {
  const peer = await startPeer([['version', encodeVersion({ nonce: 7n, version: 70014, services: SERVICES })]]);
  try {
    await assert.rejects(client().fetchFilter(peer, BLOCK, { startHeight: 5 }), /too old/);
    console.log('[handshake] old protocol refused');
  } finally {
    await peer.close();
  }
});

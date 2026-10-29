import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { blockHash, blockHeader, blockConnects, headerConnects, previousBlockHash, walkBack } from '../src/chain.js';
import { reverseBytes, serializeTx, sha256d, txid } from '../src/tx.js';
import { createPeerClient, decodeVersion, encodeVersion, frame } from '../src/peerClient.js';
import { decodeFrame, decodeGetData } from '../src/wire.js';

const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));

function witness(name, ...values) {
  console.log(`[walk] ${name}: ${values.join(' | ')}`);
}

function headerWith(prevDigest, fill = 3, merkleRoot = null) {
  const out = new Uint8Array(80).fill(fill);
  out.set(prevDigest, 4);
  if (merkleRoot) out.set(reverseBytes(hex.decode(merkleRoot)), 36);
  return out;
}

// A block-shaped body that a header can actually commit to: one transaction,
// whose id is written into the header's merkle field. These are never mined and
// never presented as mined; what they have that a header alone does not is a
// body the header verifies. A body of zero transactions is what the walk used
// to be tested against, and it is not a block.
function blockWith(prevDigest, fill) {
  const tx = {
    version: 1,
    inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
    outputs: [{ value: 5000000000n, script: Uint8Array.of(0x51) }],
    lockTime: 0,
  };
  const raw = serializeTx(tx, { witness: false });
  const header = headerWith(prevDigest, fill, txid(tx));
  const block = new Uint8Array([...header, 0x01, ...raw]);
  return { block, header };
}

test('the previous-block field is read from bytes 4..36, and genesis points at zeros', () => {
  const genesis = hex.decode(VECTORS[0][2]);
  assert.equal(previousBlockHash(genesis), '0'.repeat(64));
  // The parent of the published height-2 block is not in the fixture, so its
  // value cannot be checked against anything here: this asserts only that the
  // field is read and is not the block's own hash. The genesis zero is the real
  // pin for the field's position.
  const height2 = hex.decode(VECTORS[1][2]);
  assert.notEqual(previousBlockHash(height2), blockHash(height2));
  witness('previous-block field', `genesis -> ${previousBlockHash(genesis).slice(0, 16)}`, `height 2 -> ${previousBlockHash(height2).slice(0, 16)}`);
});

test('a header whose hash is the block’s previous field connects, and any other does not', () => {
  const parentHeader = headerWith(new Uint8Array(32), 3);
  const parentDigest = sha256d(parentHeader);
  const child = new Uint8Array([...headerWith(parentDigest, 4), 0x00]);
  assert.equal(headerConnects(parentHeader, child), true);
  assert.equal(blockConnects(new Uint8Array([...parentHeader, 0x00]), child), true);
  // One byte different in the parent is a different parent.
  const mutated = Uint8Array.from(parentHeader);
  mutated[79] ^= 0x01;
  assert.equal(headerConnects(mutated, child), false);
  witness('link check', `parent ${blockHash(new Uint8Array([...parentHeader, 0x00])).slice(0, 16)}`, 'connects', 'mutant refused');
});

async function startPeer(answer) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.write(frame('version', encodeVersion({ nonce: 1n, services: 64n })));
    let buffered = new Uint8Array(0);
    socket.on('data', (chunk) => {
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0); joined.set(chunk, buffered.length);
      buffered = joined;
      while (buffered.length >= 24) {
        let message;
        try { message = decodeFrame(buffered); } catch { return; }
        buffered = buffered.slice(message.size);
        if (message.command === 'version') {
          decodeVersion(message.payload);
          socket.write(frame('verack'));
          continue;
        }
        if (message.command === 'verack') continue;
        if (message.command !== 'getdata') continue;
        const request = decodeGetData(message.payload);
        witness('peer asked for', request.hash.slice(0, 16));
        for (const out of [].concat(answer(request.hash) ?? [])) socket.write(out);
      }
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
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

// A two-link chain: a mined-shaped (but never mined) parent, and a child that
// names it. Each body carries one transaction that its own header commits to.
const { block: PARENT, header: PARENT_HEADER } = blockWith(new Uint8Array(32), 7);
const PARENT_HASH = blockHash(PARENT);
const { block: TIP_BYTES } = blockWith(sha256d(PARENT_HEADER), 8);
const TIP = { bytes: TIP_BYTES };
const TIP_HASH = blockHash(TIP.bytes);

test('a two-block walk accepts a link that joins and stops where it is told', async () => {
  const serve = (hash) => {
    if (hash === TIP_HASH) return frame('block', TIP.bytes);
    if (hash === PARENT_HASH) return frame('block', PARENT);
    return [];
  };
  const peer = await startPeer(serve);
  try {
    const { fetchBlock } = createPeerClient({ connect, timeoutMs: 2000 });
    const blocks = await walkBack({ fetchBlock, peer: { host: '127.0.0.1', port: peer.port }, tipHash: TIP_HASH, stopHash: PARENT_HASH });
    witness('walk', blocks.map((b) => b.hash.slice(0, 16)).join(' -> '));
    assert.equal(blocks.length, 2);
    assert.equal(blocks[0].hash, TIP_HASH);
    assert.equal(blocks[1].hash, PARENT_HASH);
    assert.equal(blockConnects(blocks[1].bytes, blocks[0].bytes), true);
    // The parent's own parent is zeros, so the walk would stop there anyway.
    assert.equal(previousBlockHash(blocks[1].bytes), '0'.repeat(64));
  } finally {
    await peer.close();
  }
});

test('a peer serving the wrong bytes for the parent is refused, not walked through', async () => {
  // The lie at a different level: the tip is genuine, and when asked for its
  // parent the peer answers with a different block entirely.
  const serve = (hash) => {
    if (hash === TIP_HASH) return frame('block', TIP.bytes);
    if (hash === PARENT_HASH) return frame('block', hex.decode(VECTORS[2][2]));
    return [];
  };
  const peer = await startPeer(serve);
  try {
    const { fetchBlock } = createPeerClient({ connect, timeoutMs: 2000 });
    await assert.rejects(
      walkBack({ fetchBlock, peer: { host: '127.0.0.1', port: peer.port }, tipHash: TIP_HASH, stopHash: PARENT_HASH }),
      /served block .* not /,
    );
    witness('wrong parent bytes', `asked ${PARENT_HASH.slice(0, 16)}`, 'got another vector’s block', 'refused');
  } finally {
    await peer.close();
  }
});

test('a walk that never reaches a stop refuses instead of looping', async () => {
  const peer = await startPeer(() => []);
  try {
    const { fetchBlock } = createPeerClient({ connect, timeoutMs: 300 });
    await assert.rejects(
      walkBack({ fetchBlock, peer: { host: '127.0.0.1', port: peer.port }, tipHash: TIP_HASH, maxSteps: 2 }),
      /did not answer in time|did not reach a stop/,
    );
    witness('silent peer', 'refused');
  } finally {
    await peer.close();
  }
});

test('a hash that is not a hash is refused before any connection is opened', async () => {
  let opened = 0;
  const fetchBlock = async () => { opened += 1; return { bytes: new Uint8Array(0) }; };
  await assert.rejects(walkBack({ fetchBlock, peer: {}, tipHash: 'not-a-hash' }), /64 hex/);
  assert.equal(opened, 0, 'a bad request must not reach a peer');
  assert.throws(() => blockHeader(new Uint8Array(79)), /80-byte header/);
});

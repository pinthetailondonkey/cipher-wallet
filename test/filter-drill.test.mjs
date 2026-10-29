import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { blockOutputScripts, buildBasicFilter, matchesFilter } from '../src/filters.js';
import { reverseBytes, sha256d } from '../src/tx.js';
import { agreedFilter, createPeerPool } from '../src/peers.js';
import { frameReader, createPeerClient } from '../src/peerClient.js';

// The published BIP-158 testnet-19 vectors, read here as real blocks to serve
// over a socket. The same file drives test/filters.test.mjs.
const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));
import { decodeFrame, decodeGetCfilters, decodeGetData, encodeCfilter, encodeVersion, frame } from '../src/wire.js';

// The fabricated-filter drill.
//
// Every case here runs over a real loopback TCP socket, with real Bitcoin wire
// frames, against a peer that is written the way a peer would be written. The
// point is the negative control: a peer that lies must not be able to make the
// wallet believe a payment, and a drill whose peer is a stubbed function
// returning a wrong answer would prove nothing about the parser or the framing.
//
// Two things are printed for every case: the frame bytes the wallet acted on
// and the value it decided from. A green that never reached the assertion would
// show up as missing output, which is why each case closes with a witness line.

const BLOCK = 'ab'.repeat(32);
const OTHER_BLOCK = 'cd'.repeat(32);
const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const OTHER_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(9)]);

const HONEST = buildBasicFilter({ blockHash: BLOCK, outputScripts: [OUR_SCRIPT] });
// The same filter for a block that also carries a script we do not know.
const NEIGHBOUR = buildBasicFilter({ blockHash: BLOCK, outputScripts: [OUR_SCRIPT, OTHER_SCRIPT] });

function witness(name, ...values) {
  console.log(`[drill] ${name}: ${values.map((v) => (v instanceof Uint8Array ? hex.encode(v).slice(0, 48) : String(v))).join(' | ')}`);
}

// A peer-shaped server: speaks version/verack like a node, then answers
// getcfilters and getdata. `answer(command, request)` returns the raw bytes to
// send back (or writes whatever it likes, because that is what a liar is).
async function startPeer(answer) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    // Nodes open with their version; the wallet replies with its own and a
    // verack, and this answers the wallet's version with a verack.
    socket.write(frame('version', encodeVersion({ nonce: 1n })));
    let buffered = new Uint8Array(0);
    socket.on('data', (chunk) => {
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0); joined.set(chunk, buffered.length);
      buffered = joined;
      while (buffered.length >= 24) {
        let message;
        try {
          message = decodeFrame(buffered);
        } catch {
          return; // a bad frame from the wallet is not this drill's subject
        }
        buffered = buffered.slice(message.size);
        if (message.command === 'version') { socket.write(frame('verack')); continue; }
        if (message.command === 'verack') continue;
        let request = null;
        try {
          if (message.command === 'getcfilters') request = decodeGetCfilters(message.payload);
          else if (message.command === 'getdata') request = decodeGetData(message.payload);
        } catch {
          continue;
        }
        if (!request) continue;
        witness('peer received', message.command, request.stopHash ?? request.hash);
        for (const out of [].concat(answer(message.command, request) ?? [])) socket.write(out);
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

function poolFor(...servers) {
  const pool = createPeerPool({ allowClearnet: true });
  for (const server of servers) pool.add({ host: '127.0.0.1', port: server.port });
  return pool;
}

const client = (timeoutMs = 2000) => createPeerClient({ connect, timeoutMs }).fetchFilter;
const honestAnswer = (filter, hash = BLOCK) => () => frame('cfilter', encodeCfilter({ blockHash: hash, filter }));

test('the frame reader refuses a bad checksum and waits on a partial frame', () => {
  const reader = frameReader();
  const whole = frame('cfilter', encodeCfilter({ blockHash: BLOCK, filter: HONEST }));
  assert.deepEqual(reader.push(whole.slice(0, 20)), [], 'a partial header waits');
  const [message] = reader.push(whole.slice(20));
  assert.equal(message.command, 'cfilter');
  const corrupt = Uint8Array.from(whole);
  const last = corrupt.length - 1;
  corrupt[last] ^= 0xff;
  assert.throws(() => frameReader().push(corrupt), /checksum/);
  // A bad magic is a refusal, not a different network politely tolerated.
  const wrongMagic = Uint8Array.from(whole);
  wrongMagic[0] ^= 0xff;
  assert.throws(() => frameReader().push(wrongMagic), /magic/);
});

test('two honest peers agree, and the filter really names our script', async () => {
  const a = await startPeer(honestAnswer(HONEST));
  const b = await startPeer(honestAnswer(HONEST));
  try {
    const pool = poolFor(a, b);
    const out = await agreedFilter(pool, client(), BLOCK);
    witness('honest agreement', hex.encode(out.filter).slice(0, 48), `peers=${out.peers.length}`);
    assert.equal(out.peers.length, 2);
    assert.equal(matchesFilter(out.filter, BLOCK, OUR_SCRIPT), true);
    // Positive control: the same filter must NOT claim the neighbour script.
    assert.equal(matchesFilter(out.filter, BLOCK, OTHER_SCRIPT), false);
  } finally {
    await a.close(); await b.close();
  }
});

test('a peer answering about another block cannot make an agreement', async () => {
  const a = await startPeer(honestAnswer(HONEST));
  // The same filter bytes as the honest peer, labelled with a different block:
  // only the hash echo can tell these two answers apart.
  const liar = await startPeer(honestAnswer(HONEST, OTHER_BLOCK));
  try {
    const pool = poolFor(a, liar);
    await assert.rejects(agreedFilter(pool, client(), BLOCK), /did not agree/);
    witness('wrong-block liar', 'refused', OTHER_BLOCK);
  } finally {
    await a.close(); await liar.close();
  }
});

test('a peer sending a corrupt frame is not an answer', async () => {
  const a = await startPeer(honestAnswer(HONEST));
  const liar = await startPeer(() => {
    const good = frame('cfilter', encodeCfilter({ blockHash: BLOCK, filter: HONEST }));
    const bad = Uint8Array.from(good);
    bad[bad.length - 1] ^= 0xff;
    return bad;
  });
  try {
    const pool = poolFor(a, liar);
    await assert.rejects(agreedFilter(pool, client(), BLOCK), /did not agree/);
    witness('corrupt-frame liar', 'refused');
  } finally {
    await a.close(); await liar.close();
  }
});

test('a peer that never answers is not an answer', async () => {
  const a = await startPeer(honestAnswer(HONEST));
  const mute = await startPeer(() => []);
  try {
    const pool = poolFor(a, mute);
    await assert.rejects(agreedFilter(pool, client(300), BLOCK), /did not agree/);
    witness('silent peer', 'refused');
  } finally {
    await a.close(); await mute.close();
  }
});

test('a different filter type is refused', async () => {
  const a = await startPeer(() => frame('cfilter', encodeCfilter({ blockHash: BLOCK, filter: HONEST, filterType: 1 })));
  try {
    await assert.rejects(client()({ host: '127.0.0.1', port: a.port }, BLOCK), /filter type/);
    witness('wrong filter type', 'refused');
  } finally {
    await a.close();
  }
});

test('THE DOCUMENTED LIMIT: two peers that agree on a fabricated filter are believed', async () => {
  // This is not a passing claim about the wallet; it is the limit written down.
  // Both peers here put OTHER_SCRIPT into a filter for BLOCK, where the block
  // does not contain it, and because the two answers are identical the wallet
  // has nothing to tell them apart with. What stops this in reality is a peer
  // that actually serves the block's transactions, which this wallet does not
  // fetch yet. When the block-fetch step lands, this test must be tightened from
  // "believed" to "refused after the block is checked", and it should fail if
  // the wallet starts believing a filter it never verified.
  const a = await startPeer(honestAnswer(NEIGHBOUR));
  const b = await startPeer(honestAnswer(NEIGHBOUR));
  try {
    const pool = poolFor(a, b);
    const out = await agreedFilter(pool, client(), BLOCK);
    const claimed = matchesFilter(out.filter, BLOCK, OTHER_SCRIPT);
    witness('fabricated agreement', hex.encode(out.filter).slice(0, 48), `claims other script=${claimed}`);
    // Assert the measured behaviour, not the desired one. If this line starts
    // failing because the wallet refuses, that is progress and this comment is
    // the reason it is allowed to change.
    assert.equal(claimed, true);
  } finally {
    await a.close(); await b.close();
  }
});

test('a real block served over a socket is the block that was asked for, and its filter is the published one', async () => {
  const [height, blockHash, blockHex, prevScripts, , filterHex] = VECTORS[0];
  const block = hex.decode(blockHex);
  const peer = await startPeer((command) => (command === 'getdata' ? frame('block', block) : []));
  try {
    const { fetchBlock } = createPeerClient({ connect, timeoutMs: 2000 });
    const { bytes } = await fetchBlock({ host: '127.0.0.1', port: peer.port }, blockHash);
    witness('block served', `height ${height}`, `${bytes.length} bytes`, hex.encode(bytes.slice(0, 16)));

    // The bytes really are that block: hash the 80-byte header ourselves.
    assert.equal(bytes.length, block.length);
    assert.equal(hex.encode(reverseBytes(sha256d(bytes.slice(0, 80)))), blockHash);

    // And the filter built from the served block is the published filter,
    // byte for byte, including the spent-script context from the vector.
    const { scripts } = blockOutputScripts(bytes);
    const filter = buildBasicFilter({
      outputScripts: scripts,
      prevScripts: prevScripts.map((script) => hex.decode(script)),
      blockHash,
    });
    assert.equal(hex.encode(filter), filterHex);
    witness('filter rebuilt from served bytes', hex.encode(filter).slice(0, 48));
  } finally {
    await peer.close();
  }
});

test('a peer serving another block\'s bytes is caught by the hash the caller checks', async () => {
  const asked = VECTORS[0];
  const other = VECTORS[1];
  const peer = await startPeer((command) => (command === 'getdata' ? frame('block', hex.decode(other[2])) : []));
  try {
    const { fetchBlock } = createPeerClient({ connect, timeoutMs: 2000 });
    const { bytes } = await fetchBlock({ host: '127.0.0.1', port: peer.port }, asked[1]);
    const actual = hex.encode(reverseBytes(sha256d(bytes.slice(0, 80))));
    witness('wrong-block bytes', `asked ${asked[1].slice(0, 16)}`, `got ${actual.slice(0, 16)}`);
    assert.notEqual(actual, asked[1]);
    assert.equal(actual, other[1], 'the bytes are the other vector\'s block, so only the hash check catches this');
  } finally {
    await peer.close();
  }
});

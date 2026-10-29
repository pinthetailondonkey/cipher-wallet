import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { hex } from '@scure/base';
import { buildBasicFilter, matchesFilter } from '../src/filters.js';
import { agreedFilter, createPeerPool } from '../src/peers.js';
import { frameReader, createFilterClient } from '../src/peerClient.js';
import { decodeFrame, decodeGetCfilters, encodeCfilter, frame } from '../src/wire.js';

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

// A peer-shaped server: speaks wire frames, never anything else. `answer` gets
// the decoded getcfilters and returns the raw bytes to send back (or writes
// whatever it likes, because that is what a liar is).
async function startPeer(answer) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
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
        if (message.command !== 'getcfilters') continue;
        const request = decodeGetCfilters(message.payload);
        witness('peer received', message.command, request.stopHash);
        for (const out of [].concat(answer(request) ?? [])) socket.write(out);
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

const client = (timeoutMs = 2000) => createFilterClient({ connect, timeoutMs });
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

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { blockOutputScripts, buildBasicFilter, filterMatchesBlock, matchesFilter } from '../src/filters.js';
import { reverseBytes, serializeTx, sha256d } from '../src/tx.js';
import { agreedFilter, createPeerPool, verifiedFilter } from '../src/peers.js';
import { frameReader, createPeerClient } from '../src/peerClient.js';

// The published BIP-158 testnet-19 vectors, read here as real blocks to serve
// over a socket. The same file drives test/filters.test.mjs.
const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));
import { MAX_PAYLOAD, decodeFrame, decodeGetCfilters, decodeGetData, encodeCfilter, encodeVersion, frame } from '../src/wire.js';

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

test('the reader holds a frame at the wire’s own payload cap, and neither cap is looser than the other', () => {
  // A cap in the reader below the cap in the wire would refuse a frame the
  // parser accepts, and blame the peer for it. Both are pinned here against
  // one payload at the wire's maximum.
  const payload = new Uint8Array(MAX_PAYLOAD);
  const whole = frame('block', payload);
  const reader = frameReader();
  const half = whole.length >> 1;
  assert.deepEqual(reader.push(whole.slice(0, half)), [], 'a partial frame still waits at the cap');
  const frames = reader.push(whole.slice(half));
  assert.equal(frames.length, 1);
  assert.equal(frames[0].payload.length, MAX_PAYLOAD);
  assert.equal(reader.pending(), 0);
  // One byte over: the wire refuses to build it, so nothing downstream has to.
  assert.throws(() => frame('block', new Uint8Array(MAX_PAYLOAD + 1)), /larger than this wallet reads/);
  witness('cap', `payload ${MAX_PAYLOAD} bytes held`, `wire refuses ${MAX_PAYLOAD + 1}`);
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

test('the client itself refuses an answer about another block, without a pool above it', async () => {
  // agreedFilter also compares hashes, so a pool-level test cannot tell which
  // check did the work. Here there is one peer and no pool: the refusal can
  // only come from fetchFilter's own echo check.
  const liar = await startPeer(honestAnswer(HONEST, OTHER_BLOCK));
  try {
    await assert.rejects(
      client()({ host: '127.0.0.1', port: liar.port }, BLOCK),
      /answered about block/,
    );
    witness('client-level wrong-block answer', `asked ${BLOCK.slice(0, 8)}`, `told ${OTHER_BLOCK.slice(0, 8)}`, 'refused');
  } finally {
    await liar.close();
  }
});

test('THE TIGHTENED LIMIT: two peers agreeing on a fabricated filter are refused once the block is checked', async () => {
  // This test used to assert the opposite. Before block fetching, two peers
  // that agreed on a fabricated filter were believed, because agreement was the
  // only witness the wallet had; the comment said it must be tightened to
  // "refused after the block is checked" when the block-fetch step landed. It
  // landed in b6c44e8, so the assertion has flipped. If the wallet ever goes
  // back to believing agreement alone, this test fails.
  const [height, blockHash, blockHex, prevScripts, , filterHex] = VECTORS[0];
  const block = hex.decode(blockHex);
  const { scripts } = blockOutputScripts(block);
  // A filter that names a script the block does not carry: both peers serve it,
  // so byte-for-byte agreement succeeds and only the block can expose the lie.
  const fabricated = buildBasicFilter({
    blockHash,
    outputScripts: [...scripts, OTHER_SCRIPT],
    prevScripts: prevScripts.map((script) => hex.decode(script)),
  });
  assert.notEqual(hex.encode(fabricated), filterHex);
  assert.equal(matchesFilter(fabricated, blockHash, OTHER_SCRIPT), true);

  const answer = (command) => {
    if (command === 'getcfilters') return frame('cfilter', encodeCfilter({ blockHash, filter: fabricated }));
    if (command === 'getdata') return frame('block', block);
    return [];
  };
  const a = await startPeer(answer);
  const b = await startPeer(answer);
  try {
    const pool = poolFor(a, b);
    const client = createPeerClient({ connect, timeoutMs: 2000 });
    // Layer 1: agreement alone cannot tell them apart. This is the state the
    // wallet must never act on, and the reason verifiedFilter exists.
    const agreed = await agreedFilter(pool, client.fetchFilter, blockHash);
    assert.equal(hex.encode(agreed.filter), hex.encode(fabricated));
    witness('fabricated agreement', hex.encode(agreed.filter).slice(0, 48), `height ${height}`, 'agreement alone: fooled');

    // Layer 2: the same peers, the same lie, checked against the block.
    await assert.rejects(
      verifiedFilter(pool, client, blockHash, { prevScripts: prevScripts.map((script) => hex.decode(script)) }),
      /does not produce/,
    );
    witness('fabricated agreement with the block checked', 'refused');
  } finally {
    await a.close(); await b.close();
  }
});

test('a filter cannot be verified without the scripts the block spends, and says so instead of answering false', () => {
  const [, , blockHex, prevScripts, , filterHex] = VECTORS[0];
  const block = hex.decode(blockHex);
  // No context at all is a refusal: "this wallet cannot tell" is not the same
  // answer as "this filter is wrong", and returning false would hide which one
  // it was.
  assert.throws(() => filterMatchesBlock({ filter: hex.decode(filterHex), block }), /scripts this block's inputs spend/);
  // An empty list is a claim, and for the genesis block it is the true one:
  // nothing outside the block is spent.
  assert.equal(filterMatchesBlock({ filter: hex.decode(filterHex), block, prevScripts: [] }), true);
  // With the published context it is also true.
  assert.equal(filterMatchesBlock({
    filter: hex.decode(filterHex),
    block,
    prevScripts: prevScripts.map((script) => hex.decode(script)),
  }), true);
  witness('missing context', 'refused, not false');
});

test('THE FORGE: a real header carrying a body it does not commit to is refused, at the socket', async () => {
  // Executed against this wallet by AUDITOR before the merkle check existed:
  // two peers agree on a filter (so agreement is satisfied), and serve a real,
  // public header under which they attach a body that pays our script. The
  // header hashes to the advertised block hash and the filter matches the body,
  // so every check but one passes. The one that does not is the header's merkle
  // root, and the refusal has to be the outcome.
  const [, blockHash, realBlock] = VECTORS[0];
  const forged = new Uint8Array([
    ...hex.decode(realBlock).slice(0, 80),
    0x01,
    ...serializeTx({
      version: 2,
      inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(0x51), sequence: 0xffffffff }],
      outputs: [{ value: 5000000000n, script: OUR_SCRIPT }],
      lockTime: 0,
    }, { witness: false }),
  ]);
  // The lie is real: the header is unchanged, so it still hashes to the block
  // hash both peers are quoting.
  assert.equal(hex.encode(reverseBytes(sha256d(forged.slice(0, 80)))), blockHash);

  const fabricated = buildBasicFilter({ blockHash, outputScripts: [OUR_SCRIPT] });
  const answer = (command) => {
    if (command === 'getcfilters') return frame('cfilter', encodeCfilter({ blockHash, filter: fabricated }));
    if (command === 'getdata') return frame('block', forged);
    return [];
  };
  const a = await startPeer(answer);
  const b = await startPeer(answer);
  try {
    const pool = poolFor(a, b);
    const client = createPeerClient({ connect, timeoutMs: 2000 });
    // Agreement is satisfied — two peers, the same bytes.
    const agreed = await agreedFilter(pool, client.fetchFilter, blockHash);
    assert.equal(hex.encode(agreed.filter), hex.encode(fabricated));
    // And the filter matches the forged body, which is why the body check is
    // the only thing standing between this and a believed payment.
    assert.equal(matchesFilter(agreed.filter, blockHash, OUR_SCRIPT), true);

    await assert.rejects(verifiedFilter(pool, client, blockHash), /merkle root/);
    witness('forged body under a real header', `agreement ${agreed.peers.length} peers`, 'merkle root: refused');
  } finally {
    await a.close(); await b.close();
  }
});

test('an honest filter verified against its block is accepted', async () => {
  const [, blockHash, blockHex, prevScripts, , filterHex] = VECTORS[0];
  const block = hex.decode(blockHex);
  const answer = (command) => {
    if (command === 'getcfilters') return frame('cfilter', encodeCfilter({ blockHash, filter: hex.decode(filterHex) }));
    if (command === 'getdata') return frame('block', block);
    return [];
  };
  const a = await startPeer(answer);
  const b = await startPeer(answer);
  try {
    const pool = poolFor(a, b);
    const client = createPeerClient({ connect, timeoutMs: 2000 });
    const out = await verifiedFilter(pool, client, blockHash, { prevScripts: prevScripts.map((script) => hex.decode(script)) });
    witness('verified honest filter', hex.encode(out.filter).slice(0, 48));
    assert.equal(hex.encode(out.filter), filterHex);
    assert.equal(out.peers.length, 2);
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

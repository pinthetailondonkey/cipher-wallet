// A2 independent-auditor probe: the Bitcoin network and scan side.
//
// Runs real loopback sockets with real wire frames, like test/filter-drill. Each
// numbered section is a hypothesis from README to break. Prints [A2 WITNESS]
// lines so a green cannot hide a never-run assertion.
//
//   node state/findings/probe-A2.mjs

import net from 'node:net';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import {
  blockOutputScripts, buildBasicFilter, filterMatchesBlock, matchesFilter,
} from '../../src/filters.js';
import { reverseBytes, serializeTx, sha256d, txid, readVarint } from '../../src/tx.js';
import { agreedFilter, createPeerPool, verifiedFilter } from '../../src/peers.js';
import { createPeerClient, frame, encodeCfilter, encodeVersion, PROTOCOL_VERSION } from '../../src/peerClient.js';
import { decodeGetCfilters, decodeGetData, decodeFrame } from '../../src/wire.js';
import { blockHash, blockHeader, previousBlockHash, walkBack, walkHeadersForward } from '../../src/chain.js';
import { scanBack, scanHeaderFirst } from '../../src/blockScan.js';
import { verifyBlockBody } from '../../src/merkle.js';

const VECTORS = JSON.parse(
  readFileSync(new URL('../../test/fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((f) => (typeof f === 'string' ? f.replace(/ /g, '') : f)));

const OUR_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(7)]);
const OTHER_SCRIPT = Uint8Array.from([0x00, 0x14, ...new Uint8Array(20).fill(9)]);
const vh = 1;

let failures = 0;
function check(name, cond) {
  console.log(`[A2 ${cond ? 'PASS' : 'FAIL'}] ${name}`);
  if (!cond) failures += 1;
}
function witness(...v) { console.log(`[A2 WITNESS] ${v.join(' | ')}`); }

// ---- socket harness --------------------------------------------------------

// A peer-shaped server. `answer(command, request)` returns raw frame bytes (or a
// list). `honorRange` makes getcfilters send from startHeight..stopHeight like a
// real node; default off (stub always answers the asked hash, like filter-drill).
async function startPeer(answer, { honorRange = false, heightOf = new Map() } = {}) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.write(frame('version', encodeVersion({ nonce: 1n, services: 1n | 64n })));
    let buffered = new Uint8Array(0);
    socket.on('data', (chunk) => {
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0); joined.set(chunk, buffered.length);
      buffered = joined;
      while (buffered.length >= 24) {
        let message;
        try { message = decodeFrame(buffered); } catch { return; }
        buffered = buffered.slice(message.size);
        if (message.command === 'version') { socket.write(frame('verack')); continue; }
        if (message.command === 'verack') continue;
        let request = null;
        try {
          if (message.command === 'getcfilters') request = decodeGetCfilters(message.payload);
          else if (message.command === 'getdata') request = decodeGetData(message.payload);
        } catch { continue; }
        if (!request) continue;
        if (honorRange && message.command === 'getcfilters') {
          const { startHeight, stopHash } = request;
          const top = heightOf.get(stopHash);
          if (top === undefined || startHeight > top) continue; // a real node sends nothing
          for (let h = startHeight; h <= top; h += 1) {
            const entry = [...heightOf.entries()].find(([, hh]) => hh === h);
            if (!entry) continue;
            const rf = rangeFilter.get(entry[0]);
            socket.write(frame('cfilter', encodeCfilter({ blockHash: entry[0], filter: rf ? rf[1] : Uint8Array.of(1) })));
            if (entry[0] === stopHash) break;
          }
          continue;
        }
        for (const out of [].concat(answer(message.command, request) ?? [])) socket.write(out);
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => new Promise((r) => { for (const s of sockets) s.destroy(); server.close(r); }) };
}

const rangeFilter = new Map(); // hash -> [hash, filter], for honorRange peers

function connect(peer) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: peer.host, port: peer.port }, () => resolve({
      write: (b) => socket.write(b),
      end: () => socket.end(),
      onData: (fn) => socket.on('data', (c) => fn(new Uint8Array(c))),
      onClose: (fn) => socket.on('close', fn),
    }));
    socket.on('error', reject);
  });
}
const client = (t = 1500) => createPeerClient({ connect, timeoutMs: t });
function poolFor(...servers) {
  const pool = createPeerPool({ allowClearnet: true });
  for (const s of servers) pool.add({ host: '127.0.0.1', port: s.port });
  return pool;
}
const honestAnswer = (filter, hash) => () => frame('cfilter', encodeCfilter({ blockHash: hash, filter }));

// ---- 1. is "two independent peers" really two? ----------------------------

console.log('\n== 1. agreement anchoring / one peer answering both sides ==');

// 1a: ONE server process answering both "peers". The same entry is passed
// twice as the peers list, so both fetches hit one socket server.
{
  let hits = 0;
  const a = await startPeer(() => { hits += 1; return frame('cfilter', encodeCfilter({ blockHash: 'ab'.repeat(32), filter: Uint8Array.of(1, 2, 3) })); });
  const b = await startPeer(() => frame('cfilter', encodeCfilter({ blockHash: 'ab'.repeat(32), filter: Uint8Array.of(1, 2, 3) })));
  try {
    const pool = createPeerPool({ allowClearnet: true });
    const one = pool.add({ host: '127.0.0.1', port: a.port });
    pool.add({ host: '127.0.0.1', port: b.port }); // pool.size()>=2 satisfies requireAgreement
    // both asks go to the SAME server entry, twice
    const out = await agreedFilter(pool, client().fetchFilter, 'ab'.repeat(32), { peers: [one, one], startHeight: vh });
    witness('1a same peer entry twice', `agreed peers=${out.peers.length}`, `server-A hits=${hits}`);
    check('1a one physical peer listed twice satisfies "two peers"', out.peers.length === 2 && hits === 2);
  } finally { await a.close(); await b.close(); }
}

// 1b: ONE server process, TWO ports -> pool sees two "peers", one operator.
{
  const filter = Uint8Array.of(9, 8, 7);
  // one handler, two listeners is overkill; two startPeer calls share one answer
  // fn = one operator. Show the pool treats them as independent.
  const a = await startPeer(honestAnswer(filter, 'cd'.repeat(32)));
  const b = await startPeer(honestAnswer(filter, 'cd'.repeat(32)));
  try {
    const pool = poolFor(a, b);
    const out = await agreedFilter(pool, client().fetchFilter, 'cd'.repeat(32), { startHeight: 1 });
    check('1b two pool entries (one operator) are counted as two agreeing peers', out.peers.length === 2);
    witness('1b one operator at two ports', `agreed peers=${out.peers.length}`);
  } finally { await a.close(); await b.close(); }
}

// 1c: one peer, no agreement at all, inventing a payment via a private chain.
// walkBack/scanBack take a SINGLE peer; nothing checks two peers there.
{
  const AMOUNT = 123456789n;
  function privBlock(prevDigest, fill) {
    const tx = {
      version: 1,
      inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }],
      outputs: [{ value: AMOUNT, script: OUR_SCRIPT }],
      lockTime: 0,
    };
    const header = new Uint8Array(80).fill(fill);
    header.set(prevDigest, 4);
    header.set(reverseBytes(hex.decode(txid(tx))), 36);
    const block = new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
    return { block, header };
  }
  const { block: P, header: PH } = privBlock(new Uint8Array(32), 0xff); // arbitrary header
  const { block: T } = privBlock(sha256d(PH), 0xee);
  const PHASH = blockHash(P); const THASH = blockHash(T);
  const TIP = T; const TIP_HASH = blockHash(TIP);
  const byHash = new Map([[THASH, TIP], [PHASH, P]]);
  const peer = await startPeer((cmd, req) => {
    if (cmd === 'getdata') {
      const bytes = byHash.get(req.hash);
      return bytes ? frame('block', bytes) : [];
    }
    if (cmd === 'getcfilters') {
      // honest filter built from the block that was asked about
      const hash = req.stopHash;
      const block = byHash.get(hash);
      if (!block) return [];
      const { scripts } = blockOutputScripts(block);
      return frame('cfilter', encodeCfilter({ blockHash: hash, filter: buildBasicFilter({ blockHash: hash, outputScripts: scripts }) }));
    }
    return [];
  });
  try {
    const c = client();
    // Single peer, peer-supplied tip. No second peer anywhere.
    const blocks = await walkBack({ fetchBlock: c.fetchBlock, peer: { host: '127.0.0.1', port: peer.port }, tipHash: TIP_HASH, tipHeight: 500 });
    check('1c a private, never-mined chain is walked and accepted from ONE peer', blocks.length === 2);
    // Header has tiny/huge bits that never meet any target, yet accepted:
    witness('1c accepted tip header bits', hex.encode(TIP.slice(72, 76)));
    // A fabricated payment appears from a single peer.
    const scan = await scanBack({
      fetchFilter: c.fetchFilter, fetchBlock: c.fetchBlock,
      peer: { host: '127.0.0.1', port: peer.port }, tipHash: TIP_HASH, tipHeight: 500, scripts: [OUR_SCRIPT],
    });
    check('1c one peer invents a payment (fabricated block body)', scan.payments.length >= 2);
    witness('1c single-peer fabricated payments', scan.payments.length, `amount=${scan.payments[0]?.value}`);
  } finally { await peer.close(); }
}

// ---- 2. is the merkle/header check run on the exact bytes believed? -------

console.log('\n== 2. checks run on the bytes that are believed ==');
{
  const [height, blockHashHex, blockHex, prevScripts, , filterHex] = VECTORS[0];
  const block = hex.decode(blockHex);
  const prev = prevScripts.map((s) => hex.decode(s));
  let blockFetches = 0;
  const answer = (cmd) => {
    if (cmd === 'getcfilters') return frame('cfilter', encodeCfilter({ blockHash: blockHashHex, filter: hex.decode(filterHex) }));
    if (cmd === 'getdata') { blockFetches += 1; return frame('block', block); }
    return [];
  };
  const a = await startPeer(answer); const b = await startPeer(answer);
  try {
    const pool = poolFor(a, b);
    const out = await verifiedFilter(pool, client(), blockHashHex, { prevScripts: prev, startHeight: height });
    check('2 verifiedFilter fetches the block exactly once (no second copy)', blockFetches === 1);
    check('2 the returned block is byte-identical to what was merkle-checked', hex.encode(out.block) === blockHex);
    // And the returned block is the very bytes the merkle check ran on: re-derive.
    const { blockHash: got } = blockOutputScripts(out.block);
    check('2 returned block still hashes to the asked hash', got === blockHashHex);

    // Mutation A: flip one body byte -> only merkle catches it (header hash still matches).
    const fakeBody = Uint8Array.from(block);
    fakeBody[fakeBody.length - 1] ^= 0xff;
    const answerA = (cmd) => cmd === 'getcfilters'
      ? frame('cfilter', encodeCfilter({ blockHash: blockHashHex, filter: hex.decode(filterHex) }))
      : cmd === 'getdata' ? frame('block', fakeBody) : [];
    const a2 = await startPeer(answerA); const b2 = await startPeer(answerA);
    const pool2 = poolFor(a2, b2);
    let caughtBy = null;
    try { await verifiedFilter(pool2, client(), blockHashHex, { prevScripts: prev, startHeight: height }); }
    catch (e) { caughtBy = e.message; }
    await a2.close(); await b2.close();
    check('2 a mutated body is refused', /merkle root|does not produce|bytes after/.test(caughtBy || ''));
    witness('2 mutated-body refusal', caughtBy);

    // Mutation B: flip a header byte -> hash check catches before merkle.
    const fakeHeader = Uint8Array.from(block); fakeHeader[0] ^= 0xff;
    const answerB = (cmd) => cmd === 'getcfilters'
      ? frame('cfilter', encodeCfilter({ blockHash: blockHashHex, filter: hex.decode(filterHex) }))
      : cmd === 'getdata' ? frame('block', fakeHeader) : [];
    const a3 = await startPeer(answerB); const b3 = await startPeer(answerB);
    const pool3 = poolFor(a3, b3);
    let caughtHdr = null;
    try { await verifiedFilter(pool3, client(), blockHashHex, { prevScripts: prev, startHeight: height }); }
    catch (e) { caughtHdr = e.message; }
    await a3.close(); await b3.close();
    check('2 a mutated header is refused', /merkle root|served block|does not produce|bytes after/.test(caughtHdr || ''));
    witness('2 mutated-header refusal', caughtHdr);
  } finally { await a.close(); await b.close(); }
}

// ---- 3. omitted script: is the README admission exact? --------------------

console.log('\n== 3. a filter that omits our script under header-first ==');
{
  const AMOUNT = 250000000n;
  function blockPaying(prevDigest, script, fill) {
    const tx = { version: 1, inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }], outputs: [{ value: AMOUNT, script }], lockTime: 0 };
    const header = new Uint8Array(80).fill(fill); header.set(prevDigest, 4); header.set(reverseBytes(hex.decode(txid(tx))), 36);
    return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  }
  const BLOCK = blockPaying(new Uint8Array(32), OUR_SCRIPT, 7);
  const HASH = blockHash(BLOCK);
  const OMITTING = buildBasicFilter({ blockHash: HASH, outputScripts: [OTHER_SCRIPT] });
  const fast = await scanHeaderFirst({
    fetchHeaders: async () => ({ headers: [BLOCK.slice(0, 80)] }),
    fetchFilter: async () => ({ filter: OMITTING, blockHash: HASH }),
    fetchBlock: async () => ({ bytes: BLOCK }),
    peer: {}, anchorHash: '00'.repeat(32), anchorHeight: 0, tipHash: HASH, scripts: [OUR_SCRIPT],
  });
  const slow = await scanBack({
    fetchFilter: async () => ({ filter: OMITTING, blockHash: HASH }),
    fetchBlock: async () => ({ bytes: BLOCK }),
    peer: {}, tipHash: HASH, tipHeight: 1, scripts: [OUR_SCRIPT],
  });
  check('3 header-first LOSES the omitted payment', fast.payments.length === 0 && fast.skipped.length === 1);
  check('3 backwards walk FINDS it (reads every body)', slow.payments.length === 1);
  witness('3 omission', `header-first payments=${fast.payments.length} bodies=${fast.bodiesFetched}`, `backwards payments=${slow.payments.length}`);
}

// ---- 4. proof of work: is any work verified? ------------------------------

console.log('\n== 4. proof of work ==');
{
  // Wire bytes 72..76 are the nBits field. Pick block headers whose hash meets
  // NO plausible target and show they are accepted anyway. Also confirm no code
  // path reads a target.
  const AMOUNT = 42n;
  function rawBlock(fill) {
    const tx = { version: 1, inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }], outputs: [{ value: AMOUNT, script: OUR_SCRIPT }], lockTime: 0 };
    const header = new Uint8Array(80).fill(fill); header.set(reverseBytes(hex.decode(txid(tx))), 36);
    header.set([0x00, 0x00, 0x00, 0x00], 72); // nBits = 0 -> target 0, impossible
    return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  }
  const B = rawBlock(0xab);
  const { bytes } = (() => ({ bytes: B }))();
  // verifyBlockBody does not consult nBits at all
  const body = verifyBlockBody(bytes);
  check('4 a block with nBits=0 (impossible target) is accepted, body checked', !!body.blockHash);
  witness('4 nBits field', hex.encode(bytes.slice(72, 76)), `hash=${body.blockHash.slice(0, 16)}`, 'no target compare');
  check('4 header-hash roundtrip still holds', body.blockHash === hex.encode(reverseBytes(sha256d(bytes.slice(0, 80)))));
  // Cost: a "mined" header is any 80 bytes; node re-derives hash. One sha256d.
  witness('4 private-chain cost', 'each block: 1 arbitrary 80-byte header + self merkle root; 0 leading zeros required');
}

// ---- 5. is a height trusted or counted? -----------------------------------

console.log('\n== 5. height: trusted claim vs count ==');
{
  // walkBack's heights are tipHeight-step; nothing in bytes proves them.
  const AMOUNT = 5n;
  function rawBlock(prevDigest, fill) {
    const tx = { version: 1, inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }], outputs: [{ value: AMOUNT, script: OUR_SCRIPT }], lockTime: 0 };
    const header = new Uint8Array(80).fill(fill); header.set(prevDigest, 4); header.set(reverseBytes(hex.decode(txid(tx))), 36);
    return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  }
  const { header: PH } = { header: rawBlock(new Uint8Array(32), 1).slice(0, 80) };
  const HASH = blockHash(rawBlock(new Uint8Array(32), 1));
  const blocks = await walkBack({
    fetchBlock: async () => ({ bytes: rawBlock(new Uint8Array(32), 1) }),
    peer: {}, tipHash: HASH, tipHeight: 777,
  });
  check('5 walkBack stamps heights from the tipHeight CLAIM (777)', blocks[0].height === 777);
  witness('5 counted height', `block height=${blocks[0].height}`, 'from claim, not bytes');
  void PH;

  // A range-honoring peer: a wrong startHeight makes fetchFilter refuse.
  const [vheight, vhash, vhex, vprev, , vfilter] = VECTORS[1];
  const vblock = hex.decode(vhex);
  const heightOf = new Map([[vhash, vheight]]);
  rangeFilter.set(vhash, [vhash, hex.decode(vfilter)]);
  // A real node's getcfilters answers the WHOLE range startHeight..stop: if we
  // ask below the block's height, the first cfilter is an EARLIER block.
  const DECOY = 'ab'.repeat(32);
  if (vheight > 0) { heightOf.set(DECOY, vheight - 1); rangeFilter.set(DECOY, [DECOY, Uint8Array.of(9)]); }
  const peer = await startPeer(null, { honorRange: true, heightOf });
  try {
    // correct height -> accepted
    const ok = await client().fetchFilter({ host: '127.0.0.1', port: peer.port }, vhash, { startHeight: vheight });
    check('5 correct height is accepted', ok.blockHash === vhash);
    // inflated height -> real node sends nothing -> timeout
    let inflated = null;
    try { await client(400).fetchFilter({ host: '127.0.0.1', port: peer.port }, vhash, { startHeight: vheight + 10 }); }
    catch (e) { inflated = e.message; }
    check('5 inflated height is refused (fail-closed)', /time|answer/.test(inflated || ''));
    witness('5 inflated height', inflated);
    // deflated height -> real node sends an EARLIER block's cfilter first -> refusal
    let deflated = null;
    try { await client(400).fetchFilter({ host: '127.0.0.1', port: peer.port }, vhash, { startHeight: Math.max(0, vheight - 1) }); }
    catch (e) { deflated = e.message; }
    check('5 deflated height is refused (fail-closed)', /answered about block|time|answer/.test(deflated || ''));
    witness('5 deflated height', deflated);
  } finally { await peer.close(); }
}

console.log('\n== 6. anchoring: first answer is the anchor, the rest is a veto ==');
{
  const askedHash = 'ef'.repeat(32);
  const X = Uint8Array.of(0xaa);
  const Z = Uint8Array.of(0xbb);
  const liarFirst = async (peer, asked) => ({ filter: peer.host === 'first' ? X : Z, blockHash: asked });
  // 6a: two peers, first says X, second says Z -> no belief (second vetoes).
  {
    const pool = createPeerPool({ allowClearnet: true });
    const peers = [pool.add({ host: 'first', port: 1 }), pool.add({ host: 'second', port: 2 })];
    let refused = null;
    try { await agreedFilter(pool, liarFirst, askedHash, { peers, startHeight: 1 }); }
    catch (e) { refused = e.message; }
    check('6a a first-answering liar is vetoed by the second (refusal, no false belief)', /did not agree/.test(refused || ''));
    witness('6a liar-first of two', refused);
  }
  // 6b: three peers, first lies X, other two honest Z -> refused, though 2 agree on Z.
  {
    const pool = createPeerPool({ allowClearnet: true });
    const peers = [pool.add({ host: 'first', port: 1 }), pool.add({ host: 'b', port: 2 }), pool.add({ host: 'c', port: 3 })];
    let refused = null;
    try { await agreedFilter(pool, liarFirst, askedHash, { peers, startHeight: 1 }); }
    catch (e) { refused = e.message; }
    check('6b anchor on a liar discards an honest 2-3 majority (acknowledged refusal)', /did not agree/.test(refused || ''));
    witness('6b liar-first of three, majority honest', refused);
  }
  // 6c: three peers, first liar X, a colluder X, third honest Z -> X believed.
  {
    const pool = createPeerPool({ allowClearnet: true });
    const peers = [pool.add({ host: 'first', port: 1 }), pool.add({ host: 'b', port: 2 }), pool.add({ host: 'c', port: 3 })];
    const answer = async (peer, asked) => ({ filter: peer.host === 'c' ? Z : X, blockHash: asked });
    const out = await agreedFilter(pool, answer, askedHash, { peers, startHeight: 1 });
    check('6c two colluding peers (one asked first) can carry a false filter', hex.encode(out.filter) === hex.encode(X));
    witness('6c liar-first + one colluder', hex.encode(out.filter));
  }
}

console.log('\n== 7. the tip-hash door, the anchor, and anchorHeight ==');
{
  const AMOUNT = 77n;
  function mk(prevDigest, fill) {
    const tx = { version: 1, inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: Uint8Array.of(fill), sequence: 0xffffffff }], outputs: [{ value: AMOUNT, script: OUR_SCRIPT }], lockTime: 0 };
    const header = new Uint8Array(80).fill(fill); header.set(prevDigest, 4); header.set(reverseBytes(hex.decode(txid(tx))), 36);
    return new Uint8Array([...header, 0x01, ...serializeTx(tx, { witness: false })]);
  }
  // Fake "anchor": a header the wallet has been told to trust, never fetched.
  const ANCHOR_HEADER = mk(new Uint8Array(32), 0x11).slice(0, 80);
  const ANCHOR_HASH = blockHash(ANCHOR_HEADER);
  // Fork A (honest-shaped) and fork B (attacker's), both children of the anchor.
  const A_HEAD = mk(sha256d(ANCHOR_HEADER), 0x22);
  const B_HEAD = mk(sha256d(ANCHOR_HEADER), 0x33);
  const A_HASH = blockHash(A_HEAD);
  const B_HASH = blockHash(B_HEAD);

  // 7a: walkHeadersForward never fetches or hashes the anchor. A completely
  // fabricated anchor hash that a header names as parent is accepted.
  const FAKE_ANCHOR = 'ff'.repeat(32);
  const FAKE_HEAD = mk(new Uint8Array(32).fill(0xff), 0x44); // names 0xff..ff as parent
  const once = (head) => { let done = false; return async () => { if (done) return { headers: [] }; done = true; return { headers: [head.slice(0, 80)] }; }; };
  let walked = null;
  try {
    walked = await walkHeadersForward({ fetchHeaders: once(FAKE_HEAD), peer: {}, anchorHash: FAKE_ANCHOR, anchorHeight: 10 });
  } catch (e) { walked = e; }
  check('7a an anchor that is not a real block is still walked (anchor hash unverified)', Array.isArray(walked) ? walked.length === 1 : false);
  witness('7a fabricated anchor', `anchor=${FAKE_ANCHOR.slice(0, 8)} walked=${Array.isArray(walked) ? walked.length : String(walked)}`);

  // 7b: two forks off one anchor both validate; nothing chooses between them.
  const headersFor = (tip) => async () => ({ headers: [tip.slice(0, 80)] });
  const a = await walkHeadersForward({ fetchHeaders: headersFor(A_HEAD), peer: {}, anchorHash: ANCHOR_HASH, anchorHeight: 10, tipHash: A_HASH });
  const b = await walkHeadersForward({ fetchHeaders: headersFor(B_HEAD), peer: {}, anchorHash: ANCHOR_HASH, anchorHeight: 10, tipHash: B_HASH });
  check('7b two competing forks off the same anchor both pass every link and work-free check', a.length === 1 && b.length === 1);
  witness('7b forks', `A=${a[0].hash.slice(0, 8)} B=${b[0].hash.slice(0, 8)}`);

  // 7c: anchorHeight is believed verbatim; a wrong one silently renumbers.
  const hi = await walkHeadersForward({ fetchHeaders: once(A_HEAD), peer: {}, anchorHash: ANCHOR_HASH, anchorHeight: 800000 });
  check('7c a wrong anchorHeight renumbers every header with nothing to contradict it', hi[0].height === 800001);
  witness('7c anchorHeight believed', `stamped height=${hi[0].height}`);

  // 7d: the walk's own height is what the filter question uses, so a lied height
  // is handed straight to getcfilters. Capture it.
  let askedStart = null;
  await scanHeaderFirst({
    fetchHeaders: headersFor(A_HEAD),
    fetchFilter: async (peer, hash, opts) => { askedStart = opts.startHeight; return { filter: buildBasicFilter({ blockHash: hash, outputScripts: blockOutputScripts(A_HEAD).scripts }), blockHash: hash }; },
    fetchBlock: async () => ({ bytes: A_HEAD }),
    peer: {}, anchorHash: ANCHOR_HASH, anchorHeight: 800000, tipHash: A_HASH, scripts: [OUR_SCRIPT],
  });
  check('7d the lied height reaches the filter question unchanged', askedStart === 800001);
  witness('7d height -> getcfilters startHeight', askedStart);
}

console.log(`\n[A2] ${failures === 0 ? 'ALL CHECKS PASS' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);

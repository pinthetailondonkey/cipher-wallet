// What the node client must refuse, and the words it refuses with.
//
// A node is a stranger's server. Every case here is a way its answer could be
// mistaken for a fact about the chain: an empty answer read as an empty block,
// an HTML error page read as success, another host's answer read as this one's,
// a different network read as ours, a node still catching up read as missing
// blocks. Each is a failed read, and none of them is ever "no payment".

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getBlock, getInfo } from '../src/monero/nodeClient.js';

const NODE = 'peer.onion:18081';
const HASH = 'ab'.repeat(32);

function response(body, { ok = true, status = 200, url = `http://${NODE}/json_rpc` } = {}) {
  return {
    ok,
    status,
    url,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  };
}

function rpc(result) {
  return response({ jsonrpc: '2.0', id: '0', result });
}

function witness(name, ...values) {
  console.log(`[monero-node] ${name}: ${values.join(' | ')}`);
}

test('a block answer without a blob is a failed read, not an empty block', async () => {
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => rpc({ status: 'OK' }) }),
    /without a block blob/,
  );
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => rpc({ blob: 'xyz' }) }),
    /without a block blob/,
  );
  witness('missing blob', 'absent and non-hex both refused');
});

test('an HTML page wearing a success code is refused as not JSON', async () => {
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => response('<html>nope</html>') }),
    /not JSON/,
  );
  witness('html', 'refused');
});

test('an answer that arrives from another host is refused, whatever it says', async () => {
  const elsewhere = response({ jsonrpc: '2.0', result: { blob: '00' } }, { url: 'http://stranger.example/json_rpc' });
  await assert.rejects(getBlock(NODE, { hash: HASH }, { fetchImpl: async () => elsewhere }), /another host/);
  witness('redirect', 'another host refused');
});

test('a non-2xx answer, and a fetch that fails outright, are both failed reads', async () => {
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => response('no', { ok: false, status: 500 }) }),
    /status 500/,
  );
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => { throw new Error('ECONNREFUSED'); } }),
    /did not answer/,
  );
  witness('transport', '500 refused', 'no answer refused');
});

test('a node that takes the connection and then says nothing is refused on a deadline, never waited on', async () => {
  let seen = null;
  const fetchImpl = (url, init) => new Promise((resolve, reject) => {
    seen = init.signal;
    // A guard on the test itself, so it fails fast and by NAME when the
    // deadline is missing. Without it the fetch never settles, the runner sees
    // an empty event loop with a pending promise, cancels the whole file and
    // prints `# fail 0` behind a column of `not ok` — a green light made of a
    // stall. The backstop is long enough that it cannot fire on a real abort.
    const backstop = setTimeout(
      () => reject(new Error('the test settled a stalled fetch: nothing aborted it')),
      400,
    );
    init.signal.addEventListener('abort', () => {
      clearTimeout(backstop);
      reject(new Error('aborted'));
    }, { once: true });
  });
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl, timeoutMs: 20 }),
    /did not answer within 20 ms/,
  );
  assert.equal(seen.aborted, true, 'the request must carry the deadline');
  witness('deadline', 'a silent node is refused, not waited on');
});

test('a caller that brings its own signal keeps it, and no second deadline is imposed', async () => {
  const own = new AbortController();
  let seen = null;
  const fetchImpl = async (url, init) => { seen = init.signal; return rpc({ height: 1, target_height: 1, nettype: 'mainnet' }); };
  const info = await getInfo(NODE, { fetchImpl, timeoutSignal: own.signal });
  assert.equal(seen, own.signal);
  assert.equal(info.height, 1);
  witness('own signal', 'passed through, controller not built');
});

// A real daemon's get_block answer, pinned as
// test/fixtures/monero-node-client-block-answer.json. The daemon sends its
// parsed copy as a STRING in `json` and its claims at the TOP LEVEL in
// `block_header`. The first claim-check read `result.json?.block_header` — an
// object lookup that never fires against the string a real daemon sends — and
// the test that "proved" it passed json as an object: the fixture-writer's
// trap a second time, in the door itself. Every case below serves the real
// shape.
const REAL_ANSWER = JSON.parse(readFileSync(new URL('./fixtures/monero-node-client-block-answer.json', import.meta.url), 'utf8'));
const squeeze = (text) => String(text).replace(/\s+/g, '');

function realRpc() {
  const r = REAL_ANSWER.result;
  const header = r.block_header;
  return rpc({
    blob: squeeze(r.blob),
    // A real daemon sends a string; so does this. The fixture's hex carries the
    // policy space every 32 characters, so the hash list is squeezed too.
    json: JSON.stringify({ ...r.json, tx_hashes: r.json.tx_hashes.map(squeeze) }),
    block_header: {
      ...header,
      hash: squeeze(header.hash),
      prev_hash: squeeze(header.prev_hash),
      miner_tx_hash: squeeze(header.miner_tx_hash),
    },
  });
}

test('a real daemon answer claiming a different hash than the one asked is refused', async () => {
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => realRpc() }),
    (err) => err.message.includes('said it served') && err.message.includes(squeeze(REAL_ANSWER.result.block_header.hash)),
  );
  witness('real-shape hash claim', 'the top-level block_header is checked; json stays a string');
});

test('a real daemon answer claiming a different height than the one asked is refused', async () => {
  const asked = REAL_ANSWER.result.block_header.height + 1;
  await assert.rejects(
    getBlock(NODE, { height: asked }, { fetchImpl: async () => realRpc() }),
    (err) => err.message.includes('said it served height') && err.message.includes(String(REAL_ANSWER.result.block_header.height)),
  );
  witness('real-shape height claim', 'refused with both heights named');
});

test('a real daemon answer asked by its own height passes the check and carries the claims home', async () => {
  const served = await getBlock(
    NODE,
    { height: REAL_ANSWER.result.block_header.height },
    { fetchImpl: async () => realRpc() },
  );
  assert.equal(served.claimedHash, squeeze(REAL_ANSWER.result.block_header.hash));
  assert.equal(served.claimedHeight, REAL_ANSWER.result.block_header.height);
  assert.equal(served.claimedPrevHash, squeeze(REAL_ANSWER.result.block_header.prev_hash));
  assert.equal(served.blob.length * 2, squeeze(REAL_ANSWER.result.blob).length, 'the blob comes home whole');
  witness('real-shape agreement', 'the claims are carried home, not dropped');
});

// The transaction hash list is what a scan needs to find a transaction in a
// block. The daemon sends it inside its parsed copy (`json`, an object in the
// pinned answer), and the claim `num_txes` names how many there should be. The
// fixture's list is checked against the mainnet block fixture's own list, which
// was captured separately from the same chain.
test('a real daemon answer carries its transaction hash list home, and the count matches num_txes', async () => {
  const served = await getBlock(
    NODE,
    { height: REAL_ANSWER.result.block_header.height },
    { fetchImpl: async () => realRpc() },
  );
  const expected = REAL_ANSWER.result.json.tx_hashes.map((h) => squeeze(h));
  assert.ok(Array.isArray(served.txHashes), 'the hash list comes home as a list');
  assert.equal(served.txHashes.length, REAL_ANSWER.result.block_header.num_txes, 'the list is as long as the node claims');
  assert.deepEqual(served.txHashes, expected, 'the list is the node\'s own list, in the node\'s order');
  for (const h of served.txHashes) assert.match(h, /^[0-9a-f]{64}$/, 'each entry is a 64-hex transaction id');
  witness('tx_hashes', `${served.txHashes.length} hashes, count equal to num_txes`);
});

test('asking by both hash and height, or by neither, is refused before any request is made', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return rpc({}); };
  await assert.rejects(getBlock(NODE, { hash: HASH, height: 1 }, { fetchImpl }), /or by its height, not both/);
  await assert.rejects(getBlock(NODE, {}, { fetchImpl }), /not both and not neither/);
  assert.equal(calls, 0, 'a malformed ask must not reach a stranger');
  witness('ask shape', 'both and neither refused before the network');
});

test('a height four bytes cannot hold is refused before any request is made', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return rpc({}); };
  await assert.rejects(getBlock(NODE, { height: 2 ** 32 }, { fetchImpl }), /0 to 4294967295/);
  await assert.rejects(getBlock(NODE, { height: -1 }, { fetchImpl }), /0 to 4294967295/);
  assert.equal(calls, 0);
  witness('height bound', '2^32 and -1 refused before the network');
});

test('a node on another network is refused, because its blocks are not this chain', async () => {
  await assert.rejects(
    getInfo(NODE, { fetchImpl: async () => rpc({ height: 100, target_height: 100, nettype: 'stagenet' }) }),
    /serves stagenet, not mainnet/,
  );
  witness('network', 'stagenet refused for a mainnet wallet');
});

test('a node still syncing is a failed read, never a chain that is missing blocks', async () => {
  await assert.rejects(
    getInfo(NODE, { fetchImpl: async () => rpc({ height: 100, target_height: 300, nettype: 'mainnet' }) }),
    /still syncing/,
  );
  witness('sync', '100 of 300 refused');
});

// O6. This test used to assert `checked === 1` with the witness "checked after
// the answer", which was true and was the defect: the pool was asked once the
// node had already received the query. A refusal that arrives after the
// disclosure keeps nothing from the stranger. It now proves the order.
test('the pinned node is checked BEFORE the request, so a refusal never discloses it', async () => {
  const log = [];
  const pool = {
    abandon: () => {},
    assertCurrent: () => {
      log.push('assert');
      throw new Error('A scan runs against one Monero node. Refusing to stitch results from two.');
    },
  };
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => { log.push('fetch'); return rpc({ blob: '00' }); }, pool }),
    /Refusing to stitch/,
  );
  assert.deepEqual(log, ['assert'], 'the pool refuses before any request is made');
  witness('pinned node', 'checked before the socket', `log=${log.join(' -> ')}`);
});

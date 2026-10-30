// What the node client must refuse, and the words it refuses with.
//
// A node is a stranger's server. Every case here is a way its answer could be
// mistaken for a fact about the chain: an empty answer read as an empty block,
// an HTML error page read as success, another host's answer read as this one's,
// a different network read as ours, a node still catching up read as missing
// blocks. Each is a failed read, and none of them is ever "no payment".

import test from 'node:test';
import assert from 'node:assert/strict';
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

test('a node that says it served a different hash than the one asked for is refused', async () => {
  const body = rpc({ blob: '00', json: { block_header: { hash: 'cd'.repeat(32), height: 7 } } });
  await assert.rejects(getBlock(NODE, { hash: HASH }, { fetchImpl: async () => body }), /served cd/);
  witness('hash claim', 'the daemon’s own claim is checked');
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

test('the pinned node is checked on every answer, so one scan cannot straddle two servers', async () => {
  let checked = 0;
  const pool = { assertCurrent: () => { checked += 1; throw new Error('A scan runs against one Monero node. Refusing to stitch results from two.'); } };
  await assert.rejects(
    getBlock(NODE, { hash: HASH }, { fetchImpl: async () => rpc({ blob: '00' }), pool }),
    /Refusing to stitch/,
  );
  assert.equal(checked, 1);
  witness('pinned node', 'checked after the answer');
});

// The one-node-per-scan rule at the door boundary. The pool's assertCurrent
// fires when the node changes mid-stream, and both doors (getBlock and
// getTransactions) call it after each read. A silent cross-node read would
// poison a walk with bytes from two nodes while looking green. These
// controls pin that the door refuses by name when the pool switched.
//
// No new code. Pure pinning of existing pool-door interaction.

import test from 'node:test';
import assert from 'node:assert/strict';
import { getBlock, getInfo, getTransactions } from '../src/monero/nodeClient.js';
import { createNodePool } from '../src/monero/nodes.js';

// .example addresses are not .onion, so the pool needs allowClearnet
// to make the test pool.
const makePool = (nodes) => createNodePool({ nodes, allowClearnet: true });

// a fetchImpl that answers with a minimal valid get_block body
const blockBody = (hash) => async (url) => ({
  ok: true, status: 200, url,
  text: async () => JSON.stringify({
    id: '0', jsonrpc: '2.0',
    result: {
      blob: 'ab'.repeat(64),
      block_header: { hash, height: 100, prev_hash: 'c'.repeat(64) },
    },
  }),
});

// a fetchImpl that answers with a minimal valid get_transactions body
const txBody = (hash) => async (url) => ({
  ok: true, status: 200, url,
  text: async () => JSON.stringify({
    status: 'OK',
    txs: [{ as_hex: 'ab'.repeat(32) }],
    missed_tx: [],
  }),
});

test('pool-door: getBlock fires assertCurrent when the pool switched nodes', async () => {
  const pool = makePool(['first.example:18081', 'second.example:18081']);
  const first = pool.pick();

  // the pool abandons the first node and picks the second
  pool.abandon(first);

  // now a door call against the ABANDONED node must refuse
  const node = 'first.example:18081';
  assert.throws(
    () => pool.assertCurrent(node),
    /A scan runs against one Monero node/,
    'the pool refuses a call against the abandoned node',
  );

  // and the door itself carries the same check
  await assert.rejects(
      getBlock(node, { height: 100 }, {
        fetchImpl: blockBody(node), pool, timeoutMs: 5000,
      }),
      /A scan runs against one Monero node/,
      'the door refuses to return bytes from a node the pool abandoned',
  );
});

test('pool-door: getTransactions carries the same assertCurrent check', async () => {
  const pool = makePool(['first.example:18081', 'second.example:18081']);
  const first = pool.pick();
  pool.abandon(first);

  await assert.rejects(
      getTransactions(first, [`${'a'.repeat(64)}`], {
        fetchImpl: txBody(first), pool, timeoutMs: 5000,
      }),
      /A scan runs against one Monero node/,
      'the transaction door also refuses the abandoned node',
  );
});

test('pool-door: a call against the CURRENT node passes the check', () => {
  const pool = makePool(['current.example:18081', 'other.example:18081']);
  const current = pool.pick();
  // no abandon: the current node is still the session's node
  // the door call should NOT refuse on the pool check
  // (it may fail on the blob shape, but the pool check must pass)
  const p = getBlock(current, { height: 100 }, {
    fetchImpl: blockBody(current), pool, timeoutMs: 5000,
  });
  // the blob is fake so the parse may fail; what matters is the pool
  // check did not fire
  const result = p.then(
    (r) => ({ kind: 'ok', r }),
    (e) => ({ kind: 'error', e }),
  );
  return result.then(({ kind, e }) => {
    if (kind === 'error' && /Monero node/.test(e.message) && /one Monero node/.test(e.message)) {
      assert.fail('the pool check refused the CURRENT node: that is wrong');
    }
    console.log('[pool-door] the current node passes the pool check');
  });
});


// ---------------------------------------------------------------------------
// O6 REGRESSION. The pool refuses, so the request must never leave.
// A recording fetchImpl and a recording pool share one log; the log is the
// evidence. Against f1fcd6f this prints `fetch:... -> assert:...` and one
// network call; after the fix it is `assert:...` alone and zero calls.
// ---------------------------------------------------------------------------

const REFUSAL = 'A scan runs against one Monero node. Refusing to stitch results from two.';

function recordingDoor() {
  const log = [];
  const fetchImpl = async (url) => {
    log.push(`fetch:${url}`);
    return {
      ok: true,
      status: 200,
      url,
      text: async () => JSON.stringify(url.endsWith('/get_transactions')
        ? { status: 'OK', txs: [{ as_hex: 'ab'.repeat(32) }], missed_tx: [] }
        : {
            jsonrpc: '2.0',
            id: '0',
            result: {
              blob: 'ab'.repeat(64),
              block_header: { hash: 'a'.repeat(64), height: 1, prev_hash: 'c'.repeat(64) },
            },
          }),
    };
  };
  const pool = {
    assertCurrent(node) {
      log.push(`assert:${node}`);
      throw new Error(REFUSAL);
    },
    abandon(node) {
      log.push(`abandon:${node}`);
    },
  };
  return { log, fetchImpl, pool };
}

const DOORS = [
  ['getBlock', (node, opts) => getBlock(node, { height: 1 }, opts)],
  ['getTransactions', (node, opts) => getTransactions(node, ['a'.repeat(64)], opts)],
  ['getInfo', (node, opts) => getInfo(node, opts)],
];

for (const [name, door] of DOORS) {
  test(`O6 regression: ${name} makes NO network call when the pool refuses`, async () => {
    const node = 'pinned.example:18081';
    const { log, fetchImpl, pool } = recordingDoor();
    await assert.rejects(door(node, { fetchImpl, pool, timeoutMs: 5000 }), /one Monero node/);
    const fetches = log.filter((line) => line.startsWith('fetch:'));
    assert.deepEqual(fetches, [], `no request may leave: ${log.join(' -> ')}`);
    assert.equal(log.length, 1, `exactly one refusal entry: ${log.join(' -> ')}`);
    assert.match(log[0], /^assert:/, 'the pool is asked before anything else');
    console.log(`[pool-door] ${name}: refused with 0 network calls`);
  });
}

test('O6 control: on the CURRENT node the pool is asked FIRST, then the request goes out', async () => {
  const node = 'pinned.example:18081';
  const log = [];
  const fetchImpl = async (url) => {
    log.push(`fetch:${url}`);
    return {
      ok: true,
      status: 200,
      url,
      text: async () => JSON.stringify({
        jsonrpc: '2.0',
        id: '0',
        result: {
          blob: 'ab'.repeat(64),
          json: JSON.stringify({ tx_hashes: [] }),
          block_header: { hash: 'a'.repeat(64), height: 1, prev_hash: 'c'.repeat(64) },
        },
      }),
    };
  };
  const pool = { assertCurrent: (seen) => { log.push(`assert:${seen}`); }, abandon: () => {} };
  await getBlock(node, { height: 1 }, { fetchImpl, pool, timeoutMs: 5000 });
  assert.deepEqual(log.map((line) => line.split(':')[0]), ['assert', 'fetch'],
    `the check must precede the socket: ${log.join(' -> ')}`);
  console.log('[pool-door] ordered: assert -> fetch');
});

// ---------------------------------------------------------------------------
// A DEAD NODE ENDS THE SCAN. It does not silently move the scan to the next
// node: that would hand back bytes from a different operator inside one walk
// and call it one answer. The transport failure abandons the node in the pool
// so the NEXT scan starts elsewhere, and the current call still refuses.
// ---------------------------------------------------------------------------
test('a dead node refuses the scan and does not fail over inside it', async () => {
  const pool = makePool(['first.example:18081', 'second.example:18081']);
  const first = pool.pick();
  const tried = [];
  const fetchImpl = async (url) => {
    tried.push(url);
    throw new Error('ECONNREFUSED');
  };

  await assert.rejects(
    getBlock(first, { height: 100 }, { fetchImpl, pool, timeoutMs: 5000 }),
    /did not answer/,
    'the call refuses on the dead node',
  );
  assert.equal(tried.length, 1, `only the pinned node was tried: ${tried.join(', ')}`);

  // The dead node was abandoned, so the NEXT scan starts on the next node...
  const next = pool.pick();
  assert.equal(next, 'second.example:18081', 'the next scan moves on by itself');

  // ...and the abandoned node is refused by the pool from then on.
  assert.throws(() => pool.assertCurrent(first), /one Monero node/);
  console.log('[pool-door] dead node: refused in-scan, next scan moved to', next);
});

test('a healthy answer leaves the pin alone, so the session stays on its node', async () => {
  const pool = makePool(['only.example:18081']);
  const node = pool.pick();
  const served = await getBlock(node, { height: 100 }, {
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      url,
      text: async () => JSON.stringify({
        jsonrpc: '2.0',
        id: '0',
        result: {
          blob: 'ab'.repeat(64),
          json: JSON.stringify({ tx_hashes: [] }),
          block_header: { hash: 'a'.repeat(64), height: 100, prev_hash: 'c'.repeat(64) },
        },
      }),
    }),
    pool,
    timeoutMs: 5000,
  });
  assert.equal(served.address, node);
  assert.equal(pool.pick(), node, 'a success must not advance the pool');
  console.log('[pool-door] healthy answer: pin kept');
});

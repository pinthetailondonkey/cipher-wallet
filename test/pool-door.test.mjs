// The one-node-per-scan rule at the door boundary. The pool's assertCurrent
// fires when the node changes mid-stream, and both doors (getBlock and
// getTransactions) call it after each read. A silent cross-node read would
// poison a walk with bytes from two nodes while looking green. These
// controls pin that the door refuses by name when the pool switched.
//
// No new code. Pure pinning of existing pool-door interaction.

import test from 'node:test';
import assert from 'node:assert/strict';
import { getBlock, getTransactions } from '../src/monero/nodeClient.js';
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

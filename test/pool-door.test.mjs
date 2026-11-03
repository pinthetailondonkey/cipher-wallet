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

// ---------------------------------------------------------------------------
// O1 CLOSED: THE DOOR WALKS THE ENVIRONMENT ITSELF.
//
// Before this, a caller that passed no pool got no check at all: nodeClient did
// not import nodes.js, so CIPHER_XMR_NODE was a name nothing read. A door with
// no pool now resolves the wallet's configuration first, so a scan cannot point
// one door at a node the wallet did not name.
//
// The one deliberate exception, stated here so it is not discovered later: when
// the environment names nothing, the caller's own `node` argument is the pin
// (createPinnedPool). Refusing every no-pool call instead was measured: it
// turns 28 door tests red across block-redirect, block-timeout, tx-answer,
// tx-door and tx-timeout, which exercise the door's parsing against a named
// node. A caller that writes host:port into the call has pinned one node; the
// refusal for "nothing configured" is emitted when a scan asks the WALLET to
// choose (nodeSourceFromEnv with an empty environment).
// ---------------------------------------------------------------------------
const ENV_KEY = 'CIPHER_XMR_NODE';

function envDoor(node) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
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
              json: JSON.stringify({ tx_hashes: [] }),
              block_header: { hash: 'a'.repeat(64), height: 1, prev_hash: 'c'.repeat(64) },
            },
          }),
    };
  };
  return { calls, fetchImpl, guests: node };
}

const ENV_DOORS = [
  ['getBlock', (node, opts) => getBlock(node, { height: 1 }, opts)],
  ['getTransactions', (node, opts) => getTransactions(node, ['a'.repeat(64)], opts)],
  ['getInfo', (node, opts) => getInfo(node, opts)],
];

for (const [name, door] of ENV_DOORS) {
  test(`O1: ${name} with no pool refuses a node the environment did not name, and calls nobody`, async () => {
    const { calls, fetchImpl } = envDoor();
    await assert.rejects(
      door('stranger.example:18081', {
        fetchImpl, timeoutMs: 5000, env: { [ENV_KEY]: 'named.example:18081' },
      }),
      /one Monero node/,
    );
    assert.deepEqual(calls, [], `the stranger must not be disclosed to: ${calls.join(', ')}`);
    console.log(`[pool-door] ${name}: environment named a different node, 0 calls`);
  });
}

test('O1: with no pool and a configured node, the door uses that node', async () => {
  const { calls, fetchImpl } = envDoor();
  const served = await getBlock('peer.example:18081', { height: 1 }, {
    fetchImpl, timeoutMs: 5000, env: { [ENV_KEY]: 'peer.example:18081' },
  });
  assert.equal(served.address, 'peer.example:18081');
  assert.equal(calls.length, 1);
  console.log('[pool-door] configured node used, 1 call');
});

test('O1: with no pool and no environment, the caller\'s own node is the pin, not a default', async () => {
  const { calls, fetchImpl } = envDoor();
  const served = await getBlock('own.example:18081', { height: 1 }, {
    fetchImpl, timeoutMs: 5000, env: {},
  });
  assert.equal(served.address, 'own.example:18081', 'the address is the one the caller wrote');
  assert.equal(calls.length, 1);
  console.log('[pool-door] no environment: caller pin used, no default invented');
});

test('O1: an injected pool is used instead of the environment, unchanged', async () => {
  const { calls, fetchImpl } = envDoor();
  let asked = 0;
  await getBlock('peer.example:18081', { height: 1 }, {
    fetchImpl,
    timeoutMs: 5000,
    env: { [ENV_KEY]: 'other.example:18081' },
    pool: { assertCurrent: () => { asked += 1; }, abandon: () => {} },
  });
  assert.equal(asked, 1, 'the injected pool is the one consulted');
  assert.equal(calls.length, 1);
  console.log('[pool-door] injected pool wins over the environment');
});

test('O1: a malformed environment address is a named refusal before any socket', async () => {
  const { calls, fetchImpl } = envDoor();
  await assert.rejects(
    getBlock('peer.example:18081', { height: 1 }, {
      fetchImpl, timeoutMs: 5000, env: { [ENV_KEY]: 'http://node.example' },
    }),
    /not a node address/,
  );
  assert.deepEqual(calls, []);
  console.log('[pool-door] malformed environment refused before the socket');
});

// The two cases that were missing, and the reason 558/558 was green while the
// env path was broken: every existing no-pool test runs with the variable
// unset, so none of them walked the configured path at all.
test('O1: with CIPHER_XMR_NODE set, a no-pool door call reaches that node', async () => {
  const host = `${'abcdefghij'.repeat(5)}abcdef`.slice(0, 56) + '.onion';
  const calls = [];
  const served = await getBlock(`${host}:18081`, { height: 1 }, {
    timeoutMs: 5000,
    env: { [ENV_KEY]: `${host}:18081` },
    fetchImpl: async (url) => {
      calls.push(url);
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
    },
  });
  assert.equal(calls.length, 1, 'the configured node is actually asked');
  assert.match(calls[0], new RegExp(host.replace(/\./g, '\\.')), 'and the URL carries that host');
  assert.equal(served.address, `${host}:18081`);
  console.log('[pool-door] configured env reached:', calls[0]);
});

test('O1: with nothing configured, asking the wallet to choose is the named refusal, 0 calls', async () => {
  // The doors themselves take the caller's node as the pin (see the pinned-pool
  // test above). The wallet's own choice, with no environment and an empty
  // shipped list, is the refusal createNodePool owns - and it happens before
  // any transport exists, so there is nothing to call.
  const calls = [];
  const before = calls.length;
  await assert.rejects(async () => {
    const { nodeSourceFromEnv } = await import('../src/monero/nodes.js');
    return nodeSourceFromEnv({ env: {} }).pick();
  }, /No Monero node is configured on this wallet/);
  assert.equal(calls.length, before, 'no transport was touched');
  console.log('[pool-door] nothing configured: named refusal, 0 calls');
});

test('O1: the configured pool is built once, so the session is sticky across calls', async () => {
  const env = { [ENV_KEY]: 'sticky.example:18081' };
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
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
  await getBlock('sticky.example:18081', { height: 1 }, { fetchImpl, timeoutMs: 5000, env });
  await getBlock('sticky.example:18081', { height: 1 }, { fetchImpl, timeoutMs: 5000, env });
  assert.equal(calls.length, 2, 'both calls went out');
  console.log('[pool-door] two calls, one cached pool, no per-call rebuild');
});

test('O1: a changed environment value is a different pool, not a stale session', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
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
  await getBlock('first.example:18081', { height: 1 },
    { fetchImpl, timeoutMs: 5000, env: { [ENV_KEY]: 'first.example:18081' } });
  await getBlock('second.example:18081', { height: 1 },
    { fetchImpl, timeoutMs: 5000, env: { [ENV_KEY]: 'second.example:18081' } });
  assert.equal(calls.length, 2, 'each configuration reached its own node');
  console.log('[pool-door] env change rebuilt the pool');
});

// ---------------------------------------------------------------------------
// The two defects the cache introduced, each with the test that would have
// caught it.
//
// D1: pick() was called only when the pool was BUILT. After a transport failure
// abandon() empties the session, and every later no-pool call reused the cached
// pool and was refused with the stitching sentence - forever, with no request -
// though nothing had been stitched, because nothing had been asked. The pool is
// now re-picked on every use, so the honest sentence is pick()'s.
//
// D2: the env-object cache was keyed on object identity alone, so editing the
// same object in place kept the stale pool. It is keyed on the configuration
// value now.
// ---------------------------------------------------------------------------
function okFetch(calls) {
  return async (url) => {
    calls.push(url);
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
}

test('O1/D1: after a transport failure the next no-pool call re-picks, and names the real refusal', async () => {
  const env = { [ENV_KEY]: 'dead.example:18081' };
  const attempts = [];

  await assert.rejects(
    getBlock('dead.example:18081', { height: 1 }, {
      env, timeoutMs: 5000,
      fetchImpl: async (url) => { attempts.push(url); throw new Error('ECONNREFUSED'); },
    }),
    /did not answer/,
    'the first call is a transport failure',
  );
  assert.equal(attempts.length, 1);

  // Same configuration, a fetch that would succeed. The node was abandoned, so
  // there is nothing left to ask - but the refusal must be the exhausted-pool
  // sentence, not "Refusing to stitch results from two", which accuses the call
  // of stitching when it never asked anyone anything.
  await assert.rejects(
    getBlock('dead.example:18081', { height: 1 }, {
      env, timeoutMs: 5000, fetchImpl: okFetch(attempts),
    }),
    (error) => /No configured Monero node answered/.test(error.message)
      && !/stitch/i.test(error.message),
    'the second call reports an exhausted pool, not a stitched scan',
  );
  assert.equal(attempts.length, 1, 'and still makes no second request');
  console.log('[pool-door] D1: abandoned node, honest exhausted-pool refusal');
});

test('O1/D1 control: a pool with a second node re-picks it after the first dies', async () => {
  // The env door names one node, so rotation is shown on the pool itself: the
  // same re-pick path a list-backed pool would take.
  const { createNodePool } = await import('../src/monero/nodes.js');
  const pool = createNodePool({ nodes: ['first.example:18081', 'second.example:18081'], allowClearnet: true });
  const first = pool.pick();
  pool.abandon(first);
  assert.equal(pool.pick(), 'second.example:18081', 'the next scan starts on the next node');
  console.log('[pool-door] D1: list pool rotates after abandon');
});

test('O1/D2: editing the same env object in place rebuilds the pool', async () => {
  const env = { [ENV_KEY]: 'first.example:18081' };
  const calls = [];
  await getBlock('first.example:18081', { height: 1 },
    { env, fetchImpl: okFetch(calls), timeoutMs: 5000 });
  assert.equal(calls.length, 1);

  env[ENV_KEY] = 'second.example:18081';
  await getBlock('second.example:18081', { height: 1 },
    { env, fetchImpl: okFetch(calls), timeoutMs: 5000 });

  assert.equal(calls.length, 2, 'the second configuration was actually asked');
  assert.match(calls[1], /second\.example:18081/, 'and it was the NEW host');
  console.log('[pool-door] D2: in-place env change rebuilt the pool ->', calls[1]);
});

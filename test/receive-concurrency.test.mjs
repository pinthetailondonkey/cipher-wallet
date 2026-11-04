// Concurrent receive.issue: two callers in one turn must get two pockets.
//
// The defect this pins: issue() read the handle outside the store's write
// queue, so two calls in one turn both read the same handle and derived the
// same index/address. The second record() then refused the second payment.
//
// Every storage access waits 5ms so the two calls genuinely interleave: with a
// synchronous kv the defect hides behind the microtask order.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createPocketStore, memoryKv, POCKET_TABLE_KEY } from '../src/pocketStore.js';
import { createReceive } from '../src/receive.js';
import { rootFromMnemonic } from '../src/root.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);
const WATCHER = 'http://127.0.0.1:8788/payment?token=a-long-secret';

const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

// A kv that awaits real latency between every operation, and counts writes.
function slowKv(inner = memoryKv()) {
  const state = { writes: 0 };
  return {
    state,
    async get(key) { await tick(); return inner.get(key); },
    async set(key, value) { await tick(); state.writes += 1; return inner.set(key, value); },
    async del(key) { await tick(); return inner.del(key); },
    async keys() { await tick(); return inner.keys(); },
    dump() { return inner.dump(); },
  };
}

function build() {
  const kv = slowKv();
  const store = createPocketStore(kv);
  const receive = createReceive({ seed: SEED, store, watcherUrl: WATCHER });
  return { kv, store, receive };
}

test('two issue calls in one turn get two different addresses and indexes', async () => {
  const { store, receive } = build();

  const [first, second] = await Promise.all([
    receive.issue({ coin: 'btc' }),
    receive.issue({ coin: 'btc' }),
  ]);

  assert.equal(first.pocket.index, 0);
  assert.equal(second.pocket.index, 1);
  assert.notEqual(first.pocket.address, second.pocket.address);
  assert.equal(first.pocket.index, first.handle.next.btc - 1);
  assert.equal(second.pocket.index, second.handle.next.btc - 1);

  const rows = await store.list();
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((row) => row.index).sort(), [0, 1]);

  // The audit probe's follow-up: both pockets must be able to name a distinct
  // transaction. Before the fix the second one reused index 0 and was refused.
  await store.record('btc', first.pocket.index, { source: 'watcher', txid: 'AAAA', confirmations: 1, amount: '0.5' }, { amount: '0.5' });
  await store.record('btc', second.pocket.index, { source: 'watcher', txid: 'BBBB', confirmations: 1, amount: '0.5' }, { amount: '0.5' });
  const paid = await store.list();
  assert.deepEqual(paid.map((row) => row.txid).sort(), ['AAAA', 'BBBB']);
});

test('many concurrent issue calls each get their own pocket', async () => {
  const { store, receive } = build();
  const issued = await Promise.all(Array.from({ length: 5 }, () => receive.issue({ coin: 'btc' })));
  const indexes = issued.map((out) => out.pocket.index).sort((a, b) => a - b);
  assert.deepEqual(indexes, [0, 1, 2, 3, 4]);
  assert.equal(new Set(issued.map((out) => out.pocket.address)).size, 5);
  assert.equal((await store.list()).length, 5);
});

test('sequential issue still advances the index one at a time', async () => {
  const { receive } = build();
  const first = await receive.issue({ coin: 'btc' });
  const second = await receive.issue({ coin: 'btc' });
  assert.equal(first.pocket.index, 0);
  assert.equal(second.pocket.index, 1);
  assert.equal(second.handle.next.btc, 2);
});

test('a duplicate issue of the same pocket does not double-write or overwrite state', async () => {
  const { kv, store, receive } = build();
  const issued = await receive.issue({ coin: 'btc' });
  await store.record('btc', issued.pocket.index, { source: 'watcher', txid: 'AAAA', confirmations: 1, amount: '0.5' }, { amount: '0.5' });

  const before = kv.state.writes;
  const repeated = await store.issue({ ...issued.pocket, state: 'address_issued' }, { handle: issued.handle });
  assert.equal(repeated.txid, 'AAAA');
  assert.equal(repeated.state, 'seen');
  assert.equal((await store.list()).length, 1);
  assert.ok(kv.state.writes > before);
  assert.deepEqual(kv.dump()[POCKET_TABLE_KEY].handle, issued.handle);
});

test('a damaged stored handle is refused and not overwritten', async () => {
  const kv = slowKv(memoryKv({
    [POCKET_TABLE_KEY]: { v: 1, pockets: {}, handle: { v: 1, id: 'not-hex', next: { btc: 0 } } },
  }));
  const store = createPocketStore(kv);
  const receive = createReceive({ seed: SEED, store, watcherUrl: WATCHER });
  await assert.rejects(receive.issue({ coin: 'btc' }), /pay handle .* damaged/);
  assert.equal((await store.list()).length, 0);
});

test('a build that crashes leaves the handle and table untouched', async () => {
  const { kv, store, receive } = build();
  await receive.issue({ coin: 'btc' });
  const docBefore = structuredClone(kv.dump()[POCKET_TABLE_KEY]);

  await assert.rejects(
    store.issueNext(async () => { throw new Error('crashed mid-issue'); }),
    /crashed mid-issue/,
  );

  assert.deepEqual(kv.dump()[POCKET_TABLE_KEY], docBefore);
  const next = await receive.issue({ coin: 'btc' });
  assert.equal(next.pocket.index, 1);
});

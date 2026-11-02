import test from 'node:test';
import assert from 'node:assert/strict';
import { createPocketStore, memoryKv, POCKET_TABLE_KEY } from '../src/pocketStore.js';

const POCKET = { coin: 'btc', index: 0, address: 'bc1qexample', path: "m/84'/0'/0'/0'/0'", state: 'address_issued' };
const report = (extra = {}) => ({ source: 'watcher', txid: 'tx-1', confirmations: 1, amount: '0.5', ...extra });

test('an issued pocket is on disk before the call returns', async () => {
  const kv = memoryKv();
  const store = createPocketStore(kv);
  await store.issue(POCKET);
  assert.ok(kv.dump()[POCKET_TABLE_KEY]);
  assert.equal((await store.list()).length, 1);
});

test('a second store over the same storage sees the pockets (survives a reload)', async () => {
  const kv = memoryKv();
  await createPocketStore(kv).issue(POCKET);
  const reloaded = createPocketStore(kv);
  const rows = await reloaded.list();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].address, POCKET.address);
});

test('issuing the same index twice does not duplicate or overwrite state', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue(POCKET);
  await store.record('btc', 0, report(), { amount: '0.5' });
  const again = await store.issue(POCKET);
  assert.equal(again.state, 'seen');
  assert.equal((await store.list()).length, 1);
});

test('a repeated report is a no-op, not a second pocket', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue(POCKET);
  const first = await store.record('btc', 0, report({ confirmations: 3 }), { amount: '0.5' });
  const second = await store.record('btc', 0, report({ confirmations: 3 }), { amount: '0.5' });
  assert.equal(first.state, 'confirmed');
  assert.equal(second.state, 'confirmed');
  assert.equal((await store.list()).length, 1);
});

test('a pocket names one transaction and refuses a second', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue(POCKET);
  await store.record('btc', 0, report(), { amount: '0.5' });
  await assert.rejects(store.record('btc', 0, report({ txid: 'tx-2' }), { amount: '0.5' }), /different transaction/);
});

test('a report for a pocket that was never issued is refused', async () => {
  const store = createPocketStore(memoryKv());
  await assert.rejects(store.record('btc', 9, report(), { amount: '0.5' }), /never issued/);
});

test('an unreadable table refuses rather than reading as empty', async () => {
  const kv = memoryKv({ [POCKET_TABLE_KEY]: 'not json' });
  const store = createPocketStore(kv);
  await assert.rejects(store.list(), /cannot be read/);
  const wrong = createPocketStore(memoryKv({ [POCKET_TABLE_KEY]: { v: 2, pockets: {} } }));
  await assert.rejects(wrong.list(), /cannot be read/);
});

test('a pocket that already holds one address cannot be re-pointed', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue(POCKET);
  await assert.rejects(store.issue({ ...POCKET, address: 'bc1qother' }), /different address/);
});

test('the pay handle and the pocket land in one write', async () => {
  const store = createPocketStore(memoryKv());
  const handle = { v: 1, id: 'a'.repeat(64), label: '', next: { btc: 1 } };
  await store.issue(POCKET, { handle });
  assert.deepEqual(await store.getHandle(), handle);
});

// --- defect 1: a short payment can be confirmed when no amount is passed ---

test('record with no amount refuses: a demand must exist to accept a payment', async () => {
  const kv = memoryKv();
  const store = createPocketStore(kv);
  await store.issue({ ...POCKET, index: 21 });
  await assert.rejects(
    () => store.record('btc', 21, report({ txid: 'ab', confirmations: 3, amount: '0.0001' }), {}),
    /amount/,
  );
  const row = await store.get('btc', 21);
  assert.equal(row.state, 'address_issued', 'the refused record leaves the state where it was');
});

test('record with an amount keeps the amount-checked behaviour unchanged', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue({ ...POCKET, index: 22 });
  await assert.rejects(
    () => store.record('btc', 22, report({ txid: 'short', confirmations: 3, amount: '0.0001' }), { amount: '1' }),
    /short of the order/,
  );
  const ok = await store.record('btc', 22, report({ txid: 'full', confirmations: 3, amount: '1' }), { amount: '1' });
  assert.equal(ok.state, 'confirmed');
});

// --- defect 2: concurrent writes lose pockets ---

test('two concurrent issue calls both persist with a slow kv', async () => {
  const slow = {
    async get(key) { await new Promise((r) => setTimeout(r, 5)); return memoryGet(key); },
    async set(key, value) { await new Promise((r) => setTimeout(r, 5)); return memorySet(key, value); },
  };
  const mem = memoryKv();
  const memoryGet = (key) => mem.get(key);
  const memorySet = (key, value) => mem.set(key, value);
  const store = createPocketStore(slow);
  const a = store.issue({ ...POCKET, index: 31 });
  const b = store.issue({ ...POCKET, index: 32, address: 'bc1qother' });
  await Promise.all([a, b]);
  const rows = await store.list();
  assert.equal(rows.length, 2, 'both pockets survive the race');
});

test('a record racing an issue does not lose the just-issued pocket', async () => {
  const mem = memoryKv();
  const slow = {
    async get(key) { await new Promise((r) => setTimeout(r, 5)); return mem.get(key); },
    async set(key, value) { await new Promise((r) => setTimeout(r, 5)); return mem.set(key, value); },
  };
  const store = createPocketStore(slow);
  const issuing = store.issue({ ...POCKET, index: 33 });
  await issuing;
  const reporting = store.record('btc', 33, report({ txid: 'race', confirmations: 1 }), { amount: '0.5' });
  const issuing2 = store.issue({ ...POCKET, index: 34, address: 'bc1qthird' });
  await Promise.all([reporting, issuing2]);
  const rows = await store.list();
  assert.equal(rows.length, 2, 'the issue and the record both land');
  const raced = await store.get('btc', 33);
  assert.ok(raced, 'the pocket recorded against still exists');
  assert.equal(raced.state, 'seen', 'the record landed on the issued pocket');
});

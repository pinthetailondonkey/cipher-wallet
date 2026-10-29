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
  await store.record('btc', 0, report());
  const again = await store.issue(POCKET);
  assert.equal(again.state, 'seen');
  assert.equal((await store.list()).length, 1);
});

test('a repeated report is a no-op, not a second pocket', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue(POCKET);
  const first = await store.record('btc', 0, report({ confirmations: 3 }));
  const second = await store.record('btc', 0, report({ confirmations: 3 }));
  assert.equal(first.state, 'confirmed');
  assert.equal(second.state, 'confirmed');
  assert.equal((await store.list()).length, 1);
});

test('a pocket names one transaction and refuses a second', async () => {
  const store = createPocketStore(memoryKv());
  await store.issue(POCKET);
  await store.record('btc', 0, report());
  await assert.rejects(store.record('btc', 0, report({ txid: 'tx-2' })), /different transaction/);
});

test('a report for a pocket that was never issued is refused', async () => {
  const store = createPocketStore(memoryKv());
  await assert.rejects(store.record('btc', 9, report()), /never issued/);
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

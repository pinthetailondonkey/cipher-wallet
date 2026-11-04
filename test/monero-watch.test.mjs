// The bridge from a Monero finding to the pocket store.
//
// A scan used to return its findings and forget them. These tests pin the
// conversion (a found output -> a watcher report) and the write (a report moves
// a pocket's state, through the SAME path the Bitcoin rail uses). Nothing here
// hits the network: the scan result is the only input.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createWallet } from '../src/index.js';
import { memoryKv } from '../src/pocketStore.js';
import { reportsFromScan } from '../src/monero/watch.js';
import { rootFromMnemonic } from '../src/root.js';

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');

// One found output, as ownOutputsInBlock shapes it.
const found = (overrides = {}) => ({ pocket: 0, output: 1, txid: 'ab'.repeat(32), coinbase: false, value: 1_000_000_000_000n, mask: new Uint8Array(32), ...overrides });

test('a found output becomes a watcher report with the value as a decimal amount', () => {
  const [entry] = reportsFromScan([found()]);
  assert.equal(entry.pocket, 0);
  assert.equal(entry.report.source, 'watcher');
  assert.equal(entry.report.txid, 'ab'.repeat(32));
  assert.equal(entry.report.amount, '1', '1e12 piconero is one xmr');
});

test('a refused or valueless output is not a report, but stays in the scan', () => {
  const rows = [
    found(),
    found({ pocket: 1, refused: 'no ecdh slice' }),
    found({ pocket: 2, value: null }),
  ];
  const out = reportsFromScan(rows);
  assert.deepEqual(out.map((entry) => entry.pocket), [0]);
});

test('confirmations are one without a height, and counted when both heights are given', () => {
  assert.equal(reportsFromScan([found()])[0].report.confirmations, 1);
  assert.equal(reportsFromScan([found()], { height: 100, tipHeight: 100 })[0].report.confirmations, 1);
  assert.equal(reportsFromScan([found()], { height: 100, tipHeight: 109 })[0].report.confirmations, 10);
});

test('a report from a scan moves the pocket to seen, and a second txid is refused and reported', async () => {
  const w = createWallet({ seed: SEED, store: memoryKv(), env: {} });
  const { pocket } = await w.issueMonero();
  assert.equal(pocket.index, 0);

  const first = await w.monero.recordFromScan({ outputs: [found({ pocket: 0 })] }, { height: 100, tipHeight: 100 });
  assert.deepEqual(first, [{ pocket: 0, output: 1, txid: 'ab'.repeat(32), ok: true }]);
  const row = await w.store.get('xmr', 0);
  assert.equal(row.state, 'seen');
  assert.equal(row.txid, 'ab'.repeat(32));

  // A second, different txid on the same pocket: reported, not thrown.
  const second = await w.monero.recordFromScan({ outputs: [found({ pocket: 0, txid: 'cd'.repeat(32) })] }, {});
  assert.equal(second[0].ok, false);
  assert.match(second[0].error, /different transaction/);
  assert.equal((await w.store.get('xmr', 0)).txid, 'ab'.repeat(32), 'the first payment stands');
});

test('deep enough confirmations walk the pocket to confirmed', async () => {
  const w = createWallet({ seed: SEED, store: memoryKv(), env: {} });
  await w.issueMonero();
  await w.monero.recordFromScan({ outputs: [found({ pocket: 0 })] }, {});
  const deep = await w.monero.recordFromScan({ outputs: [found({ pocket: 0 })] }, { height: 100, tipHeight: 120 });
  assert.equal(deep[0].ok, true);
  assert.equal((await w.store.get('xmr', 0)).state, 'confirmed');
});

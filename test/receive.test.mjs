import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createPocketStore, memoryKv } from '../src/pocketStore.js';
import { createReceive } from '../src/receive.js';
import { childWatcherToken } from '../src/watcher.js';
import { rootFromMnemonic } from '../src/root.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);
const BASE = 'a-long-secret';
const NOW = 1700000000;
const WATCHER = `http://127.0.0.1:8788/payment?token=${BASE}`;

// A watcher that answers about whatever address it was asked for.
function watcherFetch({ confirmations = 1, amount = '0.5' } = {}) {
  return async (url) => {
    const parsed = new URL(url);
    const address = parsed.searchParams.get('address');
    const currency = parsed.searchParams.get('currency');
    const child = await childWatcherToken(BASE, address, currency);
    const raw = JSON.stringify({ address, currency, txid: 'tx-1', confirmations, amount });
    const ts = NOW;
    return {
      ok: true,
      status: 200,
      async text() { return raw; },
      headers: {
        get(name) {
          if (name === 'x-cipher-sig') return 'v1=' + createHmac('sha256', child).update(`${ts}:${raw}`).digest('hex');
          if (name === 'x-cipher-ts') return String(ts);
          return null;
        },
      },
    };
  };
}

function build() {
  const kv = memoryKv();
  const store = createPocketStore(kv);
  const receive = createReceive({ seed: SEED, store, watcherUrl: WATCHER });
  return { kv, store, receive };
}

test('issue gives a customer a fresh bitcoin pocket and moves the handle', async () => {
  const { receive } = build();
  const first = await receive.issue({ coin: 'btc' });
  assert.match(first.pocket.address, /^bc1q/);
  assert.equal(first.pocket.state, 'address_issued');
  assert.equal(first.handle.next.btc, 1);

  const second = await receive.issue({ coin: 'btc' });
  assert.notEqual(first.pocket.address, second.pocket.address);
  assert.equal(second.pocket.index, 1);
});

test('the handle survives a reload', async () => {
  const { kv, store, receive } = build();
  await receive.issue({ coin: 'btc' });
  const reloadedStore = createPocketStore(kv);
  const reloaded = createReceive({ seed: SEED, store: reloadedStore, watcherUrl: WATCHER });
  const next = await reloaded.issue({ coin: 'btc' });
  assert.equal(next.pocket.index, 1);
  assert.equal((await store.list()).length, 2);
});

test('a watcher answer is recorded and moves the pocket to seen', async () => {
  const { receive } = build();
  const { pocket } = await receive.issue({ coin: 'btc' });
  const out = await receive.scan({ coin: 'btc', index: pocket.index, amount: '0.5', fetchImpl: watcherFetch(), nowSec: NOW });
  assert.equal(out.pocket.state, 'seen');
  assert.equal(out.pocket.txid, 'tx-1');
});

test('a re-fetch of the same payment does not split it or rewind it', async () => {
  const { store, receive } = build();
  const { pocket } = await receive.issue({ coin: 'btc' });
  await receive.scan({ coin: 'btc', index: pocket.index, amount: '0.5', fetchImpl: watcherFetch(), nowSec: NOW });
  const again = await receive.scan({ coin: 'btc', index: pocket.index, amount: '0.5', fetchImpl: watcherFetch(), nowSec: NOW });
  assert.equal(again.pocket.state, 'seen');
  assert.equal((await store.list()).length, 1);
  assert.equal((await store.list())[0].txid, 'tx-1');
});

test('a short payment is refused and the pocket stays issued', async () => {
  const { store, receive } = build();
  const { pocket } = await receive.issue({ coin: 'btc' });
  await assert.rejects(
    receive.scan({ coin: 'btc', index: pocket.index, amount: '1', fetchImpl: watcherFetch({ amount: '0.5' }), nowSec: NOW }),
    /short of the order/,
  );
  assert.equal((await store.get('btc', pocket.index)).state, 'address_issued');
});

test('a pocket with no address is not asked about', async () => {
  const { receive } = build();
  const { pocket } = await receive.issue({ coin: 'xmr' });
  await assert.rejects(receive.scan({ coin: 'xmr', index: pocket.index }), /no address/);
});

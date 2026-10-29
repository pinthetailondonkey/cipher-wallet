// The receive path, end to end on this device:
//
//   pay handle -> fresh pocket -> the watcher is asked about it -> the answer
//   is persisted, and a re-fetch cannot split or rewind it.
//
// The handle and the pocket are written in ONE storage write, so a crash
// between them is not possible: either the next index moved and the pocket
// exists, or neither happened.

import { createHandle, isHandle, issuePocket } from './payHandle.js';
import { checkPayment } from './watcher.js';

export function createReceive({ seed, store, watcherUrl }) {
  if (!(seed instanceof Uint8Array) || seed.length === 0) throw new Error('The receive path needs the root seed.');
  if (!store) throw new Error('The receive path needs a pocket store.');

  async function handle() {
    const stored = await store.getHandle();
    if (stored == null) return null;
    if (!isHandle(stored)) throw new Error('The pay handle on this device is damaged.');
    return stored;
  }

  // Give a customer a new thing to pay. The stored handle moves forward in the
  // same write as the pocket.
  async function issue({ coin = 'btc', network = 'bc', label = '' } = {}) {
    const current = (await handle()) || createHandle({ coin, label });
    const { pocket, handle: next } = issuePocket(current, seed, { coin, network });
    const row = await store.issue({ ...pocket, state: 'address_issued' }, { handle: next });
    return { pocket: row, handle: next };
  }

  // Ask the watcher about one pocket. `amount` is the demand it must cover;
  // leave it out only when walking states without a price.
  async function scan({ coin, index, amount, threshold, fetchImpl, nowSec } = {}) {
    const pocket = await store.get(coin, index);
    if (!pocket) throw new Error('That pocket was never issued on this device.');
    if (!pocket.address) throw new Error('This pocket has no address to ask about.');
    const answer = await checkPayment({ watcherUrl, address: pocket.address, currency: coin, fetchImpl, nowSec });
    if (answer.pending) return { pending: true, pocket };
    const row = await store.record(coin, index, answer.report, { amount, threshold });
    return { report: answer.report, pocket: row };
  }

  async function scanAll(opts = {}) {
    const pockets = (await store.list()).filter((pocket) => pocket.address);
    const results = [];
    for (const pocket of pockets) {
      results.push(await scan({ ...opts, coin: pocket.coin, index: pocket.index }));
    }
    return results;
  }

  return { handle, issue, scan, scanAll };
}

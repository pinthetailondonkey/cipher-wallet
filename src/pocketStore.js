// The pocket table: what was issued, what the watcher saw, and nothing that
// lives only in memory.
//
// Every write goes to storage before it is called done. A history fetch that
// re-saves the relay's copy must never overwrite this: the table is the
// device's own record, keyed by coin:index, and a repeated report is a no-op,
// not a second pocket.
//
// Storage is a tiny key/value interface so the same table runs on IndexedDB
// in the app and on a memory adapter in tests. The IDB adapter is browser-only
// and is exercised by the UI layer, not here.

import { applyWatcherReport, PAYMENT_STATES } from './paymentState.js';

export const POCKET_TABLE_KEY = 'wallet_pockets_v1';

export function memoryKv(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    async get(key) { return data.has(key) ? data.get(key) : null; },
    async set(key, value) { data.set(key, value); },
    async del(key) { data.delete(key); },
    async keys() { return [...data.keys()]; },
    dump() { return Object.fromEntries(data); },
  };
}

// Browser adapter. One object store, one row. Written so a refused write is an
// error the caller sees, never a silent memory-only success.
export function indexedDbKv({ dbName = 'cipher-wallet', storeName = 'kv' } = {}) {
  const open = () => new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(storeName)) request.result.createObjectStore(storeName);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('The database would not open.'));
  });
  const run = async (mode, work) => {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, mode);
        const store = tx.objectStore(storeName);
        let result;
        const request = work(store);
        if (request) request.onsuccess = () => { result = request.result; };
        tx.oncomplete = () => resolve(result);
        tx.onerror = () => reject(tx.error || new Error('The write was refused.'));
        tx.onabort = () => reject(tx.error || new Error('The write was refused.'));
      });
    } finally {
      db.close();
    }
  };
  return {
    get: (key) => run('readonly', (store) => store.get(key)).then((value) => (value === undefined ? null : value)),
    set: (key, value) => run('readwrite', (store) => store.put(value, key)),
    del: (key) => run('readwrite', (store) => store.delete(key)),
    keys: () => run('readonly', (store) => store.getAllKeys()),
  };
}

function pocketKey(coin, index) {
  return `${String(coin).toLowerCase()}:${index}`;
}

export function createPocketStore(kv) {
  // Every read-modify-write of the table goes through this queue, so two
  // callers never hold the same table copy at once. Without it, issue() and
  // record() each read the whole document, change their one row, and write
  // the whole document back: two concurrent calls and the second write
  // erases the first caller's row. The on-disk format does not change; the
  // queue only orders who may read-then-write.
  let queueTail = Promise.resolve();
  function serialized(work) {
    const run = queueTail.then(work, work);
    // the queue must keep moving even when a caller's work failed
    queueTail = run.catch(() => {});
    return run;
  }

  async function readDoc() {
    const raw = await kv.get(POCKET_TABLE_KEY);
    if (raw == null) return { ok: true, table: {}, handle: null };
    let parsed;
    try {
      parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return { ok: false, table: null, handle: null };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, table: null, handle: null };
    if (parsed.v !== 1 || !parsed.pockets || typeof parsed.pockets !== 'object' || Array.isArray(parsed.pockets)) {
      return { ok: false, table: null, handle: null };
    }
    return { ok: true, table: parsed.pockets, handle: parsed.handle ?? null };
  }

  async function readTable() {
    const doc = await readDoc();
    return { ok: doc.ok, table: doc.table };
  }

  // One document holds the pockets AND the pay handle, so issuing a pocket and
  // moving the handle forward is a single write. A crash cannot land the
  // pocket without the new index, or hand the same index out twice.
  async function writeDoc(table, handle) {
    // Awaited: a write that did not land must be an error, not a memory-only
    // success. (CLAUDE.md: state that lives only in memory dies on reload.)
    await kv.set(POCKET_TABLE_KEY, { v: 1, pockets: table, handle: handle ?? null });
  }

  async function writeTable(table) {
    const doc = await readDoc();
    await writeDoc(table, doc.handle);
  }

  // The row-writing half of an issue, without its own queue turn. Both issue()
  // and issueNext() run inside serialized() and must not re-enter it.
  async function writeIssue(table, pocket, { now = Date.now(), handle = undefined, storedHandle = null } = {}) {
    if (!pocket || !PAYMENT_STATES.includes(pocket.state)) throw new Error('A pocket needs a state.');
    const key = pocketKey(pocket.coin, pocket.index);
    const existing = table[key];
    if (existing) {
      if (String(existing.address) !== String(pocket.address)) {
        throw new Error('That pocket index already belongs to a different address.');
      }
      if (handle !== undefined) await writeDoc(table, handle);
      return existing;
    }
    const row = {
      coin: String(pocket.coin).toLowerCase(),
      index: pocket.index,
      address: pocket.address,
      path: pocket.path,
      state: pocket.state,
      // The price this pocket was issued to cover, if one was given. It is the
      // demand a later report is checked against; null means "no price known".
      demand: pocket.demand == null ? null : String(pocket.demand),
      txid: null,
      amount: null,
      confirmations: 0,
      issuedAt: now,
      seenAt: null,
      confirmedAt: null,
    };
    table[key] = row;
    await writeDoc(table, handle === undefined ? storedHandle : handle);
    return row;
  }

  return {
    async list() {
      const { ok, table } = await readTable();
      if (!ok) throw new Error('The pocket table on this device cannot be read.');
      return Object.values(table).sort((a, b) => (a.issuedAt || 0) - (b.issuedAt || 0));
    },

    async get(coin, index) {
      const { ok, table } = await readTable();
      if (!ok) throw new Error('The pocket table on this device cannot be read.');
      return table[pocketKey(coin, index)] || null;
    },

    async findByAddress(coin, address) {
      const wanted = String(address || '').trim().toLowerCase();
      if (!wanted) return null;
      const { ok, table } = await readTable();
      if (!ok) throw new Error('The pocket table on this device cannot be read.');
      for (const pocket of Object.values(table)) {
        if (String(pocket.coin).toLowerCase() === String(coin).toLowerCase()
          && String(pocket.address || '').trim().toLowerCase() === wanted) return pocket;
      }
      return null;
    },

    async getHandle() {
      const { ok, handle } = await readDoc();
      if (!ok) throw new Error('The pocket table on this device cannot be read.');
      return handle;
    },

    // Issue a pocket. Idempotent per coin:index: issuing the same one twice
    // never duplicates and never overwrites a pocket that already has state.
    // When `handle` is passed, it lands in the same write as the pocket.
    issue(pocket, { now = Date.now(), handle = undefined } = {}) {
      if (!pocket || !PAYMENT_STATES.includes(pocket.state)) throw new Error('A pocket needs a state.');
      return serialized(async () => {
        const { ok, table, handle: storedHandle } = await readDoc();
        if (!ok) throw new Error('The pocket table on this device cannot be read.');
        return writeIssue(table, pocket, { now, handle, storedHandle });
      });
    },

    // Issue the NEXT pocket atomically. The handle read, the pocket built from
    // it, and the advanced handle all happen inside one queue turn and land in
    // one write, so two callers in one turn cannot be handed the same index.
    // The builder gets the current stored handle (null on a device that has
    // never issued) and returns { pocket, handle }. It may throw: a throw is
    // before the write, so the table and handle are left untouched. The queue
    // is not re-entrant, so this does not call issue().
    issueNext(build, { now = Date.now() } = {}) {
      if (typeof build !== 'function') throw new Error('Issuing the next pocket needs a builder.');
      return serialized(async () => {
        const { ok, table, handle: storedHandle } = await readDoc();
        if (!ok) throw new Error('The pocket table on this device cannot be read.');
        const built = await build(storedHandle);
        if (!built || !built.pocket) throw new Error('The builder returned no pocket.');
        if (built.handle === undefined) throw new Error('The builder returned no next handle.');
        const row = await writeIssue(table, built.pocket, { now, handle: built.handle, storedHandle });
        return { pocket: row, handle: built.handle };
      });
    },

    // A watcher report for one pocket. One pocket names one transaction; a
    // second txid is refused rather than silently replacing the first. A
    // repeated report of the same payment is a no-op, so a re-fetch cannot
    // walk the state backwards or split one payment into two pockets.
    async record(coin, index, report, { amount, threshold, now = Date.now() } = {}) {
      // The demand is the point of the check: without it a report of any
      // amount walks the payment to confirmed, and a short payment is
      // indistinguishable from a paid one. receive.scan passes it; a caller
      // that has no price has no business recording a payment. The check
      // runs before the queue so a malformed call never queues at all.
      if (amount === undefined) {
        throw new Error('A payment is recorded against a demand: pass the amount the pocket must cover.');
      }
      return serialized(async () => {
      const { ok, table } = await readTable();
      if (!ok) throw new Error('The pocket table on this device cannot be read.');
      const key = pocketKey(coin, index);
      const row = table[key];
      if (!row) throw new Error('That pocket was never issued on this device.');
      if (!report || !report.txid) throw new Error('A report names no transaction.');
      if (row.txid && String(row.txid) !== String(report.txid)) {
        throw new Error('This pocket already names a different transaction.');
      }
      let state = row.state;
      // A confirmed pocket has nowhere left to go: the same payment reported
      // again is a no-op, not an error.
      if (state !== 'confirmed') {
        try {
          state = applyWatcherReport({ state, report, currency: row.coin, amount, threshold });
        } catch (error) {
          // "did not move" is the repeated-report case: keep the row as it is.
          if (!/did not move/.test(error.message)) throw error;
        }
      }
      const next = {
        ...row,
        state,
        txid: row.txid || String(report.txid),
        amount: report.amount != null ? String(report.amount) : row.amount,
        confirmations: Math.max(Number(row.confirmations) || 0, Number(report.confirmations) || 0),
        seenAt: row.seenAt || (state !== 'address_issued' ? now : null),
        confirmedAt: row.confirmedAt || (state === 'confirmed' ? now : null),
      };
      table[key] = next;
      await writeTable(table);
      return next;
      });
    },
  };
}

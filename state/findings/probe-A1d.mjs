import { createPocketStore, memoryKv } from '../../src/pocketStore.js';
import { createReceive } from '../../src/receive.js';
import { createRoot } from '../../src/root.js';
const root = createRoot();
// real async store (IndexedDB-like latency) so the race is not a same-tick artifact
function slowKv() {
  const mem = memoryKv();
  return {
    async get(k) { await new Promise(r=>setTimeout(r,5)); return mem.get(k); },
    async set(k,v) { await new Promise(r=>setTimeout(r,5)); return mem.set(k,v); },
    async del(k){ return mem.del(k); }, async keys(){ return mem.keys(); },
  };
}
const store = createPocketStore(slowKv());
const recv = createReceive({ seed: root.seed, store, watcherUrl: 'https://w/p?token=t' });
const [a, b] = await Promise.all([recv.issue({coin:'btc'}), recv.issue({coin:'btc'})]);
console.log('issue A -> index', a.pocket.index, a.pocket.address.slice(0,16));
console.log('issue B -> index', b.pocket.index, b.pocket.address.slice(0,16));
console.log('same address handed to two customers:', a.pocket.address === b.pocket.address);
console.log('pockets persisted:', (await store.list()).map(p=>p.index));

// Now two payments land on that shared address: watcher reports two different txids.
const r1 = await store.record('btc', a.pocket.index, {source:'watcher',txid:'tx-ONE',confirmations:1,amount:'0.5'}, {amount:'0.5'});
console.log('first payment recorded:', r1.txid, r1.state);
let e=null;
try { await store.record('btc', a.pocket.index, {source:'watcher',txid:'tx-TWO',confirmations:1,amount:'0.5'}, {amount:'0.5'}); } catch(x){e=x;}
console.log('second payment ->', e ? 'REFUSED: '+e.message : 'accepted');

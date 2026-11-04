import assert from 'node:assert/strict';
import { amountUnits, unitsToAmount, sumAmounts } from '../../src/units.js';
import { parseExactAmounts } from '../../src/watcher.js';
import { createPocketStore, memoryKv } from '../../src/pocketStore.js';
import { createReceive } from '../../src/receive.js';
import { createRoot } from '../../src/root.js';
import { decodeAddress } from '../../src/address.js';

const hr=(s)=>console.log(`\n== ${s} ==`);
const root = createRoot();

hr('A. concurrent issue after the store already has a pocket');
{
  const kv = memoryKv();
  const store = createPocketStore(kv);
  const recv = createReceive({ seed: root.seed, store, watcherUrl: 'https://w.example/p?token=t' });
  const first = await recv.issue({ coin: 'btc' });
  console.log('first index', first.pocket.index, first.pocket.address.slice(0,14));
  const [a, b] = await Promise.all([recv.issue({ coin: 'btc' }), recv.issue({ coin: 'btc' })]);
  console.log('concurrent ->', a.pocket.index, b.pocket.index, 'same addr:', a.pocket.address === b.pocket.address);
  const list = await store.list();
  console.log('persisted pockets:', list.map(p=>p.index));
  console.log('VERDICT:', a.pocket.index === b.pocket.index ? 'two issues share one pocket/address' : 'distinct');
}

hr('B. amountUnits / unitsToAmount roundtrip fuzz');
{
  let bad = 0;
  const vals = ['0.00000001','0.000000015','12345678.9','0.1','99999999.99999999','1','0.000000000001'];
  for (const v of vals) {
    const u = amountUnits(v, 'btc'); const back = unitsToAmount(u, 'btc');
    if (amountUnits(back,'btc') !== u) { bad++; console.log('  mismatch', v, u); }
  }
  console.log('btc roundtrips bad:', bad);
  // xmr scale 12
  for (const v of ['0.000000000001','1','0.123456789012','0.1234567890125']) {
    console.log('  xmr', v, '->', amountUnits(v,'xmr'));
  }
  // max money
  console.log('  21e6 btc ->', amountUnits('21000000','btc'));
}

hr('C. watcher JSON amount: exponent form');
{
  for (const raw of ['{"amount":1e-8}','{"amount":0.1}','{"amount":100000000}','{"amount":"0.5"}','{"amount":-1}','{"amount":1.5e-8}']) {
    let parsed; try { parsed = parseExactAmounts(raw); } catch (e) { parsed = e.message; }
    const amt = parsed && typeof parsed==='object' ? parsed.amount : parsed;
    console.log('  ', raw, '=> parsed.amount =', JSON.stringify(amt), '(type', typeof amt, ') amountUnits ->', amountUnits(amt,'btc'));
  }
}

hr('D. pocketStore: repeated report no-op, txid replacement, reload');
{
  const kv = memoryKv();
  const store = createPocketStore(kv);
  const recv = createReceive({ seed: root.seed, store, watcherUrl: 'https://w.example/p?token=t' });
  const p = await recv.issue({ coin: 'btc' });
  const rep = { source:'watcher', txid:'aa'.repeat(32), confirmations:0, amount:'1' };
  let r1 = await store.record('btc', p.pocket.index, rep, { amount:'1' });
  console.log('after see:', r1.state, r1.txid.slice(0,8));
  let r2 = await store.record('btc', p.pocket.index, { ...rep, confirmations: 5 }, { amount:'1' });
  console.log('after confirm:', r2.state, 'confs', r2.confirmations);
  let r3 = await store.record('btc', p.pocket.index, { ...rep, confirmations: 1 }, { amount:'1' });
  console.log('regress repeat:', r3.state, 'confs', r3.confirmations);
  let err=null; try { await store.record('btc', p.pocket.index, { source:'watcher', txid:'bb'.repeat(32), confirmations:3, amount:'1' }, { amount:'1' }); } catch(e){err=e;}
  console.log('second txid ->', err ? 'refused: '+err.message : 'accepted');
  // reload from the same kv dump (survives)
  const store2 = createPocketStore(kv);
  console.log('after reload state:', (await store2.get('btc', p.pocket.index)).state);
}

hr('E. address: bech32 / bech32m / mixed case / wrong net');
{
  const cases = [
    ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4','bc'],
    ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4','bc'],
    ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y','bc'],
    ['tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx','bc'],
    ['bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3','bc'],
  ];
  for (const [a,n] of cases) {
    let r; try { r = decodeAddress(a,n).kind; } catch(e){ r='REFUSED: '+e.message; }
    console.log('  ', a.slice(0,18), '->', r);
  }
  // tamper a valid v0 char
  let e1; try { decodeAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5','bc'); } catch(e){e1=e.message;}
  console.log('   tampered checksum ->', e1 || 'ACCEPTED (bad)');
}

hr('F. parseExactAmounts does not corrupt other numeric keys');
console.log(parseExactAmounts('{"amount":123,"outputAmount":456,"confirmations":3}'));

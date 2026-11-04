// Independent auditor probe A1. Throwaway.
import assert from 'node:assert/strict';
import { amountUnits, normalizeAmount, unitsToAmount, sumAmounts } from '../../src/units.js';
import { sealVault, openVault, isDamagedVault, isPlausiblePin } from '../../src/vault.js';
import { makeSecretProvider, wrapDeviceVault, unwrapDeviceVault, DeviceKeyError, DeviceKeyMissing } from '../../src/deviceEnvelope.js';
import { buildSpend, DUST_LIMIT } from '../../src/spend.js';
import { createPocketStore, memoryKv } from '../../src/pocketStore.js';
import { createReceive } from '../../src/receive.js';
import { createRoot, pocketFor } from '../../src/root.js';
import { createHandle, issuePocket } from '../../src/payHandle.js';
import { applyWatcherReport, nextPaymentState } from '../../src/paymentState.js';
import { childWatcherToken, verifyWatcherResponse, checkPayment } from '../../src/watcher.js';
import { decodeAddress } from '../../src/address.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const hr = (s) => console.log(`\n===== ${s} =====`);
let fails = [];
const check = (name, fn) => { try { fn(); console.log(`ok   ${name}`); } catch (e) { console.log(`FAIL ${name}: ${e.message}`); fails.push(name); } };

hr('AREA1 units: float / rounding / negative / exponent');
check('round half up at the 8th place keeps the sat', () => {
  assert.equal(amountUnits('0.000000015', 'btc'), 2n);
  assert.equal(amountUnits('0.000000014', 'btc'), 1n);
});
check('a JS number anywhere is refused (not silently rounded)', () => {
  assert.throws(() => normalizeAmount(0.1));
  assert.equal(amountUnits(0.1, 'btc'), null);
});
check('negative decimal string is REFUSED by amountUnits', () => {
  // unitsToAmount supports '-', amountUnits does not.
  assert.throws(() => normalizeAmount('-1'));
  assert.equal(amountUnits('-1', 'btc'), null);
  assert.equal(unitsToAmount(-1n, 'btc'), '-0.00000001');
});
check('scientific notation from a watcher is refused', () => {
  assert.equal(amountUnits('1e-8', 'btc'), null);       // raw string with e
  assert.equal(amountUnits(1e-8, 'btc'), null);         // JSON number
});
check('unitsToAmount with an unsafe integer number is accepted', () => {
  // number accepted despite > 2^53
  const big = 9007199254740993; // literal already collapsed to ...992
  assert.equal(big, 9007199254740992); // proof: an unsafe integer literal is not what you typed
  const back = unitsToAmount(big, 'btc');
  assert.equal(back, '90071992.54740992');
  console.log('   number 9007199254740993 ->', back);
});
check('unknown rail returns null from amountUnits (refusal)', () => {
  assert.equal(amountUnits('1', 'usd'), null);
});

hr('AREA2 vault/envelope: copied blob, PIN vs device error');
const pin = '12345678';
const secretA = new Uint8Array(32).fill(7);
const secretB = new Uint8Array(32).fill(9);
const providerFor = (secret, kind = 'prf') => makeSecretProvider({
  kind,
  available: async () => true,
  enroll: async () => ({ k: kind, handle: 'h' }),
  getSecret: async () => secret,
  destroy: async () => {},
});
const inner = await sealVault(new TextEncoder().encode('root seed'), pin);
const pk = 'acct';
const blob = await wrapDeviceVault(providerFor(secretA), pk, { k: 'prf', handle: 'h' }, inner);
await (async () => {
  // same device: opens
  const back = await unwrapDeviceVault(blob, pk, providerFor(secretA));
  assert.equal(new TextDecoder().decode(await openVault(back, pin)), 'root seed');
  console.log('ok   same-device copied blob opens');
  // copied to another device: device key missing, NOT wrong PIN
  let err = null;
  try { await unwrapDeviceVault(blob, pk, providerFor(secretB)); } catch (e) { err = e; }
  assert.ok(err instanceof DeviceKeyMissing, 'expected DeviceKeyMissing, got ' + (err && err.name));
  assert.notEqual(err.code, 'wrong-pin');
  console.log('ok   copied blob on another device -> DeviceKeyMissing/' + err.code);
  // a DeviceKeyError is never a wrong pin
  assert.equal(err instanceof DeviceKeyError, true);

  // wrong PIN distinct code
  let werr = null;
  try { await openVault(back, '87654321'); } catch (e) { werr = e; }
  assert.equal(werr.code, 'wrong-pin');
  // short pin distinct
  let serr = null;
  try { await openVault(back, '12345'); } catch (e) { serr = e; }
  assert.equal(serr.code, 'pin-too-short');
  // damaged distinct
  let derr = null;
  try { await openVault({ v: 1 }, pin); } catch (e) { derr = e; }
  assert.equal(derr.code, 'damaged-vault');
  console.log('ok   wrong-pin / pin-too-short / damaged-vault are distinct codes');

  // Wait: openVault(back, '12345') -- does '12345' actually TAG as too-short (yes)
  console.log('   isPlausiblePin("12345") =', isPlausiblePin('12345'));
  console.log('   isPlausiblePin("abcdef") =', isPlausiblePin('abcdef'));
})();

hr('AREA3 spend: change / dust / one pocket / signed == validated');
const root = createRoot();
const pocket = pocketFor(root.seed, { coin: 'btc', index: 0 });
const to = pocketFor(root.seed, { coin: 'btc', index: 5 }).address;   // payee
const change = pocketFor(root.seed, { coin: 'btc', index: 6 }).address; // change
const utxo = { txid: 'ab'.repeat(32), vout: 0, value: 100000n };
check('change never silently to payee', () => {
  assert.throws(() => buildSpend({ pocket, utxo, to, amount: 50000n, fee: 1000n, changeAddress: to }), /payee/);
});
check('change address as different casing still caught (bech32 upper)', () => {
  const shouted = to.toUpperCase();
  assert.throws(() => buildSpend({ pocket, utxo, to, amount: 50000n, fee: 1000n, changeAddress: shouted }), /payee/);
});
check('sum(outputs)+effectiveFee == spendable', () => {
  for (const v of [100000n, 51000n + 293n, 51000n + 294n, 51000n + 295n]) {
    const r = buildSpend({ pocket, utxo: { ...utxo, value: v }, to, amount: 50000n, fee: 1000n, changeAddress: change });
    const sum = r.tx.outputs.reduce((a, o) => a + o.value, 0n);
    assert.equal(sum + r.fee, v, `value ${v}`);
  }
});
check('dust change (293) to miner, at 294 kept', () => {
  const a = buildSpend({ pocket, utxo: { ...utxo, value: 50000n + 1000n + 293n }, to, amount: 50000n, fee: 1000n, changeAddress: change });
  assert.equal(a.change, 0n);
  assert.equal(a.tx.outputs.length, 1);
  assert.equal(a.fee, 1293n);
  const b = buildSpend({ pocket, utxo: { ...utxo, value: 50000n + 1000n + 294n }, to, amount: 50000n, fee: 1000n, changeAddress: change });
  assert.equal(b.change, 294n);
});
check('one-pocket: short utxo refused', () => {
  assert.throws(() => buildSpend({ pocket, utxo: { ...utxo, value: 50999n }, to, amount: 50000n, fee: 1000n, changeAddress: change }), /does not cover/);
});
check('payee output value equals the amount validated', () => {
  const r = buildSpend({ pocket, utxo, to, amount: 12345n, fee: 1000n, changeAddress: change });
  assert.equal(r.tx.outputs[0].value, 12345n);
});
check('amount below dust still allowed as payee output', () => {
  const r = buildSpend({ pocket, utxo, to, amount: 100n, fee: 1000n, changeAddress: change });
  assert.equal(r.tx.outputs[0].value, 100n);
  console.log('   a 100-sat payee output is created (below 294 dust):', r.tx.outputs.map(o=>o.value.toString()));
});

hr('AREA4 paymentState/watcher');
check('created + a 3-conf report is refused (cannot reach confirmed without address_issued)', () => {
  assert.throws(() => applyWatcherReport({ state: 'created', report: { source: 'watcher', txid: 'x', confirmations: 3, amount: '1' }, currency: 'btc', amount: '1' }), /seen before/);
});
check('address_issued + 3-conf report jumps straight to confirmed (seen skipped)', () => {
  assert.equal(applyWatcherReport({ state: 'address_issued', report: { source: 'watcher', txid: 'x', confirmations: 3, amount: '1' }, currency: 'btc', amount: '1' }), 'confirmed');
});
check('seen + 0 conf does not move', () => {
  assert.throws(() => applyWatcherReport({ state: 'seen', report: { source: 'watcher', txid: 'x', confirmations: 0, amount: '1' }, currency: 'btc', amount: '1' }), /did not move/);
});
check('a short amount is refused', () => {
  assert.throws(() => applyWatcherReport({ state: 'address_issued', report: { source: 'watcher', txid: 'x', confirmations: 1, amount: '0.5' }, currency: 'btc', amount: '1' }), /short/);
});
check('a report without source watcher cannot move', () => {
  assert.throws(() => applyWatcherReport({ state: 'address_issued', report: { txid: 'x', confirmations: 5 }, currency: 'btc', amount: '1' }), /watcher/);
});
await (async () => {
  // watcher signed response path
  const base = 'secret-base-token';
  const watcherUrl = 'https://watcher.example/pay?token=' + base;
  const address = pocket.address;
  const child = await childWatcherToken(base, address, 'btc');
  const body = JSON.stringify({ address, currency: 'btc', txid: 'de'.repeat(32), confirmations: 0, amount: '0.5' });
  const ts = String(Math.floor(Date.now() / 1000));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(child), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${ts}:${body}`)));
  const sig = 'v1=' + [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
  const fetchImpl = async () => ({ ok: true, status: 200, headers: { get: (k) => (k === 'x-cipher-sig' ? sig : k === 'x-cipher-ts' ? ts : null) }, text: async () => body });
  const ans = await checkPayment({ watcherUrl, address, currency: 'btc', fetchImpl });
  console.log('   signed watcher answer ->', JSON.stringify(ans.report));
  assert.equal(ans.report.amount, '0.5');
  // tampered body fails signature
  const badFetch = async () => ({ ok: true, status: 200, headers: { get: (k) => (k === 'x-cipher-sig' ? sig : k === 'x-cipher-ts' ? ts : null) }, text: async () => body.replace('0.5','9.9') });
  let berr = null; try { await checkPayment({ watcherUrl, address, currency: 'btc', fetchImpl: badFetch }); } catch (e) { berr = e; }
  assert.match(berr.message, /signature/);
  console.log('ok   tampered watcher body refused');
})();

hr('AREA5 receive: crash between handle and pocket / xmr reachability');
await (async () => {
  const store = createPocketStore(memoryKv());
  const recv = createReceive({ seed: root.seed, store, watcherUrl: 'https://w.example/p?token=t' });
  const a = await recv.issue({ coin: 'btc' });
  // simulate a crash AFTER derivation but BEFORE the write landing: kv.set throws
  const kv = memoryKv();
  const store2 = createPocketStore(kv);
  const recv2 = createReceive({ seed: root.seed, store: store2, watcherUrl: 'https://w.example/p?token=t' });
  const origSet = kv.set;
  kv.set = async () => { throw new Error('disk full'); };
  let crashed = false;
  try { await recv2.issue({ coin: 'btc' }); } catch { crashed = true; }
  kv.set = origSet;
  assert.equal(crashed, true);
  const after = await recv2.issue({ coin: 'btc' });
  console.log('   crash mid-write -> retry index', after.pocket.index, 'handle.next', JSON.stringify(after.handle.next));
  assert.equal(after.pocket.index, 0, 'no index skipped or reused after a crash');
  console.log('ok   crash mid-write: retry reuses index 0 (not 1), no gap');

  // CONCURRENCY: two issue() calls without awaiting -> same handle read twice
  const store3 = createPocketStore(memoryKv());
  const recv3 = createReceive({ seed: root.seed, store: store3, watcherUrl: 'https://w.example/p?token=t' });
  const [x, y] = await Promise.all([recv3.issue({ coin: 'btc' }), recv3.issue({ coin: 'btc' })]);
  console.log('   concurrent issue -> indices', x.pocket.index, y.pocket.index, '| addresses equal:', x.pocket.address === y.pocket.address);
  const list = await store3.list();
  console.log('   pockets persisted:', list.length);

  // xmr reachability
  const xmr = await recv3.issue({ coin: 'xmr' });
  console.log('   xmr issued pocket address =', xmr.pocket.address);
  let scanErr = null;
  try { await recv3.scan({ coin: 'xmr', index: xmr.pocket.index, amount: '1' }); } catch (e) { scanErr = e; }
  console.log('   xmr scan ->', scanErr ? scanErr.message : 'ok');
})();

console.log('\nFAILS:', fails.length ? fails.join(' | ') : 'none');

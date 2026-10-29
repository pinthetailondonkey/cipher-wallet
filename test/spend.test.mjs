import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { derivePocket, rootFromMnemonic } from '../src/root.js';
import { decodeAddress } from '../src/address.js';
import { parseTx, txid } from '../src/tx.js';
import { decodePsbt, encodePsbt } from '../src/psbt.js';
import { DUST_LIMIT, buildSpend, finalizeSpend, signSpend, spendAsBase64 } from '../src/spend.js';

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const POCKET = derivePocket(SEED, 'btc', 0);
const CHANGE = derivePocket(SEED, 'btc', 1);

const PREV = 'ab'.repeat(32);
const PAY_TO = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
// A different valid mainnet address from the BIP-350 vectors. Note that
// rewriting "tb1..." into "bc1..." does NOT give a valid address: the checksum
// covers the prefix, which is exactly what this decoder refuses.
const CHANGE_TO = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0';

function utxoOf(value) {
  return { txid: PREV, vout: 0, value };
}

// The default change address is a second address, not the payee. It used to be
// the payee, which meant four tests were quietly asserting the shape the guard
// above now refuses.
function spendOf({ value = 100000n, amount = 50000n, fee = 1000n, changeAddress = CHANGE_TO } = {}) {
  return buildSpend({ pocket: POCKET, utxo: utxoOf(value), to: PAY_TO, amount, fee, changeAddress });
}

test('a spend pays the payee and returns the change to a pocket of ours', () => {
  const { tx, change, fee } = spendOf();
  assert.equal(change, 49000n);
  assert.equal(fee, 1000n);
  assert.equal(tx.outputs.length, 2);
  assert.equal(tx.outputs[0].value, 50000n);
  assert.equal(tx.outputs[1].value, 49000n);
  assert.equal(hex.encode(tx.outputs[0].script), hex.encode(decodeAddress(PAY_TO, 'bc').script));
  // inputs plus the fee are exactly the outputs: no satoshi invented or lost
  const total = tx.outputs.reduce((sum, output) => sum + output.value, 0n);
  assert.equal(total + fee, 100000n);
});

test('the change output goes where it was told, not to the payee', () => {
  const { tx } = buildSpend({
    pocket: POCKET, utxo: utxoOf(100000n), to: PAY_TO, amount: 50000n, fee: 1000n, changeAddress: CHANGE_TO,
  });
  assert.equal(hex.encode(tx.outputs[1].script), hex.encode(decodeAddress(CHANGE_TO, 'bc').script));
});

test('change below the dust limit goes to the miner instead of being made', () => {
  const value = 50000n + 1000n + DUST_LIMIT - 1n;
  const out = buildSpend({ pocket: POCKET, utxo: utxoOf(value), to: PAY_TO, amount: 50000n, fee: 1000n });
  assert.equal(out.tx.outputs.length, 1);
  assert.equal(out.change, 0n);
  assert.equal(out.fee, 1000n + DUST_LIMIT - 1n);
});

test('change exactly at the dust limit is still an output', () => {
  const value = 50000n + 1000n + DUST_LIMIT;
  const out = buildSpend({ pocket: POCKET, utxo: utxoOf(value), to: PAY_TO, amount: 50000n, fee: 1000n, changeAddress: CHANGE_TO });
  assert.equal(out.tx.outputs.length, 2);
  assert.equal(out.change, DUST_LIMIT);
});

test('change sent to the payee is refused, not folded into an overpayment', () => {
  assert.throws(
    () => buildSpend({
      pocket: POCKET, utxo: utxoOf(100000n), to: PAY_TO, amount: 50000n, fee: 1000n, changeAddress: PAY_TO,
    }),
    /change address is the payee/,
  );
});

test('a normal spend to a separate change pocket is unaffected by that guard', () => {
  const { tx, change } = buildSpend({
    pocket: POCKET, utxo: utxoOf(100000n), to: PAY_TO, amount: 50000n, fee: 1000n, changeAddress: CHANGE_TO,
  });
  assert.equal(tx.outputs.length, 2);
  assert.equal(change, 49000n);
  assert.notEqual(hex.encode(tx.outputs[1].script), hex.encode(tx.outputs[0].script));
});

test('a spend with change and nowhere to put it is refused', () => {
  assert.throws(
    () => buildSpend({ pocket: POCKET, utxo: utxoOf(100000n), to: PAY_TO, amount: 50000n, fee: 1000n }),
    /needs somewhere for the change/,
  );
});

test('a pocket that does not cover the payment and fee is refused', () => {
  assert.throws(() => spendOf({ value: 50000n, amount: 50000n, fee: 1000n }), /does not cover/);
});

test('an amount or fee that is a number is refused', () => {
  assert.throws(() => spendOf({ amount: 0.5 }), /bigint of satoshis/);
  assert.throws(() => spendOf({ fee: 0.0001 }), /bigint of satoshis/);
});

test('a payment of nothing is refused', () => {
  assert.throws(() => spendOf({ amount: 0n }), /not a payment/);
});

test('a negative fee is refused', () => {
  assert.throws(() => spendOf({ fee: -1n }), /cannot be negative/);
});

test('a spend is signed on this device and finalizes to bytes', () => {
  const { psbt, tx } = spendOf();
  signSpend({ psbt, pocket: POCKET });
  const out = finalizeSpend(psbt);
  assert.equal(out.txid, txid(tx));
  const back = parseTx(out.raw);
  assert.equal(back.inputs[0].witness.length, 2);
  assert.equal(back.inputs[0].witness[1].length, 33, 'the compressed public key rides in the witness');
});

test('building a spend does not sign it', () => {
  const { psbt } = spendOf();
  assert.throws(() => finalizeSpend(psbt), /no signature/);
});

test('a spend survives the base64 form and decrypts back to the same transaction', () => {
  const { psbt, tx } = spendOf();
  signSpend({ psbt, pocket: POCKET });
  const back = decodePsbt(encodePsbt(decodePsbt(encodePsbt(psbt))));
  assert.equal(txid(back.tx), txid(tx));
  assert.equal(typeof spendAsBase64(psbt), 'string');
});

test('the pocket can only sign a spend from itself', () => {
  const { psbt } = buildSpend({
    pocket: CHANGE, utxo: utxoOf(100000n), to: PAY_TO, amount: 50000n, fee: 1000n, changeAddress: CHANGE_TO,
  });
  // Built for CHANGE, signed with POCKET: the output does not belong to it.
  assert.throws(() => signSpend({ psbt, pocket: POCKET }), /does not belong to this pocket key/);
});

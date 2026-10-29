import test from 'node:test';
import assert from 'node:assert/strict';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import {
  hashToScalar,
  keyDerivation,
  derivePublicKey,
  secretToPublic,
  viewTag,
  varint,
} from '../src/monero/keys.js';
import { scanForPockets, scanTransaction, transactionPublicKey } from '../src/monero/scan.js';

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');

// A sender, built the way Monero's sender builds a transaction: a random
// per-transaction secret r, R = rG in the extra, and each output key from
// 8*(r*V). The scanner must agree with a sender it never talks to.
function sendTo(pocket, { outputs = 1, secret = 'tx' } = {}) {
  const r = hashToScalar(keccak_256(new TextEncoder().encode(secret)));
  const txPublicKey = secretToPublic(r);
  const derivation = keyDerivation(pocket.view, r);
  const list = [];
  for (let index = 0; index < outputs; index += 1) {
    list.push({
      key: derivePublicKey(derivation, index, pocket.spend),
      viewTag: viewTag(derivation, index),
    });
  }
  return { transactionPublicKey: txPublicKey, outputs: list, derivation };
}

function extraOf(txPublicKey, nonce = new Uint8Array([9, 8, 7])) {
  return new Uint8Array([0x01, ...txPublicKey, 0x02, ...varint(nonce.length), ...nonce]);
}

const POCKET = moneroPocket(SEED, 0);
const OTHER = moneroPocket(SEED, 1);

test('an output built for a pocket is found, and only by that pocket', () => {
  const tx = sendTo(POCKET, { outputs: 3 });
  assert.deepEqual(scanTransaction({ pocket: POCKET, ...tx }), [0, 1, 2]);
  assert.deepEqual(scanTransaction({ pocket: OTHER, ...tx }), []);
});

test('a transaction that pays two pockets is attributed to each', () => {
  // One sender, one transaction secret, three outputs: two to the first pocket
  // and the third to a different whole wallet.
  const r = hashToScalar(keccak_256(new TextEncoder().encode('two pockets')));
  const toFirst = keyDerivation(POCKET.view, r);
  const toSecond = keyDerivation(OTHER.view, r);
  const outputs = [
    { key: derivePublicKey(toFirst, 0, POCKET.spend), viewTag: viewTag(toFirst, 0) },
    { key: derivePublicKey(toFirst, 1, POCKET.spend), viewTag: viewTag(toFirst, 1) },
    { key: derivePublicKey(toSecond, 2, OTHER.spend), viewTag: viewTag(toSecond, 2) },
  ];
  const found = scanForPockets([POCKET, OTHER], { extra: extraOf(secretToPublic(r)), outputs });
  assert.deepEqual(found, [{ pocket: 0, output: 0 }, { pocket: 0, output: 1 }, { pocket: 1, output: 2 }]);
});

test('the output index is part of the derivation', () => {
  const tx = sendTo(POCKET, { outputs: 2 });
  // Move the second output key to the first position: the key is ours, but it
  // is not the key for index 0, so it must not match there.
  const shuffled = [tx.outputs[1], tx.outputs[0]];
  assert.deepEqual(scanTransaction({ pocket: POCKET, ...tx, outputs: shuffled }), []);
});

test('the view tag is a filter, and a wrong one skips the output', () => {
  const tx = sendTo(POCKET, { outputs: 2 });
  const lying = [{ ...tx.outputs[0], viewTag: tx.outputs[0].viewTag ^ 0xff }, tx.outputs[1]];
  assert.deepEqual(scanTransaction({ pocket: POCKET, ...tx, outputs: lying }), [1]);
  // The tag is one byte, so it can collide. A colliding tag must not invent a
  // match: the full comparison still decides.
  const colliding = [{ ...sendTo(OTHER, { secret: 'x' }).outputs[0], viewTag: tx.outputs[0].viewTag }];
  assert.deepEqual(scanTransaction({ pocket: POCKET, ...tx, outputs: colliding }), []);
});

test('an output with another one-time key is not ours', () => {
  const tx = sendTo(POCKET, { outputs: 2 });
  const other = sendTo(OTHER, { secret: 'x' }).outputs[0];
  const mixed = [tx.outputs[0], { ...other, viewTag: tx.outputs[1].viewTag }];
  assert.deepEqual(scanTransaction({ pocket: POCKET, ...tx, outputs: mixed }), [0]);
});

test('an output key that is not a curve point is not a match, and does not stop the scan', () => {
  // What is asserted is the outcome: junk keys are not ours, the real one still
  // is, and the scan returns. It is not asserted that a validity guard skipped
  // them — there is no such guard, because the comparison is bytes and a guard
  // whose removal changed nothing was not doing any work.
  const tx = sendTo(POCKET, { outputs: 3 });
  const junk = [
    { key: new Uint8Array(32), viewTag: tx.outputs[0].viewTag }, // zero key
    { key: new Uint8Array([0x01, ...new Uint8Array(31)]), viewTag: tx.outputs[1].viewTag }, // identity
    tx.outputs[2],
  ];
  assert.deepEqual(scanTransaction({ pocket: POCKET, ...tx, outputs: junk }), [2]);
});

test('the transaction public key is read from the extra field', () => {
  const tx = sendTo(POCKET);
  assert.deepEqual(transactionPublicKey(extraOf(tx.transactionPublicKey)), tx.transactionPublicKey);
  // Padding and an additional-pubkey field around it change nothing.
  const padded = new Uint8Array([0x00, 0x01, ...tx.transactionPublicKey, 0x04, 0x01, ...OTHER.spend, 0x02, 0x01, 0x07]);
  assert.deepEqual(transactionPublicKey(padded), tx.transactionPublicKey);
});

test('a malformed extra field is refused, not read past', () => {
  const tx = sendTo(POCKET);
  const key = tx.transactionPublicKey;
  assert.throws(() => transactionPublicKey(new Uint8Array()), /extra field/);
  assert.throws(() => transactionPublicKey(new Uint8Array([0x01, ...key.slice(0, 10)])), /cut short/);
  assert.throws(() => transactionPublicKey(new Uint8Array([0x01, ...key, 0x02, 0x05, 0x01])), /cut short/);
  assert.throws(() => transactionPublicKey(new Uint8Array([0x01, ...key, 0x77])), /cannot read/);
  assert.throws(() => transactionPublicKey(new Uint8Array([0x01, ...key, 0x01, ...key])), /twice/);
  assert.throws(() => transactionPublicKey(new Uint8Array([0x00, 0x00])), /names no public key/);
});

test('a transaction public key that is not a key is refused', () => {
  for (const bad of [new Uint8Array(32), new Uint8Array([0x01, ...new Uint8Array(31)])]) {
    assert.throws(
      () => scanTransaction({ pocket: POCKET, transactionPublicKey: bad, outputs: [] }),
      /not a usable transaction public key/,
    );
  }
});

test('a scan without a pocket or an output list is refused', () => {
  const tx = sendTo(POCKET);
  assert.throws(() => scanTransaction({ ...tx }), /needs a pocket/);
  assert.throws(() => scanTransaction({ pocket: POCKET, transactionPublicKey: tx.transactionPublicKey }), /list/);
  assert.throws(() => scanForPockets(POCKET, tx), /list/);
});

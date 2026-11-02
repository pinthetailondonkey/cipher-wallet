// The scan-input contract: EXACTLY what fields, types, and byte-formats
// scanForPockets requires of a transaction. This is the spec Lane C's
// implementation will code against. No ownership logic, no keys, no
// derivation against anything but the published 'abandon' seed.
//
// The contract, pinned by execution against the real zeroamount fixture:
//   scanForPockets(pockets, transaction) where transaction is:
//     { extra: Uint8Array (the walked tx.extra, raw bytes),
//       outputs: [{ key: Uint8Array (32B one-time key),
//                   viewTag: number or undefined,
//                   amount: not read by the scan ] }
//   and pockets is: [{ spend: Uint8Array (32B), viewSecret: Uint8Array (32B),
//                      index: number }]
//
// What the walk produces (readTransaction) does NOT match this contract
// directly: walked output keys are hex strings, not bytes. The conversion
// is the boundary the bridge test pinned. This test proves the contract
// by walking a real transaction, converting at the boundary, and feeding
// the result to the scan — the same path Lane C's implementation will use.
//
// Lane C stays gated: the pocket here is derived from the published
// 'abandon' seed, and the transaction is a stranger's real mainnet tx.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';
import { scanForPockets, scanTransaction, transactionPublicKey } from '../src/monero/scan.js';
import { keyDerivation, derivePublicKey, scReduce32, secretToPublic } from '../src/monero/keys.js';

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const POCKET = moneroPocket(SEED, 0);
const ZEROAMOUNT = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-zeroamount.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const BYTES = Uint8Array.from(Buffer.from(unspaced(ZEROAMOUNT.asHex), 'hex'));
const walked = readTransaction(BYTES, 0, 'zeroamount fixture');

// ---- contract field 1: transaction.extra must be Uint8Array ----

test('contract: transaction.extra must be Uint8Array (the walked tx.extra qualifies)', () => {
  assert.ok(walked.extra instanceof Uint8Array,
    'the walked tx.extra is already Uint8Array: no conversion needed for extra');
  // scanForPockets accesses transactionPublicKey(transaction.extra)
  const txPub = transactionPublicKey(walked.extra);
  assert.equal(txPub.length, 32, 'the extracted tx public key is 32 bytes');
  console.log('[contract] extra: Uint8Array, tx public key extractable, 32B');
});

// ---- contract field 2: output.key must be Uint8Array (32B) ----

test('contract: output.key must be Uint8Array 32B (the walk emits hex, the adapter converts)', () => {
  // what the walk emits: hex strings
  assert.equal(typeof walked.outputs[0].key, 'string',
    'the walk emits output keys as hex strings');
  // what the scan requires: Uint8Array 32B
  // the conversion is the adapter's job (proven in walk-scan-bridge.test.mjs)
  const converted = hex.decode(walked.outputs[0].key);
  assert.ok(converted instanceof Uint8Array, 'the converted key is Uint8Array');
  assert.equal(converted.length, 32, 'the converted key is 32 bytes');
  console.log('[contract] output.key: walk emits hex, adapter converts to Uint8Array 32B');
});

// ---- contract field 3: output.viewTag is number or undefined ----

test('contract: output.viewTag is a number (the walk emits it as a number)', () => {
  // the zeroamount fixture's walked outputs have viewTags (type 6 carries them)
  for (const [i, output] of walked.outputs.entries()) {
    if (output.viewTag !== undefined) {
      assert.equal(typeof output.viewTag, 'number',
        `output ${i} viewTag is a number (the walk emits it correctly)`);
    }
    // the scan checks: output.viewTag !== undefined && output.viewTag !== viewTag(...)
    // a number passes this check; a string would always mismatch
  }
  console.log('[contract] viewTag: number, no conversion needed');
});

// ---- contract field 4: pocket.spend and pocket.viewSecret must be Uint8Array 32B ----

test('contract: pocket.spend and viewSecret must be Uint8Array 32B', () => {
  assert.ok(POCKET.spend instanceof Uint8Array && POCKET.spend.length === 32,
    'pocket.spend is Uint8Array 32B');
  assert.ok(POCKET.viewSecret instanceof Uint8Array && POCKET.viewSecret.length === 32,
    'pocket.viewSecret is Uint8Array 32B');
  console.log('[contract] pocket keys: Uint8Array 32B each');
});

// ---- the full pipeline: walked tx -> adapter -> scan, against real bytes ----

test('contract: the full walked-to-scanned pipeline runs on the real fixture', () => {
  // this is the path Lane C's implementation will follow, with the real
  // pocket keys substituted for the throwaway ones
  const shaped = {
    extra: walked.extra,
    outputs: walked.outputs.map((o) => ({
      amount: o.amount,
      key: typeof o.key === 'string' ? hex.decode(o.key) : o.key,
      viewTag: o.viewTag,
    })),
  };
  // the scan runs without error on the real fixture + throwaway pocket
  const matches = scanForPockets([POCKET], shaped);
  assert.deepEqual(matches, [], 'the foreign tx matches nothing (honest answer)');
  console.log('[contract] the full pipeline runs clean on real bytes');
});

// ---- the positive arm: the scan finds a matching derivation through the adapter ----

test('contract: the positive path survives (a pocket finds its own derivation)', () => {
  const SCALAR = scReduce32(new Uint8Array(32).fill(0x42));
  const txPub = secretToPublic(SCALAR);
  const extra = new Uint8Array(33);
  extra[0] = 0x01;
  extra.set(txPub, 1);
  const derivation = keyDerivation(txPub, POCKET.viewSecret);
  const own = derivePublicKey(derivation, 0, POCKET.spend);
  // walk-shaped: key as hex string, as the walk emits
  const walkedShaped = {
    extra,
    outputs: [{ amount: 0n, key: hex.encode(own), viewTag: undefined }],
  };
  // adapter converts
  const shaped = {
    extra: walkedShaped.extra,
    outputs: walkedShaped.outputs.map((o) => ({
      amount: o.amount,
      key: hex.decode(o.key),
      viewTag: o.viewTag,
    })),
  };
  const matches = scanForPockets([POCKET], shaped);
  assert.deepEqual(matches, [{ pocket: 0, output: 0 }],
    'the derivation lands on the pocket through the full walk-adapter-scan path');
  console.log('[contract] positive path: derivation found through the full pipeline');
});

// The walk-to-scan adapter: moves DATA across the boundary; it must not
// decide OWNERSHIP. Scope ruling from Zebra-1, drawn here in prose:
//
//   ALLOWED: convert hex keys to bytes (the boundary the bridge test
//   pinned), pass walked transactions to scanForPockets, assert the scan
//   refuses/accepts honestly on real fixture bytes.
//
//   NOT ALLOWED: recognize any output as the wallet's own, derive against
//   anything but a throwaway published seed, touch scan.js's ownership
//   logic.
//
// The adapter lives in this test (not in src/) because its only current
// caller is a proof. When a future lane wires walk-to-scan in production,
// this test is the reference for where the conversion belongs and what it
// must never grow into.
//
// If scan.js itself needed a change to accept walked transactions, this
// work stops and reports first (decode-path surface). It did not: the
// conversion at the boundary is sufficient, proven below.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { parseBlock, readTransaction } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';
import { scanForPockets } from '../src/monero/scan.js';
import { keyDerivation, derivePublicKey, scReduce32, secretToPublic } from '../src/monero/keys.js';

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const POCKET_A = moneroPocket(SEED, 0);
const POCKET_B = moneroPocket(SEED, 1);

const ZEROAMOUNT = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-zeroamount.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

// THE ADAPTER. Data movement only: every field passes through, keys and view
// tags are converted from the walk's hex strings to the bytes the scan
// requires, and nothing is decided about who owns what.
function walkedToScanShape(walkedTx) {
  return {
    extra: walkedTx.extra,
    outputs: walkedTx.outputs.map((output) => ({
      amount: output.amount,
      key: typeof output.key === 'string' ? hex.decode(output.key) : output.key,
      viewTag: output.viewTag === undefined ? undefined : (
        typeof output.viewTag === 'string' ? hex.decode(output.viewTag) : output.viewTag
      ),
    })),
  };
}

const walkedZeroamount = readTransaction(bytesOf(ZEROAMOUNT.asHex), 0, 'zeroamount fixture');

test('adapter: a walked real transaction passes through to the scan unchanged in meaning', () => {
  const shaped = walkedToScanShape(walkedZeroamount);
  // data identity: the conversion changes types, not values
  assert.equal(hex.encode(shaped.outputs[0].key), walkedZeroamount.outputs[0].key,
    'the key bytes are exactly the hex the walk emitted');
  assert.equal(shaped.extra, walkedZeroamount.extra,
    'the extra is passed by reference, untouched');
  // and the scan accepts it: the honest answer for a foreign tx is no match
  const matches = scanForPockets([POCKET_A, POCKET_B], shaped);
  assert.deepEqual(matches, [], 'a stranger\u2019s transaction matches no throwaway pocket');
  console.log('[adapter] data crossed the boundary; ownership was never decided');
});

test('adapter: the whole walked block flows through, transaction by transaction', () => {
  // the load-bearing path: blockWalk proves ids against the block's own hash
  // list, then every proven transaction goes through the adapter to the scan.
  // The pinned 33-tx block is the real chain data for both halves.
  const BLOCK = JSON.parse(readFileSync(new URL('./fixtures/monero-block-3796965.json', import.meta.url), 'utf8'));
  const TXS = JSON.parse(readFileSync(new URL('./fixtures/monero-block-3796965-txs.json', import.meta.url), 'utf8'));
  const block = parseBlock(bytesOf(BLOCK.block.blob));
  const walk = walkBlockTxs(block, TXS.txs.map((t) => bytesOf(t.asHex)));
  // every walked transaction is scan-shaped without error
  const scans = walk.ids.map((id, i) => {
    const walkedTx = readTransaction(TXS.txs[i].asHex ? bytesOf(TXS.txs[i].asHex) : new Uint8Array(0), 0, `block tx ${i}`);
    const shaped = walkedToScanShape(walkedTx);
    return scanForPockets([POCKET_A, POCKET_B], shaped);
  });
  assert.equal(scans.length, 33, 'all 33 proven transactions scanned');
  // the honest answer for all of them against throwaway pockets: no matches
  for (const matches of scans) assert.deepEqual(matches, []);
  console.log('[adapter] 33/33 walked transactions crossed to the scan cleanly');
});

test('adapter: a matching derivation is still found through the adapter (the positive path survives)', () => {
  // the adapter must not lose the positive path: a pocket whose derivation
  // the extra carries still finds its own output, through the same conversion
  const SCALAR = scReduce32(new Uint8Array(32).fill(0x42));
  const txPub = secretToPublic(SCALAR);
  const extra = new Uint8Array(33);
  extra[0] = 0x01;
  extra.set(txPub, 1);
  const own = derivePublicKey(keyDerivation(txPub, POCKET_A.viewSecret), 0, POCKET_A.spend);
  // a walked-shaped transaction carrying that derivation: hex strings, as
  // the walk would emit them
  const walkedShaped = {
    extra,
    outputs: [{ amount: 0n, key: hex.encode(own), viewTag: undefined }],
  };
  const matches = scanForPockets([POCKET_A], walkedToScanShape(walkedShaped));
  assert.deepEqual(matches, [{ pocket: 0, output: 0 }],
    'the positive path survives the conversion: the derivation lands on its own pocket');
  console.log('[adapter] positive path intact through the conversion');
});


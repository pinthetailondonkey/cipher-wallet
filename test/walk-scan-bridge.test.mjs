// The walk-and-scan bridge: what a walked transaction is, and what the scan
// takes. The finding, pinned by a real transaction:
//
//   1. readTransaction emits output keys as HEX STRINGS (cursor.hex), and
//      view tags as NUMBERS. That is what a monerod answer carries.
//   2. scanTransaction requires Uint8Array output keys. A walked transaction
//      fed to scanForPockets RAW is refused with the named error
//      "Output 0 has no one-time key" - the mismatch is real and the refusal
//      is honest.
//   3. The conversion (hex.decode on the key strings, at the boundary, before
//      the scan) is the bridge. After it, the scan runs clean against the
//      real pinned transaction and returns the honest answer for a foreign
//      transaction: no match.
//
// The pin: the conversion lives at the bridge, not inside readTransaction
// (whose hex-string output is the wire's own shape) and not inside
// scanTransaction (whose byte requirement is its own contract). Future lanes
// wire the two through this named step.
//
// Lane C stays gated: the pocket here is derived from the published
// 'abandon' seed, a throwaway, and the transaction is a stranger's real
// mainnet transaction. Nothing about a wallet the founder owns is scanned.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';
import { scanForPockets } from '../src/monero/scan.js';
import { keyDerivation as keyDerivationFor, derivePublicKey as derivePublicKeyFor, scReduce32, secretToPublic } from '../src/monero/keys.js';

const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const POCKET = moneroPocket(SEED, 0);
const ZEROAMOUNT = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-zeroamount.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const BYTES = Uint8Array.from(Buffer.from(unspaced(ZEROAMOUNT.asHex), 'hex'));
const walked = readTransaction(BYTES, 0, 'zeroamount fixture');

test('the walk reproduces the pinned tx_hash from the real bytes', () => {
  assert.equal(transactionIdOf(walked), unspaced(ZEROAMOUNT.txHash),
    'the walk\u2019s id matches the fixture\u2019s tx_hash, as every needle test already proves');
});

test('a walked transaction fed to the scan raw is refused, by name', () => {
  assert.throws(
    () => scanForPockets([POCKET], walked),
    /Output 0 has no one-time key/,
    'the walk emits hex strings; the scan wants bytes; the refusal names the gap',
  );
});

test('the bridge: hex-decoded outputs scan clean and answer honestly for a foreign transaction', () => {
  const converted = walked.outputs.map((output) => ({
    amount: output.amount,
    key: typeof output.key === 'string' ? hex.decode(output.key) : output.key,
    viewTag: output.viewTag,
  }));
  const matches = scanForPockets([POCKET], { extra: walked.extra, outputs: converted });
  assert.deepEqual(matches, [], 'a stranger\u2019s transaction matches none of a throwaway pocket\u2019s derivations');
  console.log('[bridge] converted outputs scan clean; the foreign tx honestly matches nothing');
});

test('positive arm: a pocket whose derivation the extra carries finds its own output', () => {
  // the same pocket, but the extra names a transaction public key the pocket
  // derived against: the one-time key built from that derivation must match.
  // A real tx pubkey is a curve point; 0x42 repeated is not, so the scalar
  // is reduced and PUBLISHED (secretToPublic) before the extra carries it.
  const SCALAR = scReduce32(new Uint8Array(32).fill(0x42));
  const txPub = secretToPublic(SCALAR);
  const extra = new Uint8Array(33);
  extra[0] = 0x01;
  extra.set(txPub, 1);
  const derivation = keyDerivationFor(txPub, POCKET.viewSecret);
  const own = derivePublicKeyFor(derivation, 0, POCKET.spend);
  const matches = scanForPockets([POCKET], { extra, outputs: [{ key: own }] });
  assert.deepEqual(matches, [{ pocket: 0, output: 0 }],
    'the derivation lands on the pocket that carries the view secret');
  console.log('[bridge] positive arm: the derivation lands on its own pocket');
});

// key derivation helpers, imported here so the test file owns its dependency
// list and the reader sees exactly which curve operations the bridge needs.

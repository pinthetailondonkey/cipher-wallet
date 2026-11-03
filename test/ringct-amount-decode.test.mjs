// The amount path, rebuilt against Monero's own encoding rather than against
// the decoder's own inverse.
//
// state/FINDING-F1-ringct-amount.md proved the old decoder was unreachable from
// real data: it demanded sixteen bytes of ecdh info where no RingCT type writes
// sixteen, it padded with keccak(derivation || varint(i)) without sc_reduce32 or
// the "amount" domain tag, and it read a mask that the modern types derive.
//
// What is pinned HERE, and to what:
//
//   1. derivation_to_scalar is pinned to Monero's OWN generated vectors. The
//      vendored tests.txt carries 256 derive_secret_key rows; each row is
//      derive_secret_key(derivation, index, base) = base + H_s(derivation,
//      index), so subtracting the base mod l recovers the per-output scalar
//      without this repository writing a single expected value. That is the
//      step the old code got wrong (no sc_reduce32).
//   2. The commitment generator H is pinned to the 32 bytes Monero compiles in
//      (crypto/generators.cpp, "pedersen commitment generator H"), and is
//      reproduced here from G + keccak + point decompression + cofactor 8.
//   3. The two domain-separated pads are pinned to literal bytes computed from
//      the quoted upstream construction in rctOps.cpp (genAmountEncodingFactor,
//      genCommitmentMask).
//   4. The widths are pinned on REAL mainnet bytes: 8 bytes per output for
//      types 4/5/6 and 64 for types 1/2/3. Sixteen appears nowhere.
//   5. The decoded pair must reproduce the transaction's own Pedersen
//      commitment, C = mask*G + amount*H. That check runs on real chain bytes
//      with a derivation that is not the owner's, and it must REFUSE.
//
// What is still not pinned, and cannot be from inside this repository: a real
// transaction's true amount. The pad needs the owner's view secret, and keys
// stay out. What changed is that a wrong answer can no longer be reported as a
// number: decodeAmount refuses unless the claim it returns rebuilds the
// commitment the chain carries.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hex } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { GROUP_ORDER, bytesToNumberLE, decodePoint, encodePoint, numberToBytesLE } from '../src/monero/keys.js';
import { readTransaction } from '../src/monero/block.js';
import {
  COMMITMENT_H,
  MAX_ATOMIC,
  amountEncodingFactor,
  commitmentMask,
  commitmentOf,
  decodeAmount,
  derivationToScalar,
  encodeAmountForTest,
} from '../src/monero/ringct.js';

const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (text) => Uint8Array.from(Buffer.from(unspaced(text), 'hex'));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const G = bytesOf('58666666666666666666666666666666 66666666666666666666666666666666');

function fixture(name) {
  const json = JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
  return { json, bytes: bytesOf(json.asHex) };
}

// The vendored vector file, read the way test/monero-keys.test.mjs reads it:
// hex words of sixteen characters, the index a decimal token.
function deriveSecretKeyVectors() {
  const path = fileURLToPath(new URL('./fixtures/monero-crypto.txt', import.meta.url));
  const rows = [];
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const t = line.trim().split(/\s+/).filter(Boolean);
    if (t[0] !== 'derive_secret_key') continue;
    rows.push({
      derivation: bytesOf(t[1] + t[2]),
      index: Number(t[3]),
      base: bytesOf(t[4] + t[5]),
      derived: bytesOf(t[6] + t[7]),
    });
  }
  return rows;
}

const subtractScalars = (a, b) => numberToBytesLE(
  ((bytesToNumberLE(a) - bytesToNumberLE(b)) % GROUP_ORDER + GROUP_ORDER) % GROUP_ORDER,
);

// 1 — derivation_to_scalar, against Monero's own vectors, with no expected
// value written by this repository.
test('derivation_to_scalar matches all 256 of Monero\'s own derive_secret_key vectors', () => {
  const rows = deriveSecretKeyVectors();
  assert.equal(rows.length, 256, 'the derive_secret_key vectors went missing');
  for (const row of rows) {
    // derive_secret_key = base + H_s(derivation, index) mod l, so the per-output
    // scalar is the difference. Nothing here is a value this repo authored.
    const expected = subtractScalars(row.derived, row.base);
    const got = derivationToScalar(row.derivation, row.index);
    assert.equal(hex.encode(got), hex.encode(expected), `index ${row.index}`);
  }
  console.log(`[ringct-amount] derivation_to_scalar pinned on ${rows.length} external vectors`);
});

test('the old unreduced pad is not the derivation_to_scalar Monero uses', () => {
  // The kill shot, kept as a live check: keccak(derivation || varint(index))
  // WITHOUT sc_reduce32 is a different 32-byte value, which is why the old
  // decoder could not have been right even with the correct widths.
  const row = deriveSecretKeyVectors()[0];
  const raw = keccak_256(concat(row.derivation, Uint8Array.from([row.index])));
  const reduced = derivationToScalar(row.derivation, row.index);
  assert.notEqual(hex.encode(raw), hex.encode(reduced));
});

// 2 — the commitment generator, against the constant Monero compiles in.
test('the commitment generator H is the chain\'s H, recomputed from G', () => {
  assert.equal(COMMITMENT_H, '8b655970153799af2aeadc9ff1add0ea 6c7251d54154cfa92c173a0dd39c1f94');
  // crypto/generators.cpp reproduce_generator_H: interpret keccak(G) as a
  // compressed point directly (ge_frombytes_vartime), then multiply by 8.
  const reproduced = encodePoint(decodePoint(keccak_256(G)).clearCofactor());
  assert.equal(hex.encode(reproduced), unspaced(COMMITMENT_H));
  console.log('[ringct-amount] H reproduced from G and matches the compiled constant');
});

// 3 — the pads, pinned to literal bytes from the quoted upstream construction.
test('the two domain-separated pads are pinned to upstream bytes', () => {
  const sharedSec = bytesOf('ff0fb7390c13ddfae0d1c6f9970b169f d7ef31c62e6ecc041c088dc3bab87303');
  // rctOps.cpp genAmountEncodingFactor: cn_fast_hash("amount" || k), 38 bytes.
  assert.equal(
    hex.encode(amountEncodingFactor(sharedSec)),
    unspaced('3508fe59125d311cff90a738bcf9f871 c0b2769436ae454fa0da3682d1960230'),
  );
  // rctOps.cpp genCommitmentMask: hash_to_scalar("commitment_mask" || k), 47 bytes.
  assert.equal(
    hex.encode(commitmentMask(sharedSec)),
    unspaced('cd8c8208b4dede50c037ab2ee654a0c5 05f47d7dece2dc56b569487ee7c5a30e'),
  );
  console.log('[ringct-amount] both pads pinned to literal upstream bytes');
});

// 4 — the widths, on real mainnet bytes. This is the claim F1 killed: no type
// writes sixteen bytes per output.
test('real transactions carry 8 or 64 bytes of ecdh per output, never 16', () => {
  const widths = {
    'monero-tx-type3-1in': 64,
    'monero-tx-type3-2in': 64,
    'monero-tx-rct-1': 64,
    'monero-tx-rct-2': 64,
    'monero-tx-rct-4': 8,
    'monero-tx-rct-5': 8,
    'monero-tx-ringct-type6': 8,
    // Three more type 6 captures, so the width rule is not resting on one.
    'monero-tx-1in-manyout': 8,
    'monero-tx-manyin': 8,
    'monero-tx-smallfee': 8,
    'monero-tx-zeroamount': 8,
  };
  for (const [name, width] of Object.entries(widths)) {
    const { bytes } = fixture(name);
    const tx = readTransaction(bytes, 0, `${name} fixture`);
    assert.ok(tx.rctType >= 1 && tx.rctType <= 6, `${name}: rctType ${tx.rctType}`);
    assert.ok(tx.outputs.length > 0);
    for (const output of tx.outputs) {
      assert.ok(output.ecdh instanceof Uint8Array, `${name}: output has no ecdh slice`);
      assert.equal(output.ecdh.length, width, `${name}: type ${tx.rctType} ecdh width`);
      assert.match(output.commitment, /^[0-9a-f]{64}$/);
    }
    console.log(`[ringct-amount] ${name}: type ${tx.rctType}, ${tx.outputs.length} outputs, ${width}B ecdh each`);
  }
});

test('decodeAmount refuses sixteen bytes by name, for every type', () => {
  for (const rctType of [1, 2, 3, 4, 5, 6]) {
    assert.throws(
      () => decodeAmount({
        derivation: new Uint8Array(32),
        index: 0,
        info: new Uint8Array(16),
        rctType,
        commitment: '00'.repeat(32),
      }),
      /eight|sixty-four/,
    );
  }
});

// 5 — the guard on real bytes. With a derivation that is not the owner's, the
// decoded pair cannot rebuild the commitment, and decodeAmount must refuse
// rather than return a number.
test('a wrong derivation on real bytes is refused by the commitment check', () => {
  const { bytes } = fixture('monero-tx-ringct-type6');
  const tx = readTransaction(bytes, 0, 'type6 fixture');
  const output = tx.outputs[0];
  assert.throws(
    () => decodeAmount({
      derivation: new Uint8Array(32).fill(0x11),
      index: 0,
      info: output.ecdh,
      rctType: tx.rctType,
      commitment: output.commitment,
    }),
    /commitment/i,
  );
  console.log('[ringct-amount] real bytes + wrong derivation: refused by the commitment, not reported');
});

// The wiring: encode a known pair through the public inverse, decode it back
// with the same derivation, and require the commitment to be reproduced. This
// is a round trip and says so; the pads above are what make the bytes mean
// something, and the commitment is what makes the pair mean something.
for (const rctType of [1, 3, 4, 6]) {
  test(`type ${rctType}: a known amount round trips and rebuilds its commitment`, () => {
    const derivation = bytesOf('ff0fb7390c13ddfae0d1c6f9970b169f d7ef31c62e6ecc041c088dc3bab87303');
    const index = 3;
    const value = 123456789012n;
    const sharedSec = derivationToScalar(derivation, index);
    // One canonical mask for both layouts. For types 4/5/6 this is the mask the
    // wire does not carry; the encoder checks it against the derived value.
    const mask = commitmentMask(sharedSec);
    const info = encodeAmountForTest({ derivation, index, value, rctType, mask });
    assert.equal(info.length, rctType >= 4 ? 8 : 64);
    const commitment = commitmentOf({ amount: value, mask });
    const out = decodeAmount({ derivation, index, info, rctType, commitment });
    assert.equal(out.value, value);
    assert.equal(hex.encode(out.mask), hex.encode(mask));
    // A different output index changes the pad. The uncompressed types usually
    // fail the superfluous-data bound first; the compressed types fail the
    // commitment. Either way there is a named refusal, never a number.
    assert.throws(
      () => decodeAmount({ derivation, index: index + 1, info, rctType, commitment }),
      /commitment|superfluous/i,
    );
  });
}

test('an amount above the widest atomic value is refused, not wrapped', () => {
  const derivation = new Uint8Array(32).fill(0x22);
  assert.throws(
    () => encodeAmountForTest({ derivation, index: 0, value: MAX_ATOMIC + 1n, rctType: 6 }),
    /bigint|widest/,
  );
  assert.throws(
    () => encodeAmountForTest({ derivation, index: 0, value: 1.5, rctType: 6 }),
    /bigint/,
  );
});

// The arithmetic the handoff flagged as unresolved: the type 3 base ends at
// 401 and its Bulletproof opens at 405, because four bytes of proof count sit
// between. There was never a discrepancy; the two numbers measure different
// things.
test('the type 3 base ends at 401 and the first Bulletproof field starts at 405', () => {
  const { bytes } = fixture('monero-tx-type3-1in');
  const tx = readTransaction(bytes, 0, 'type3 fixture');
  assert.equal(tx.baseEnd, 401);
  const proofCount = tx.prunableBytes.slice(0, 4);
  assert.equal(bytesToNumberLE(proofCount), 1n, 'nbp is a 4-byte little-endian count');
  const firstProofField = 4;
  assert.equal(tx.prunableBytes.length - firstProofField > 0, true);
  // The Bulletproof's A..mu block is six keys, so the L-count follows at 405+192.
  const lCountAt = firstProofField + 32 * 6;
  let at = lCountAt;
  let lCount = 0n;
  let shift = 0n;
  for (;;) {
    const byte = tx.prunableBytes[at]; at += 1;
    lCount |= BigInt(byte & 0x7f) << shift;
    shift += 7n;
    if (!(byte & 0x80)) break;
  }
  assert.equal(lCount, 7n, 'a two-output Bulletproof has 7 rounds');
  console.log('[ringct-amount] baseEnd 401 + 4B nbp = 405; the two numbers were never in conflict');
});

// The guard's own limit, pinned so nobody overclaims it. A caller that supplies
// BOTH the info and the commitment can always satisfy the check, because it
// commits to its own answer. That is not a bug, it is what the check can and
// cannot do; the real transaction's commitment is what makes it evidence.
test('the guard is only as strong as where the commitment came from', () => {
  const bogus = new Uint8Array(32).fill(0x99);
  const info = encodeAmountForTest({ derivation: bogus, index: 0, value: 42n, rctType: 6 });
  const mask = commitmentMask(derivationToScalar(bogus, 0));
  // Both sides the caller's: passes, and proves only self-consistency.
  assert.equal(
    decodeAmount({ derivation: bogus, index: 0, info, rctType: 6, commitment: commitmentOf({ amount: 42n, mask }) }).value,
    42n,
  );
  // The commitment from the chain instead: the made-up derivation is refused.
  const { bytes } = fixture('monero-tx-ringct-type6');
  const tx = readTransaction(bytes, 0, 'type6 fixture');
  assert.throws(
    () => decodeAmount({
      derivation: bogus, index: 0, info: tx.outputs[0].ecdh, rctType: 6, commitment: tx.outputs[0].commitment,
    }),
    /commitment/i,
  );
  console.log('[ringct-amount] guard pinned at its real strength: chain commitment refuses, self-supplied does not');
});

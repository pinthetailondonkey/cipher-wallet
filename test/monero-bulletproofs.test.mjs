// A Bulletproof+, judged from three sides at once.
//
// ONE: THE PROOF CAN BE CHECKED, and the check is tested against a STRANGER'S
// PROOF. `test/fixtures/monero-tx-ringct-type6.json` is a real mainnet
// transaction carrying a real Bulletproof+ built by monerod's own code. Our
// verifier must accept it. Nothing about the transcript, the split-half fold, the
// challenge products, the INV_EIGHT scaling or the generator derivation can be
// wrong and still accept it, and that is the whole reason this test exists: our
// prover and our verifier sharing a mistake would agree with each other forever.
//
// TWO: THE PROOF CAN BE MADE. Our prover's output is verified by our verifier for
// one and two amounts, at the edges (0 and 2^64 - 1), reproducibly, and with V
// checked independently as each output commitment divided by eight.
//
// THREE: IT SURVIVES THE JOIN. A signed spend built through buildSpend is parsed
// back by this build's own reader; the proof is lifted OUT of the wire bytes at
// the offsets the serializer wrote, its commitments are lifted out of the same
// bytes, and the pair verifies. Then one byte inside the proof is flipped and it
// must stop verifying, and the signature is checked against a message recomputed
// from the proof's keys, so a proof that is written but not SIGNED OVER is caught.
//
// WHAT THIS DOES NOT PROVE, stated rather than implied: a proof of the right
// range is not a proof that the amounts are the ones the commitments hold. The
// balance check is what ties those together and it lives in the transaction, not
// in the proof.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { readTransaction } from '../src/monero/block.js';
import { commitmentOf } from '../src/monero/ringct.js';
import {
  proveBulletproofPlus, verifyBulletproofPlus, writeBulletproofPlus, bulletproofPlusKeys,
  bulletproofPlusLSize, INV_EIGHT, windowedVector,
} from '../src/monero/bulletproofs.js';
import { bulletproofPlusWidth, writeType6Prunable } from '../src/monero/txWriter.js';
import { bytesToNumberLE, decodePoint, encodePoint, hashToScalar, GROUP_ORDER, numberToBytesLE } from '../src/monero/keys.js';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import * as keys from '../src/monero/keys.js';
import { buildOutput, buildSpend } from '../src/monero/build.js';
import { clsagMessage, verifyClsag } from '../src/monero/clsag.js';

const REAL = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-ringct-type6.json', import.meta.url), 'utf8'));
const realTx = readTransaction(hex.decode(REAL.asHex.replace(/ /g, '')), 0, 'real type 6 tx');

const mask = (n) => hashToScalar(Uint8Array.from([n]));
const commitmentsFor = (amounts, masks) => amounts.map((amount, i) => commitmentOf({ amount, mask: masks[i] }));
const flip = (bytes, at) => {
  const out = Uint8Array.from(bytes);
  out[at] ^= 0x01;
  return out;
};

// A small signed spend through the real builder, used by the join tests. Two
// outputs, a ring of five members, all of it reproducible.
const JOIN_RING = [];
for (let i = 0; i < 5; i += 1) {
  JOIN_RING.push({
    amount: 0,
    index: BigInt(1000 + i),
    key: keys.secretToPublic(mask(40 + i)),
    mask: commitmentOf({ amount: 1234n + BigInt(i), mask: mask(50 + i) }),
  });
}

let joinedCache = null;
const buildJoined = () => {
  const seed = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const sender = moneroPocket(seed, 0);
  const recipient = moneroPocket(seed, 1);
  const priorSecret = mask(7);
  const derivation = keys.keyDerivation(keys.secretToPublic(priorSecret), sender.viewSecret);
  const owned = buildOutput({ derivation, index: 0, spendPublic: sender.spend, value: 5_000_000_000n });
  const ownedSecret = keys.deriveSecretKey(derivation, 0, sender.spendSecret);
  // `ours` names the ABSOLUTE index of our member, not its position: it is what
  // ringFromOuts searches for, and the position is what it returns.
  const ours = 1002n;
  return buildSpend({
    input: {
      ring: JOIN_RING.map((member) => (member.index === ours
        ? { ...member, key: owned.key, mask: owned.commitment }
        : member)),
      ours,
      secret: ownedSecret,
      mask: owned.mask,
      value: 5_000_000_000n,
    },
    recipients: [
      { spendPublic: recipient.spend, viewPublic: recipient.view, value: 1_000_000_000n },
      { spendPublic: sender.spend, viewPublic: sender.view, value: 3_999_000_000n },
    ],
    fee: 1_000_000n,
    txSecret: mask(11),
  });
};

test('a real mainnet Bulletproof+ verifies against the commitments it covers', () => {
  assert.equal(realTx.bulletproofsPlus.length, 1, 'a type 6 transaction carries exactly one proof, whatever its output count');
  const proof = realTx.bulletproofsPlus[0];
  assert.equal(proof.L.length, bulletproofPlusWidth(realTx.outputs.length), 'and its width is the one an output count implies');
  const commitments = realTx.outputs.map((o) => o.commitment);
  assert.equal(verifyBulletproofPlus({ proof, commitments }), null);
});

test('every field of that real proof matters: one flipped byte refuses it', () => {
  const proof = realTx.bulletproofsPlus[0];
  const commitments = realTx.outputs.map((o) => o.commitment);
  const cases = {
    A: () => ({ ...proof, A: flip(proof.A, 3) }),
    A1: () => ({ ...proof, A1: flip(proof.A1, 3) }),
    B: () => ({ ...proof, B: flip(proof.B, 3) }),
    r1: () => ({ ...proof, r1: flip(proof.r1, 0) }),
    s1: () => ({ ...proof, s1: flip(proof.s1, 0) }),
    d1: () => ({ ...proof, d1: flip(proof.d1, 0) }),
    'L[0]': () => ({ ...proof, L: proof.L.map((k, i) => (i === 0 ? flip(k, 5) : k)) }),
    'R[last]': () => ({ ...proof, R: proof.R.map((k, i) => (i === proof.R.length - 1 ? flip(k, 5) : k)) }),
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const reason = verifyBulletproofPlus({ proof: mutate(), commitments });
    assert.notEqual(reason, null, `${name} is load-bearing`);
    assert.equal(typeof reason, 'string');
  }
  // And the commitments, which are not part of the proof at all: V is rebuilt
  // from them, so a proof cannot be moved onto another transaction's outputs.
  for (const at of [0, 8, 31]) {
    assert.notEqual(verifyBulletproofPlus({ proof, commitments: commitments.map((c, i) => (i === 0 ? flip(c, at) : c)) }), null);
  }
});

test('the proof count and width are refused when they do not describe the outputs', () => {
  const proof = realTx.bulletproofsPlus[0];
  const commitments = realTx.outputs.map((o) => o.commitment);
  assert.match(verifyBulletproofPlus({ proof, commitments: commitments.slice(0, 1) }) || '', /wider than/);
  assert.match(verifyBulletproofPlus({ proof, commitments: [...commitments, commitments[0]] }) || '', /covers 2 outputs/);
  const short = { ...proof, L: proof.L.slice(0, 5), R: proof.R.slice(0, 5) };
  assert.match(verifyBulletproofPlus({ proof: short, commitments }) || '', /at least 6/);
  const lopsided = { ...proof, R: proof.R.slice(0, 3) };
  assert.match(verifyBulletproofPlus({ proof: lopsided, commitments }) || '', /different lengths/);
  assert.match(verifyBulletproofPlus({ proof: { ...proof, d1: new Uint8Array(32) } , commitments }) || '', /does not verify|canonical/);
  assert.match(verifyBulletproofPlus({}) || '', /at least one output/);
});

test('the reference proof is refused when its commitments move by one output', () => {
  // A proof covers a contiguous set of amounts, and its first V term is weighted
  // z^2 while the second is z^4: swapping them is not a relabeling.
  const proof = realTx.bulletproofsPlus[0];
  const commitments = realTx.outputs.map((o) => o.commitment);
  const swapped = [commitments[1], commitments[0]];
  assert.notEqual(verifyBulletproofPlus({ proof, commitments: swapped }), null);
  assert.equal(verifyBulletproofPlus({ proof, commitments }), null);
});

test('our own proof verifies, for one amount and for two, at the range edges', () => {
  const cases = [
    { amounts: [0n], masks: [mask(1)] },
    { amounts: [(1n << 64n) - 1n], masks: [mask(2)] },
    { amounts: [1234n, 5_000_000_000n], masks: [mask(3), mask(4)] },
  ];
  for (const { amounts, masks } of cases) {
    const proof = proveBulletproofPlus({ amounts, masks });
    assert.equal(proof.L.length, bulletproofPlusLSize(amounts.length));
    assert.equal(proof.L.length, bulletproofPlusWidth(amounts.length), 'the two modules agree on the width');
    assert.equal(verifyBulletproofPlus({ proof, commitments: commitmentsFor(amounts, masks) }), null);
    // V is the commitment divided by eight, re-derived here from the commitment
    // rather than taken from the prover's own arithmetic.
    proof.V.forEach((v, i) => {
      const expected = encodePoint(decodePoint(commitmentsFor(amounts, masks)[i]).multiplyUnsafe(INV_EIGHT));
      assert.deepEqual(v, expected, `V ${i} is the commitment over eight`);
    });
  }
});

test('a proof is reproducible, and it is bound to the amounts it proves', () => {
  const amounts = [42n, 7n];
  const masks = [mask(5), mask(6)];
  const first = proveBulletproofPlus({ amounts, masks });
  const second = proveBulletproofPlus({ amounts, masks });
  assert.deepEqual(writeBulletproofPlus(first), writeBulletproofPlus(second), 'the same inputs give the same proof');
  assert.equal(verifyBulletproofPlus({ proof: first, commitments: commitmentsFor(amounts, masks) }), null);
  // The same masks with a different amount: the commitments move and the proof is
  // about the old ones.
  const other = [43n, 7n];
  assert.notEqual(verifyBulletproofPlus({ proof: first, commitments: commitmentsFor(other, masks) }), null);
  // The same amounts under different masks: same story, because V is committed to.
  assert.notEqual(verifyBulletproofPlus({ proof: first, commitments: commitmentsFor(amounts, [mask(9), mask(6)]) }), null);
});

test('the windowed vector sums to the closed form the verifier uses', () => {
  // The verifier computes sum(d) as (2^64 - 1) * sum of even powers of z rather
  // than adding 64 * M numbers, which is an optimization and an opportunity to be
  // wrong. The two agree only for the exact shape the prover builds.
  for (const [z, M] of [[mask(1), 1], [mask(2), 2], [mask(3), 4]]) {
    const zValue = bytesToNumberLE(z);
    const d = windowedVector(zValue, M);
    assert.equal(d.length, 64 * M, 'one 64-bit row per covered output power');
    const direct = d.reduce((total, value) => total + value, 0n) % GROUP_ORDER;
    let even = 0n;
    let power = (zValue * zValue) % GROUP_ORDER;
    for (let k = 0; k < M; k += 1) {
      even = (even + power) % GROUP_ORDER;
      power = (power * ((zValue * zValue) % GROUP_ORDER)) % GROUP_ORDER;
    }
    const closed = (((1n << 64n) - 1n) * even) % GROUP_ORDER;
    assert.equal(direct, closed, `the sum of the windowed vector, for M=${M}`);
  }
});

test('what the prover refuses, and why', () => {
  assert.throws(() => proveBulletproofPlus({ amounts: [], masks: [] }), /at least one amount/);
  assert.throws(() => proveBulletproofPlus({ amounts: [1n], masks: [] }), /one blinding factor per amount/);
  assert.throws(() => proveBulletproofPlus({ amounts: [1, 2], masks: [mask(1), mask(2)] }), /bigint/);
  assert.throws(() => proveBulletproofPlus({ amounts: [-1n], masks: [mask(1)] }), /negative/);
  assert.throws(() => proveBulletproofPlus({ amounts: [1n << 64n], masks: [mask(1)] }), /sixty-four bits/);
  assert.throws(() => proveBulletproofPlus({ amounts: [1n], masks: [numberToBytesLE(GROUP_ORDER + 1n)] }), /not a canonical scalar/);
  const many = Array.from({ length: 17 }, (_, i) => BigInt(i));
  assert.throws(() => proveBulletproofPlus({ amounts: many, masks: many.map((_, i) => mask(i)) }), /at most 16/);
});

test('the wire form is six keys then two count-prefixed vectors, and V is absent', () => {
  const proof = proveBulletproofPlus({ amounts: [9n], masks: [mask(8)] });
  const bytes = writeBulletproofPlus(proof);
  assert.equal(bytes.length, 32 * 18 + 2, 'six fixed keys then six L and six R keys, plus two one-byte counts');
  assert.deepEqual(bytes.slice(0, 32), proof.A);
  assert.deepEqual(bytes.slice(32 * 5, 32 * 6), proof.d1);
  assert.equal(bytes[32 * 6], proof.L.length, 'the L count is a varint');
  // Exactly one proof, in the prunable, and its width must match the outputs.
  const prunable = writeType6Prunable({ inputCount: 1, outputCount: 1, ringSize: 4, proofs: [proof] });
  assert.equal(prunable[0], 1, 'one aggregated proof');
  assert.deepEqual(prunable.slice(1, 1 + bytes.length), bytes);
  assert.throws(() => writeType6Prunable({ inputCount: 1, outputCount: 2, ringSize: 4, proofs: [proof] }), /where the width is 7/);
  assert.throws(() => writeType6Prunable({ inputCount: 1, outputCount: 1, ringSize: 4, proofs: [proof, proof] }), /exactly one/);
  assert.throws(() => writeBulletproofPlus({ ...proof, s1: new Uint8Array(31) }), /s1 is 32 bytes/);
  assert.throws(() => writeBulletproofPlus({ ...proof, R: [] }), /non-empty R/);
});

test('the proof keys are what a signature hashes, in hashed order', () => {
  const proof = proveBulletproofPlus({ amounts: [3n], masks: [mask(12)] });
  const flat = bulletproofPlusKeys(proof);
  assert.equal(flat.length, 32 * (6 + 2 * proof.L.length));
  assert.deepEqual(flat.slice(0, 32), proof.A);
  assert.deepEqual(flat.slice(32 * 6, 32 * 7), proof.L[0], 'the six fixed keys, then L, then R');
  assert.deepEqual(flat.slice(32 * (6 + proof.L.length), 32 * (7 + proof.L.length)), proof.R[0]);
});

test('a proof lifted back out of a built transaction verifies against that transaction', () => {
  joinedCache ??= buildJoined();
  const built = joinedCache;
  const tx = readTransaction(built.bytes, 0, 'built spend');
  assert.equal(tx.bulletproofsPlus.length, 1);
  const commitments = tx.outputs.map((o) => o.commitment);
  assert.equal(verifyBulletproofPlus({ proof: tx.bulletproofsPlus[0], commitments }), null);
  // The proof came off the wire, not out of the builder: rewriting it gives the
  // bytes it was read from.
  const prunableBytes = tx.prunableBytes;
  assert.deepEqual(prunableBytes.slice(1, 1 + writeBulletproofPlus(tx.bulletproofsPlus[0]).length), writeBulletproofPlus(built.proof));
  // One byte inside the proof, in the middle of the transaction.
  const at = tx.baseEnd + 1 + 32 * 3;
  const damaged = readTransaction(flip(built.bytes, at), 0, 'damaged');
  assert.notEqual(verifyBulletproofPlus({ proof: damaged.bulletproofsPlus[0], commitments: damaged.outputs.map((o) => o.commitment) }), null);
  // And an output commitment moved inside the same transaction.
  const moved = readTransaction(flip(built.bytes, tx.baseEnd - 1), 0, 'moved');
  assert.notEqual(verifyBulletproofPlus({ proof: moved.bulletproofsPlus[0], commitments: moved.outputs.map((o) => o.commitment) }), null);
});

test('the built signature is over the PROOF KEYS, not over a width of zeroes', () => {
  // The message a CLSAG signs hashes the proof's own keys (get_pre_mlsag_hash).
  // Before this lane the proof was zero bytes of the right WIDTH, so a signature
  // over zeroes verified; now a signature must fail against zeroes and pass
  // against the real keys.
  joinedCache ??= buildJoined();
  const built = joinedCache;
  const tx = readTransaction(built.bytes, 0, 'built spend');
  const pseudo = 32 * tx.inputs.length;
  const ringSize = tx.inputs[0].keyOffsets.length;
  const tail = tx.prunableBytes;
  const signature = {
    I: hex.decode(tx.inputs[0].keyImage),
    s: Array.from({ length: ringSize }, (_, i) => (
      tail.slice(tail.length - pseudo - 64 - 32 * (ringSize - i), tail.length - pseudo - 64 - 32 * (ringSize - i - 1))
    )),
    c1: tail.slice(tail.length - pseudo - 64, tail.length - pseudo - 32),
    D: tail.slice(tail.length - pseudo - 32, tail.length - pseudo),
  };
  const realKeys = { prefixBytes: tx.prefixBytes, baseBytes: tx.baseBytes, proofKeys: bulletproofPlusKeys(tx.bulletproofsPlus[0]) };
  const reason = verifyClsag({
    ring: built.ring,
    pseudoOut: tx.pseudoOuts[0],
    signature,
    message: clsagMessage(realKeys),
  });
  assert.equal(reason, null, `the signature verifies over the real proof keys: ${reason}`);
  // The same signature against a message built from the OLD assumption -- zero
  // bytes of the right width -- must fail, which is what pins that the proof is
  // in the message and not merely in the transaction.
  const zeroKeys = { ...realKeys, proofKeys: new Uint8Array(32 * (6 + 2 * tx.bulletproofsPlus[0].L.length)) };
  assert.notEqual(verifyClsag({ ring: built.ring, pseudoOut: tx.pseudoOuts[0], signature, message: clsagMessage(zeroKeys) }), null);
});

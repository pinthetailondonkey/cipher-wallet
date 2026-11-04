// Bulletproof+: the range proof one transaction carries for ALL of its outputs.
//
// A Monero output hides its amount, so a verifier has to be told that the hidden
// number is in [0, 2^64) without being told what it is: otherwise an attacker
// could pay with a negative amount and mint coins. A Bulletproof+ is that
// statement, aggregated for every output of the transaction at once, and it is
// the last piece of a spend that was still zero bytes.
//
// EVERY RULE BELOW IS TAKEN FROM UPSTREAM, not from a paper's prose:
// bulletproof_plus_PROVE, bulletproof_plus_VERIFY, init_exponents, compute_LR,
// hadamard_fold, weighted_inner_product and the transcript helpers in
// src/ringct/bulletproofs_plus.cc, the wrappers proveRangeBulletproofPlus /
// verBulletproofPlus and the V reconstruction in expand_transaction_1 in
// src/ringct/rctSigs.cpp and src/cryptonote_basic/cryptonote_format_utils.cpp,
// HASH_KEY_BULLETPROOF_PLUS_EXPONENT and HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT in
// src/cryptonote_config.h, monero-project at commit
// 3fd0f88c20f559839cafb20911cb13cb45eba7bd. The parts that are easy to get wrong,
// named so a reader can check them against that source:
//
//   - THE PROOF IS ONE, FOR EVERYTHING. Bulletproofs aggregate; `bulletproofs_plus`
//     holds exactly one proof however many outputs there are, and its L and R
//     vectors are sized by the output count. The txWriter says this too, and a
//     real daemon (expand_transaction_1) refuses any other count.
//
//   - V IS NOT ON THE WIRE. The prover's V is each output commitment divided by
//     eight, and the verifier rebuilds it as commitment * INV_EIGHT from outPk.
//     That scaling is why the generators and most scalars here carry an INV_EIGHT
//     factor: it is the trick that lets the verifier multiply the proof's points
//     by eight instead of clearing cofactors.
//
//   - THE FOLD IS SPLIT-HALF, NOT INTERLEAVED. hadamard_fold pairs v[n] with
//     v[sz+n]; the bit order in the challenge products follows from that, and the
//     verifier's `challenges_cache` loop has an odd shape (two writes per index,
//     stepping over odd indices) that must be copied literally rather than
//     tidied. It walks index i down the low half by halves: cache[2t] takes the
//     inverse challenge and cache[2t+1] the challenge, from cache[t].
//
//   - y and z AND e MUST BE NONZERO, and upstream regenerates its nonces if one
//     comes out zero. Nonces here are DERIVED rather than drawn (below), so a
//     retry changes the seed instead of re-rolling dice.
//
//   - THE TRANSCRIPT IS A CHAIN OF SCALARS. transcript_update hashes the current
//     transcript key together with the new value, so the running value is a
//     scalar and the update is keccak over 64 (or 96) bytes.
//
// NONCES ARE DERIVED, and that is the one deliberate difference from upstream,
// which draws them from a random source. alpha, every dL/dR, r, s, d_ and eta
// come from a hash chain seeded with the proof's own V and an attempt counter, so
// a proof is byte-reproducible for the same inputs and a fixture can pin it.
// Deriving them is as unlinkable as drawing them (the chain is a hash), and the
// one place it could bite is the retry path, which the attempt counter handles.
//
// WHAT THIS FILE DOES NOT DO: it is not a proof of knowledge of anything but the
// range, so it cannot tell whether the amounts it proves are also the amounts the
// commitments were built from. That is what the balance check is for, and a
// caller who proves a lie produces a proof that verifies and a transaction that
// does not.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  bytesToNumberLE, concatBytes, decodePoint, encodePoint, hashToScalar, hashToPoint,
  numberToBytesLE, GROUP_ORDER, varint,
} from './keys.js';
import { COMMITMENT_H_BYTES } from './ringct.js';

const Point = ed25519.Point;
const G_POINT = Point.BASE; // noble tables the base point already
const H_POINT = decodePoint(COMMITMENT_H_BYTES).precompute(4);

export const RANGE_BITS = 64;
// BULLETPROOF_PLUS_MAX_OUTPUTS (src/cryptonote_config.h): one proof covers at
// most sixteen outputs, and the count of L and R keys follows from it.
export const MAX_OUTPUTS = 16;
const LOG_RANGE_BITS = 6;

const UTF8 = new TextEncoder();
const EXPONENT_DOMAIN = UTF8.encode('bulletproof_plus');
const TRANSCRIPT_DOMAIN = UTF8.encode('bulletproof_plus_transcript');
const NONCE_DOMAIN = UTF8.encode('bulletproof_plus_nonce');

const modL = (value) => ((value % GROUP_ORDER) + GROUP_ORDER) % GROUP_ORDER;
const scalarBytes = (value) => numberToBytesLE(modL(value));

// A scalar is canonical when it is reduced. Upstream checks this on the proof's
// scalars and on the prover's masks (is_reduced / sc_check) and refuses the rest.
function scalarNumber(bytes, what) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error(`A ${what} is a 32-byte scalar.`);
  const value = bytesToNumberLE(bytes);
  if (value >= GROUP_ORDER) throw new Error(`That ${what} is not a canonical scalar, so it is not a scalar.`);
  return value;
}

// Fermat: x**(l-2) mod l, which is upstream's `invert`.
function inverse(value) {
  const n = modL(value);
  if (n === 0n) throw new Error('Zero has no inverse, and the proof never has a zero challenge here.');
  let result = 1n;
  let base = n;
  let exponent = GROUP_ORDER - 2n;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % GROUP_ORDER;
    base = (base * base) % GROUP_ORDER;
    exponent >>= 1n;
  }
  return result;
}

// Scalar multiplication. `multiplyUnsafe` on a point that has been through
// `precompute` is the fastest of the three shapes this library offers and it was
// measured rather than guessed (window 8 was slower than 4, and the safe
// `multiply` was slower than both). A zero scalar is common -- half the scalars of
// the first L and R vector are zero -- so it short-circuits.
const mul = (point, scalar) => {
  const k = modL(scalar);
  return k === 0n ? Point.ZERO : point.multiplyUnsafe(k);
};
const withTable = (point) => point.precompute(4);
const add = (points) => points.reduce((total, point) => total.add(point), Point.ZERO);
const mul8 = (point) => point.multiplyUnsafe(8n);
const pointOf = (bytes, what) => {
  try {
    return decodePoint(bytes);
  } catch {
    throw new Error(`That ${what} is not a point on the curve, so the proof is not one.`);
  }
};

export const INV_EIGHT = scalarNumber(Uint8Array.from([
  0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
]), 'INV_EIGHT');
const MINUS_ONE = GROUP_ORDER - 1n;
const MINUS_INV_EIGHT = modL(-INV_EIGHT);
const TWO = 2n;
const TWO_SIXTY_FOUR_MINUS_ONE = modL((1n << 64n) - 1n);

// The indexed generators, from upstream's get_exponent: a hash of H's bytes, the
// domain word and a varint index, mapped to the curve and cleared of its cofactor.
// Cached because a proof needs 2*MN of them and they never change.
const exponentCache = [];
function exponent(index) {
  const cached = exponentCache[index];
  if (cached) return cached;
  const hashed = keccak_256(concatBytes([COMMITMENT_H_BYTES, EXPONENT_DOMAIN, varint(index)]));
  const point = withTable(decodePoint(hashToPoint(hashed)));
  if (point.is0()) throw new Error(`Bulletproof+ exponent ${index} is the identity, which upstream also refuses.`);
  exponentCache[index] = point;
  return point;
}
const Hi = (i) => exponent(i * 2);
const Gi = (i) => exponent(i * 2 + 1);

// The transcript starts from a fixed POINT, kept in its encoded form because the
// transcript is over bytes: hash_to_p3 of the domain word, so the chain is domain
// separated and no proof can be replayed into another. Upstream holds this in a
// `key` too; the decode here is only for the identity check.
const initialTranscript = hashToPoint(keccak_256(TRANSCRIPT_DOMAIN));
if (decodePoint(initialTranscript).is0()) throw new Error('The Bulletproof+ transcript seed is the identity.');
const transcriptUpdate = (transcript, ...updates) => hashToScalar(concatBytes([transcript, ...updates]));

// sum over i of a_i*b_i*y**(i+1). Upstream's weighted_inner_product.
function weightedInnerProduct(a, b, y) {
  let result = 0n;
  let yPower = 1n;
  for (let i = 0; i < a.length; i += 1) {
    yPower = modL(yPower * y);
    result = modL(result + modL(a[i] * b[i]) * yPower);
  }
  return result;
}

// v[n] = a*v[n] + b*v[sz+n]. The pairing is with the OTHER half, not with the
// neighbouring index, and the challenges parity follows from it.
function hadamardFold(vector, a, b) {
  if (vector.length % 2 !== 0) throw new Error('A folded vector has an even length.');
  const half = vector.length / 2;
  const folded = Array.from({ length: half });
  for (let i = 0; i < half; i += 1) folded[i] = withTable(add([mul(vector[i], a), mul(vector[half + i], b)]));
  return folded;
}

// The windowed vector d[j*64+i] = z**(2*(j+1)) * 2**i. Exported because its SUM
// has a closed form and the test checks the two against each other.
export function windowedVector(z, M) {
  const size = M * RANGE_BITS;
  const d = Array.from({ length: size }, () => 0n);
  const zSquared = modL(z * z);
  d[0] = zSquared;
  for (let i = 1; i < RANGE_BITS; i += 1) d[i] = modL(d[i - 1] * TWO);
  for (let j = 1; j < M; j += 1) {
    for (let i = 0; i < RANGE_BITS; i += 1) d[j * RANGE_BITS + i] = modL(d[(j - 1) * RANGE_BITS + i] * zSquared);
  }
  return d;
}

const powersOf = (x, n) => {
  const out = Array.from({ length: n });
  out[0] = 1n;
  for (let i = 1; i < n; i += 1) out[i] = modL(out[i - 1] * x);
  return out;
};

const sumOf = (list) => list.reduce((total, value) => modL(total + value), 0n);

// The L or R term of one inner-product round: the vector's two halves with the
// y weighting, plus the two blinders. Every point here is one of the indexed
// generators or G/H, and the scalars all carry INV_EIGHT.
function computeLR({ size, y, G, G0, H, H0, a, a0, b, b0, c, d }) {
  const terms = [];
  for (let i = 0; i < size; i += 1) {
    const sa = modL(a[a0 + i] * y * INV_EIGHT);
    const sb = modL(b[b0 + i] * INV_EIGHT);
    if (sa !== 0n) terms.push(mul(G[G0 + i], sa));
    if (sb !== 0n) terms.push(mul(H[H0 + i], sb));
  }
  terms.push(mul(H_POINT, c * INV_EIGHT));
  terms.push(mul(G_POINT, d * INV_EIGHT));
  return add(terms);
}

function vectorExponent(a, b) {
  const terms = [];
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== 0n) terms.push(mul(Gi(i), a[i]));
    if (b[i] !== 0n) terms.push(mul(Hi(i), b[i]));
  }
  return add(terms);
}

// The L (and R) vector width for a proof covering `outputs` amounts: six keys per
// doubling of the 64-bit range, so the width is the log of the padded count.
export function bulletproofPlusLogM(outputs) {
  let logM = 0;
  while ((1 << logM) < outputs) logM += 1;
  return logM;
}

export function bulletproofPlusLSize(outputs) {
  if (!Number.isInteger(outputs) || outputs < 1 || outputs > MAX_OUTPUTS) {
    throw new Error(`A Bulletproof+ covers between 1 and ${MAX_OUTPUTS} outputs, not ${outputs}.`);
  }
  return LOG_RANGE_BITS + bulletproofPlusLogM(outputs);
}

const amountsOf = (amounts) => {
  if (!Array.isArray(amounts) || amounts.length === 0) throw new Error('A Bulletproof+ proves at least one amount.');
  if (amounts.length > MAX_OUTPUTS) {
    throw new Error(`A Bulletproof+ aggregates at most ${MAX_OUTPUTS} amounts and ${amounts.length} were given; upstream's maxM refuses the rest.`);
  }
  return amounts.map((value, i) => {
    if (typeof value !== 'bigint') throw new Error(`Amount ${i} is a bigint, in atomic units.`);
    if (value < 0n) throw new Error(`Amount ${i} is negative; a range proof is over [0, 2^64).`);
    if (value >= 1n << 64n) throw new Error(`Amount ${i} does not fit in sixty-four bits, so no Bulletproof+ covers it.`);
    return value;
  });
};

// Prove that every amount in `amounts` is in [0, 2^64), under the blinding
// factors `masks`, for a transaction whose outputs are those commitments. The
// masks must be the ones the commitments were built from; the proof cannot tell,
// and a caller who gets it wrong is caught by the balance check instead.
export function proveBulletproofPlus({ amounts, masks } = {}) {
  const values = amountsOf(amounts);
  if (!Array.isArray(masks) || masks.length !== values.length) {
    throw new Error(`A Bulletproof+ needs one blinding factor per amount: ${values.length} amount(s), ${masks?.length ?? 0} mask(s).`);
  }
  const gammas = masks.map((mask, i) => scalarNumber(mask, `mask ${i}`));

  const logM = bulletproofPlusLogM(values.length);
  const M = 1 << logM;
  const logMN = logM + LOG_RANGE_BITS;
  const MN = M * RANGE_BITS;

  // V is each commitment divided by eight, and the amount and mask are scaled by
  // INV_EIGHT with it. It is NOT serialized: the verifier rebuilds it from outPk.
  const V = values.map((value, i) => encodePoint(add([
    mul(G_POINT, gammas[i] * INV_EIGHT),
    mul(H_POINT, value * INV_EIGHT),
  ])));

  // The bit decomposition, padded to a power of two with zeroes (which is why the
  // padding is aR = -1 and aL = 0: 0 = 0*1 + (-1)*y^... shape).
  const aL = Array.from({ length: MN });
  const aR = Array.from({ length: MN });
  const aL8 = Array.from({ length: MN });
  const aR8 = Array.from({ length: MN });
  for (let j = 0; j < M; j += 1) {
    for (let i = 0; i < RANGE_BITS; i += 1) {
      const bit = j < values.length && ((values[j] >> BigInt(i)) & 1n) === 1n;
      const at = j * RANGE_BITS + i;
      aL[at] = bit ? 1n : 0n;
      aR[at] = bit ? 0n : MINUS_ONE;
      aL8[at] = bit ? INV_EIGHT : 0n;
      aR8[at] = bit ? 0n : MINUS_INV_EIGHT;
    }
  }

  // The Fiat-Shamir transcript begins with a hash of V, so the proof is bound to
  // the commitments it is about before a single challenge exists.
  const vSeed = concatBytes(V);
  for (let attempt = 0; ; attempt += 1) {
    let counter = 0;
    const stream = () => bytesToNumberLE(hashToScalar(concatBytes([NONCE_DOMAIN, vSeed, varint(attempt), varint(counter++)])));
    let transcript = transcriptUpdate(initialTranscript, hashToScalar(vSeed));

    const alpha = stream();
    const preA = vectorExponent(aL8, aR8);
    const A = encodePoint(add([preA, mul(G_POINT, alpha * INV_EIGHT)]));

    const y = transcriptUpdate(transcript, A);
    const yValue = bytesToNumberLE(y);
    if (yValue === 0n) continue; // upstream's goto try_again: a zero challenge is a fresh start
    const z = transcriptUpdate(y);
    const zValue = bytesToNumberLE(z);
    if (zValue === 0n) continue;
    transcript = z;

    const zSquared = modL(zValue * zValue);
    const d = windowedVector(zValue, M);
    const yPowers = powersOf(yValue, MN + 2);

    const aL1 = aL.map((value) => modL(value - zValue));
    const aR1 = aR.map((value, i) => modL(value + zValue + modL(d[i] * yPowers[MN - i])));

    let alpha1 = alpha;
    let temp = 1n;
    for (let j = 0; j < values.length; j += 1) {
      temp = modL(temp * zSquared);
      alpha1 = modL(alpha1 + modL(modL(yPowers[MN + 1] * temp) * gammas[j]));
    }

    let Gprime = Array.from({ length: MN }, (_, i) => Gi(i));
    let Hprime = Array.from({ length: MN }, (_, i) => Hi(i));
    let aprime = aL1;
    let bprime = aR1;

    const yInv = inverse(yValue);
    const yInvPow = powersOf(yInv, MN);
    const L = Array.from({ length: logMN });
    const R = Array.from({ length: logMN });
    let roundsOk = true;

    for (let round = 0; round < logMN; round += 1) {
      const nprime = MN >> (round + 1);
      const cL = weightedInnerProduct(aprime.slice(0, nprime), bprime.slice(nprime), yValue);
      const cR = weightedInnerProduct(aprime.slice(nprime).map((v) => modL(v * yPowers[nprime])), bprime.slice(0, nprime), yValue);
      const dL = stream();
      const dR = stream();

      L[round] = encodePoint(computeLR({
        size: nprime, y: yInvPow[nprime], G: Gprime, G0: nprime, H: Hprime, H0: 0,
        a: aprime, a0: 0, b: bprime, b0: nprime, c: cL, d: dL,
      }));
      R[round] = encodePoint(computeLR({
        size: nprime, y: yPowers[nprime], G: Gprime, G0: 0, H: Hprime, H0: nprime,
        a: aprime, a0: nprime, b: bprime, b0: 0, c: cR, d: dR,
      }));

      const challenge = transcriptUpdate(transcript, L[round], R[round]);
      const challengeValue = bytesToNumberLE(challenge);
      if (challengeValue === 0n) { roundsOk = false; break; }
      transcript = challenge;
      const challengeInv = inverse(challengeValue);

      Gprime = hadamardFold(Gprime, challengeInv, modL(yInvPow[nprime] * challengeValue));
      Hprime = hadamardFold(Hprime, challengeValue, challengeInv);

      const lowA = aprime.slice(0, nprime);
      const highA = aprime.slice(nprime);
      aprime = lowA.map((value, i) => modL(value * challengeValue + modL(highA[i] * modL(challengeInv * yPowers[nprime]))));
      const lowB = bprime.slice(0, nprime);
      const highB = bprime.slice(nprime);
      bprime = lowB.map((value, i) => modL(value * challengeInv + highB[i] * challengeValue));

      alpha1 = modL(alpha1 + modL(dL * modL(challengeValue * challengeValue)) + modL(dR * modL(challengeInv * challengeInv)));
    }
    if (!roundsOk) continue;

    const r = stream();
    const s = stream();
    const d_ = stream();
    const eta = stream();

    const A1 = encodePoint(add([
      mul(Gprime[0], r * INV_EIGHT),
      mul(Hprime[0], s * INV_EIGHT),
      mul(G_POINT, d_ * INV_EIGHT),
      mul(H_POINT, modL(r * yValue * bprime[0] + s * yValue * aprime[0]) * INV_EIGHT),
    ]));
    // B = (eta/8)*G + (r*y*s/8)*H: the FIRST term is against G, not H, which is
    // the kind of thing a reader assumes and a test has to pin.
    const B = encodePoint(add([
      mul(G_POINT, eta * INV_EIGHT),
      mul(H_POINT, modL(r * yValue * s) * INV_EIGHT),
    ]));

    const e = transcriptUpdate(transcript, A1, B);
    const eValue = bytesToNumberLE(e);
    if (eValue === 0n) continue;
    const eSquared = modL(eValue * eValue);

    const r1 = modL(r + eValue * aprime[0]);
    const s1 = modL(s + eValue * bprime[0]);
    const d1 = modL(eta + eValue * d_ + eSquared * alpha1);

    return {
      V,
      A,
      A1,
      B,
      r1: scalarBytes(r1),
      s1: scalarBytes(s1),
      d1: scalarBytes(d1),
      L,
      R,
      logM,
    };
  }
}

// The proof's own keys in the order get_pre_mlsag_hash hashes them: the six
// fixed keys then L then R, with no length prefixes, because the message is a
// hash of the keys and not of the encoding. THIS is what a CLSAG signs over, so a
// caller signing a transaction must build it from the SAME proof it writes.
export function bulletproofPlusKeys(proof) {
  const parts = [];
  for (const field of ['A', 'A1', 'B', 'r1', 's1', 'd1']) parts.push(asKey(proof?.[field], field));
  for (const vector of ['L', 'R']) {
    if (!Array.isArray(proof?.[vector]) || proof[vector].length === 0) {
      throw new Error(`A Bulletproof+ needs a non-empty ${vector} vector.`);
    }
    for (const [i, key] of proof[vector].entries()) parts.push(asKey(key, `${vector} ${i}`));
  }
  return concatBytes(parts);
}

const asKey = (value, what) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error(`A Bulletproof+ ${what} is 32 bytes.`);
  return value;
};

// The proof as the wire carries it: six fixed keys, then L and R count-prefixed
// (rctTypes.h, the BulletproofPlus serializer). V is deliberately absent.
export function writeBulletproofPlus(proof) {
  const p = proof ?? {};
  const parts = [];
  for (const field of ['A', 'A1', 'B', 'r1', 's1', 'd1']) parts.push(asKey(p[field], field));
  for (const vector of ['L', 'R']) {
    if (!Array.isArray(p[vector]) || p[vector].length === 0) throw new Error(`A Bulletproof+ needs a non-empty ${vector} vector.`);
    parts.push(varint(p[vector].length));
    for (const [i, key] of p[vector].entries()) parts.push(asKey(key, `${vector} ${i}`));
  }
  return concatBytes(parts);
}

// Check one proof against the commitments it claims to cover. Returns null when
// it verifies and a REASON STRING when it does not, like the CLSAG verifier, so a
// caller can tell a forged proof from a malformed one. The whole body runs inside
// a try because a flipped byte can decode to something that is not a point.
//
// The single-proof form of upstream's batch verifier, with the random batch
// weight set to one: for one proof the weight is a nonzero scaling of the same
// equation, so it cancels out and the check stays deterministic.
export function verifyBulletproofPlus({ proof, commitments } = {}) {
  try {
    return verifyInner({ proof, commitments });
  } catch (error) {
    if (process.env.BP_DEBUG) console.error(error.stack);
    return error?.message || 'the proof could not be checked';
  }
}

function verifyInner({ proof, commitments } = {}) {
  const p = proof ?? {};
  if (!Array.isArray(commitments) || commitments.length === 0) return 'a proof covers at least one output commitment';
  if (commitments.length > MAX_OUTPUTS) return `a proof covers at most ${MAX_OUTPUTS} outputs`;
  if (!Array.isArray(p.L) || !Array.isArray(p.R)) return 'the proof has no L or R vector';
  if (p.L.length !== p.R.length) return 'the L and R vectors are different lengths';
  if (p.L.length < LOG_RANGE_BITS) return `a Bulletproof+ has at least ${LOG_RANGE_BITS} L and R keys`;
  if (p.L.length >= 32) return 'that L vector is too long for any proof this build knows';

  const logM = p.L.length - LOG_RANGE_BITS;
  const covered = 1 << logM;
  // n_bulletproof_amounts_base: the width covers at least the commitments, and
  // less than twice as many, so a proof cannot be stretched over another tx's.
  if (commitments.length > covered) return `the proof covers ${covered} outputs and ${commitments.length} commitments were given`;
  if (commitments.length * 2 <= covered) return `the proof is wider than the ${commitments.length} commitment(s) it covers`;

  for (const field of ['A', 'A1', 'B']) {
    if (!(p[field] instanceof Uint8Array) || p[field].length !== 32) return `${field} is not a 32-byte key`;
  }
  for (const field of ['r1', 's1', 'd1']) {
    try { scalarNumber(p[field], field); } catch { return `${field} is not a canonical scalar`; }
  }
  const A = pointOf(p.A, 'A');
  const A1 = pointOf(p.A1, 'A1');
  const B = pointOf(p.B, 'B');
  const L = p.L.map((key, i) => pointOf(key, `L ${i}`));
  const R = p.R.map((key, i) => pointOf(key, `R ${i}`));
  const V = commitments.map((commitment, i) => pointOf(commitment, `commitment ${i}`));
  for (const [i, commitment] of V.entries()) {
    if (commitment.is0()) return `commitment ${i} is the identity, which carries no amount`;
  }

  const MN = covered * RANGE_BITS;
  const rounds = logM + LOG_RANGE_BITS;
  const weight = 1n;

  // Rebuild the challenges from the proof itself. Every step mirrors the prover.
  // THE TRANSCRIPT HASHES V, WHICH IS THE COMMITMENT DIVIDED BY EIGHT, while the
  // equation's V terms use the commitment itself (eight times V). Hashing the
  // commitments here was the first defect in this file: the proof's V is what
  // expand_transaction_1 rebuilds as outPk.mask * INV_EIGHT, and its bytes are
  // what the prover hashed.
  const vHash = concatBytes(V.map((commitment) => encodePoint(mul(commitment, INV_EIGHT))));
  let transcript = transcriptUpdate(initialTranscript, hashToScalar(vHash));
  const y = transcriptUpdate(transcript, p.A);
  const yValue = bytesToNumberLE(y);
  if (yValue === 0n) return 'the y challenge is zero';
  const z = transcriptUpdate(y);
  const zValue = bytesToNumberLE(z);
  if (zValue === 0n) return 'the z challenge is zero';
  transcript = z;

  const challenges = Array.from({ length: rounds });
  for (let j = 0; j < rounds; j += 1) {
    const challenge = transcriptUpdate(transcript, p.L[j], p.R[j]);
    const value = bytesToNumberLE(challenge);
    if (value === 0n) return `challenge ${j} is zero`;
    challenges[j] = value;
    transcript = challenge;
  }
  const e = transcriptUpdate(transcript, p.A1, p.B);
  const eValue = bytesToNumberLE(e);
  if (eValue === 0n) return 'the e challenge is zero';

  const eSquared = modL(eValue * eValue);
  const zSquared = modL(zValue * zValue);
  const yInv = inverse(yValue);
  // y**MN, by repeated squaring, then y**(MN+1): both appear in the equation.
  let yPowMN = yValue;
  for (let n = MN; n > 1; n >>= 1) yPowMN = modL(yPowMN * yPowMN);
  const yPowMN1 = modL(yPowMN * yValue);

  // The challenge products, exactly as upstream builds them: one write for an odd
  // index and one for the even index below it, stepping down over the odd ones
  // only, so each index is written once and the low half is finished before it is
  // read. cache[i] = prod_j challenges[j]**bit_j(i) with the bit taken from the
  // index's low half, which is the pairing the split-half fold produced.
  const invChallenges = challenges.map(inverse);
  const cache = Array.from({ length: 1 << rounds });
  cache[0] = invChallenges[0];
  cache[1] = challenges[0];
  for (let j = 1; j < rounds; j += 1) {
    const slots = 1 << (j + 1);
    for (let s = slots; (s -= 1) >= 0; s -= 1) {
      const half = s >> 1;
      cache[s] = modL(cache[half] * challenges[j]);
      cache[s - 1] = modL(cache[half] * invChallenges[j]);
    }
  }

  const d = windowedVector(zValue, covered);
  // sum(d), in the closed form upstream uses: (2^64 - 1) times the even powers of
  // z from z^2 to z^(2M). Each row of d is z^(2(j+1)) times two to the sixty-four
  // minus one, so the row sums are a geometric series; the direct sum over the
  // vector is the same number and the test compares the two.
  let evenPowers = 0n;
  let zPower = zSquared;
  for (let k = 0; k < covered; k += 1) {
    evenPowers = modL(evenPowers + zPower);
    zPower = modL(zPower * zSquared);
  }
  const sumD = modL(TWO_SIXTY_FOUR_MINUS_ONE * evenPowers);
  const sumY = sumOf(powersOf(yValue, MN + 1).slice(1));

  const terms = [];
  const term = (scalar, point) => { if (modL(scalar) !== 0n) terms.push({ scalar: modL(scalar), point }); };

  // V_j: -e^2 * y^(MN+1) * w * z^(2(j+1)), against the commitment itself, because
  // eight times the prover's V IS the commitment.
  let vScalar = modL(-modL(eSquared * yPowMN1) * weight);
  for (let j = 0; j < V.length; j += 1) {
    vScalar = modL(vScalar * zSquared);
    term(vScalar, V[j]);
  }
  // Upstream rescales the proof's OWN points by eight (scalarmult8) before adding
  // them, so A, A1, B, L and R go in as eight times themselves. V is already eight
  // times the prover's V, because V_proof is the commitment divided by eight, so
  // the commitment itself is the rescaled value and needs no multiply.
  const minusWeightE = modL(MINUS_ONE * weight * eValue);
  const minusWeightESquared = modL(MINUS_ONE * weight * eSquared);
  term(modL(MINUS_ONE * weight), mul8(B));
  term(minusWeightE, mul8(A1));
  term(minusWeightESquared, mul8(A));

  term(modL(weight * bytesToNumberLE(p.d1)), G_POINT);
  const hInner = modL(
    modL(bytesToNumberLE(p.r1) * yValue * bytesToNumberLE(p.s1))
    + modL(eSquared * modL(modL(yPowMN1 * zValue) * sumD + modL(modL(zSquared - zValue) * sumY))),
  );
  term(modL(hInner * weight), H_POINT);

  let eR1WY = modL(eValue * bytesToNumberLE(p.r1) * weight);
  const eS1W = modL(eValue * bytesToNumberLE(p.s1) * weight);
  const eSquaredZW = modL(eSquared * zValue * weight);
  const minusESquaredZY = modL(-eSquaredZW);
  let minusESquaredWY = modL(-eSquared * weight * yPowMN);
  for (let i = 0; i < MN; i += 1) {
    const gScalar = modL(eR1WY * cache[i] + eSquaredZW);
    let hScalar = modL(eS1W * cache[(~i) & (MN - 1)] + minusESquaredZY);
    term(gScalar, Gi(i));
    hScalar = modL(minusESquaredWY * d[i] + hScalar);
    term(hScalar, Hi(i));
    eR1WY = modL(eR1WY * yInv);
    minusESquaredWY = modL(minusESquaredWY * yInv);
  }

  for (let j = 0; j < rounds; j += 1) {
    term(modL(minusWeightESquared * modL(challenges[j] * challenges[j])), mul8(L[j]));
    term(modL(minusWeightESquared * modL(invChallenges[j] * invChallenges[j])), mul8(R[j]));
  }

  const sum = add(terms.map((t) => mul(t.point, t.scalar)));
  if (!sum.is0()) return 'the proof does not verify: the multiexp check is not the identity';
  return null;
}

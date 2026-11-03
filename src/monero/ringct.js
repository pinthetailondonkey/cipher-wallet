// RingCT amounts: what an output is worth, once the scan says the output is ours.
//
// THE CHAIN DOES NOT CARRY AMOUNTS IN THE CLEAR. Each output carries an "ecdh
// info" entry, one per output, XORed with a one-time pad that only the owner of
// the output can compute. How wide that entry is, and how the pad is built,
// depends on the RingCT type, and this module now follows Monero rather than a
// remembered convention. Every rule below is taken from monero-project at commit
// 3fd0f88c20f559839cafb20911cb13cb45eba7bd, file by file, and named where used:
//
//   widths          src/ringct/rctTypes.h  serialize_rctsig_base
//                     compressed_ecdh = (type == 4 || 5 || 6)
//                     compressed:  crypto::hash8 amount only        -> 8 bytes
//                     otherwise:   key mask, key amount             -> 64 bytes
//                   There is no type that writes sixteen bytes.
//
//   per-output pad  src/crypto/crypto.cpp  derivation_to_scalar
//                     sharedSec = sc_reduce32(keccak(derivation || varint(i)))
//                   The reduce is not decoration: without it the pad is a
//                   different 32 bytes (see the kill shot in the test).
//
//   type 4/5/6      src/ringct/rctOps.cpp  ecdhDecode, v2 branch
//                     amount = info[0..8] XOR keccak("amount" || sharedSec)[0..8]
//                     mask   = hash_to_scalar("commitment_mask" || sharedSec)
//                   The mask is DERIVED. Nothing on the wire carries it.
//
//   types 1/2/3     src/ringct/rctOps.cpp  ecdhDecode, non-v2 branch
//                     s1 = hash_to_scalar(sharedSec)
//                     s2 = hash_to_scalar(s1)
//                     mask   = info.mask   - s1  (mod l)
//                     amount = info.amount - s2  (mod l)
//                   These are scalar subtractions, not XOR.
//
//   amount bound    src/ringct/rctOps.cpp  decodeRct
//                     h2d() refuses a decoded amount whose upper bytes are set
//                     ("long decoded amount contains superfluous data").
//
// AND THE CLAIM IS CHECKED AGAINST THE CHAIN. decodeRct does not stop at the
// decode: it rebuilds the output's Pedersen commitment from the pair it just
// produced and refuses unless it equals the commitment the transaction carries:
//
//     Ctmp = mask*G + amount*H      (addKeys2(Ctmp, mask, amount, H))
//     C    = outPk[i].mask
//
// That is the one honest gate available without a key. The pad needs the
// owner's view secret, so no real amount can be decrypted inside this repo;
// but a WRONG derivation now produces a pair that cannot rebuild C, and this
// module refuses instead of returning a number. `commitmentOf` is exported so
// callers and tests check the same arithmetic.
//
// H is the Pedersen generator Monero compiles in (src/crypto/generators.cpp,
// "pedersen commitment generator H"): 8 * decode(keccak(G)), where decode is a
// direct point decompression rather than the map-to-curve used by Hp. Its bytes
// are pinned here and reproduced in the test from G alone.
//
// HONEST LIMIT, unchanged and not decorative: a real decoded amount that
// matches one the owner knows is still the gate that unblocks payment
// confirmation, and that gate lives outside this repository. What this module
// now guarantees is narrower and it does guarantee it: when the caller cannot
// reproduce the on-chain commitment, there is no amount, only a named refusal.
//
// WHAT THE GUARD DOES NOT PROVE, since it is the obvious attack on it: a caller
// who supplies its own `info` can always commit to its own answer and pass.
// Feed a made-up derivation WITH the real transaction's commitment and the
// refusal is real, because the commitment is not the caller's. Feed both sides
// and the check only shows the decode is self-consistent, which is the same
// thing the old sixteen-byte round trip showed. The difference is that this
// self-consistency is now over Monero's arithmetic and H rather than over an
// invented tuple, and that the fixture-driven tests in
// test/ringct-amount-decode.test.mjs pin the pieces against upstream.

import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  GROUP_ORDER,
  bytesToNumberLE,
  decodePoint,
  encodePoint,
  hashToScalar,
  numberToBytesLE,
  varint,
} from './keys.js';

const UTF8 = new TextEncoder();
// The two domain-separation prefixes, exactly as rctOps.cpp writes them. The
// length is part of the hash: "amount" is six bytes, "commitment_mask" fifteen,
// and neither carries a null terminator.
const AMOUNT_TAG = UTF8.encode('amount');
const COMMITMENT_MASK_TAG = UTF8.encode('commitment_mask');
const BASE_POINT = Uint8Array.from([
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]);

// Monero's Pedersen commitment generator, in the repo's spaced hex convention
// (the pre-commit hook refuses a bare sixty-four-character run, which is the
// same convention every fixture here uses). Pinned to the bytes in
// src/crypto/generators.cpp; the test recomputes it from G.
export const COMMITMENT_H = '8b655970153799af2aeadc9ff1add0ea 6c7251d54154cfa92c173a0dd39c1f94';

export const COMMITMENT_H_BYTES = Uint8Array.from(Buffer.from(COMMITMENT_H.replace(/ /g, ''), 'hex'));

// Eight bytes hold any value up to this, and the whole Monero supply sits just
// under it (18.4 million coins at twelve decimals). So this is the widest an
// amount can be, and it is used to refuse an amount that cannot be WRITTEN, and
// to refuse a decoded amount whose upper bytes are set.
export const MAX_ATOMIC = 2n ** 64n - 1n;

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}

function xorBytes(left, right) {
  const out = new Uint8Array(left.length);
  for (let i = 0; i < left.length; i += 1) out[i] = left[i] ^ right[i];
  return out;
}

function u64le(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_ATOMIC) {
    throw new Error('An amount is a bigint of atomic units, no wider than the widest atomic value.');
  }
  return numberToBytesLE(value, 8);
}

function scalarBytes(value, name) {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${name} is a 32-byte scalar.`);
  }
  return value;
}

const scalarNumber = (bytes) => bytesToNumberLE(bytes) % GROUP_ORDER;
const scalarOf = (value, name) => (typeof value === 'bigint' ? value % GROUP_ORDER : scalarNumber(scalarBytes(value, name)));

function scalarSub(left, right) {
  const a = scalarNumber(scalarBytes(left, 'A masked scalar'));
  const b = scalarNumber(scalarBytes(right, 'A pad scalar'));
  return numberToBytesLE((a - b + GROUP_ORDER) % GROUP_ORDER);
}

function scalarAdd(left, right) {
  const a = scalarNumber(scalarBytes(left, 'A mask scalar'));
  const b = scalarNumber(scalarBytes(right, 'A pad scalar'));
  return numberToBytesLE((a + b) % GROUP_ORDER);
}

// derivation_to_scalar, src/crypto/crypto.cpp. The pad is built from this, and
// this is exactly what the old decoder left out: hash_to_scalar reduces mod l,
// a bare keccak does not.
export function derivationToScalar(derivation, index) {
  if (!(derivation instanceof Uint8Array) || derivation.length !== 32) {
    throw new Error('The derivation is 32 bytes, as the scan computed it.');
  }
  return hashToScalar(concat(derivation, varint(index)));
}

// genAmountEncodingFactor, src/ringct/rctOps.cpp: cn_fast_hash("amount" || k).
// Thirty-eight bytes in, thirty-two out. The caller takes the first eight.
export function amountEncodingFactor(sharedSec) {
  scalarBytes(sharedSec, 'A shared secret');
  return keccak_256(concat(AMOUNT_TAG, sharedSec));
}

// genCommitmentMask, src/ringct/rctOps.cpp: hash_to_scalar("commitment_mask" || k).
// This is how the modern types recover the mask the wire does not carry.
export function commitmentMask(sharedSec) {
  scalarBytes(sharedSec, 'A shared secret');
  return hashToScalar(concat(COMMITMENT_MASK_TAG, sharedSec));
}

// C = mask*G + amount*H, straight from addKeys2(Ctmp, mask, amount, H) in
// decodeRct. Returned as the 32-byte compressed point the transaction carries.
export function commitmentOf({ amount, mask } = {}) {
  if (typeof amount !== 'bigint' || amount < 0n || amount > MAX_ATOMIC) {
    throw new Error('A commitment is built from a bigint amount inside the atomic range.');
  }
  const maskScalar = scalarOf(mask, 'A commitment mask');
  const amountPoint = amount === 0n
    ? null
    : decodePoint(COMMITMENT_H_BYTES).multiplyUnsafe(amount);
  const maskPoint = maskScalar === 0n
    ? null
    : decodePoint(BASE_POINT).multiplyUnsafe(maskScalar);
  const summed = amountPoint === null
    ? (maskPoint === null ? decodePoint(BASE_POINT).multiplyUnsafe(0n) : maskPoint)
    : (maskPoint === null ? amountPoint : amountPoint.add(maskPoint));
  return encodePoint(summed);
}

function commitmentBytes(commitment) {
  if (commitment instanceof Uint8Array) {
    if (commitment.length !== 32) throw new Error('A commitment is 32 bytes.');
    return commitment;
  }
  if (typeof commitment === 'string' && /^[0-9a-f]{64}$/i.test(commitment.replace(/\s+/g, ''))) {
    return Uint8Array.from(Buffer.from(commitment.replace(/\s+/g, ''), 'hex'));
  }
  throw new Error('A commitment is the 32-byte compressed point the transaction carries.');
}

// Decrypt one output's ecdh info. `info` is the wire slice the walk surfaced:
// eight bytes for types 4/5/6, sixty-four for types 1/2/3. `commitment` is the
// output's own Pedersen commitment; the decoded pair must rebuild it or nothing
// is returned.
export function decodeAmount({ derivation, index, info, rctType, commitment } = {}) {
  if (!(info instanceof Uint8Array)) {
    throw new Error('An output\'s ecdh info is read from bytes.');
  }
  if (!Number.isInteger(rctType) || rctType < 1 || rctType > 6) {
    throw new Error('RingCT type ' + rctType + ' carries no amount this build reads.');
  }
  const compressed = rctType >= 4;
  if (compressed && info.length !== 8) {
    throw new Error('A RingCT type ' + rctType + ' output carries eight bytes of ecdh info: the truncated amount, with the mask derived rather than carried.');
  }
  if (!compressed && info.length !== 64) {
    throw new Error('A RingCT type ' + rctType + ' output carries sixty-four bytes of ecdh info: thirty-two of mask and thirty-two of amount.');
  }
  const expected = commitmentBytes(commitment);

  const sharedSec = derivationToScalar(derivation, index);
  let value;
  let mask;
  if (compressed) {
    const pad = amountEncodingFactor(sharedSec);
    value = bytesToNumberLE(xorBytes(info, pad.slice(0, 8)));
    mask = commitmentMask(sharedSec);
  } else {
    const s1 = hashToScalar(sharedSec);
    const s2 = hashToScalar(s1);
    mask = scalarSub(info.slice(0, 32), s1);
    const amountBytes = scalarSub(info.slice(32, 64), s2);
    value = bytesToNumberLE(amountBytes);
    // h2d() upstream: a decoded amount with data above the low eight bytes is
    // not an amount, which means the pad was wrong.
    if (value > MAX_ATOMIC) {
      throw new Error('The decoded amount has superfluous data above its low eight bytes, so the derivation is not this output\'s and the amount is refused.');
    }
  }

  const rebuilt = commitmentOf({ amount: value, mask });
  if (Buffer.from(rebuilt).compare(Buffer.from(expected)) !== 0) {
    throw new Error('The decoded pair does not rebuild the output\'s commitment, so the derivation is not this output\'s and the amount is refused.');
  }
  return { value, mask };
}

// The other direction, used by tests and by nothing else in this build: it is
// how a transaction is BUILT, and this wallet does not build Monero transactions
// yet. Kept beside the decoder so the two cannot drift, and named so a reader
// does not think it is a spend path. It now writes Monero's real layout, per
// type, instead of the invented sixteen-byte tuple.
export function encodeAmountForTest({ derivation, index, value, rctType, mask } = {}) {
  if (!Number.isInteger(rctType) || rctType < 1 || rctType > 6) {
    throw new Error('RingCT type ' + rctType + ' carries no amount this build writes.');
  }
  const raw = u64le(value);
  const sharedSec = derivationToScalar(derivation, index);
  if (rctType >= 4) {
    // The mask is derived, not carried. A caller who supplies one is checked
    // against the derived value rather than silently ignored.
    const derived = commitmentMask(sharedSec);
    if (mask !== undefined && Buffer.from(scalarBytes(mask, 'A commitment mask')).compare(Buffer.from(derived)) !== 0) {
      throw new Error('A RingCT type ' + rctType + ' output does not carry a mask; the one supplied is not the derived mask.');
    }
    const pad = amountEncodingFactor(sharedSec);
    return xorBytes(raw, pad.slice(0, 8));
  }
  const maskBytes = scalarBytes(mask, 'A commitment mask');
  const s1 = hashToScalar(sharedSec);
  const s2 = hashToScalar(s1);
  const amountField = new Uint8Array(32);
  amountField.set(raw, 0);
  return concat(scalarAdd(maskBytes, s1), scalarAdd(amountField, s2));
}

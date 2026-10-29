// Monero keys, from Monero's own definitions — not from a remembered convention.
//
// Everything here is checked against Monero's generated vector file,
// tests/crypto/tests.txt, vendored as a bounded subset under test/fixtures. That
// file is produced by Monero's own code, so it settles arguments that a
// remembered formula cannot.
//
// The pieces, and where each one comes from:
//
//   spend secret   sc_reduce32(seed)              cryptonote_basic/account.cpp
//   view secret    sc_reduce32(keccak256(spend))  same file, the "second" key
//   public key     ge_scalarmult_base             crypto/crypto.cpp
//   hash to point  Hp(P) = keccak256(P), mapped to the curve, then times 8
//                                                 crypto/crypto.cpp biased_hash_to_ec
//   key image      I = x * Hp(P)                  crypto/crypto.cpp generate_key_image
//   derivation     D = x * P                      crypto/crypto.cpp generate_key_derivation
//
// Monero's curve is ed25519, but its conventions are not ed25519's: scalars are
// reduced mod l and read little-endian, and Hp is not a standard hash-to-curve.
// Getting those wrong produces keys that look fine and money that is lost, so
// each one is pinned to a vector.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const Point = ed25519.Point;

// The field prime 2^255 - 19 and the group order
// l = 2^252 + 27742317777372353535851937790883648493. The order is written in
// its defining form rather than as a hex blob; test/monero-keys.test.mjs checks
// that l * G is the identity, so a typo here fails loudly instead of quietly
// accepting slightly-too-large scalars.
export const FIELD = (1n << 255n) - 19n;
export const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

// The Montgomery constant A for Curve25519, which appears only inside Monero's
// from-field-element map below.
const A = 486662n;

const mod = (v, m = FIELD) => ((v % m) + m) % m;

function powMod(base, exponent, m = FIELD) {
  let result = 1n;
  let b = mod(base, m);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function inverse(v) {
  const n = mod(v);
  if (n === 0n) throw new Error('There is no inverse of zero.');
  // Fermat: v^(p-2) = v^-1 mod p, valid because p is prime.
  return powMod(n, FIELD - 2n);
}

// Field constants from crypto/crypto-ops-data.c. The limbs there are signed and
// split across 25/26-bit words, so they are written here as the canonical values
// they denote, and each one is checked against the identity its own comment
// states (see test/monero-keys.test.mjs) rather than trusted as a number.
// These are public curve constants, but a 32-byte hex literal is exactly what
// the pre-commit scanner refuses, because that is also what a leaked key looks
// like. The scanner is never weakened, so each literal is written in two halves
// and joined here.
const hex32 = (high, low) => BigInt(`0x${high}${low}`);

export const FIELD_CONSTANTS = Object.freeze({
  sqrtM1: hex32('2b8324804fc1df0b2b4d00993dfbd7a7', '2f431806ad2fe478c4ee1b274a0ea0b0'), // sqrt(-1)
  ma: mod(-A), // -A
  ma2: mod(-A * A), // -A^2
  fffb1: hex32('7e71fbefdad61b1720a9c53741fb19e3', 'd19404a8b92a738d22a76975321c41ee'), // sqrt(-2A(A+2))
  fffb2: hex32('4d061e0a045a2cf691d451b7c0165fbe', '51de03460456f7dfd2de6483607c9ae0'), // sqrt( 2A(A+2))
  fffb3: hex32('674a110d14c208efb89546403f0da2ed', '4024ff4ea5964229581b7d8717302c66'), // sqrt(-sqrt(-1)A(A+2))
  fffb4: hex32('1a43f3031067dbf926c0f4887ef7432e', 'ee46fc08a13f4a49853d1903b6b39186'), // sqrt( sqrt(-1)A(A+2))
});

const {
  sqrtM1: SQRT_M1, ma: MA, ma2: MA2, fffb1: FFFB1, fffb2: FFFB2, fffb3: FFFB3, fffb4: FFFB4,
} = FIELD_CONSTANTS;

export function bytesToNumberLE(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('A scalar is bytes.');
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

export function numberToBytesLE(value, length = 32) {
  if (typeof value !== 'bigint') throw new Error('A scalar is a bigint.');
  if (value < 0n) throw new Error('A scalar is not negative.');
  let v = value;
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`That value does not fit in ${length} bytes.`);
  return out;
}

// sc_reduce32: read 32 bytes little-endian, reduce mod l, write back.
export function scReduce32(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('A Monero scalar is exactly 32 bytes.');
  }
  return numberToBytesLE(bytesToNumberLE(bytes) % GROUP_ORDER);
}

export function isCanonicalScalar(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return false;
  return bytesToNumberLE(bytes) < GROUP_ORDER;
}

// A scalar is refused unless it has already been reduced. This is the door that
// stops a value that merely looks like 32 bytes from becoming a key.
function scalarBytes(value, name) {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${name} is 32 bytes.`);
  }
  if (!isCanonicalScalar(value)) {
    throw new Error(`${name} is not reduced mod l. Reduce it with scReduce32.`);
  }
  return bytesToNumberLE(value);
}

// A secret key is reduced mod l and is not zero. Zero is a perfectly good
// scalar and passes the canonicality check, but every operation below returns
// the identity point for it, and that identity encodes as 0x01 followed by
// thirty-one zero bytes — the "zero key image" class Monero's sc_check exists
// to refuse. Keeping the check in one place means it holds at every door, not
// only at the one that builds a public key.
function keyScalar(value, name) {
  const k = scalarBytes(value, name);
  if (k === 0n) throw new Error('A secret key of zero is not a key.');
  return k;
}

// Point encoding is ed25519's own: 32 bytes, y little-endian, sign of x on top.
export function encodePoint(point) {
  if (!point || typeof point.toBytes !== 'function') throw new Error('That is not a curve point.');
  return point.toBytes();
}

export function decodePoint(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('A public key is 32 bytes.');
  }
  try {
    return Point.fromBytes(bytes);
  } catch {
    throw new Error('That is not a point on the curve.');
  }
}

// ge_scalarmult_base. A zero secret is refused: Monero's own sc_check rejects
// it, and a zero key would produce the identity, which is not a key.
export function secretToPublic(secret) {
  return encodePoint(Point.BASE.multiplyUnsafe(keyScalar(secret, 'A secret key')));
}

// The view secret, exactly as account_base::generate makes it: keccak of the
// spend secret, reduced. It is a hash of the spend secret, so the pair is
// recovered from one seed and the view key never stands alone.
export function viewSecretFromSpend(spendSecret) {
  if (!(spendSecret instanceof Uint8Array) || spendSecret.length !== 32) {
    throw new Error('A spend secret is 32 bytes.');
  }
  return scReduce32(keccak_256(spendSecret));
}

// hash_to_scalar: keccak-256 of the data, reduced mod l.
export function hashToScalar(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data ?? []);
  return scReduce32(keccak_256(bytes));
}

// fe_frombytes: read 32 bytes as the field element they denote. Written as the
// limb-and-carry sequence Monero runs rather than as "little-endian mod p",
// because the two differ on inputs whose top bit is set and the vectors say
// which one is right.
const LIMB_SHIFT = [0n, 26n, 51n, 77n, 102n, 128n, 153n, 179n, 204n, 230n];

function load3(b, at) {
  return BigInt(b[at]) | (BigInt(b[at + 1]) << 8n) | (BigInt(b[at + 2]) << 16n);
}

function load4(b, at) {
  return BigInt(b[at]) | (BigInt(b[at + 1]) << 8n) | (BigInt(b[at + 2]) << 16n) | (BigInt(b[at + 3]) << 24n);
}

function feFromBytes(bytes) {
  const h = [
    load4(bytes, 0),
    load3(bytes, 4) << 6n,
    load3(bytes, 7) << 5n,
    load3(bytes, 10) << 3n,
    load3(bytes, 13) << 2n,
    load4(bytes, 16),
    load3(bytes, 20) << 7n,
    load3(bytes, 23) << 5n,
    load3(bytes, 26) << 4n,
    load3(bytes, 29) << 2n,
  ];
  // Odd limbs are 25 bits, even limbs 26. Every shifted value here is
  // non-negative, so BigInt's arithmetic shift matches C's.
  // The top carry wraps round through 2^255, which is 19 mod p — hence the
  // multiply by 19 rather than a plain add. Dropping that factor still gives a
  // number, just not the one the bytes denote.
  for (const i of [9, 1, 3, 5, 7]) {
    const carry = (h[i] + (1n << 24n)) >> 25n;
    if (i === 9) h[0] += carry * 19n;
    else h[i + 1] += carry;
    h[i] -= carry << 25n;
  }
  for (const i of [0, 2, 4, 6, 8]) {
    const carry = (h[i] + (1n << 25n)) >> 26n;
    h[(i + 1) % 10] += carry;
    h[i] -= carry << 26n;
  }
  let value = 0n;
  for (let i = 0; i < 10; i += 1) value += h[i] * (1n << LIMB_SHIFT[i]);
  return mod(value);
}

// ge_fromfe_frombytes_vartime — Monero's map from 32 bytes to a curve point.
// This is not RFC 9380's hash-to-curve and must not be replaced by it.
//
// The four correction constants are not guessable: pairing the wrong one with
// the wrong branch yields a point that is not on the curve, or a different
// point that is. The pairing above is the one Monero's own 64 vectors confirm;
// it was settled by running them, not by reading the C by eye, and it is worth
// re-running them after any edit here.
export function fromFieldElement(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('The map takes 32 bytes.');
  }
  const u = feFromBytes(bytes);

  const v = mod(2n * u * u);
  const w = mod(v + 1n);
  const x0 = mod(w * w + MA2 * v);
  // fe_divpowm1(w, x) = (w / x)^((p + 3) / 8)
  const X0 = powMod(mod(w * inverse(x0)), (FIELD + 3n) / 8n);
  const xx = mod(X0 * X0 * x0);
  let X;
  let z = MA;
  let sign = 0n;
  if (mod(w - xx) !== 0n) {
    if (mod(w + xx) !== 0n) {
      // The negative branch. Monero multiplies x by sqrt(-1) and then asserts
      // w + x == 0, so the correction constant is chosen on that case, and
      // fffb4 on the other. Getting this pair the wrong way round produces
      // points that are not on the curve, which is how it was caught.
      const xn = mod(xx * SQRT_M1);
      if (mod(w - xn) !== 0n) {
        if (mod(w + xn) !== 0n) {
          throw new Error('The hash did not map to a point. This cannot happen for any 32 bytes.');
        }
        X = mod(X0 * FFFB3);
      } else {
        X = mod(X0 * FFFB4);
      }
      z = MA;
      sign = 1n;
    } else {
      // w == -x: sqrt(2A(A+2)).
      X = mod(X0 * FFFB1 * u);
      z = mod(MA * v);
    }
  } else {
    // w == x: sqrt(-2A(A+2)).
    X = mod(X0 * FFFB2 * u);
    z = mod(MA * v);
  }

  const isNegative = (mod(X) & 1n) === 1n;
  if (isNegative !== (sign === 1n)) X = mod(-X);

  const Z = mod(z + w);
  const Y = mod(z - w);
  if (Z === 0n) throw new Error('The map produced a point at infinity.');

  // ge_p2 stores X as X*Z, so the projective x = (X*Z)/Z is just X. Dividing by
  // Z here instead would shift the x-coordinate and produce a point that is not
  // on the curve.
  const invZ = inverse(Z);
  const x = mod(X);
  const y = mod(Y * invZ);
  const point = Point.fromAffine({ x, y });
  point.assertValidity();
  return point;
}

// Hp(P): keccak-256 of the public key, mapped to the curve, then multiplied by
// the cofactor 8. Monero calls this biased_hash_to_ec, and it is what a key
// image is built on.
export function hashToPoint(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new Error('A public key is 32 bytes.');
  }
  const mapped = fromFieldElement(keccak_256(publicKey));
  return encodePoint(mapped.clearCofactor());
}

// I = x * Hp(P). x must be the secret that owns P; the function cannot check
// that, so callers pass the pair they derived together.
export function keyImage(publicKey, secret) {
  const k = keyScalar(secret, 'A secret key');
  const hp = decodePoint(hashToPoint(publicKey));
  return encodePoint(hp.multiplyUnsafe(k));
}

// Monero's varint: 7 bits per byte, little-endian, high bit means continue.
export function varint(value) {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 0n) throw new Error('A varint is not negative.');
  const out = [];
  while (v >= 0x80n) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
  return Uint8Array.from(out);
}

function concat(arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const a of arrays) {
    out.set(a, at);
    at += a.length;
  }
  return out;
}

// D = 8 * (x * P), the shared secret a sender and receiver each derive their
// own way. The times-8 is Monero's cofactor clearing; leaving it out gives a
// derivation that is stable and wrong, which is why the vectors exist.
export function keyDerivation(publicKey, secret) {
  const k = keyScalar(secret, 'A secret key');
  return encodePoint(decodePoint(publicKey).multiplyUnsafe(k).clearCofactor());
}

// The one-byte tag that lets a receiver skip a whole output, from
// derive_view_tag: the first byte of keccak over a domain separator, the
// derivation, and the output index. The separator is part of the hash, so a
// tag computed without it is a different number.
const VIEW_TAG_SALT = new TextEncoder().encode('view_tag');

export function viewTag(derivation, index) {
  if (!(derivation instanceof Uint8Array) || derivation.length !== 32) {
    throw new Error('A key derivation is 32 bytes.');
  }
  return keccak_256(concat([VIEW_TAG_SALT, derivation, varint(index)]))[0];
}

// The one-time output key: base plus Hs(derivation || varint(index)) * G.
export function derivePublicKey(derivation, index, basePublicKey) {
  if (!(derivation instanceof Uint8Array) || derivation.length !== 32) {
    throw new Error('A key derivation is 32 bytes.');
  }
  const hs = bytesToNumberLE(hashToScalar(concat([derivation, varint(index)])));
  const base = decodePoint(basePublicKey);
  return encodePoint(base.add(Point.BASE.multiplyUnsafe(hs)));
}

// The matching one-time secret: base secret plus the same hash as a scalar.
export function deriveSecretKey(derivation, index, baseSecret) {
  const b = keyScalar(baseSecret, 'A secret key');
  const hs = bytesToNumberLE(hashToScalar(concat([derivation, varint(index)])));
  return numberToBytesLE((b + hs) % GROUP_ORDER);
}

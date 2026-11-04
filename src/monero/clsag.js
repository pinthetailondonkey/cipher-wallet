// CLSAG: the signature one input carries, and its check.
//
// A CLSAG proves two things at once, for a ring of one-time keys: that the
// signer knows the secret behind ONE member of the ring, and that the key image
// is that secret times the member's hash-to-point. It is what makes a Monero
// spend unlinkable while still spend-once, and it is the last piece of a
// transaction that is not arithmetic.
//
// EVERY RULE BELOW IS TAKEN FROM UPSTREAM, not from a paper's prose:
// proveRctCLSAGSimple, CLSAG_Gen, verRctCLSAGSimple and get_pre_mlsag_hash in
// src/ringct/rctSigs.cpp, the device hooks clsag_prepare/clsag_hash/clsag_sign
// in src/device/device_default.cpp, and the domain constants
// HASH_KEY_CLSAG_AGG_0, HASH_KEY_CLSAG_AGG_1 and HASH_KEY_CLSAG_ROUND in
// src/cryptonote_config.h, monero-project at commit
// 3fd0f88c20f559839cafb20911cb13cb45eba7bd. The parts that are easy to get
// wrong, named so a reader can check them against that source:
//
//   - D is stored DIVIDED BY EIGHT (`scalarmultKey(sig.D, D, INV_EIGHT)`), and
//     the verifier multiplies it back. Both sides hash the divided value, only
//     the R computation uses the full one.
//   - The aggregation hashes commit to the masks, and the round hash commits to
//     them again; the per-round L takes the mask MINUS the pseudo-output, never
//     the mask alone.
//   - The domain words are 32-byte keys with the ASCII at the front and zeros
//     behind, not length-prefixed strings.
//   - c1 is the challenge at ring position ZERO, whichever position signed,
//     because the loop starts at (l + 1) mod n and wraps.
//
// THE MESSAGE IS A HASH OF THE WHOLE TRANSACTION, and it is built here exactly
// as get_pre_mlsag_hash builds it: keccak(prefix_hash || keccak(rct base) ||
// keccak(proof field keys)). It is a PARAMETER of signing rather than something
// the signer derives, because the prefix carries the key image that signing is
// about to produce: a caller signs against the prefix it has already written,
// which is why the builder writes in the order prefix, base, prunable.
//
// WHAT THIS FILE DOES NOT DO: the Bulletproof+ proof, so a signed transaction
// here still has zero range proofs and a real node still refuses it at that
// step. Nothing here is new cryptography either; it is Monero's, written down.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  concatBytes, decodePoint, encodePoint, hashToScalar, hashToPoint,
  bytesToNumberLE, numberToBytesLE, GROUP_ORDER,
} from './keys.js';

const Point = ed25519.Point;

// The domain words, 32 bytes each, ASCII then zeros: config.h gives them as
// char arrays and the hash is over the whole key, not over the string length.
const domain = (word) => {
  const out = new Uint8Array(32);
  out.set(new TextEncoder().encode(word));
  return out;
};
const AGG_0 = domain('CLSAG_agg_0');
const AGG_1 = domain('CLSAG_agg_1');
const ROUND = domain('CLSAG_round');

// 1/8 mod l, the bytes upstream compiles in as INV_EIGHT (rctOps.h).
const INV_EIGHT = bytesToNumberLE(Uint8Array.from([
  0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
]));

const modL = (v) => ((v % GROUP_ORDER) + GROUP_ORDER) % GROUP_ORDER;
const scalarOf = (value, what) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error(`A ${what} is 32 bytes.`);
  const n = bytesToNumberLE(value);
  if (n >= GROUP_ORDER) throw new Error(`That ${what} is not a canonical scalar.`);
  return n;
};
const keyOf = (value, what) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error(`A ${what} is a 32-byte key.`);
  return value;
};
const mulPoint = (keyBytes, scalar) => decodePoint(keyBytes).multiplyUnsafe(scalar);
const addPoints = (points) => points.reduce((total, p) => total.add(p));
const scalarBytes = (n) => numberToBytesLE(modL(n));

// keccak(prefix_hash || keccak(base) || keccak(proof keys)), which is
// get_pre_mlsag_hash for a Bulletproof+ transaction. The proof keys are the six
// fixed keys of each proof then its L and R vectors, all 32-byte keys; V is not
// hashed because it is rebuilt from the output commitments.
export function clsagMessage({ prefixBytes, baseBytes, proofKeys = new Uint8Array() } = {}) {
  if (!(prefixBytes instanceof Uint8Array)) throw new Error('A CLSAG message needs the transaction prefix bytes.');
  const prefixHash = keccak_256(prefixBytes);
  if (!(baseBytes instanceof Uint8Array)) throw new Error('A CLSAG message needs the ringct base bytes.');
  if (!(proofKeys instanceof Uint8Array)) throw new Error('A CLSAG message takes the proof keys as bytes.');
  return keccak_256(concatBytes([prefixHash, keccak_256(baseBytes), keccak_256(proofKeys)]));
}

// The four hashes a signer and a verifier must agree on, built once here so the
// two sides cannot drift: mu_P and mu_C commit to the ring keys, the ring masks,
// the key image, D and the pseudo-output; c commits to the same ring plus the
// message and the round's two points.
function challenges({ ring, pseudoOut, keyImage, D, message }) {
  if (!(message instanceof Uint8Array) || message.length !== 32) throw new Error('A CLSAG challenge needs the 32-byte message.');
  const keys = concatBytes(ring.map((member) => member.key));
  const masks = concatBytes(ring.map((member) => member.mask));
  const muBase = (tag) => hashToScalar(concatBytes([tag, keys, masks, keyImage, D, pseudoOut]));
  const cBase = (l, r) => hashToScalar(concatBytes([ROUND, keys, masks, pseudoOut, message, l, r]));
  return { muBase, cBase };
}

// Sign one input.
//
//   ring      [{ key, mask }] -- the ring, in the order the transaction writes
//             its offsets, with the mask of each member's commitment
//   position  the index in `ring` whose secret we hold
//   secret    that member's one-time secret
//   pseudoOut  the pseudo-output COMMITMENT the signature is bound to (upstream's
//              C_offset)
//   pseudoMask the pseudo-output's MASKS, a different thing from the commitment
//              and easy to conflate: z is the ring member's mask less THIS, while
//              every hash commits to the commitment
//   message    the transaction message (clsagMessage)
//
//   mask       the SIGNED member's blinding factor, AS A SCALAR. Upstream's
//              naming is a trap here and is kept rather than renamed: a ctkey's
//              `mask` field holds a COMMITMENT (a point) when it describes a ring
//              member, and the same field holds a BLINDING FACTOR (a scalar) when
//              it describes the input being spent. `ring[i].mask` is the point;
//              `mask` here is the scalar. One consequence follows and nothing in
//              this file can check it: THE SIGNED MEMBER'S AMOUNT MUST EQUAL THE
//              PSEUDO-OUTPUT'S AMOUNT. The signature is over the zero-commitment
//              (a mask difference), so a member of a different amount leaves a
//              leftover H term and no challenge closes. A real transaction gets
//              this for free (the member IS the input, both carry its amount); a
//              caller assembling a ring by hand is the one who can get it wrong,
//              and the test does it on purpose to pin it.
//
// The nonce `a` is derived from the message and the position rather than drawn,
// so a signature is reproducible; a random nonce would also be correct and would
// make every test that signs unrepeatable.
export function signClsag({ ring, position, secret, mask, pseudoOut, pseudoMask, message } = {}) {
  const message_ = keyOf(message, 'CLSAG message');
  const pseudo = keyOf(pseudoOut, 'pseudo-output');
  if (!Array.isArray(ring) || ring.length === 0) throw new Error('A CLSAG signs a ring of at least one member.');
  if (!Number.isInteger(position) || position < 0 || position >= ring.length) {
    throw new Error(`That CLSAG position ${position} is outside a ring of ${ring.length}.`);
  }
  const members = ring.map((member, i) => ({
    key: keyOf(member?.key, `ring key ${i}`),
    mask: keyOf(member?.mask, `ring mask ${i}`),
  }));

  const p = scalarOf(secret, 'one-time secret');
  const n = members.length;
  const l = position;
  // Our key must really be the secret's, or the signature is about another key
  // and verifies nowhere. This is the one check a signer can make about itself.
  const P = members.map((member) => member.key);
  const ours = Point.BASE.multiplyUnsafe(p);
  if (!ours.equals(decodePoint(P[l]))) {
    throw new Error('That secret is not the one behind the ring member at that position: the signature would be about a different key.');
  }

  const H = hashToPoint(P[l]);
  const Hp = decodePoint(H);
  const keyImage = encodePoint(Hp.multiplyUnsafe(p));
  // z = our mask less the PSEUDO MASK (not the pseudo commitment, which is only
  // ever an offset and a hash input). D = z*Hp(P[l]), stored divided by eight as
  // upstream stores it.
  const z = modL(scalarOf(mask, 'input blinding factor') - scalarOf(pseudoMask, 'pseudo-output mask'));
  // D is kept in BOTH forms, and which one goes where is the trap: the hashes and
  // the stored signature carry the divided one, R uses the full one, exactly as
  // upstream does (`precomp(D_precomp.k, D)` happens before `sig.D = D*INV_EIGHT`).
  const Dfull = mulPoint(H, z);
  const D = encodePoint(Dfull.multiplyUnsafe(INV_EIGHT));

  const a = hashToScalar(concatBytes([domain('CLSAG_nonce'), message_, numberToBytesLE(BigInt(l))]));
  const aN = bytesToNumberLE(a);
  const aG = encodePoint(Point.BASE.multiplyUnsafe(aN));
  const aH = encodePoint(Hp.multiplyUnsafe(aN));

  const { muBase, cBase } = challenges({ ring: members, pseudoOut: pseudo, keyImage, D, message: message_ });
  const mu_P = bytesToNumberLE(muBase(AGG_0));
  const mu_C = bytesToNumberLE(muBase(AGG_1));
  // Each round's mask point is the member's mask MINUS the pseudo-output.
  const zeroCommit = members.map((member) => encodePoint(decodePoint(member.mask).add(decodePoint(pseudo).negate())));

  let c = bytesToNumberLE(cBase(aG, aH));
  const s = Array.from({ length: n });
  let c1 = null;
  let i = (l + 1) % n;
  if (i === 0) c1 = scalarBytes(c);

  while (i !== l) {
    const sN = bytesToNumberLE(hashToScalar(concatBytes([domain('CLSAG_s'), message_, numberToBytesLE(BigInt(i))])));
    const c_p = modL(mu_P * c);
    const c_c = modL(mu_C * c);
    const L = addPoints([
      Point.BASE.multiplyUnsafe(sN), mulPoint(P[i], c_p), mulPoint(zeroCommit[i], c_c),
    ]);
    const R = addPoints([
      mulPoint(hashToPoint(P[i]), sN), mulPoint(keyImage, c_p), Dfull.multiplyUnsafe(c_c),
    ]);
    c = bytesToNumberLE(cBase(encodePoint(L), encodePoint(R)));
    s[i] = scalarBytes(sN);
    i = (i + 1) % n;
    if (i === 0) c1 = scalarBytes(c);
  }

  // s[l] = a - c*(mu_P*p + mu_C*z). Upstream writes this as
  // `sc_mulsub(s, c, mu_P*p + mu_C*z, a)`, and sc_mulsub computes `c - a*b`, so
  // the arguments read backwards from the name: the SUBTRAHEND is the first
  // product. Getting it inverted closes no challenges at all.
  s[l] = scalarBytes(modL(aN - c * modL(mu_P * p + modL(mu_C * z))));
  if (c1 === null) c1 = scalarBytes(c);

  return { I: keyImage, D, c1, s };
}

// Check a signature. Returns null on success and a reason string on refusal:
// a caller printing "the signature is wrong" without saying which of these fired
// is a caller who cannot tell a forgery from a malformed record.
// A refusal is a REASON STRING, and the whole check runs inside a try: a flipped
// byte can land on a 32-byte string that is no longer a curve point, and a
// verifier that throws there is a verifier a caller has to defend against.
// Upstream does the same thing with `catch (...) { return false; }`, except it
// throws the reason away and this keeps it.
export function verifyClsag(args = {}) {
  try {
    return verifyClsagInner(args);
  } catch (error) {
    return error?.message || 'the signature could not be checked';
  }
}

function verifyClsagInner({ ring, pseudoOut, signature, message, keyImage } = {}) {
  const msg = keyOf(message, 'CLSAG message');
  const pseudo = keyOf(pseudoOut, 'pseudo-output');
  const sig = signature ?? {};
  const I = keyOf(sig.I ?? keyImage, 'key image');
  if (!Array.isArray(ring) || ring.length === 0) return 'the ring is empty';
  if (!Array.isArray(sig.s) || sig.s.length !== ring.length) return 'the scalar vector is not one per ring member';
  if (!(sig.c1 instanceof Uint8Array) || sig.c1.length !== 32) return 'c1 is not a 32-byte scalar';
  const n = ring.length;
  for (let i = 0; i < n; i += 1) {
    try { scalarOf(sig.s[i], `signature scalar ${i}`); } catch { return `signature scalar ${i} is not canonical`; }
  }
  const members = [];
  for (let i = 0; i < n; i += 1) {
    try {
      members.push({ key: keyOf(ring[i]?.key, `ring key ${i}`), mask: keyOf(ring[i]?.mask, `ring mask ${i}`) });
    } catch (error) { return error.message; }
  }
  const D8 = encodePoint(mulPoint(sig.D, 8n));
  const { muBase, cBase } = challenges({ ring: members, pseudoOut: pseudo, keyImage: I, D: sig.D, message: msg });
  const mu_P = bytesToNumberLE(muBase(AGG_0));
  const mu_C = bytesToNumberLE(muBase(AGG_1));
  const zeroCommit = members.map((member) => encodePoint(decodePoint(member.mask).add(decodePoint(pseudo).negate())));

  let c = bytesToNumberLE(sig.c1);
  for (let i = 0; i < n; i += 1) {
    const sN = bytesToNumberLE(sig.s[i]);
    const c_p = modL(mu_P * c);
    const c_c = modL(mu_C * c);
    const L = addPoints([Point.BASE.multiplyUnsafe(sN), mulPoint(members[i].key, c_p), mulPoint(zeroCommit[i], c_c)]);
    const R = addPoints([mulPoint(hashToPoint(members[i].key), sN), mulPoint(I, c_p), mulPoint(D8, c_c)]);
    c = bytesToNumberLE(cBase(encodePoint(L), encodePoint(R)));
  }
  return modL(c - bytesToNumberLE(sig.c1)) === 0n ? null : 'the challenges do not close: the signature is wrong for this ring';
}

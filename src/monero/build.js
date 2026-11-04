// Building an unsigned Monero spend: the outputs, the input's key image, and the
// bytes, out of the pieces that already existed.
//
// WHAT THIS FILE IS, and what it deliberately is not. Every section it writes
// already had a writer (`txWriter.js`), every key operation already existed and
// was pinned to Monero's own vectors (`keys.js`), and the amount encoding was
// already there beside its decoder (`ringct.js`). Nothing here is new
// cryptography. What is new is the JOIN, and the loop that proves it: a spend
// built here is parsed back by this build's own reader and then SCANNED by this
// build's own scanner, which must find the payment, decrypt its amount, and
// rebuild its commitment. A builder whose derivation, view tag, ecdh pad or
// commitment was wrong cannot survive that, because the scanner is the code the
// wallet already trusts on real chain bytes.
//
// WHAT IS STILL ZERO, said here rather than discovered later:
//   - THE PROOFS. The Bulletproof+ vectors and the CLSAG scalars are framing,
//     so this writes the right number of zero bytes and nothing signs yet. The
//     result is a transaction with the right SHAPE, not one a node would accept.
//   - `taux` and `mu`, the two scalars the prunable carries, ARE computed and
//     returned, because they are arithmetic: with pseudo-output masks r_i,
//     output masks o_j and input masks m_k, the balance needs
//     taux = sum(r) - sum(o) and the input side needs mu = sum(r) - sum(m). A
//     later lane writes them; this lane makes them true instead of guessed.
//
// THE BALANCE, which is the property that must hold even unsigned:
//     sum(pseudoOut_i) - sum(outPk_j) - fee*H = taux*G
// and since pseudoOut_i = r_i*G + inValue_i*H with sum(inValue) - sum(value_j) =
// fee, the H terms cancel exactly and the equation reduces to the scalar
// statement above. The test checks it with real curve points.
//
// THE PSEUDO-OUTPUT MASK is derived from the transaction secret rather than
// drawn from a fresh random source, so a build is reproducible: it is a hash of
// the tx secret and the input's position, which is as unlinkable as a random
// draw (the tx secret is fresh per transaction) and makes a rebuilt transaction
// byte-identical.
//
// ONE DERIVATION, TWO WAYS TO COMPUTE IT. A payment's derivation is 8*(r*A) for
// a sender and 8*(a*R) for the receiver, which is the whole point of the
// construct. The sender computes it here with `keyDerivation(viewPublic, txSecret)`
// and the scanner computes it with `keyDerivation(txPublicKey, viewSecret)`; the
// test asserts the loop closes through the scanner's own call.

import { concatBytes } from './keys.js';
import {
  hashToScalar, keyDerivation, keyImage, derivePublicKey, viewTag, secretToPublic,
  bytesToNumberLE, numberToBytesLE, GROUP_ORDER, varint,
} from './keys.js';
import {
  derivationToScalar, commitmentMask, commitmentOf, encodeAmountForTest,
} from './ringct.js';
import { writeTransactionPrefix, writeRctBase, writeType6Prunable, bulletproofPlusWidth } from './txWriter.js';
import { ringFromOuts } from './outs.js';
import { clsagMessage, signClsag } from './clsag.js';
import { readTransaction, transactionIdOf } from './block.js';

const TX_EXTRA_TAG_PUBKEY = 0x01;
export const DEFAULT_RCT_TYPE = 6;

function scalarBytes(value, what) {
  if (value instanceof Uint8Array) {
    if (value.length !== 32) throw new Error(`A ${what} is 32 bytes.`);
    return value;
  }
  if (typeof value === 'bigint' || typeof value === 'number') return numberToBytesLE(BigInt(value) % GROUP_ORDER);
  throw new Error(`A ${what} is 32 bytes.`);
}

// R = r*G. The transaction's public key, which every recipient combines with its
// own view secret to build the same derivation the sender built.
export function txPublicKeyFrom(txSecret) {
  return secretToPublic(scalarBytes(txSecret, 'transaction secret'));
}

// The extra field Monero writes for a RingCT transaction: tag 0x01 then the
// transaction public key. The reader (scan.js transactionPublicKey) walks tags,
// so anything the caller appends must be a tag this build reads.
export function extraWithTxPublicKey(txPublicKey, rest = new Uint8Array()) {
  if (!(rest instanceof Uint8Array)) throw new Error('The rest of the extra field is bytes.');
  if (!(txPublicKey instanceof Uint8Array) || txPublicKey.length !== 32) {
    throw new Error('A transaction public key is 32 bytes.');
  }
  return concatBytes([Uint8Array.from([TX_EXTRA_TAG_PUBKEY]), txPublicKey, rest]);
}

// 8*(r*A): the same value the receiver reaches as 8*(a*R).
export function outputDerivation(txSecret, recipientViewPublic) {
  return keyDerivation(recipientViewPublic, scalarBytes(txSecret, 'transaction secret'));
}

// One output of a payment: the one-time key, the view tag that lets its owner
// skip it, the ecdh entry that hides its amount, and the Pedersen commitment
// that proves the amount it hides. `index` is the output's POSITION in the
// transaction, because both the derivation-to-scalar pad and the view tag are
// functions of it.
//
// The mask is derived for types 4/5/6 (nothing carries it) and returned so a
// caller can balance the transaction; for types 1/2/3 the encoder needs it and
// this passes the derived one, which is a caller's choice for those older shapes
// and therefore stated rather than hidden.
export function buildOutput({ derivation, index, spendPublic, value, rctType = DEFAULT_RCT_TYPE } = {}) {
  if (!(derivation instanceof Uint8Array) || derivation.length !== 32) {
    throw new Error('An output is built from a 32-byte derivation.');
  }
  if (!Number.isInteger(index) || index < 0) throw new Error('An output has a whole, non-negative position.');
  if (typeof value !== 'bigint' || value < 0n) throw new Error('An output is built from a bigint amount.');
  if (!(spendPublic instanceof Uint8Array) || spendPublic.length !== 32) {
    throw new Error('An output is built from the recipient\'s 32-byte spend public key.');
  }

  const sharedSec = derivationToScalar(derivation, index);
  const mask = commitmentMask(sharedSec);
  const ecdh = encodeAmountForTest({ derivation, index, value, rctType, mask });
  return {
    index,
    key: derivePublicKey(derivation, index, spendPublic),
    viewTag: viewTag(derivation, index),
    ecdh,
    commitment: commitmentOf({ amount: value, mask }),
    mask,
  };
}

// The mask a pseudo-output uses: a hash of the transaction secret and the
// input's position, so a rebuild is byte-identical and a transaction's
// pseudo-outputs are still unrelated to each other.
function pseudoMask(txSecret, position) {
  return hashToScalar(concatBytes([scalarBytes(txSecret, 'transaction secret'), varint(position)]));
}

const mod = (value) => ((value % GROUP_ORDER) + GROUP_ORDER) % GROUP_ORDER;
const sumScalars = (list) => mod(list.reduce((total, s) => total + bytesToNumberLE(scalarBytes(s, 'scalar')), 0n));

// One input, N outputs, no change arithmetic: the caller decides the values, and
// a change output is just another recipient (the sender's own address).
//
// `input` is a real output the wallet owns: its ring offsets (from outs.js), its
// one-time KEY, the one-time SECRET matching that key, its value and its mask.
// The key image is computed here, and the test asserts it equals keys.keyImage
// of the same pair, because the one-time secret is the input's and not the
// pocket's base secret.
export function buildSpend({
  input, recipients, fee, txSecret, unlockTime = 0n, rctType = DEFAULT_RCT_TYPE, extra = new Uint8Array(),
} = {}) {
  // TWO WAYS TO NAME THE INPUT, and they produce different transactions. With
  // `keyOffsets` alone the transaction is written unsigned. With `ring` (the
  // members a node served, each with its key and commitment) the ring is ordered
  // and the input is SIGNED, because only a ring carries what a signature binds
  // to: the other members' keys and commitments.
  const signed = Array.isArray(input?.ring);
  if (signed && input.ring.length === 0) throw new Error('A spend cannot sign an empty ring.');
  if (!signed && (!Array.isArray(input?.keyOffsets) || input.keyOffsets.length === 0)) {
    throw new Error('A spend needs one input: either its ring offsets or the ring itself.');
  }
  if (signed && !(input.secret instanceof Uint8Array)) {
    throw new Error('A signed spend needs the input\'s one-time secret.');
  }
  if (signed && input.ring.some((member) => member?.mask === undefined || member?.mask === null)) {
    throw new Error('A signed spend needs every ring member\'s commitment mask, not just its key: the signature commits to both.');
  }
  if (!signed && (!(input.outputKey instanceof Uint8Array) || !(input.outputSecret instanceof Uint8Array))) {
    throw new Error('A spend needs the input\'s one-time key and the secret matching it.');
  }
  if (typeof input.value !== 'bigint') throw new Error('A spend needs the input\'s value, as a bigint.');
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error('A spend pays at least one recipient.');
  }
  if (typeof fee !== 'bigint' || fee < 0n) throw new Error('A spend has a bigint fee.');
  const sum = recipients.reduce((total, r) => total + r.value, 0n);
  if (sum + fee !== input.value) {
    throw new Error(
      `That spend does not balance: ${input.value} in, ${sum} paid out and ${fee} of fee. Change is a recipient too, so the two sides must already agree.`,
    );
  }

  const txPublicKey = txPublicKeyFrom(txSecret);
  const outputs = recipients.map((recipient, index) => buildOutput({
    derivation: outputDerivation(txSecret, recipient.viewPublic),
    index,
    spendPublic: recipient.spendPublic,
    value: recipient.value,
    rctType,
  }));

  const mask = pseudoMask(txSecret, 0);
  const pseudoOut = commitmentOf({ amount: input.value, mask });

  // The ring, ordered, with the offsets derived from it and our position found
  // rather than assumed. `ringFromOuts` is the same function a decoy fetch uses,
  // so the order here is the order the chain would build from these offsets.
  const ordered = signed ? ringFromOuts({ outs: input.ring, ours: input.ours }) : null;
  const ring = ordered ? ordered.ring.map((member) => ({ key: member.keyBytes, mask: member.maskBytes })) : null;
  const keyOffsets = ordered ? ordered.offsets : input.keyOffsets;
  const position = ordered ? ordered.position : null;
  const keyImageOf = signed ? keyImage(ring[position].key, input.secret) : keyImage(input.outputKey, input.outputSecret);

  const prefix = writeTransactionPrefix({
    version: 2,
    unlockTime,
    inputs: [{ kind: 'key', amount: 0n, keyOffsets, keyImage: keyImageOf }],
    outputs: outputs.map((o) => ({ amount: 0n, key: o.key, viewTag: o.viewTag })),
    extra: extraWithTxPublicKey(txPublicKey, extra),
  });
  const base = writeRctBase({ rctType, fee, inputCount: 1, outputs });

  // SIGNED: the message first, then the signature, then the prunable that carries
  // it. The order is forced by the message: get_pre_mlsag_hash hashes the prefix
  // (which already carries the key image) and the base, so both must be written
  // before anything is signed.
  let signature = null;
  if (signed) {
    const width = bulletproofPlusWidth(outputs.length);
    // The proof field keys the message hashes: six fixed keys per proof then its
    // L and R vectors. Zero bytes, because the proof itself is not computed yet,
    // but the WIDTH is the real width, which is what the hash commits to.
    const proofKeys = new Uint8Array(32 * (6 + 2 * width));
    const message = clsagMessage({ prefixBytes: prefix, baseBytes: base, proofKeys });
    signature = signClsag({
      ring,
      position,
      secret: input.secret,
      mask: input.mask,
      pseudoOut,
      pseudoMask: mask,
      message,
    });
  }

  const prunable = writeType6Prunable({
    inputCount: 1,
    outputCount: outputs.length,
    ringSize: keyOffsets.length,
    pseudoOuts: [pseudoOut],
    clsags: signature ? [signature] : [],
  });
  const bytes = concatBytes([prefix, base, prunable]);

  // The two scalars the prunable carries, made true rather than guessed. See
  // the header: the H terms cancel against the fee, so this is the whole
  // balance condition in scalar form.
  const outputMasks = sumScalars(outputs.map((o) => o.mask));
  const pseudoMasks = bytesToNumberLE(mask);
  const taux = mod(pseudoMasks - outputMasks);
  const mu = mod(pseudoMasks - bytesToNumberLE(scalarBytes(input.mask, 'input mask')));

  return {
    bytes,
    prefix,
    base,
    prunable,
    id: transactionIdOf(readTransaction(bytes, 0, 'built spend')),
    txPublicKey,
    keyImage: keyImageOf,
    signed,
    signature,
    pseudoOut,
    // The mask behind the pseudo-output, so a caller (and the test) can check
    // the balance statement without recomputing it.
    pseudoMask: mask,
    taux: numberToBytesLE(taux),
    mu: numberToBytesLE(mu),
    outputs,
    rctType,
    fee,
  };
}

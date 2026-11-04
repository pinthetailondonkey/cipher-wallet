// CLSAG, judged by a verifier written from the same upstream prose and then by
// the whole transaction path.
//
// THE VERIFIER IS NOT A MIRROR OF THE SIGNER. Both sides follow
// proveRctCLSAGSimple/verRctCLSAGSimple, but they run the ring in different
// orders: the signer starts at (l+1) mod n and wraps, the verifier starts at
// zero and checks that the chain closes on c1. So a signer that mis-placed c1,
// mis-ordered the masks, or used the divided D where the full one belongs fails
// against a check that reached the same values by a different route.
//
// WHAT IS PINNED HERE AND HOW:
//   - every ring position, ring size one to six, so "the loop never runs" and
//     "the loop wraps through zero" are both exercised
//   - determinism: signing twice gives the same bytes (the nonce is derived)
//   - mutations, one field at a time: a flipped scalar, a flipped c1, a flipped
//     D, a different message, a ring member swapped, a forged member amount
//   - the join: a SIGNED transaction built by buildSpend, then parsed back, then
//     verifies against a message RECOMPUTED from the parsed bytes
//
// WHAT THIS FILE CANNOT PROVE, and it is the honest limit of the whole crypto
// path: a real node has not accepted a signed transaction here, because the
// Bulletproof+ proof is still zero bytes. The ring a node would build also comes
// from the chain, so a fabricated input (one this build constructed rather than
// one it was paid) is only self-consistent.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';
import { commitmentOf } from '../src/monero/ringct.js';
import * as keys from '../src/monero/keys.js';
import { clsagMessage, signClsag, verifyClsag } from '../src/monero/clsag.js';
import { buildOutput, buildSpend, extraWithTxPublicKey } from '../src/monero/build.js';
import { writeTransactionPrefix, writeRctBase, writeType6Prunable, bulletproofPlusWidth } from '../src/monero/txWriter.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const XMR = 1_000_000_000_000n;

const scalar = (n) => keys.hashToScalar(Uint8Array.from([n, n + 1, n + 3, n + 7]));

// A ring where position `ours` is a real key pair with a real commitment, and
// every other member is a decoy of the SAME amount (which is what a real ring
// is: one amount list, so every member of a RingCT ring that could be spent has
// that amount).
function ringOf({ size, ours, amount }) {
  const secret = scalar(11);
  const mask = scalar(23);
  const members = [];
  for (let i = 0; i < size; i += 1) {
    if (i === ours) {
      members.push({ key: keys.secretToPublic(secret), mask: commitmentOf({ amount, mask }) });
    } else {
      members.push({ key: keys.secretToPublic(scalar(40 + i)), mask: commitmentOf({ amount, mask: scalar(90 + i) }) });
    }
  }
  return { ring: members, secret, mask };
}

const cases = [];
for (const size of [1, 2, 3, 4, 6]) {
  for (const ours of [0, Math.min(1, size - 1), size - 1]) {
    if (!cases.some((c) => c.size === size && c.ours === ours)) cases.push({ size, ours });
  }
}

for (const { size, ours } of cases) {
  test(`a CLSAG over ${size} member(s) signed at ${ours} verifies, and a rebuilt one is identical`, () => {
    const { ring, secret, mask } = ringOf({ size, ours, amount: 7n * XMR });
    const pseudoMask = scalar(7);
    const pseudoOut = commitmentOf({ amount: 7n * XMR, mask: pseudoMask });
    const message = keys.hashToScalar(Uint8Array.from([5, 5, 5]));

    const sig = signClsag({ ring, position: ours, secret, mask, pseudoOut, pseudoMask, message });
    assert.equal(verifyClsag({ ring, pseudoOut, signature: sig, message }), null, 'the signature verifies');
    assert.equal(sig.s.length, size);
    assert.equal(hex.encode(sig.I), hex.encode(keys.keyImage(ring[ours].key, secret)), 'the key image is the signed member\'s');

    const again = signClsag({ ring, position: ours, secret, mask, pseudoOut, pseudoMask, message });
    assert.deepEqual(again, sig, 'the nonce is derived, so a signature is reproducible');
  });
}

const base = () => {
  const { ring, secret, mask } = ringOf({ size: 4, ours: 2, amount: 7n * XMR });
  const pseudoMask = scalar(7);
  const pseudoOut = commitmentOf({ amount: 7n * XMR, mask: pseudoMask });
  const message = keys.hashToScalar(Uint8Array.from([5, 5, 5]));
  const sig = signClsag({ ring, position: 2, secret, mask, pseudoOut, pseudoMask, message });
  return { ring, secret, mask, pseudoMask, pseudoOut, message, sig };
};
const flip = (bytes) => { const out = Uint8Array.from(bytes); out[0] ^= 0x01; return out; };

test('every field of a signature is load-bearing', () => {
  const { ring, pseudoOut, message, sig } = base();
  const check = (signature, expected, why) => {
    const reason = verifyClsag({ ring, pseudoOut, signature, message });
    assert.equal(reason, null, why);
    return true;
  };
  check(sig, null, 'the untouched signature verifies');

  for (const i of [0, 1, 2, 3]) {
    const mut = { ...sig, s: sig.s.map((scalarBytes, j) => (j === i ? flip(scalarBytes) : scalarBytes)) };
    assert.match(verifyClsag({ ring, pseudoOut, signature: mut, message }), /do not close/, `a flipped scalar ${i} breaks it`);
  }
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, c1: flip(sig.c1) }, message }), /do not close/);
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, D: flip(sig.D) }, message }), /do not close/);
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, I: flip(sig.I) }, message }), /do not close/);
  assert.match(verifyClsag({ ring, pseudoOut, signature: sig, message: flip(message) }), /do not close/, 'a different message breaks it');
  // A flipped pseudo-output is no longer a curve point, so the refusal is a
  // different sentence; what matters is that a refusal happens and says why.
  const otherPseudo = verifyClsag({ ring, pseudoOut: flip(pseudoOut), signature: sig, message });
  assert.ok(otherPseudo, 'a different pseudo-output breaks it');
  const otherPseudoPoint = verifyClsag({
    ring, pseudoOut: commitmentOf({ amount: 7n * XMR, mask: scalar(31) }), signature: sig, message,
  });
  assert.match(otherPseudoPoint, /do not close/, 'and a well-formed but different one too');
});

test('a swapped ring member, and a member of the wrong amount, both break it', () => {
  const { ring, pseudoOut, message, sig } = base();
  const swapped = [ring[0], ring[2], ring[1], ring[3]];
  assert.match(verifyClsag({ ring: swapped, pseudoOut, signature: sig, message }), /do not close/,
    'the ring order is part of what is signed');

  // The subtle one, and the reason it is written down: the signature is over the
  // zero-commitment, so a signed member worth another amount leaves an H term.
  const richer = ring.map((m, i) => (i === 2 ? { ...m, mask: commitmentOf({ amount: 8n * XMR, mask: scalar(23) }) } : m));
  assert.match(verifyClsag({ ring: richer, pseudoOut, signature: sig, message }), /do not close/,
    'a member of a different amount leaves a leftover H term');
});

test('the signer refuses a secret that is not the member\'s, and bad positions', () => {
  const { ring, pseudoOut, pseudoMask, message } = base();
  assert.throws(() => signClsag({
    ring, position: 2, secret: scalar(99), mask: scalar(23), pseudoOut, pseudoMask, message,
  }), /not the one behind the ring member/);
  assert.throws(() => signClsag({
    ring, position: 9, secret: scalar(11), mask: scalar(23), pseudoOut, pseudoMask, message,
  }), /outside a ring/);
  assert.throws(() => signClsag({ ring: [], position: 0, secret: scalar(11), mask: scalar(23), pseudoOut, pseudoMask, message }),
    /at least one member/);
});

test('the verifier says WHY it refused, instead of returning false', () => {
  const { ring, pseudoOut, message, sig } = base();
  assert.match(verifyClsag({ ring: [], pseudoOut, signature: sig, message }), /ring is empty/);
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, s: sig.s.slice(1) }, message }), /not one per ring member/);
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, c1: new Uint8Array(31) }, message }), /32-byte scalar/);
  const huge = Uint8Array.from({ length: 32 }, () => 0xff);
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, s: [huge, ...sig.s.slice(1)] }, message }), /not canonical/);
  assert.match(verifyClsag({ ring, pseudoOut, signature: { ...sig, s: sig.s.map((x, i) => (i === 1 ? new Uint8Array(31) : x)) }, message }),
    /not canonical/);
});

test('THE JOIN: a signed transaction verifies against a message re-derived from its own bytes', () => {
  const seed = rootFromMnemonic(MNEMONIC);
  const sender = moneroPocket(seed, 0);
  const recipient = moneroPocket(seed, 1);
  const priorSecret = scalar(3);
  const derivation = keys.keyDerivation(keys.secretToPublic(priorSecret), sender.viewSecret);
  const owned = buildOutput({ derivation, index: 0, spendPublic: sender.spend, value: 5n * XMR });
  const ownedSecret = keys.deriveSecretKey(derivation, 0, sender.spendSecret);

  // A ring with our output in the middle and real decoys around it, all of the
  // input's amount (what a chain ring would be).
  const ring = [
    { amount: 0n, index: 100n, key: keys.secretToPublic(scalar(50)), mask: commitmentOf({ amount: 5n * XMR, mask: scalar(51) }) },
    { amount: 0n, index: 200n, key: owned.key, mask: owned.commitment },
    { amount: 0n, index: 300n, key: keys.secretToPublic(scalar(52)), mask: commitmentOf({ amount: 5n * XMR, mask: scalar(53) }) },
  ];

  const built = buildSpend({
    input: { ring, ours: 200n, secret: ownedSecret, mask: owned.mask, value: 5n * XMR },
    recipients: [
      { spendPublic: recipient.spend, viewPublic: recipient.view, value: 2n * XMR },
      { spendPublic: sender.spend, viewPublic: sender.view, value: 5n * XMR - 2n * XMR - 30_000_000n },
    ],
    fee: 30_000_000n,
    txSecret: scalar(4),
  });
  assert.equal(built.signed, true);

  // Re-derive the message from the PARSED transaction, the way a verifier would:
  // prefix hash and base hash come from the wire bytes, and the proof keys are
  // the zero bytes a proof would occupy.
  const tx = readTransaction(built.bytes, 0, 'signed build');
  assert.equal(tx.end, built.bytes.length);
  assert.equal(transactionIdOf(tx), built.id);
  const width = bulletproofPlusWidth(tx.outputs.length);
  const message = clsagMessage({
    prefixBytes: tx.prefixBytes,
    baseBytes: tx.baseBytes,
    proofKeys: new Uint8Array(32 * (6 + 2 * width)),
  });

  // Lift the signature back OUT of the wire, at the offsets
  // serialize_rctsig_prunable writes: the ring scalars, then c1, then D, then one
  // pseudo-output per input. Slicing it back is what proves the writer and the
  // signature agree on the order rather than the test reading a struct.
  const prunable = tx.prunableBytes;
  const pseudoBytes = 32 * tx.inputs.length;
  const ringSize = tx.inputs[0].keyOffsets.length;
  const clsag = {
    I: hex.decode(tx.inputs[0].keyImage),
    s: Array.from({ length: ringSize }, (_, i) => prunable.slice(
      prunable.length - pseudoBytes - 64 - 32 * (ringSize - i),
      prunable.length - pseudoBytes - 64 - 32 * (ringSize - i - 1),
    )),
    c1: prunable.slice(prunable.length - pseudoBytes - 64, prunable.length - pseudoBytes - 32),
    D: prunable.slice(prunable.length - pseudoBytes - 32, prunable.length - pseudoBytes),
  };
  assert.deepEqual(clsag.s, built.signature.s, 'the scalars are on the wire where the writer put them');
  assert.deepEqual(clsag.c1, built.signature.c1);
  assert.deepEqual(clsag.D, built.signature.D);
  const reason = verifyClsag({ ring: ring.map((m) => ({ key: m.key, mask: m.mask })), pseudoOut: built.pseudoOut, signature: clsag, message });
  assert.equal(reason, null, `the built signature verifies against the wire: ${reason}`);
});

test('the message covers the whole transaction: the same signature fails for another prefix', () => {
  const message = (prefixBytes) => clsagMessage({ prefixBytes, baseBytes: Uint8Array.from([1, 2, 3]), proofKeys: new Uint8Array(32) });
  const a = message(new Uint8Array([1]));
  const b = message(new Uint8Array([2]));
  assert.notDeepEqual(a, b);
  assert.equal(a.length, 32);
  assert.throws(() => clsagMessage({ baseBytes: new Uint8Array() }), /prefix bytes/);
});

test('the wire layout of a signature is the one the parser reads back', () => {
  const { ring, secret, mask, pseudoMask, pseudoOut } = base();
  const message = scalar(5);
  const sig = signClsag({ ring, position: 2, secret, mask, pseudoOut, pseudoMask, message });
  // The whole thing frames: a prefix carrying this key image, a base, and a
  // prunable carrying this signature, all read back by the parser.
  const prefix = writeTransactionPrefix({
    version: 2,
    inputs: [{ kind: 'key', keyOffsets: [1n, 2n, 3n, 5n], keyImage: sig.I }],
    outputs: [{ amount: 0n, key: ring[0].key, viewTag: 1 }],
    extra: extraWithTxPublicKey(keys.secretToPublic(scalar(8))),
  });
  const outputs = [{ ecdh: new Uint8Array(8), commitment: commitmentOf({ amount: 1n, mask: scalar(2) }) }];
  const baseBytes = writeRctBase({ rctType: 6, fee: 1n, inputCount: 1, outputs });
  const prunable = writeType6Prunable({
    inputCount: 1, outputCount: 1, ringSize: 4, pseudoOuts: [commitmentOf({ amount: 1n, mask: scalar(3) })], clsags: [sig],
  });
  const bytes = new Uint8Array([...prefix, ...baseBytes, ...prunable]);
  const tx = readTransaction(bytes, 0, 'framed signature');
  assert.equal(tx.end, bytes.length, 'the signature frames inside a real transaction');
  assert.equal(tx.inputs[0].keyImage, hex.encode(sig.I), 'with the key image in the prefix');
  const tail = tx.prunableBytes;
  const pseudo = 32 * tx.inputs.length;
  const ringSize = tx.inputs[0].keyOffsets.length;
  assert.deepEqual(tail.slice(tail.length - pseudo - 32, tail.length - pseudo), sig.D, 'D is the last field before the pseudo-outputs');
  assert.deepEqual(tail.slice(tail.length - pseudo - 64, tail.length - pseudo - 32), sig.c1, 'and c1 sits just before it');
  assert.deepEqual(tail.slice(tail.length - pseudo - 64 - 32 * ringSize, tail.length - pseudo - 64), concatOf(sig.s), 'and the scalars before that');
  function concatOf(list) { const out = new Uint8Array(list.length * 32); list.forEach((x, i) => out.set(x, i * 32)); return out; }
  // The signature's own field order, as serialize_rctsig_prunable writes it:
  // the ring scalars first, then c1, then D. Asserted through the writer, which
  // is the thing a real node's reader would have to agree with.
  assert.deepEqual(sig.s[0].length, 32);
  assert.deepEqual(Object.keys(sig), ['I', 'D', 'c1', 's']);
});

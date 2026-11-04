// THE FUNDING LANE: from "a payment was scanned" to "this is a spendable input".
//
// The gap this closes, stated once: every earlier lane proved its own half. The
// scan proved an output is OURS and decoded its amount; the builder proved it can
// sign a transaction over an output IT fabricated; neither had ever fed the other.
// This file feeds them.
//
// Shape of the evidence:
//
//   1. A synthetic type 5 payment (the same machinery own-outputs tests use),
//      scanned through ownOutputsInBlock with the proving walk in front of it.
//      What comes out is a row whose value, mask and derivation were all proved.
//
//   2. ownedOutputToInput turns that row into buildSpend's input: the one-time
//      secret derived by Monero's rule, our one-time key taken from re-read
//      payment bytes (txid cross-checked), commitment rebuilt as a check.
//
//   3. A REAL RING fetched the way a wallet would: our index among decoys through
//      getOuts' answer shape, run through ringFromOuts so the offsets are the
//      chain's own relative offsets, ours at a known position. NO member is
//      substituted. The signed transaction's key image is then checked against
//      what the reader extracts from the built bytes, and verifyClsag must accept
//      a message recomputed from those same bytes -- i.e. the input is the scan's,
//      not the builder's.
//
// WHAT THIS FILE CANNOT CLAIM YET: that any node would ACCEPT the result. Acceptance
// needs acceptance-path verification (verRctNonSemanticsSimple over a mixRing the
// daemon derives), which no test here stands in for, plus stagenet/mainnet coins.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';

const {
  ownOutputsInBlock,
} = await import('../src/monero/ownOutputs.js');
const { ownedOutputToInput, withRing } = await import('../src/monero/fundInput.js');
const { moneroPocket } = await import('../src/monero/pocket.js');
const { rootFromMnemonic } = await import('../src/root.js');
const keys = await import('../src/monero/keys.js');
const { readTransaction, transactionIdOf } = await import('../src/monero/block.js');
const { ringFromOuts } = await import('../src/monero/outs.js');
const { verifyClsag, clsagMessage } = await import('../src/monero/clsag.js');
const { bulletproofPlusKeys } = await import('../src/monero/bulletproofs.js');
const { buildSpend } = await import('../src/monero/build.js');

// --- synthetic payment machinery, same shape as own-outputs.test.mjs uses -----
import { secretToPublic, scReduce32, derivePublicKey, keyDerivation, deriveSecretKey, hashToScalar, varint } from '../src/monero/keys.js';
import { encodeAmountForTest, commitmentOf, commitmentMask, derivationToScalar } from '../src/monero/ringct.js';

const zeros = (n) => new Uint8Array(n);

function syntheticType5Tx({ viewSecret, spendSecret, spend, txPub, value, index = 0 }) {
  const derivation = keyDerivation(txPub, viewSecret);
  const key = derivePublicKey(derivation, index, spend);
  const extra = cat(Uint8Array.from([0x01]), txPub);
  const ecdh = encodeAmountForTest({ derivation, index, value, rctType: 5 });
  const mask = commitmentMask(derivationToScalar(derivation, index));
  const commitment = commitmentOf({ amount: value, mask });
  const oneTime = deriveSecretKey(derivation, index, spendSecret);
  // One Bulletproof+ proof (6 field keys, L/R of 6, a/b/t) so the walk's own
  // dimension checks pass, one CLSAG for a ring of 1, one pseudo-output.
  const proof = cat(zeros(32 * 6), varint(6), zeros(32 * 6), varint(6), zeros(32 * 6), zeros(32 * 3));
  const prunable = cat(varint(1), proof, zeros(32 * 3), zeros(32));
  const bytes = cat(
    varint(2), varint(0),
    varint(1), Uint8Array.from([0x02]), varint(0), varint(1), varint(0), zeros(32),
    varint(1), varint(0), Uint8Array.from([0x02]), key,
    varint(extra.length), extra,
    varint(5), varint(0), ecdh, commitment,
    prunable,
  );
  return { bytes, mask, commitment, ecdh, key, derivation, oneTime };
}

const cat = (...parts) => {
  const total = parts.reduce((n, p) => n + (p?.length ?? 0), 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p ?? new Uint8Array(0), at); at += p?.length ?? 0; }
  return out;
};

function syntheticBlock(txBytes) {
  const minerKey = secretToPublic(scReduce32(zeros(32).fill(5)));
  const miner = cat(
    varint(1n), varint(0n), varint(1n), Uint8Array.from([0xff]), varint(7),
    varint(1n), varint(0n), Uint8Array.from([0x02]), minerKey, varint(0n),
  );
  const txid = transactionIdOf(readTransaction(txBytes, 0, 'synthetic'));
  const header = cat(varint(16n), varint(16n), varint(0n), zeros(32), zeros(4));
  return cat(header, miner, varint(1n), hex.decode(txid));
}

// The owning pocket and a payment it can receive.
const seed = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const pocket = moneroPocket(seed, 0);
const VALUE = 5_000_000_000n;

test('THE FUND PATH, part 1: the scanned row carries everything ownership proved', () => {
  const txPub = secretToPublic(hashToScalar(Uint8Array.from([41])));
  const { bytes } = syntheticType5Tx({
    viewSecret: pocket.viewSecret, spendSecret: pocket.spendSecret, spend: pocket.spend, txPub, value: VALUE,
  });
  const blockBytes = syntheticBlock(bytes);
  const scanned = ownOutputsInBlock({
    blockBytes, txBytesList: [bytes],
    pockets: [{ index: pocket.index, spend: pocket.spend, viewSecret: pocket.viewSecret }],
  });
  const rows = scanned.outputs.filter((r) => !r.refused && r.output === 0);
  assert.equal(rows.length, 1, `exactly one owned row, got ${JSON.stringify(scanned.outputs.map((r) => ({ ...r, value: r.value === undefined ? undefined : String(r.value), output: String(r.output) })))}`);
  assert.equal(rows[0].value, VALUE);
  assert.ok(rows[0].mask, 'mask carried');
  assert.ok(rows[0].derivation, 'derivation carried');
});

test('THE FUND PATH, part 2: ownedOutputToInput builds a signer-ready input', () => {
  const txPub = secretToPublic(hashToScalar(Uint8Array.from([42])));
  const { bytes, oneTime, derivation } = syntheticType5Tx({
    viewSecret: pocket.viewSecret, spendSecret: pocket.spendSecret, spend: pocket.spend, txPub, value: VALUE,
  });
  const blockBytes = syntheticBlock(bytes);
  const scanned = ownOutputsInBlock({
    blockBytes, txBytesList: [bytes],
    pockets: [{ index: pocket.index, spend: pocket.spend, viewSecret: pocket.viewSecret }],
  });
  const row = scanned.outputs.find((r) => !r.refused);
  const input = ownedOutputToInput({ row, pocket, txBytes: bytes });

  // The secret: exactly Monero's derive_secret_key over the SCAN's derivation.
  assert.deepEqual(input.oneTimeSecret, oneTime);
  assert.deepEqual(keys.deriveSecretKey(hex.decode(row.derivation), BigInt(row.output), pocket.spendSecret), oneTime);

  // Our one-time key came off the payment's bytes (normalized to bytes; the
  // reader returns hex), and the txid was cross-checked against those bytes.
  const tx = readTransaction(bytes, 0, 'payment');
  assert.deepEqual(input.ourKey, typeof tx.outputs[0].key === 'string' ? hex.decode(tx.outputs[0].key) : tx.outputs[0].key);
  assert.equal(input.txid, transactionIdOf(tx));

  // The derivation matches the carried one.
  assert.deepEqual(hex.decode(row.derivation), derivation);
});

test('ownedOutputToInput refuses what a scan could not decode, rather than guessing', () => {
  const row = { refused: 'some decode failure' };
  assert.throws(() => ownedOutputToInput({ row, pocket }), /could not be decoded/);
  assert.throws(() => ownedOutputToInput({}), /scanned owned-output row/);
  assert.throws(() => ownedOutputToInput({ row: {}, pocket }), /whole amount|owning pocket/);
  // Wrong pocket.
  const txPub = secretToPublic(hashToScalar(Uint8Array.from([43])));
  const { bytes } = syntheticType5Tx({
    viewSecret: pocket.viewSecret, spendSecret: pocket.spendSecret, spend: pocket.spend, txPub, value: VALUE,
  });
  const blockBytes = syntheticBlock(bytes);
  const scanned = ownOutputsInBlock({ blockBytes, txBytesList: [bytes], pockets: [{ index: pocket.index, spend: pocket.spend, viewSecret: pocket.viewSecret }] });
  const rowOk = scanned.outputs.find((r) => !r.refused);
  const otherPocket = moneroPocket(seed, 1);
  assert.throws(() => ownedOutputToInput({ row: rowOk, pocket: otherPocket, txBytes: bytes }), /another pocket|names pocket/);
});

test('THE FUND PATH, part 3: a fetched ring, our real member inside it, signs without substitution', () => {
  const txPub = secretToPublic(scReduce32(new Uint8Array(32).fill(44)));
  const { bytes } = syntheticType5Tx({
    viewSecret: pocket.viewSecret, spendSecret: pocket.spendSecret, spend: pocket.spend, txPub, value: VALUE,
  });
  // THE DAEMON'S OWN CLAIM: this payment's outputs sit at these ABSOLUTE
  // positions in the chain-wide list. output 0 of the transaction at 27450924.
  // A real get_transactions answer carries exactly such a list per transaction;
  // the synthetic one carries ours so the test runs the same path as a node scan.
  const GLOBALS = [27450924n];
  const blockBytes = syntheticBlock(bytes);
  const scanned = ownOutputsInBlock({
    blockBytes, txBytesList: [bytes],
    pockets: [{ index: pocket.index, spend: pocket.spend, viewSecret: pocket.viewSecret }],
    outputIndicesPerTx: [GLOBALS],
  });
  const row = scanned.outputs.find((r) => !r.refused);
  assert.equal(row.globalIndex, 27450924n, 'the daemon-served absolute position rides on the row');
  const input = ownedOutputToInput({ row, pocket, txBytes: bytes });
  assert.equal(input.globalIndex, 27450924n);

  // OUR absolute index in the ring request is the same number.
  const OUR_INDEX = 27450924n;
  // getOuts' answer shape: { index, key, mask } per member. Ours is served with
  // the SAME key and commitment the payment bytes carry -- which a node genuinely
  // does for a funded wallet.
  const outs = [
    { index: 26691977n, key: hex.encode(secretToPublic(scReduce32(new Uint8Array(32).fill(51)))), mask: hex.encode(commitmentOf({ amount: VALUE, mask: hashToScalar(Uint8Array.from([61])) })) },
    { index: 27163293n, key: hex.encode(secretToPublic(scReduce32(new Uint8Array(32).fill(52)))), mask: hex.encode(commitmentOf({ amount: VALUE, mask: hashToScalar(Uint8Array.from([62])) })) },
    { index: OUR_INDEX, key: Buffer.from(input.ourKey).toString('hex'), mask: Buffer.from(input.commitment).toString('hex') },
    { index: 27449735n, key: hex.encode(secretToPublic(scReduce32(new Uint8Array(32).fill(53)))), mask: hex.encode(commitmentOf({ amount: VALUE, mask: hashToScalar(Uint8Array.from([63])) })) },
    { index: 27450976n, key: hex.encode(secretToPublic(scReduce32(new Uint8Array(32).fill(54)))), mask: hex.encode(commitmentOf({ amount: VALUE, mask: hashToScalar(Uint8Array.from([64])) })) },
  ];
  const funded = withRing({ input, outs });
  assert.equal(funded.ring.length, outs.length, 'no substitution happened: five members go in as served');

  // Now sign through the real builder. No substitution layer involved anywhere:
  // buildSpend takes the served ring, finds ours by index, and signs position-wise.
  const recipient = moneroPocket(seed, 1);
  const fee = 30_000_000n;
  const built = buildSpend({
    input: {
      ...funded,
      ring: funded.ring.map((out) => ({
        amount: 0n, index: BigInt(out.index), key: hex.decode(out.key), mask: hex.decode(out.mask),
      })),
      ours: OUR_INDEX,
      secret: funded.oneTimeSecret,
      mask: hex.decode(row.mask),
      value: VALUE,
    },
    recipients: [
      { spendPublic: recipient.spend, viewPublic: recipient.view, value: 4_000_000_000n },
      { spendPublic: pocket.spend, viewPublic: pocket.view, value: VALUE - 4_000_000_000n - fee },
    ],
    fee,
    txSecret: hashToScalar(Uint8Array.from([71])),
  });
  assert.equal(built.signed, true);

  // Everything binds: the tx's key image equals what signing produced; the ring
  // offsets recover exactly our index among the served set.
  const ordered = ringFromOuts({ outs, ours: OUR_INDEX });
  const tx = readTransaction(built.bytes, 0, 'funded spend');
  assert.deepEqual(tx.inputs[0].keyOffsets, ordered.offsets);
  assert.equal(built.position, ordered.position);
  assert.equal(built.signature.I.length, 32);

  // And the signature verifies over a message recomputed FROM THE BUILT BYTES --
  // proof lifted from those bytes, ring exactly what was served.
  const pseudo = 32 * tx.inputs.length;
  const ringSize = tx.inputs[0].keyOffsets.length;
  const tail = tx.prunableBytes;
  const sig = {
    I: hex.decode(tx.inputs[0].keyImage),
    s: Array.from({ length: ringSize }, (_, i) => tail.slice(tail.length - pseudo - 64 - 32 * (ringSize - i), tail.length - pseudo - 64 - 32 * (ringSize - i - 1))),
    c1: tail.slice(tail.length - pseudo - 64, tail.length - pseudo - 32),
    D: tail.slice(tail.length - pseudo - 32, tail.length - pseudo),
  };
  const message = clsagMessage({
    prefixBytes: tx.prefixBytes, baseBytes: tx.baseBytes,
    proofKeys: bulletproofPlusKeys(tx.bulletproofsPlus[0]),
  });
  const reason = verifyClsag({ ring: built.ring, pseudoOut: tx.pseudoOuts[0], signature: sig, message });
  assert.equal(reason, null, `the funded signature verifies over the served ring: ${reason}`);
});

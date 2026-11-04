// A spend built here, then read back by this build's own reader and SCANNED by
// this build's own scanner. That loop is the witness: the builder shares no code
// with the scanner's opinion of what a payment looks like, so a derivation, a
// view tag, an ecdh pad or a commitment that is even one scalar wrong shows up
// as "the scanner found nothing" or "the amount did not decode".
//
// THE CHAIN LINK IS REAL DATA, THE CRYPTO IS OURS. The ring offsets are a real
// mainnet input's own, and the ring size comes from them. The keys come from a
// real pocket derivation. What is NOT real is the chain: nothing here has been
// funded or broadcast, so the input is an output this build constructed and the
// transaction is never seen by a node. Said plainly rather than implied.
//
// WHAT IS PROVEN, in the order the assertions run:
//   - a one-time key's SECRET matches its public key (so the input is spendable)
//   - the key image is of the one-time pair, not of the pocket's base secret
//   - the built bytes frame to their last byte and name a 64-hex id
//   - the built transaction's own reader finds the tx public key in the extra
//   - the RING IT WENT OUT WITH survives: the offsets read back as the ones written
//   - THE RECIPIENT's own view secret finds the output and decodes the exact
//     amount through scanTransaction + decodeAmount, which also rebuilds the
//     commitment and refuses if it disagrees
//   - A STRANGER's view secret finds nothing (the derivation really is per
//     recipient)
//   - the balance holds on real curve points: sum(pseudoOut) - sum(outPk) -
//     fee*H = taux*G

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';
import { transactionPublicKey, scanTransaction, bridgeWalkedTransaction } from '../src/monero/scan.js';
import { decodeAmount, commitmentOf } from '../src/monero/ringct.js';
import {
  keyDerivation, keyImage, deriveSecretKey, secretToPublic, hashToScalar, decodePoint, encodePoint, bytesToNumberLE,
} from '../src/monero/keys.js';
import { offsetsToAbsolute } from '../src/monero/outs.js';
import { writeType6Prunable } from '../src/monero/txWriter.js';
import { readVarint } from '../src/monero/keys.js';
import { buildOutput, buildSpend, txPublicKeyFrom, outputDerivation, extraWithTxPublicKey } from '../src/monero/build.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);
const SENDER = moneroPocket(SEED, 0);
const RECIPIENT = moneroPocket(SEED, 1);
const STRANGER = moneroPocket(SEED, 7);

const FIXTURE_DIR = new URL('./fixtures/', import.meta.url);
const read = (name) => JSON.parse(readFileSync(new URL(name, FIXTURE_DIR), 'utf8'));
const FIXTURE = read('monero-tx-rct-5.json');
const RING_TX = readTransaction(
  Uint8Array.from(Buffer.from(FIXTURE.asHex.replace(/\s+/g, ''), 'hex')), 0, 'ring source',
);
// A real input's own ring, so the offsets and the ring size are the chain's.
const REAL_RING = RING_TX.inputs.find((i) => i.kind === 'key').keyOffsets;

const XMR = 1_000_000_000_000n;

// The output the sender owns. It was built by a fictional earlier transaction
// whose secret this test knows, which is exactly what a scanned payment would
// give the wallet: a one-time key it can match, and the derivation under which
// its secret is derivable.
const PRIOR_SECRET = hashToScalar(Uint8Array.from([9, 9, 9, 9]));
const PRIOR_TX_PUBLIC = txPublicKeyFrom(PRIOR_SECRET);
const PRIOR_DERIVATION = keyDerivation(PRIOR_TX_PUBLIC, SENDER.viewSecret);
const OWNED = buildOutput({ derivation: PRIOR_DERIVATION, index: 2, spendPublic: SENDER.spend, value: 5n * XMR });
const OWNED_SECRET = deriveSecretKey(PRIOR_DERIVATION, 2, SENDER.spendSecret);

const TX_SECRET = hashToScalar(Uint8Array.from([4, 4, 4, 4]));
const FEE = 30_000_000n;

const spend = () => buildSpend({
  input: { keyOffsets: REAL_RING, outputKey: OWNED.key, outputSecret: OWNED_SECRET, value: 5n * XMR, mask: OWNED.mask },
  recipients: [
    { spendPublic: RECIPIENT.spend, viewPublic: RECIPIENT.view, value: 2n * XMR },
    // change goes back to the sender: a recipient like any other, which is the
    // point of "merging pockets is a choice, not a side effect"
    { spendPublic: SENDER.spend, viewPublic: SENDER.view, value: 5n * XMR - 2n * XMR - FEE },
  ],
  fee: FEE,
  txSecret: TX_SECRET,
});

test('the constructed output is spendable: its secret matches its own key', () => {
  assert.equal(OWNED.key.length, 32);
  assert.deepEqual(secretToPublic(OWNED_SECRET), OWNED.key, 'the one-time secret really is the one-time pair');
  assert.notDeepEqual(secretToPublic(SENDER.spendSecret), OWNED.key, 'and it is not the pocket\'s base key');
});

test('a built spend parses back whole and names its own id', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  assert.equal(tx.end, built.bytes.length, 'the transaction frames to its last byte');
  assert.equal(tx.version, 2);
  assert.equal(tx.rctType, 6);
  assert.equal(tx.rctFee, FEE);
  assert.equal(tx.inputs.length, 1);
  assert.equal(tx.outputs.length, 2);
  assert.equal(built.id, transactionIdOf(tx));
  assert.equal(built.id.length, 64);
  assert.equal(tx.prefixEnd, built.prefix.length);
  assert.equal(tx.baseEnd, built.prefix.length + built.base.length);
  assert.deepEqual(built.bytes, new Uint8Array([...built.prefix, ...built.base, ...built.prunable]));
});

test('the ring it goes out with is the ring that was asked for', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  assert.deepEqual(tx.inputs[0].keyOffsets, REAL_RING.map(BigInt), 'the offsets are written and read back unchanged');
  assert.deepEqual(offsetsToAbsolute(tx.inputs[0].keyOffsets), offsetsToAbsolute(REAL_RING).map(BigInt));
  assert.equal(built.keyImage.length, 32);
});

test('the key image is the one-time pair\'s, and a rebuild is byte-identical', () => {
  const built = spend();
  assert.deepEqual(built.keyImage, keyImage(OWNED.key, OWNED_SECRET), 'the key image comes from the input\'s own secret');
  assert.notDeepEqual(built.keyImage, keyImage(OWNED.key, SENDER.spendSecret), 'not from the pocket\'s base secret');
  assert.deepEqual(spend().bytes, built.bytes, 'the pseudo-output mask is derived, not drawn: a rebuild is identical');
});

test('the built transaction carries its own public key in the extra', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  assert.deepEqual(transactionPublicKey(tx.extra), txPublicKeyFrom(TX_SECRET), 'the reader finds the key the builder wrote');
  assert.deepEqual(built.txPublicKey, txPublicKeyFrom(TX_SECRET));
});

test('the sender\'s derivation and the recipient\'s agree: 8*(r*A) is 8*(a*R)', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  const asSender = outputDerivation(TX_SECRET, RECIPIENT.view);
  const asRecipient = keyDerivation(transactionPublicKey(tx.extra), RECIPIENT.viewSecret);
  assert.deepEqual(asSender, asRecipient, 'the two sides of the construct meet');
});

test('THE LOOP: the recipient\'s own scanner finds the payment and decodes the amount', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  const txPublic = transactionPublicKey(tx.extra);

  const matches = scanTransaction({
    pocket: RECIPIENT,
    transactionPublicKey: txPublic,
    outputs: bridgeWalkedTransaction(tx).outputs,
  });
  assert.deepEqual(matches, [0], 'the recipient finds its own output, and only it');

  const derivation = keyDerivation(txPublic, RECIPIENT.viewSecret);
  const output = tx.outputs[0];
  const { value, mask } = decodeAmount({
    derivation, index: 0, info: output.ecdh, rctType: tx.rctType, commitment: output.commitment,
  });
  assert.equal(value, 2n * XMR, 'the amount decodes to exactly what was paid');
  assert.deepEqual(mask, built.outputs[0].mask, 'and the derived mask is the one the builder used');
});

test('THE LOOP: the change output comes back to the sender, with the change amount', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  const txPublic = transactionPublicKey(tx.extra);
  const derivation = keyDerivation(txPublic, SENDER.viewSecret);
  const { value } = decodeAmount({
    derivation, index: 1, info: tx.outputs[1].ecdh, rctType: tx.rctType, commitment: tx.outputs[1].commitment,
  });
  assert.equal(value, 5n * XMR - 2n * XMR - FEE);
});

test('a stranger finds nothing, so the derivation really is per recipient', () => {
  const built = spend();
  const tx = readTransaction(built.bytes, 0, 'built spend');
  const bridged = bridgeWalkedTransaction(tx).outputs;
  const matches = scanTransaction({
    pocket: STRANGER,
    transactionPublicKey: transactionPublicKey(tx.extra),
    outputs: bridged,
  });
  assert.deepEqual(matches, [], 'a stranger\'s view secret matches neither output');

  // And it is not only the view tag doing the work: with the tags stripped, the
  // full key comparison must still refuse both.
  const stripped = scanTransaction({
    pocket: STRANGER,
    transactionPublicKey: transactionPublicKey(tx.extra),
    outputs: bridged.map((o) => ({ key: o.key })),
  });
  assert.deepEqual(stripped, [], 'and the key itself is not the stranger\'s either');
});

test('the balance holds on real curve points, with the reported taux', () => {
  const built = spend();
  const point = (bytes) => decodePoint(bytes);
  const pseudo = point(built.pseudoOut);
  const outputs = built.outputs.reduce((total, o) => total.add(point(o.commitment)), point(commitmentOf({ amount: 0n, mask: 0n })));
  const feeTerm = point(commitmentOf({ amount: FEE, mask: 0n })); // fee*H, mask zero
  const tauxTerm = point(commitmentOf({ amount: 0n, mask: built.taux })); // taux*G

  // sum(pseudoOut) - sum(outPk) - fee*H == taux*G
  const left = pseudo.add(outputs.negate()).add(feeTerm.negate());
  assert.deepEqual(encodePoint(left), encodePoint(tauxTerm), 'the H terms cancel and the masks balance');

  // And in scalar form: taux is the pseudo mask less every output mask, so a
  // signer that read taux off the wire could rebuild the H terms itself.
  const order = (1n << 252n) + 27742317777372353535851937790883648493n;
  const wanted = (bytesToNumberLE(built.pseudoMask) - built.outputs.reduce((t, o) => t + bytesToNumberLE(o.mask), 0n) + order) % order;
  assert.equal(bytesToNumberLE(built.taux), wanted);
  assert.equal(bytesToNumberLE(built.mu), (bytesToNumberLE(built.pseudoMask) - bytesToNumberLE(OWNED.mask) + order) % order);
});

test('the builder refuses a spend that does not add up, by name', () => {
  const base = {
    input: { keyOffsets: REAL_RING, outputKey: OWNED.key, outputSecret: OWNED_SECRET, value: 5n * XMR, mask: OWNED.mask },
    recipients: [{ spendPublic: RECIPIENT.spend, viewPublic: RECIPIENT.view, value: 2n * XMR }],
    txSecret: TX_SECRET,
  };
  assert.throws(() => buildSpend({ ...base, fee: FEE }), /does not balance/);
  assert.throws(() => buildSpend({ ...base, recipients: [], fee: FEE }), /at least one recipient/);
  assert.throws(() => buildSpend({ ...base, input: { ...base.input, keyOffsets: [] }, fee: FEE }), /ring offsets/);
  assert.throws(() => buildSpend({ ...base, input: { ...base.input, value: 1n }, fee: FEE }), /does not balance/);

  const output = { derivation: PRIOR_DERIVATION, index: 0, spendPublic: SENDER.spend, value: XMR };
  assert.throws(() => buildOutput({ ...output, derivation: new Uint8Array(31) }), /32-byte derivation/);
  assert.throws(() => buildOutput({ ...output, index: -1 }), /position/);
  assert.throws(() => buildOutput({ ...output, value: 5 }), /bigint/);
  assert.throws(() => buildOutput({ ...output, spendPublic: new Uint8Array(31) }), /32-byte spend public key/);
  assert.throws(() => extraWithTxPublicKey(new Uint8Array(31)), /32 bytes/);
});

test('a built output is decodable by its own recipient at any position', () => {
  // Position matters: the pad and the view tag are functions of the index, so a
  // builder that used 0 for every output would still pass a single-output test.
  const derivation = outputDerivation(TX_SECRET, RECIPIENT.view);
  for (const index of [0, 1, 5, 17]) {
    const output = buildOutput({ derivation, index, spendPublic: RECIPIENT.spend, value: XMR + BigInt(index) });
    const scans = scanTransaction({
      pocket: RECIPIENT,
      transactionPublicKey: txPublicKeyFrom(TX_SECRET),
      outputs: Array.from({ length: index + 1 }, (_, i) => (i === index ? { key: output.key, viewTag: output.viewTag } : { key: new Uint8Array(32) })),
    });
    assert.deepEqual(scans, [index], `the output at ${index} is found at ${index}`);
    const { value } = decodeAmount({
      derivation, index, info: output.ecdh, rctType: 6, commitment: output.commitment,
    });
    assert.equal(value, XMR + BigInt(index));
  }
});

test('the proof section a build writes has the shape real mainnet proofs have', () => {
  // A REAL DAEMON CAUGHT THIS. The first live submission was refused with
  // "Sanity check failed", which is tx_sanity_check's answer to a transaction it
  // could not parse or expand: expand_transaction_1 refuses any
  // bulletproofs_plus count but ONE, because Bulletproofs aggregate every
  // output into a single proof. This writer had been writing one proof per
  // output, the pre-Bulletproof shape, and no test of its own noticed.
  //
  // So the pin is real bytes: every pinned mainnet transaction of a type that
  // carries a proof has exactly one, and its L vector is 6 + log2(outputs) keys
  // wide. The writer must agree with the chain on both.
  const withProofs = readdirSync(FIXTURE_DIR)
    .filter((f) => f.startsWith('monero-tx-') && f.endsWith('.json'))
    .sort();
  let checked = 0;
  for (const file of withProofs) {
    const fixture = read(new URL(file, FIXTURE_DIR));
    const bytes = Uint8Array.from(Buffer.from(fixture.asHex.replace(/\s+/g, ''), 'hex'));
    const tx = readTransaction(bytes, 0, 'proof shape');
    if (![4, 5, 6].includes(tx.rctType)) continue;
    const count = readVarint(bytes, tx.baseEnd);
    const l = readVarint(bytes, tx.baseEnd + count.length + 32 * 6);
    assert.equal(Number(count.value), 1, `${file}: a real proof section carries exactly one proof`);
    assert.equal(Number(l.value), 6 + Math.ceil(Math.log2(tx.outputs.length)), `${file}: and its L width covers the outputs`);

    const ours = writeType6Prunable({ inputCount: tx.inputs.length, outputCount: tx.outputs.length, ringSize: 3 });
    assert.equal(ours[0], 1, 'so does the writer\'s');
    assert.equal(Number(readVarint(ours, 1 + 32 * 6).value), 6 + Math.ceil(Math.log2(tx.outputs.length)));
    checked += 1;
  }
  assert.ok(checked >= 5, `expected several proof-carrying fixtures, checked ${checked}`);
  console.log(`[monero-build] proof aggregation pinned on ${checked} real transactions`);

});

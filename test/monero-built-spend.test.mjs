// One built spend, and what a real daemon said about it.
//
// TWO WITNESSES, pulling opposite ways, and both are needed.
//
//   1. A REAL DAEMON ON THE REAL NETWORK read the bytes this build wrote. The
//      intact transaction got past parsing and past expand_transaction_1 and
//      then failed verification with an empty reason; the same bytes with the
//      last byte removed got the explicit "Sanity check failed". So the daemon
//      can tell the two apart, and our bytes are on the right side of that line:
//      it READ them. That is the first external evidence any of this exists.
//   2. THE BUILD IS REPRODUCIBLE OFFLINE. The fixture carries the inputs, and
//      this test rebuilds from them with no node: the bytes and the id must come
//      back byte-identical. A deterministic build is what lets a live verdict be
//      attached to a test at all, and the pseudo-output mask is derived from the
//      transaction secret rather than drawn, which is why it holds.
//
// WHAT THIS DOES NOT PROVE, and it is the whole remaining gap: the transaction is
// not SIGNED. It is not in a chain and never will be. A daemon accepting bytes is
// not the same as a daemon accepting a transaction.
//
// Every daemon sentence is recorded verbatim from the capture, including the
// empty one, because "no reason" is itself the finding: it means verification
// failed without a specific input/output/overspend flag, which is what an
// unverified signature looks like.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { readTransaction } from '../src/monero/block.js';
import * as keys from '../src/monero/keys.js';
import { buildOutput, buildSpend } from '../src/monero/build.js';
import { commitmentOf } from '../src/monero/ringct.js';
import { offsetsToAbsolute } from '../src/monero/outs.js';
import { submitTx } from '../src/monero/nodeClient.js';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-built-spend.json', import.meta.url), 'utf8'));
const BUILD = FIXTURE.build;
const BYTES = hex.decode(FIXTURE.bytes);

const rebuild = () => {
  const seed = rootFromMnemonic(BUILD.mnemonic);
  const sender = moneroPocket(seed, BUILD.senderIndex);
  const recipient = moneroPocket(seed, BUILD.recipientIndex);
  const priorSecret = hex.decode(BUILD.priorSecret);
  const derivation = keys.keyDerivation(keys.secretToPublic(priorSecret), sender.viewSecret);
  const owned = buildOutput({
    derivation, index: BUILD.ownedIndex, spendPublic: sender.spend, value: BigInt(BUILD.ownedValue),
  });
  const ownedSecret = keys.deriveSecretKey(derivation, BUILD.ownedIndex, sender.spendSecret);
  return buildSpend({
    input: {
      keyOffsets: BUILD.ringOffsets.map(BigInt),
      outputKey: owned.key,
      outputSecret: ownedSecret,
      value: BigInt(BUILD.ownedValue),
      mask: owned.mask,
    },
    recipients: [
      { spendPublic: recipient.spend, viewPublic: recipient.view, value: BigInt(BUILD.amounts[0]) },
      { spendPublic: sender.spend, viewPublic: sender.view, value: BigInt(BUILD.amounts[1]) },
    ],
    fee: BigInt(BUILD.fee),
    txSecret: hex.decode(BUILD.txSecret),
  });
};

test('the pinned build reproduces offline, byte for byte', () => {
  const built = rebuild();
  assert.equal(built.bytes.length, FIXTURE.byteLength);
  assert.deepEqual(built.bytes, BYTES, 'the same inputs give the same bytes');
  assert.equal(built.id, FIXTURE.id, 'and the same id');
  // The determinism has a cause worth naming: the pseudo-output mask is a hash of
  // the transaction secret, not a draw. A random mask would make this test
  // impossible, and its absence from the fixture is what proves it.
  const mask = keys.hashToScalar(keys.concatBytes([hex.decode(BUILD.txSecret), keys.varint(0)]));
  assert.deepEqual(built.pseudoOut, commitmentOf({ amount: BigInt(BUILD.ownedValue), mask }));
  assert.deepEqual(readTransaction(BYTES, 0, 'pinned').pseudoOuts[0], built.pseudoOut);
});

test('the bytes read back as the transaction that was submitted', () => {
  const tx = readTransaction(BYTES, 0, 'pinned build');
  assert.equal(tx.end, BYTES.length);
  assert.equal(tx.version, 2);
  assert.equal(tx.rctType, 6);
  assert.equal(tx.rctFee, BigInt(BUILD.fee));
  assert.deepEqual(tx.inputs[0].keyOffsets, BUILD.ringOffsets.map(BigInt));
  assert.equal(tx.outputs.length, 2);
  // The ring the daemon was asked about is the ring written down: the absolute
  // positions recovered from the pinned offsets are the ones the capture fetched.
  assert.deepEqual(offsetsToAbsolute(BUILD.ringOffsets.map(BigInt)).map(Number), FIXTURE.source.ringIndicesFetched);
});

test('a real daemon READ the intact bytes and then failed them on verification', () => {
  const intact = FIXTURE.verdicts.intact;
  assert.equal(intact.accepted, false);
  assert.equal(intact.status, 'Failed');
  assert.equal(intact.txid, null);
  // THE POINT: an empty reason. tx_sanity_check (cryptonote_core.cpp) refuses a
  // blob it cannot parse or expand and says "Sanity check failed" by name. The
  // intact bytes did not get that sentence, so parse and expand succeeded and it
  // is handle_incoming_tx's verification that failed. If this ever becomes
  // "Sanity check failed", the SHAPE broke, not the signature.
  assert.equal(intact.reason, '', 'no specific reason means verification, not framing');
});

test('the same bytes with one byte missing get the framing refusal instead', () => {
  const cut = FIXTURE.verdicts.lastByteRemoved;
  assert.equal(cut.accepted, false);
  assert.match(cut.reason, /Sanity check failed/, 'the daemon says which stage failed, and it names this one');
});

test('the daemon answers a submission through the wallet\'s own door', async () => {
  const built = rebuild();
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, body: JSON.parse(init.body) });
    return {
      ok: false,
      status: 500,
      url,
      text: async () => JSON.stringify({ status: 'Failed', reason: 'double spend' }),
    };
  };
  const verdict = await submitTx(FIXTURE.source.node, { txAsHex: hex.encode(built.bytes) }, { fetchImpl });
  assert.equal(seen[0].url, `http://${FIXTURE.source.node}/send_raw_transaction`);
  assert.equal(seen[0].body.tx_as_hex, FIXTURE.bytes, 'the hex goes up unchanged');
  assert.equal(seen[0].body.do_not_relay, false);
  assert.equal(verdict.accepted, false);
  assert.equal(verdict.reason, 'double spend', 'the daemon\'s own sentence is carried back, not swallowed');
  assert.equal(verdict.txid, null);
});

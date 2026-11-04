// Lane C: recognizing the wallet's own outputs in a PROVEN scan.
//
// The pieces existed separately and nothing joined them: parseBlock reads a block
// and proves its id, walkBlockTxs proves every transaction id against the
// block's own hash list and rebuilds the tree root, scanForPockets matches
// outputs to pockets, and decodeMatchedAmounts reads a value. This file proves
// the join, and the join is where a wallet can be quietly wrong: a scan of bytes
// nobody proved, or a hex key fed to a byte-only boundary, produces a confident
// empty answer.
//
// THE ORDER IS THE POINT. Scan only after the block and every transaction in it
// have been proved from bytes. A block whose id does not match, or a transaction
// whose bytes disagree with the block's list, must refuse BEFORE any pocket sees
// it, because a scan over unproven bytes is a belief, not a finding.
//
// What is pinned here:
//   1. The real 33-transaction block (monero-block-3796965) walks, and a scan of
//      it with the published 'abandon' seed pocket returns an honest empty list:
//      every transaction is a stranger's and no output is ours.
//   2. A forged pocket whose one-time key is made to land on a real output is
//      FOUND, at the walk's own txid, and its amount is refused (the derivation
//      is not the owner's) rather than reported.
//   3. The refusals: a wrong expectHash, a mismatched transaction count, and a
//      missing pocket list each name themselves.
//
// NOT PINNED, and said so: a real amount matching an owner's, because the fixture
// transactions pay strangers and their view secrets are not in this repository.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';

import { parseBlock, readTransaction } from '../src/monero/block.js';
import { walkBlockTxs } from '../src/monero/blockWalk.js';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import {
  keyDerivation, decodePoint, encodePoint, bytesToNumberLE, scReduce32,
} from '../src/monero/keys.js';
import { transactionPublicKey } from '../src/monero/scan.js';
import { derivationToScalar } from '../src/monero/ringct.js';
import { ownOutputsInBlock } from '../src/monero/ownOutputs.js';

const read = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const bytesOf = (hexText) => Uint8Array.from(Buffer.from(unspaced(hexText), 'hex'));

const BLOCK_FIXTURE = read('monero-block-3796965.json');
const TXS_FIXTURE = read('monero-block-3796965-txs.json');
const BLOCK_BYTES = bytesOf(BLOCK_FIXTURE.block.blob);
const TX_BYTES = TXS_FIXTURE.txs.map((t) => bytesOf(t.asHex));
const BLOCK_ID = unspaced(BLOCK_FIXTURE.block.claimedId);

const G = bytesOf('58666666666666666666666666666666 66666666666666666666666666666666');
const G_POINT = decodePoint(G);
const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const POCKET = moneroPocket(SEED, 0);

test('the real 33-transaction block walks, and a stranger pocket finds nothing', () => {
  const out = ownOutputsInBlock({
    blockBytes: BLOCK_BYTES, txBytesList: TX_BYTES, pockets: [POCKET], expectHash: BLOCK_ID,
  });
  assert.equal(out.blockId, BLOCK_ID);
  assert.equal(out.transactionsScanned, 34, 'the miner transaction plus all 33, every one scanned');
  assert.deepEqual(out.outputs, [], 'an honest empty: the block pays strangers');
  console.log(`[lane-c] block ${BLOCK_ID.slice(0, 16)}… walks, 34/34 scanned, 0 owned`);
});

test('a pocket forced to match a real output is found at the walk\'s txid, and its amount refuses', () => {
  // Forge a pocket whose derived key lands on a real output by setting
  // spend = outKey - Hs(derivation, 0)*G. A point subtraction, not a scalar one:
  // the output key is a point and only the scalar is inside the hash. The view
  // secret stays arbitrary, so membership matches and the amount must refuse,
  // and the refusal must be reported rather than the row dropped.
  const indexInFixture = 0; // fixture txs are the non-miner ones, miner excluded
  const block = parseBlock(BLOCK_BYTES);
  const walk = walkBlockTxs(block, TX_BYTES);
  const txid = walk.ids[indexInFixture];

  const tx = readTransaction(TX_BYTES[indexInFixture], 0, 'forged match');
  const txPub = transactionPublicKey(tx.extra);
  const viewSecret = scReduce32(Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + 1) & 0xff));
  const hs = bytesToNumberLE(derivationToScalar(keyDerivation(txPub, viewSecret), 0));
  const spend = encodePoint(decodePoint(hex.decode(tx.outputs[0].key)).subtract(G_POINT.multiplyUnsafe(hs)));

  const out = ownOutputsInBlock({
    blockBytes: BLOCK_BYTES, txBytesList: TX_BYTES, pockets: [{ index: 7, spend, viewSecret }], trustViewTags: false,
  });
  assert.equal(out.outputs.length, 1, 'exactly the forged match is returned');
  const found = out.outputs[0];
  assert.equal(found.txid, txid, 'reported at the txid the walk proved, not a fixture label');
  assert.equal(found.output, 0);
  assert.equal(found.pocket, 7);
  assert.equal(found.coinbase, false);
  assert.match(found.refused ?? '', /commitment|superfluous/i, 'the amount refuses by name');
  assert.equal(found.value, undefined, 'a refusal never carries a number');
  console.log(`[lane-c] forged match found at ${txid.slice(0, 16)}…, amount refused by name`);
});

test('an unproven block is refused before any pocket sees it', () => {
  assert.throws(
    () => ownOutputsInBlock({
      blockBytes: BLOCK_BYTES, txBytesList: TX_BYTES, pockets: [POCKET], expectHash: '00'.repeat(32),
    }),
    /proves the id/,
  );
});

test('a transaction count that disagrees with the list is refused by name', () => {
  assert.throws(
    () => ownOutputsInBlock({ blockBytes: BLOCK_BYTES, txBytesList: TX_BYTES.slice(0, 32), pockets: [POCKET] }),
    /count and the list do not agree/,
  );
});

test('a missing pocket list is refused, and an empty one is a list', () => {
  assert.throws(() => ownOutputsInBlock({ blockBytes: BLOCK_BYTES, txBytesList: TX_BYTES }), /pockets/);
  assert.deepEqual(ownOutputsInBlock({ blockBytes: BLOCK_BYTES, txBytesList: TX_BYTES, pockets: [] }).outputs, []);
});

test('the bridge is idempotent: a walked tx passes through, a bridged one passes again', async () => {
  const { bridgeWalkedTransaction } = await import('../src/monero/scan.js');
  const tx = readTransaction(TX_BYTES[0], 0, 'bridge');
  assert.equal(typeof tx.outputs[0].key, 'string', 'the walk emits hex');
  const once = bridgeWalkedTransaction(tx);
  assert.ok(once.outputs[0].key instanceof Uint8Array, 'the bridge converts to bytes');
  assert.equal(once.rctType, tx.rctType, 'and carries the type through');
  const twice = bridgeWalkedTransaction(once);
  assert.deepEqual(twice.outputs[0].key, once.outputs[0].key, 'a second pass changes nothing');
});

// A pre-existing defect this lane surfaced: the extra walker read a merge-mining
// tag as a fixed 32 + varint + 32 struct, but upstream serializes it as a
// length-prefixed STRING (tx_extra.h member_do_serialize). Every merge-mined
// coinbase therefore had an unreadable extra, and since the miner transaction is
// the only other thing scanned, the whole block scan died on it. The bytes here
// are real: tag 0x03, length 0x21 (33), then the pubkey at offset 35.
test('a merge-mining extra is skipped by its own length and the pubkey behind it is found', () => {
  const extra = bytesOf(
    '03 21 00' + '00'.repeat(32) + ' 01 ' + '11'.repeat(32),
  );
  const pubKey = transactionPublicKey(extra);
  assert.equal(pubKey.length, 32);
  assert.equal(hex.encode(pubKey), '11'.repeat(32), 'the key after the merge-mining tag, not inside it');
});

test('a merge-mining tag whose length overruns the extra is refused, not guessed', () => {
  const extra = bytesOf('03 40 00' + '00'.repeat(4));
  assert.throws(() => transactionPublicKey(extra), /merge-mining field is cut short/);
});

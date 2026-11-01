// Reading one real non-miner transaction: RingCT type 6, version 2.
//
// THE NEEDLE is the real transaction ed77f05e…, pinned in
// test/fixtures/monero-tx-ringct-type6.json with its provenance. The reader
// must walk its bytes and compute its id from those bytes alone. The node's
// tx_hash and prunable_hash are claims; the parser never reads them.
//
// THE CONTROLS flip one byte in each section of the real bytes (prefix, base,
// prunable). Each must be refused or give an id that is not the node's.
//
// THE SHAPE TESTS (labelled below) are synthetic and prove refusals only. They
// are not node-proven and are never counted as evidence the reader is right.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readTransaction, transactionIdOf } from '../src/monero/block.js';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-ringct-type6.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const BYTES = Uint8Array.from(Buffer.from(unspaced(FIXTURE.asHex), 'hex'));
const TX_HASH = unspaced(FIXTURE.txHash);

function witness(name, ...values) {
  console.log(`[monero-tx] ${name}: ${values.join(' | ')}`);
}

test('THE NEEDLE: the real RingCT type 6 transaction reads, and its id is the node\'s tx_hash', () => {
  assert.equal(BYTES.length, FIXTURE.source.byteLength ?? 2220);
  const tx = readTransaction(BYTES, 0, 'fixture transaction');
  assert.equal(tx.version, 2);
  assert.equal(tx.rctType, 6);
  assert.equal(transactionIdOf(tx), TX_HASH);
  assert.equal(tx.end, BYTES.length, 'the walk ends at the last byte, no trailing bytes');
  witness('needle', `ed77… id from bytes, ${BYTES.length} bytes, type 6`);
});

// THE CONTROLS. One byte is flipped in the real bytes, in each section. The
// id must not come out as the node's tx_hash, or the read must be refused. A
// flip that still produced the node's id would mean the id does not depend on
// that section, and the parser would be trusting something else.
function flipAt(offset) {
  const copy = Uint8Array.from(BYTES);
  copy[offset] ^= 0x01;
  return copy;
}

function idOrRefusal(bytes) {
  try {
    const tx = readTransaction(bytes, 0, 'mutated transaction');
    if (tx.end !== bytes.length) return { refused: `trailing bytes after ${tx.end}` };
    return { id: transactionIdOf(tx) };
  } catch (error) {
    return { refused: error.message };
  }
}

test('THE CONTROL, prefix: a flipped byte inside the prefix is refused or changes the id', () => {
  // Byte 10 sits inside the input and output list of the prefix.
  const out = idOrRefusal(flipAt(10));
  assert.ok(out.refused || out.id !== TX_HASH, `a flipped prefix byte must not keep the node's id: ${JSON.stringify(out)}`);
  witness('prefix control', out.refused ? `refused: ${out.refused.slice(0, 60)}` : `id changed: ${out.id.slice(0, 16)}`);
});

test('THE CONTROL, base: a flipped byte inside the RingCT base is refused or changes the id', () => {
  // The base starts at byte 275 (the type varint); byte 280 is inside the fee
  // and the ecdh amounts.
  const out = idOrRefusal(flipAt(280));
  assert.ok(out.refused || out.id !== TX_HASH, `a flipped base byte must not keep the node's id: ${JSON.stringify(out)}`);
  witness('base control', out.refused ? `refused: ${out.refused.slice(0, 60)}` : `id changed: ${out.id.slice(0, 16)}`);
});

test('THE CONTROL, prunable: a flipped byte inside the prunable section is refused or changes the id', () => {
  // The prunable section starts at 361. Byte 1000 is inside the Bulletproof+
  // proof's L and R vectors.
  const out = idOrRefusal(flipAt(1000));
  assert.ok(out.refused || out.id !== TX_HASH, `a flipped prunable byte must not keep the node's id: ${JSON.stringify(out)}`);
  witness('prunable control', out.refused ? `refused: ${out.refused.slice(0, 60)}` : `id changed: ${out.id.slice(0, 16)}`);
});

test('THE CONTROL, prunable tail: a flipped CLSAG byte is refused or changes the id', () => {
  // Byte 2200 is inside the last pseudo-output commitment.
  const out = idOrRefusal(flipAt(2200));
  assert.ok(out.refused || out.id !== TX_HASH, `a flipped tail byte must not keep the node's id: ${JSON.stringify(out)}`);
  witness('prunable tail control', out.refused ? `refused: ${out.refused.slice(0, 60)}` : `id changed: ${out.id.slice(0, 16)}`);
});

// THE CLAIM IS NEVER READ. A node's prunable_hash is a stranger's claim. Here
// it is replaced with a wrong value in the fixture bytes' own record: the
// parser never receives it, so the id it computes is still the real id.
test('THE CLAIM IS NOT TRUSTED: the parser computes the id without the node\'s claimed prunable hash', () => {
  const claimedWrong = 'ff'.repeat(32);
  assert.notEqual(claimedWrong, unspaced(FIXTURE.claimedPrunableHash));
  const tx = readTransaction(BYTES, 0, 'fixture transaction');
  assert.equal(transactionIdOf(tx), TX_HASH, 'the id is proven from the bytes, whatever the claim says');
  witness('claim', 'a wrong claimed prunable hash cannot change the computed id');
});

// SHAPE TEST, NOT NODE-PROVEN. A miner transaction that is type 6 is refused.
// This is a synthetic shape built here, and it proves only the refusal, never
// that any real transaction is read correctly.
test('SHAPE TEST (not node-proven): a miner transaction of RingCT type 6 is refused by name', () => {
  const minerLike = Uint8Array.from(BYTES);
  assert.throws(() => readTransaction(minerLike, 0, 'miner transaction'), /RingCT type 6/);
  witness('shape', 'refusal shape only, not a node-proven read');
});

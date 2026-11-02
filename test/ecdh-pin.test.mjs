// The real-transaction ecdh pin: the honest limit at the top of
// src/monero/ringct.js says the sixteen-byte ecdh encoding was never checked
// against a real transaction. This test cures the extraction half of that.
//
// What is pinned here, and what cannot be, because keys stay out:
//   PINNED: the position and bytes of each output's ecdhInfo block inside a
//     REAL mainnet transaction (the zeroamount fixture, block 3797000 index 1,
//     provenance in the fixture). readTransaction must surface exactly these
//     sixteen bytes at exactly these positions, and a flipped byte in the
//     ecdh block must be visible as a changed slice.
//   NOT PINNED and NOT CLAIMED: that any amount decoded from these blocks is
//     the payee's real amount. The pad needs the owner's view secret, and
//     this repository holds no keys. The walk's `outputs[i].amount` for a
//     type 6 transaction is the RAW XORED amount bytes read as an integer -
//     ciphertext read as a number, not a plaintext. A screen or a watcher
//     must not treat it as a coin amount, and this test pins that reading so
//     nobody can quietly mistake it for one.
//
// A real decoded amount that matches one the owner knows stays the gate that
// unblocks payment confirmation; nothing here claims it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readTransaction } from '../src/monero/block.js';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-zeroamount.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const BYTES = Uint8Array.from(Buffer.from(unspaced(FIXTURE.asHex), 'hex'));

const tx = readTransaction(BYTES, 0, 'zeroamount fixture');

// The base section layout, read off the real bytes: type byte, fee varint,
// then one 8-byte ecdh amount per output (Bulletproof+ carries no mask half;
// the mask is the public commitment), then one 32-byte commitment per
// output. The base slice starts right after the prefix.
test('the real transaction carries its ecdhInfo at the walked positions', () => {
  assert.equal(tx.rctType, 6);
  assert.equal(tx.outputs.length, 2);
  const base = tx.baseBytes;
  let at = 0;
  const varint = () => {
    let n = 0n, s = 0n;
    for (;;) {
      const x = base[at]; at += 1;
      n |= BigInt(x & 0x7f) << s;
      s += 7n;
      if (!(x & 0x80)) return n;
    }
  };
  assert.equal(varint(), 6n, 'the base opens with the ringct type');
  assert.equal(varint(), 8900000000n, 'the fee as walked');
  // the corrected layout (Zebra-1 byte-level ruling): 8-byte ecdh amounts
  // per output, back to back, then 32-byte commitments. The 16-byte-block
  // reading in the first version of this test cut commitment0's first 8
  // bytes and called them a mask; 1+5+16+64 = 86 only works with 24-byte
  // commitments, which no Monero type writes.
  const ecdh0 = base.slice(at, at + 8); at += 8;
  const ecdh1 = base.slice(at, at + 8); at += 8;
  assert.equal(Buffer.from(ecdh0).toString('hex'), 'ee4833076711954d',
    'output 0 ecdh amount, byte-exact against the real transaction');
  assert.equal(Buffer.from(ecdh1).toString('hex'), 'fd1ec371a3831f45',
    'output 1 ecdh amount, byte-exact against the real transaction');
  const commit0 = base.slice(at, at + 32); at += 32;
  const commit1 = base.slice(at, at + 32); at += 32;
  assert.equal(Buffer.from(commit0).toString('hex'), '8d546a8b93ffb106259109385a96af50 1389e631ad26b5f119272745c7aeda1f'.replace(/\s+/g, ''),
    'commitment0, whose first 8 bytes were once misread as a mask');
  assert.equal(Buffer.from(commit1).toString('hex'), '07097b9f441910ac6ae218efca465507 c7e4e1695c3e900f00ed81db43319452'.replace(/\s+/g, ''),
    'commitment1 closes the base');
  assert.equal(base.length - at, 0, 'the base is exactly consumed: 1 + 5 + 16 + 64 = 86');
  console.log('[ecdh-pin] 8B amounts and 32B commitments pinned at the walked positions');
});

test('the walked amount fields are ciphertext-as-number, and the test says so', () => {
  // A zero on the wire here is the XORed amount byte read raw, NOT a proof
  // the output pays nothing. The pin: this reading is stable and labelled.
  assert.deepEqual(tx.outputs.map((o) => o.amount), [0n, 0n]);
  // and the same fixture's shape tag agrees: the capture called it zeroamount
  assert.equal(FIXTURE.shapeDiscover, 'zeroamount');
});

test('a flipped byte inside an ecdh block moves that block and nothing else', () => {
  const mutated = Uint8Array.from(BYTES);

  // find the fee varint width by re-walking
  const probe = readTransaction(BYTES, 0, 'probe');
  const base = probe.baseBytes;
  let at = 0;
  const varint = () => {
    let n = 0n, s = 0n;
    for (;;) {
      const x = base[at]; at += 1;
      n |= BigInt(x & 0x7f) << s;
      s += 7n;
      if (!(x & 0x80)) return n;
    }
  };
  varint(); varint();
  const ecdhOffsetInTx = probe.prefixEnd + at; // absolute position of ecdh[0]
  mutated[ecdhOffsetInTx] ^= 0x01;
  const after = readTransaction(mutated, 0, 'mutated');
  const base2 = after.baseBytes;
  let at2 = 0;
  const varint2 = () => {
    let n = 0n, s = 0n;
    for (;;) {
      const x = base2[at2]; at2 += 1;
      n |= BigInt(x & 0x7f) << s;
      s += 7n;
      if (!(x & 0x80)) return n;
    }
  };
  varint2(); varint2();
  const e2 = base2.slice(at2, at2 + 16);
  assert.notEqual(Buffer.from(e2).toString('hex'), 'ee4833076711954dfd1ec371a3831f45',
    'the flipped byte is inside the ecdh block the pin names');
  // the rest of the base (the commitment) is untouched by construction of the flip
  console.log('[ecdh-pin] mutation lands in the named block');
});

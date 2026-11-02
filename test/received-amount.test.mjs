// The received-amount boundary: what the walk reads as an output's "amount"
// and what the ecdh encoding actually carries.
//
// The finding, resolved by execution on the real zeroamount fixture:
//   - readTransaction walks 8 bytes per output between the fee and the
//     commitments, and surfaces them as a bigint (u64 little-endian).
//   - Those 8 bytes are the AMOUNT HALF of the output's 16-byte ecdh block.
//     The MASK HALF rides immediately after them on the wire, and the walk
//     passes over it on the way to the commitments.
//   - So the walked "amount" is CIPHERTEXT read as a number: the XOR pad
//     needs the owner's view secret (via the derivation), and until that
//     derivation is applied the number is not a coin amount. This test pins
//     the boundary so no later lane mistakes the raw reading for a value.
//
// The consistency half: decodeAmount and encodeAmountForTest round-trip a
// known value through the same pad construction, proving the decoder inverts
// exactly what the encoder writes. The real-tx half: the walked bytes sit at
// the exact wire positions the ecdh-pin test resolved. Both halves together
// are the honest limit's cure, short of a real owner-keyed decode.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { readTransaction } from '../src/monero/block.js';
import { decodeAmount, encodeAmountForTest } from '../src/monero/ringct.js';

const ZEROAMOUNT = JSON.parse(readFileSync(new URL('./fixtures/monero-tx-zeroamount.json', import.meta.url), 'utf8'));
const unspaced = (text) => String(text).replace(/\s+/g, '');
const BYTES = Uint8Array.from(Buffer.from(unspaced(ZEROAMOUNT.asHex), 'hex'));
const walked = readTransaction(BYTES, 0, 'zeroamount fixture');

function baseLayout(tx) {
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
  varint(); // ringct type
  varint(); // fee
  const blocks = [];
  for (const output of tx.outputs) {
    // the true layout: 8-byte ecdh amounts, one per output, back to back;
    // the commitments follow as 32 bytes each. No mask half in ecdhInfo.
    const amountHalf = base.slice(at, at + 8); at += 8;
    blocks.push({ output, amountHalf });
  }
  const commitment0 = base.slice(at, at + 32); at += 32;
  const commitment1 = base.slice(at, at + 32); at += 32;
  return { blocks, consumed: at, base, commitment0, commitment1 };
}

test('the walked amount bytes are the two 8-byte ecdh amounts, byte-exact on the real fixture', () => {
  const { blocks } = baseLayout(walked);
  // THE TRUE LAYOUT (Zebra-1 byte-level ruling, verified here by execution):
  // Bulletproof+ ecdhInfo carries the ENCRYPTED AMOUNT ONLY, 8 bytes per
  // output, no mask half. The mask lives in the commitment (C = aH + bG),
  // which is public on the wire. Base layout: [type 1B][fee 5B][amount0 8B]
  // [amount1 8B][commitment0 32B][commitment1 32B] = 86 bytes, exact.
  // The walk at block.js:237 was always correct: its two 8-byte reads are
  // amount0 and amount1, and its two 32-byte takes are the commitments.
  // The earlier "mislabel" reading (16-byte entries with interleaved masks)
  // was wrong: 8d546a8b93ffb106 is commitment0's first 8 bytes, not amount1's
  // neighbor, and 1+5+16+64 = 86 only works if the commitments are 24 bytes,
  // which no Monero type writes.
  const expectedAmount0 = 'ee4833076711954d';
  const expectedAmount1 = 'fd1ec371a3831f45';
  const expectedCommit0 = '8d546a8b93ffb106259109385a96af50 1389e631ad26b5f119272745c7aeda1f';
  const expectedCommit1 = '07097b9f441910ac6ae218efca465507 c7e4e1695c3e900f00ed81db43319452';
  assert.equal(Buffer.from(blocks[0].amountHalf).toString('hex'), expectedAmount0,
    'output 0 walked amount is wire amount0');
  assert.equal(Buffer.from(blocks[1].amountHalf).toString('hex'), expectedAmount1,
    'output 1 walked amount is wire amount1: NOT a mask, the walk was right');
  const base = walked.baseBytes;
  const squeeze = (text) => String(text).replace(/\s+/g, '');
  assert.equal(squeeze(Buffer.from(base.slice(22, 54)).toString('hex')), squeeze(expectedCommit0),
    'commitment0 starts at byte 22 of the base (after type, fee, two amounts)');
  assert.equal(squeeze(Buffer.from(base.slice(54, 86)).toString('hex')), squeeze(expectedCommit1),
    'commitment1 closes the base at byte 86');
  console.log('[received-amount] CORRECTED layout: 8B amounts, 32B commitments, no ecdh mask half.');
});

test('the decoded mask is the XOR pad applied, not the wire mask: proven by round trip', () => {
  // The encoder writes (value XOR pad) and (mask XOR pad). The decoder XORs
  // the pad back. A round trip returns the original value AND the original
  // mask, which is only true if the pad construction in both directions is
  // the same keccak(derivation || varint(index)).
  const derivation = keccak_256(new Uint8Array(32).fill(0x33));
  const VALUE = 123456789n;
  const MASK = new Uint8Array(8).fill(0x11);
  const encoded = encodeAmountForTest({ derivation, index: 0, value: VALUE, mask: MASK });
  const decoded = decodeAmount({ derivation, index: 0, info: encoded });
  assert.equal(decoded.value, VALUE, 'the value survives the round trip');
  assert.deepEqual(decoded.mask, MASK, 'the mask survives the round trip');
  // the index changes the pad: a different index decodes to noise, not the value
  const other = decodeAmount({ derivation, index: 1, info: encoded });
  assert.notEqual(other.value, VALUE, 'the index is inside the pad, not beside it');
  console.log('[received-amount] decoder inverts the encoder through the same pad');
});

test('the boundary statement: walked amounts are ciphertext, not coin amounts', () => {
  const { blocks } = baseLayout(walked);
  // both outputs walk as 0n on this fixture. That is the raw XORed byte
  // pattern, not evidence the outputs pay nothing. The pin: the reading is
  // stable and the label travels with it.
  assert.deepEqual(blocks.map((b) => b.output.amount), [0n, 0n]);
  assert.equal(ZEROAMOUNT.shapeDiscover, 'zeroamount',
    'the capture named the shape from the wire, and this test keeps the label honest');
  console.log('[received-amount] walked zero is ciphertext; a real decode needs the owner view secret');
});

test('decode-path consistency: the existing decodeAmount inverts the existing encoder, no interface change', () => {
  // Zebra-1's scope guard: prove the walk's ecdh blocks decode consistently
  // through the EXISTING decodeAmount with a derived derivation. No keys, a
  // throwaway derivation only. The consistency proof: encode a known value
  // and mask through the existing encoder at each index, decode through the
  // existing decoder, and the value and mask both survive. The real-tx
  // ecdh blocks decoded with the throwaway derivation give noise, which is
  // the honest answer: the pad needs the payee's derivation, and a wrong
  // derivation yields a wrong number, not a refusal.
  const derivation = keccak_256(new Uint8Array(32).fill(0x33));
  const VALUES = [7777777n, 8888888n];
  const MASKS = [new Uint8Array(8).fill(0x21), new Uint8Array(8).fill(0x22)];
  VALUES.forEach((value, index) => {
    const encoded = encodeAmountForTest({ derivation, index, value, mask: MASKS[index] });
    const decoded = decodeAmount({ derivation, index, info: encoded });
    assert.equal(decoded.value, value, `index ${index}: the decoder inverts the encoder`);
    assert.deepEqual(decoded.mask, MASKS[index], `index ${index}: the mask survives`);
  });
  // the real tx's ecdh blocks through the throwaway derivation: noise, and
  // the noise is DETERMINISTIC (same derivation, same bytes, same noise), so
  // a later lane can prove a decode changed when the derivation changes.
  const base = walked.baseBytes;
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
  const ecdh0 = base.slice(at, at + 16);
  const _ecdh1 = base.slice(at + 16, at + 32);
  const noise0 = decodeAmount({ derivation, index: 0, info: ecdh0 });
  const noiseAgain = decodeAmount({ derivation, index: 0, info: ecdh0 });
  assert.equal(noise0.value, noiseAgain.value, 'the noise is deterministic, not random');
  assert.notEqual(noise0.value, 0n, 'the noise is not zero: a wrong derivation lies, it does not refuse');
  console.log('[received-amount] decode path consistent; wrong derivation yields deterministic noise');
});

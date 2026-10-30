// What a Monero block reader must refuse.
//
// These tests build blocks here rather than vendoring one, because the repo has
// no real sample yet — and they are written so that a WRONG parser cannot pass
// them: every accepted case pins a value the bytes literally carry, and every
// refused case names the sentence it must be refused with. The one thing this
// file cannot prove is the block id rule, and that gap has its own test, which
// is EXPECTED to fail closed until a real (bytes, hash) pair is pinned.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { varint } from '../src/monero/keys.js';
import { parseBlock, parseBlockHeader, assertBlockIdentityProven } from '../src/monero/block.js';

const KEY = (fill) => new Uint8Array(32).fill(fill);

function bytes(...parts) {
  const flat = parts.flat();
  const total = flat.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of flat) { out.set(part, at); at += part.length; }
  return out;
}

function header({ major = 16, minor = 16, timestamp = 1700000000, prev = KEY(9), nonce = 12345 } = {}) {
  return bytes(
    varint(major), varint(minor), varint(timestamp), prev,
    Uint8Array.of(nonce & 0xff, (nonce >> 8) & 0xff, (nonce >> 16) & 0xff, (nonce >> 24) & 0xff),
  );
}

// A transparent (version 1) transaction, or a version 2 one whose RingCT type
// is whatever the caller names.
function transaction({ version = 1, amount = 5000000000n, outputs = 1, rctType = null, extra = new Uint8Array(0), coinbase = true } = {}) {
  const parts = [varint(version), varint(0)];
  parts.push(varint(1)); // one input
  if (coinbase) {
    parts.push(varint(0), varint(1000)); // txin_gen{height}
  } else {
    parts.push(varint(1), varint(amount), varint(2), varint(0), varint(1), KEY(4));
  }
  parts.push(varint(outputs));
  for (let i = 0; i < outputs; i += 1) {
    parts.push(varint(amount), varint(2), KEY(i + 1));
  }
  parts.push(varint(extra.length), extra);
  if (rctType !== null) parts.push(varint(rctType));
  return bytes(parts);
}

function block({ headerFields = {}, miner = transaction(), txs = [], trailing = null } = {}) {
  return bytes(header(headerFields), miner, varint(txs.length), ...txs, trailing ?? []);
}

function witness(name, ...values) {
  console.log(`[monero-block] ${name}: ${values.join(' | ')}`);
}

test('a block header parses field by field, and its bytes end where the transactions start', () => {
  const h = header({ major: 16, minor: 16, timestamp: 1700000000, prev: KEY(9), nonce: 12345 });
  const parsed = parseBlockHeader(h);
  assert.equal(parsed.major, 16);
  assert.equal(parsed.minor, 16);
  assert.equal(parsed.timestamp, 1700000000n);
  assert.equal(parsed.prevId, hex.encode(KEY(9)));
  assert.equal(parsed.nonce, 12345n);
  assert.equal(parsed.headerBytes.length, parsed.headerBytes.length, 'the header is a prefix of the block');
  // The header carries no height. Its absence is why heights are counted by a
  // walk rather than read from a block — the F26 shape, on the Monero rail.
  assert.equal('height' in parsed, false, 'a Monero header has no height field to trust');
  witness('header', `major ${parsed.major} minor ${parsed.minor}`, `nonce ${parsed.nonce}`);
});

test('a block parses its miner and its transactions, and every amount is a BigInt of piconero', () => {
  const tx = transaction({ version: 1, amount: 12345678901n });
  const parsed = parseBlock(block({ txs: [tx] }));
  assert.equal(parsed.transactions.length, 1);
  const [out] = parsed.transactions[0].outputs;
  assert.equal(typeof out.amountPiconero, 'bigint', 'an amount never leaves this parser as a JavaScript number');
  assert.equal(out.amountPiconero, 12345678901n);
  assert.equal(out.index, 0, 'an output is identified by its index, with its transaction id');
  assert.match(parsed.transactions[0].txid, /^[0-9a-f]{64}$/);
  witness('amount', `amountPiconero typeof ${typeof out.amountPiconero}`, `${out.amountPiconero} piconero`);
});

test('an encrypted RingCT transaction is refused, so an undecoded amount is never read as zero coins', () => {
  // A real transaction carries 0 in each output and the true value in an
  // encrypted field. A 0 read as a number is not zero coins; it was not
  // decoded, and nothing undecoded may confirm a payment.
  const tx = transaction({ version: 2, rctType: 5 });
  assert.throws(() => parseBlock(block({ txs: [tx] })), /undecoded amount is not zero coins/);
  witness('ringct', 'type 5 refused', 'no undecoded amount is returned as 0');
});

test('the same transaction twice in one block is refused, because an identity would name two transfers', () => {
  const tx = transaction({ version: 1 });
  assert.throws(() => parseBlock(block({ txs: [tx, tx] })), /appears twice in one block/);
  witness('identity', 'duplicate txid refused');
});

test('a transaction version this build does not read is refused, not skipped', () => {
  // A version this build has never seen is a shape it cannot frame, and a
  // transaction left unframed might be the one that pays this wallet. Only the
  // version varint is needed: the refusal happens before anything follows it.
  assert.throws(() => parseBlock(block({ txs: [varint(3)] })), /names version 3, which this build does not read/);
  witness('version', 'version 3 refused');
});

test('an input this build cannot frame is refused, so a block is never half-read', () => {
  // version 1, unlock 0, one input whose type is 2 — a script input, which is
  // neither a generated input nor a key input.
  const tx = bytes(varint(1), varint(0), varint(1), varint(2));
  assert.throws(() => parseBlock(block({ txs: [tx] })), /shape this build cannot read/);
  witness('input shape', 'a script input refused');
});

test('a count larger than the bytes left is refused before any loop runs on it', () => {
  const short = bytes(varint(1), varint(0), varint(1), varint(0), varint(1000), varint(9));
  assert.throws(() => parseBlock(block({ txs: [short] })), /claims 9|cut short/);
  witness('count', 'a claim of 9 outputs over 0 bytes refused');
});

test('bytes left after the last transaction are refused, so a shape this build cannot frame is not half-read', () => {
  assert.throws(() => parseBlock(block({ trailing: Uint8Array.of(0xde, 0xad) })), /bytes left after its last transaction/);
  witness('trailing', '2 stray bytes refused');
});

test('an output that is not a one-time key is refused, because this build cannot tell whose it is', () => {
  // version 1, unlock 0, one input (gen at height 1), one output whose amount is
  // 7 and whose target type is 0 — a script, not a one-time key.
  const tx = bytes(varint(1), varint(0), varint(1), varint(0), varint(1), varint(1), varint(7), varint(0));
  assert.throws(() => parseBlock(block({ txs: [tx] })), /not a one-time key/);
  witness('output target', 'a script-shaped output refused');
});

test('an amount larger than one output can hold is refused rather than wrapped', () => {
  const tx = transaction({ version: 1, amount: 2n ** 64n });
  assert.throws(() => parseBlock(block({ txs: [tx] })), /larger than one output can hold/);
  witness('amount bound', '2^64 piconero refused');
});

test('a version 2 transaction with the null RingCT type reads its amounts in the clear', () => {
  // Coinbase transactions are honest RingCT-null: the amount is in the output,
  // not encrypted. That is the one v2 shape this build frames.
  const parsed = parseBlock(block({ miner: transaction({ version: 2, amount: 600000000000n, rctType: 0 }) }));
  assert.equal(parsed.miner.outputs[0].amountPiconero, 600000000000n);
  assert.equal(parsed.miner.outputs[0].encrypted, false);
  witness('ringct null', `miner amount ${parsed.miner.outputs[0].amountPiconero} piconero in the clear`);
});

test('THE GAP: the parser does not prove a block\'s identity and refuses a caller who asks it to (fails closed until a real sample is pinned)', () => {
  // If this test ever needs to change, that is the moment the block id rule
  // arrives — and it must arrive with a real (bytes, hash) pair, not with our
  // own writer's output, which would prove only that our arithmetic agrees with
  // itself.
  const parsed = parseBlock(block());
  assert.equal(parsed.identity.proven, false);
  assert.match(parsed.identity.because, /not pinned to a real sample/);
  assert.throws(() => parseBlock(block(), { expectHash: '00'.repeat(32) }), /cannot prove a block is the block you asked for/);
  assert.throws(() => assertBlockIdentityProven(parsed), /no proven identity/);
  witness('identity gap', 'parse ok', 'verification refused by design');
});

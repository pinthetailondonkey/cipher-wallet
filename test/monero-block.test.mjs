// What the block reader must refuse, and why the tests look like this.
//
// The first version of this file tested a parser that accepted a block body
// layout Monero does not use, because the same hand wrote the fixture and the
// parser. Both defects it hid (F1: wrong body model, F2: wrong version 2
// transaction id) were found by review, not by this suite. So the tests below
// are written from OUTSIDE that loop: they assert the two shapes that matter —
// the real one and the fictional one this repository used to build — are both
// refused, and that no transaction id is emitted for any version 2 shape.
//
// If one of these tests ever needs to change, that is the moment a real
// (bytes, hash) pair has been pinned and a body model built to it. It must not
// be changed to make a fixture written here pass.

import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { varint } from '../src/monero/keys.js';
import { parseBlock, parseBlockHeader } from '../src/monero/block.js';

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

// A version 2 coinbase with the null RingCT type: the shape every real miner
// transaction has. It is the one that matters for F2, because that is the shape
// whose id this repository used to compute with the wrong rule.
function minerTxV2Null() {
  return bytes(
    varint(2), varint(0), // version, unlock time
    varint(1), varint(0), varint(5), // one input, txin_gen{height 5}
    varint(1), varint(600000000000n), varint(2), KEY(1), // one output, amount clear, one-time key
    varint(0), // extra length
    varint(0), // RingCT type 0 (null)
  );
}

// A version 1 transaction, the filler the old test writer used.
function fillerTxV1() {
  return bytes(
    varint(1), varint(0), varint(1), varint(0), varint(7),
    varint(1), varint(5000n), varint(2), KEY(4), varint(0),
  );
}

function witness(name, ...values) {
  console.log(`[monero-block] ${name}: ${values.join(' | ')}`);
}

test('a block header parses field by field, and its bytes end where the body would start', () => {
  const h = header({ major: 16, minor: 16, timestamp: 1700000000, prev: KEY(9), nonce: 12345 });
  const parsed = parseBlockHeader(h);
  assert.equal(parsed.major, 16);
  assert.equal(parsed.minor, 16);
  assert.equal(parsed.timestamp, 1700000000n);
  assert.equal(parsed.prevId, hex.encode(KEY(9)));
  assert.equal(parsed.nonce, 12345n);
  assert.equal(parsed.headerBytes.length, h.length, 'the header is the whole input when the input is a header');
  // The header carries no height. Its absence is why heights are counted by a
  // walk rather than read from a block — the F26 shape, on the Monero rail.
  assert.equal('height' in parsed, false, 'a Monero header has no height field to trust');
  witness('header', `major ${parsed.major} minor ${parsed.minor}`, `nonce ${parsed.nonce}`);
});

test('a header cut short is refused, and the refusal names the header, not the block', () => {
  const cut = header().slice(0, header().length - 2);
  assert.throws(() => parseBlockHeader(cut), /block header is cut short/);
  witness('header cut', 'a truncated header refused by the header reader');
});

test('F1: a blob in the shape a real node returns is refused, and the refusal names the byte model', () => {
  // header || miner_tx || varint(count) || 32-byte hash × count, which is what
  // get_block documents and what the daemon serializes.
  const realShape = bytes(header(), minerTxV2Null(), varint(1), KEY(0xab));
  assert.throws(() => parseBlock(realShape), /byte model is not Monero's/);
  witness('F1 real shape', 'refused by name, not mistaken for a cut-short varint');
});

test('F1: the fictional layout this repository used to build is refused too, so a fixture cannot reopen the door', () => {
  // header || miner_tx || varint(count) || FULL TRANSACTION × count. This is the
  // layout the first version of this file accepted, and the layout its own test
  // writer emitted. It must not be accepted by anything.
  const fictional = bytes(header(), minerTxV2Null(), varint(1), fillerTxV1());
  assert.throws(() => parseBlock(fictional), /byte model is not Monero's/);
  witness('F1 fictional shape', 'the old fixture layout is refused as well');
});

test('F2: no transaction id is emitted for a version 2 transaction, because that rule was never Monero\'s', () => {
  // Every real miner transaction is version 2 with the null RingCT type. The
  // first version computed an id for exactly this shape and got it wrong; the
  // only safe answer is to emit none at all.
  const blob = bytes(header(), minerTxV2Null(), varint(0));
  assert.throws(
    () => parseBlock(blob),
    /transaction id rule this build carried was never correct for version 2/,
  );
  witness('F2', 'a v2-null coinbase yields no id, because a wrong id is worse than none');
});

test('THE GAP: a block has no proven identity, and a caller asking for verification is refused like everything else', () => {
  // The block id rule is unpinned, so even a body model would not make a block
  // identifiable. The refusal here is the same door: nothing this file returns
  // may gate a payment.
  assert.throws(() => parseBlock(bytes(header(), minerTxV2Null(), varint(0)), { expectHash: '00'.repeat(32) }), /byte model is not Monero's/);
  witness('identity gap', 'verification is refused because parsing is refused');
});

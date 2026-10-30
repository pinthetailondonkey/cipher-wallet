// The test that matters is the one that can fail against real bytes.
//
// The first version of this file tested a parser that accepted a block body
// layout Monero does not use, because the same hand wrote the fixture and the
// parser. Both defects it hid (F1: header || miner_tx || count || FULL
// TRANSACTIONS, where Monero rides the other transactions as hashes; F2: a
// version 2 transaction id rule that was never Monero's) were found by review,
// not by this suite. Its header said the rewrite moment would come when a real
// (bytes, hash) pair was pinned. That moment came: FIVE mainnet blocks, bytes
// and ids from a monerod's own get_block answers, pinned with provenance in
// test/fixtures/monero-block-*.json by scripts/fetch-monero-block-fixture.mjs.
// Five, not one, on purpose, and counted per rule: the version 2 rules are
// witnessed by three blocks (transaction tree shapes 7, 5 and 1 — every
// branch the chain produces — and three blob lengths, so neither the tree
// arithmetic nor the string-length fold in the block id can pass on one lucky
// pair); the version 1 coinbase rule by two (block 100, plain, and block
// 202612, the chain's one exception, whose own bytes prove the exception's
// constants — the one abnormality on the chain is never left testifying about
// itself alone).
//
// So this file is three layers, and only the first is a value test:
//
//   THE NEEDLE — the pinned bytes, all three pairs. This reader must name each
//   block the id its node says it has, name its miner transaction the id the
//   node says it has, name its parent by the parent's own claimed id, and walk
//   the same transaction hash list. Every rule in block.js feeds that one id
//   per pair; a regression in any of them — body model, tree arithmetic, the
//   transaction id split, or the string-length fold in the block id — turns
//   the computed id into a different, plausible id, and this fails.
//
//   THE CONTROLS — mutated copies of the REAL bytes. Each proves the id is
//   bound to one part of the walk: a flipped header byte, a flipped byte inside
//   the miner transaction, a flipped transaction hash, a trailing byte. These
//   are the tests a fixture written in this repository could never fake,
//   because the bytes are not ours.
//
//   THE REFUSALS — shapes this build refuses on purpose, built synthetically
//   here and labelled as shape tests: version 1 miner transactions, non-Null
//   RingCT types, a first transaction that is not the coinbase, truncated
//   input, a malformed claim.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { varint } from '../src/monero/keys.js';
import { parseBlock, parseBlockHeader, txTreeRootOf } from '../src/monero/block.js';

const squeeze = (text) => String(text).replace(/\s+/g, '');
const load = (file) => JSON.parse(readFileSync(new URL(`./fixtures/${file}`, import.meta.url), 'utf8'));

const PAIR_FILES = [
  'monero-block-mainnet.json',
  'monero-block-mainnet-b.json',
  'monero-block-mainnet-c.json',
  'monero-block-202612.json',
  'monero-block-v1-early.json',
];
const PAIRS = PAIR_FILES.map((file) => {
  const fixture = load(file);
  return {
    file,
    fixture,
    blob: Uint8Array.from(Buffer.from(squeeze(fixture.block.blob), 'hex')),
    claimedId: squeeze(fixture.block.claimedId),
    claimedPrevId: squeeze(fixture.block.claimedPrevId),
    claimedMinerTxId: squeeze(fixture.block.claimedMinerTxId),
    claimedTxHashes: fixture.block.claimedTxHashes.map(squeeze),
    parentClaimedId: squeeze(fixture.parent.claimedId),
  };
});

// The first pair is the one the controls mutate.
const CLAIMED_ID = PAIRS[0].claimedId;
const CLAIMED_MINER_TX_ID = PAIRS[0].claimedMinerTxId;
const CLAIMED_TX_HASHES = PAIRS[0].claimedTxHashes;
const PARENT_CLAIMED_ID = PAIRS[0].parentClaimedId;
const BLOB = PAIRS[0].blob;

// The last four header bytes are the nonce: a byte no other field backs, so
// flipping it proves the id depends on the header without breaking the walk.
const HEADER_LEN = parseBlockHeader(BLOB).headerBytes.length;

function witness(name, ...values) {
  console.log(`[monero-block] ${name}: ${values.join(' | ')}`);
}

test('THE NEEDLE: every pinned pair — this reader names each block the id its node says it has', () => {
  // The one test a self-written fixture could never satisfy. expectHash is the
  // daemon's own claim, recorded at capture; if the walk, the tree, either id
  // rule, or the string-length fold is wrong, the computed id is a different
  // id and this refuses right here. Three pairs: tree shapes 7, 5 and 1, and
  // three blob lengths, so no single coincidence carries it.
  for (const pair of PAIRS) {
    const block = parseBlock(pair.blob, { expectHash: pair.claimedId });
    assert.equal(block.id, pair.claimedId, pair.file);
    assert.equal(block.minerTxId, pair.claimedMinerTxId, `${pair.file}: the miner transaction id is the daemon's own miner_tx_hash`);
    assert.equal(block.header.prevId, pair.claimedPrevId, pair.file);
    assert.equal(block.header.prevId, pair.parentClaimedId, `${pair.file}: the child names the parent the parent's own claimed id`);
    assert.deepEqual(block.txHashes, pair.claimedTxHashes, `${pair.file}: the walked hash list is the daemon's list`);
    assert.equal(block.byteLength, pair.blob.length, `${pair.file}: the walk ends at the last byte of the blob`);
    assert.equal(block.header.major, pair.fixture.block.majorVersion, pair.file);
    assert.equal(block.header.minor, pair.fixture.block.minorVersion, pair.file);
    assert.equal(block.minerTx.coinbase, true, pair.file);
    assert.equal(block.minerTx.genHeight, BigInt(pair.fixture.block.height), `${pair.file}: a coinbase generates at its own height`);
    witness(pair.file, `height ${pair.fixture.block.height}`, `tree of ${block.txHashes.length + 1}`, `id ${block.id.slice(0, 16)}…`);
    witness(`${pair.file} miner tx`, `id ${block.minerTxId.slice(0, 16)}…`, `${block.minerTx.outputs.length} outputs`);
  }
});

test('THE CONTROL: a wrong claim against the real bytes is refused, and the refusal names both ids', () => {
  // The parent's id is a real id, just not this block's: the near-miss a
  // rubber-stamp check would wave through.
  const parent = PARENT_CLAIMED_ID;
  assert.throws(
    () => parseBlock(BLOB, { expectHash: parent }),
    (err) => err.message.includes('proves the id') && err.message.includes(CLAIMED_ID) && err.message.includes(parent),
  );
  witness('wrong claim', 'refused, naming the proven id and the claimed one');
});

test('THE CONTROL: one flipped nonce byte and the bytes prove a different id', () => {
  const flipped = new Uint8Array(BLOB);
  flipped[HEADER_LEN - 1] ^= 0xff;
  const reparsed = parseBlock(flipped);
  assert.notEqual(reparsed.id, CLAIMED_ID);
  assert.throws(() => parseBlock(flipped, { expectHash: CLAIMED_ID }), /proves the id/);
  witness('header flip', `id ${reparsed.id.slice(0, 16)}… instead of ${CLAIMED_ID.slice(0, 16)}…`);
});

test('THE CONTROL: one flipped byte inside the miner transaction and the claimed ids refuse', () => {
  // The last byte of the miner transaction's prefix is inside its extra: the
  // framing survives, the walked sections change, so this tests the id rules
  // and not the walk's balance.
  const whole = parseBlock(BLOB);
  const extraLastAt = whole.minerTx.prefixEnd - 1;
  const flipped = new Uint8Array(BLOB);
  flipped[extraLastAt] ^= 0xff;
  const reparsed = parseBlock(flipped);
  assert.notEqual(reparsed.minerTxId, CLAIMED_MINER_TX_ID, 'the miner transaction id follows its own bytes');
  assert.notEqual(reparsed.id, CLAIMED_ID, 'a changed miner id means a changed tree and a changed block id');
  assert.throws(() => parseBlock(flipped, { expectHash: CLAIMED_ID }), /proves the id/);
  witness('miner tx flip', `miner id ${reparsed.minerTxId.slice(0, 16)}… instead of ${CLAIMED_MINER_TX_ID.slice(0, 16)}…`);
});

test('THE CONTROL: one flipped transaction hash and the claimed id refuses', () => {
  const flipped = new Uint8Array(BLOB);
  flipped[flipped.length - 1] ^= 0xff; // the last byte of the last walked hash
  assert.notEqual(parseBlock(flipped).id, CLAIMED_ID);
  assert.throws(() => parseBlock(flipped, { expectHash: CLAIMED_ID }), /proves the id/);
  witness('hash flip', 'the tree follows the walked hashes, and the id follows the tree');
});

test('THE CONTROL: one trailing byte is refused, which is the door the fictional layout reopens', () => {
  const padded = new Uint8Array(BLOB.length + 1);
  padded.set(BLOB, 0);
  padded[BLOB.length] = 0x00;
  assert.throws(() => parseBlock(padded), /after its last transaction hash/);
  witness('trailing byte', 'refused: Monero\'s body ends at the last hash');
});

test('THE CONTROL: the 202612 exception is bound to the exact bytes, never to the claimed height', () => {
  // The exception's height comes out of the bytes, so it is a claim. Flip one
  // byte of the real 202612 blob: the walk completes, the claim survives, but
  // the blob hash no longer equals Monero's constant — so the recorded id is
  // not substituted, the computed id stands, and the recorded claim refuses.
  const fixture = load('monero-block-202612.json');
  const blob = Uint8Array.from(Buffer.from(squeeze(fixture.block.blob), 'hex'));
  const flipped = new Uint8Array(blob);
  flipped[flipped.length - 1] ^= 0xff; // the last byte of the last walked hash
  const reparsed = parseBlock(flipped);
  assert.equal(reparsed.minerTx.genHeight, 202612n, 'the flipped bytes still claim the exception height');
  assert.notEqual(reparsed.id, squeeze(fixture.block.claimedId));
  assert.throws(() => parseBlock(flipped, { expectHash: squeeze(fixture.block.claimedId) }), /proves the id/);
  witness('exception flip', 'a claimed height without the bytes gets its computed id; the recorded id is refused');
});

// ---------------------------------------------------------------------------
// Shape tests below: synthetic bytes, built here from the pinned source's own
// rules. They prove refusals, never values.
// ---------------------------------------------------------------------------

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

function minerTxV2Null() {
  return bytes(
    varint(2), varint(0), // version, unlock time
    varint(1), Uint8Array.of(0xff), varint(5), // one input: txin_gen is tagged 0xff, then the height
    varint(1), varint(600000000000n), varint(2), KEY(1), // one output, amount clear, one-time key
    varint(0), // extra length
    varint(0), // RingCT type 0 (null)
  );
}

function fillerTxV1() {
  // Never walked past its version byte: version 1 is refused on sight. The
  // rest is shape-honest filler so the bytes read as a transaction to the eye.
  return bytes(
    varint(1), varint(0), varint(1), Uint8Array.of(0xff), varint(7),
    varint(1), varint(5000n), varint(2), KEY(4), varint(0),
  );
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
  assert.equal('height' in parsed, false, 'a Monero header has no height field to trust');
  witness('header', `major ${parsed.major} minor ${parsed.minor}`, `nonce ${parsed.nonce}`);
});

test('a header cut short is refused, and the refusal names the header, not the block', () => {
  const cut = header().slice(0, header().length - 2);
  assert.throws(() => parseBlockHeader(cut), /block header is cut short/);
  witness('header cut', 'a truncated header refused by the header reader');
});

test('the fictional layout this repository used to build is refused: full transactions after the count', () => {
  // header || miner_tx || varint(count) || FULL TRANSACTION × count. This is
  // the layout the first version of this file accepted and its own test writer
  // emitted. Against today's reader the leftover bytes are trailing bytes.
  const fictional = bytes(header(), minerTxV2Null(), varint(1), fillerTxV1());
  assert.throws(() => parseBlock(fictional), /after its last transaction hash/);
  witness('F1 fictional shape', 'refused, and by the same rule that refuses any trailing byte');
});

test('a truncated block is refused where it is cut, and the refusal names the field', () => {
  assert.throws(() => parseBlock(BLOB.slice(0, BLOB.length - 5)), /cut short/);
  witness('block cut', 'a truncated blob refused inside the last hash');
});

test('a version 1 transaction that is not the miner\'s own is refused, and the refusal names the pre-RingCT era', () => {
  // Version 1 with a key input: its signatures ride inline behind the inputs,
  // a section no pinned bytes in this repository prove. The refusal names the
  // era and the shape so it never reads as a bug — the miner's own v1
  // transaction IS read (blocks 100 and 202612 prove it).
  const v1KeyInput = bytes(
    varint(1), varint(0), // version, unlock time
    varint(1), Uint8Array.of(0x02), varint(5000n), varint(1), varint(0), KEY(7), // one txin_to_key
    varint(1), varint(5000n), varint(2), KEY(1), // one output
    varint(0), // extra length
  );
  assert.throws(() => parseBlock(bytes(header(), v1KeyInput, varint(0))), /pre-RingCT era/);
  witness('v1 key-input refusal', 'the era and the shape are named, not just "unsupported"');
});

test('a miner transaction whose RingCT type is not Null is refused by name', () => {
  const nonNull = bytes(
    varint(2), varint(0),
    varint(1), Uint8Array.of(0xff), varint(5),
    varint(1), varint(600000000000n), varint(2), KEY(1),
    varint(0),
    varint(1), // RingCT type 1: a prunable section this build refuses to guess through
  );
  assert.throws(() => parseBlock(bytes(header(), nonNull, varint(0))), /RingCT type 1/);
  witness('rct refusal', 'a prunable section is a refused read, not a finding');
});

test('a block whose first transaction is not the coinbase is refused by name', () => {
  const keyInput = bytes(
    varint(2), varint(0), // version, unlock time
    varint(1), Uint8Array.of(0x02), varint(5000n), varint(1), varint(0), KEY(7), // one txin_to_key
    varint(1), varint(5000n), varint(2), KEY(1), // one output
    varint(0), // extra length
    varint(0), // RingCT type null
  );
  assert.throws(() => parseBlock(bytes(header(), keyInput, varint(0))), /not a miner transaction/);
  witness('non-coinbase refusal', 'Monero puts the coinbase first and nothing else in full');
});

test('a claim that is not 64 hex characters is refused before any comparison', () => {
  assert.throws(() => parseBlock(BLOB, { expectHash: 'not-an-id' }), /64 hex/);
  witness('malformed claim', 'a claim must be an id before it can be wrong');
});

// ---------------------------------------------------------------------------
// Tree unit pins from tree-hash.c's own rules. The composition the chain
// actually uses — the pinned block's seven ids — is value-proven above; these
// cover the small branches that block cannot reach.
// ---------------------------------------------------------------------------

test('tree: one id is the root, verbatim', () => {
  const lone = hex.decode(CLAIMED_TX_HASHES[0]);
  assert.equal(hex.encode(txTreeRootOf([lone])), CLAIMED_TX_HASHES[0]);
  witness('tree of one', 'returned verbatim');
});

test('tree: two ids hash together', () => {
  const [a, b] = CLAIMED_TX_HASHES.map(hex.decode);
  const expected = hex.encode(keccak_256(bytes(a, b)));
  assert.equal(hex.encode(txTreeRootOf([a, b])), expected);
  witness('tree of two', 'keccak of the pair');
});

test('tree: three ids ride the first verbatim, then fold — the shape that once tripped the chain itself', () => {
  const [a, b, c] = CLAIMED_TX_HASHES.map(hex.decode);
  const expected = hex.encode(keccak_256(bytes(a, keccak_256(bytes(b, c)))));
  assert.equal(hex.encode(txTreeRootOf([a, b, c])), expected);
  witness('tree of three', 'one verbatim, one pair, one final fold');
});

test('tree: an empty list is refused', () => {
  assert.throws(() => txTreeRootOf([]), /at least one transaction id/);
  witness('tree of none', 'refused');
});

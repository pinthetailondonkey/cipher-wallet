// getheaders: the question a header-first walk asks.
//
// It is a FORWARD question. A locator names blocks the wallet already believes;
// the peer answers with headers that come AFTER them, oldest first, up to a
// stop hash. There is no backwards form, which is why header-first walking is a
// forward sync from an anchor and not a cheaper version of walkBack.
//
// The bytes are pinned against the same BIP-158 testnet-19 fixture the other
// wire pins use: the height-3 header names the height-2 block, so a locator
// carrying the height-2 hash is exactly what a peer needs to answer with the
// height-3 header first.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import {
  MAX_LOCATOR,
  PROTOCOL_VERSION,
  decodeCfHeaders,
  decodeHeaders,
  encodeCfHeaders,
  encodeGetCFHeaders,
  encodeGetHeaders,
  encodeHeaders,
} from '../src/wire.js';
import { headerHash } from '../src/chain.js';
import { filterHeader } from '../src/filters.js';

const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));

const HEIGHT_2 = VECTORS[1];
const HEIGHT_3 = VECTORS[2];
const PARENT_DISPLAY = HEIGHT_2[1];
const CHILD_DISPLAY = HEIGHT_3[1];
// The fixture's third column is the whole block; its first 80 bytes are the
// header, which is the only part a getheaders answer carries.
const CHILD_HEADER = hex.decode(HEIGHT_3[2]).slice(0, 80);
// Filter-header chain: each row's "Basic Header" continues the row before it.
const FILTER_2 = HEIGHT_2;
const FILTER_1 = VECTORS[0];
const FILTER_HEADER_1 = FILTER_1[6];
const FILTER_HEADER_2 = FILTER_2[6];

function witness(name, ...values) {
  console.log(`[headers] ${name}: ${values.join(' | ')}`);
}

test('getheaders writes its locator and stop hash in internal order', () => {
  const message = encodeGetHeaders({ locator: [PARENT_DISPLAY], stopHash: CHILD_DISPLAY });
  // version (4), then a canonical count of one, then the hash, then the stop.
  assert.equal(message.length, 4 + 1 + 32 + 32);
  assert.equal(hex.encode(message.slice(0, 4)), '80110100', 'protocol version 70016, little-endian');
  assert.equal(message[4], 1, 'a one-entry locator is one byte, not a padded form');
  assert.equal(hex.encode(message.slice(5, 37)), hex.encode(hex.decode(PARENT_DISPLAY).reverse()));
  assert.equal(hex.encode(message.slice(37, 69)), hex.encode(hex.decode(CHILD_DISPLAY).reverse()));
  witness('getheaders', `version ${PROTOCOL_VERSION}`, `locator ${PARENT_DISPLAY.slice(0, 16)}`);
});

test('a locator that names no block is refused, because it asks from genesis', () => {
  assert.throws(() => encodeGetHeaders({ locator: [], stopHash: CHILD_DISPLAY }), /at least one block hash/);
  assert.throws(() => encodeGetHeaders({ stopHash: CHILD_DISPLAY }), /at least one block hash/);
});

test('a locator longer than a node will read is refused', () => {
  const many = Array.from({ length: MAX_LOCATOR + 1 }, () => PARENT_DISPLAY);
  assert.throws(() => encodeGetHeaders({ locator: many, stopHash: CHILD_DISPLAY }), /at most/);
  assert.doesNotThrow(() => encodeGetHeaders({ locator: many.slice(0, MAX_LOCATOR), stopHash: CHILD_DISPLAY }));
});

test('headers decodes a count of 80-byte headers, oldest first', () => {
  const message = encodeHeaders([CHILD_HEADER]);
  assert.equal(message.length, 1 + 80);
  const decoded = decodeHeaders(message);
  assert.equal(decoded.headers.length, 1);
  assert.equal(hex.encode(decoded.headers[0]), hex.encode(CHILD_HEADER));
  // The bytes are the block the fixture names, not merely 80 bytes that
  // round-trip: a header decodes to a block nobody asked about otherwise.
  assert.equal(headerHash(decoded.headers[0]), CHILD_DISPLAY);
  witness('headers', `one header, ${decoded.headers[0].length} bytes`);
});

test('a headers answer whose length disagrees with its count is refused, not partly read', () => {
  const message = encodeHeaders([CHILD_HEADER]);
  assert.throws(() => decodeHeaders(message.slice(0, message.length - 1)), /cut short|80 bytes|disagree/);
  const extra = new Uint8Array(message.length + 1);
  extra.set(message, 0);
  assert.throws(() => decodeHeaders(extra), /cut short|80 bytes|disagree/);
  assert.throws(() => decodeHeaders(new Uint8Array(0)), /count|varint|short/i);
});

test('getcfheaders asks the same range question a filter does, by height and stop hash', () => {
  const message = encodeGetCFHeaders({ startHeight: 2, stopHash: CHILD_DISPLAY });
  assert.equal(message.length, 1 + 4 + 32);
  assert.equal(message[0], 0x00, 'basic filter type');
  assert.equal(hex.encode(message.slice(1, 5)), '02000000', 'height 2, little-endian');
  assert.equal(hex.encode(message.slice(5, 37)), hex.encode(hex.decode(CHILD_DISPLAY).reverse()));
  // The same four bytes, bounded the same way, for the same reason: 2^32 would
  // wrap to zero and ask for the chain from genesis.
  assert.throws(() => encodeGetCFHeaders({ startHeight: 2 ** 32, stopHash: CHILD_DISPLAY }), /start height/);
  assert.throws(() => encodeGetCFHeaders({ startHeight: -1, stopHash: CHILD_DISPLAY }), /start height/);
  witness('getcfheaders', `height 2`, `stop ${CHILD_DISPLAY.slice(0, 16)}`);
});

test('cfheaders answers with filter hashes in order, under the header they continue', () => {
  const message = encodeCfHeaders({
    stopHash: CHILD_DISPLAY,
    prevFilterHeader: FILTER_HEADER_1,
    filterHashes: [FILTER_HEADER_2],
  });
  assert.equal(message.length, 1 + 32 + 32 + 1 + 32);
  assert.equal(message[0], 0x00);
  assert.equal(hex.encode(message.slice(1, 33)), hex.encode(hex.decode(CHILD_DISPLAY).reverse()));
  const decoded = decodeCfHeaders(message);
  assert.equal(decoded.stopHash, CHILD_DISPLAY);
  assert.equal(decoded.prevFilterHeader, FILTER_HEADER_1);
  assert.deepEqual(decoded.filterHashes, [FILTER_HEADER_2]);
  // What the answer means: a filter header is the previous one continued, which
  // is the field the fixture carries for exactly this row. A peer that skips or
  // reorders a filter breaks the chain here rather than quietly serving a
  // shorter range.
  assert.equal(
    FILTER_HEADER_2,
    hex.encode(filterHeader(hex.decode(FILTER_2[5]), hex.decode(FILTER_2[4]))),
    'the row’s own filter, continued under the header it names',
  );
  assert.notEqual(
    FILTER_HEADER_2,
    FILTER_2[4],
    'a filter header that equals the one it continues would make this pin vacuous',
  );
  witness('cfheaders', `prev ${FILTER_HEADER_1.slice(0, 16)}`, `next ${FILTER_HEADER_2.slice(0, 16)}`);
});

test('a cfheaders answer whose count and bytes disagree is refused', () => {
  const message = encodeCfHeaders({
    stopHash: CHILD_DISPLAY,
    prevFilterHeader: FILTER_HEADER_1,
    filterHashes: [FILTER_HEADER_2, FILTER_HEADER_2],
  });
  assert.throws(() => decodeCfHeaders(message.slice(0, message.length - 1)), /disagree|cut short/);
  // Truncated before its count byte: refused too, and not by reading a count
  // out of the middle of a hash.
  assert.throws(() => decodeCfHeaders(message.slice(0, 1 + 64)), /disagree|cut short|count/);
});

test('an empty headers answer is a valid answer, and it is not a refusal', () => {
  // A peer that has nothing after the locator sends count 0. That is a fact
  // about the peer's view, and the caller — not this parser — decides whether
  // it means "at the tip" or "a lying peer".
  const decoded = decodeHeaders(Uint8Array.of(0));
  assert.deepEqual(decoded.headers, []);
});

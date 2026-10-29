// The byte order of a block hash on the wire.
//
// Bitcoin writes a hash in internal (little-endian) order; the order a person
// and a peer name a block in is the reverse. Get this wrong and every message
// names a block that does not exist — the wallet would be asking about
// "20782a00…" while the block is called "00000000…2a7820". Nothing on screen
// would say so, which is exactly why it needs a pin.
//
// The ground truth here is not my word: a block's own header carries its
// parent's hash in internal order, in bytes 4..36. The published BIP-158
// testnet-19 vectors include the block at height 2 and the block at height 3,
// and the height-3 header names the height-2 block. So a getdata naming the
// height-2 block, spelled the way a person spells it, must contain exactly the
// bytes the height-3 header carries.
//
// This pin was built from fixture bytes, not from a captured frame: no live
// peer was reachable when this was written. The header field is the same
// encoding a frame carries, so it pins the same bytes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import {
  decodeCfilter,
  decodeGetCfilters,
  decodeGetData,
  encodeCfilter,
  encodeGetCfilters,
  encodeGetData,
} from '../src/wire.js';

const VECTORS = JSON.parse(
  readFileSync(new URL('./fixtures/bip158-testnet-19.json', import.meta.url), 'utf8'),
).slice(1).map((row) => row.map((field) => (typeof field === 'string' ? field.replace(/ /g, '') : field)));

const HEIGHT_2 = VECTORS[1];
const HEIGHT_3 = VECTORS[2];

const PARENT_DISPLAY = HEIGHT_2[1];
// The bytes the height-3 header carries for its parent: internal order.
const PARENT_INTERNAL = hex.encode(hex.decode(HEIGHT_3[2]).slice(4, 36));

function witness(name, ...values) {
  console.log(`[order] ${name}: ${values.join(' | ')}`);
}

test('a block’s own header names its parent in internal order, which is the reverse of its display hash', () => {
  const reversed = hex.encode(hex.decode(PARENT_DISPLAY).reverse());
  assert.equal(PARENT_INTERNAL, reversed);
  assert.notEqual(PARENT_INTERNAL, PARENT_DISPLAY, 'if these were equal this pin would prove nothing');
  witness('parent of height 3', `display ${PARENT_DISPLAY.slice(0, 16)}`, `internal ${PARENT_INTERNAL.slice(0, 16)}`);
});

test('getdata carries the hash in internal order and decodes back to the display hash', () => {
  const message = encodeGetData({ hash: PARENT_DISPLAY });
  assert.equal(message.length, 1 + 4 + 32);
  // Byte 0 is the count, 1..5 the type; the hash follows.
  assert.equal(hex.encode(message.slice(5)), PARENT_INTERNAL);
  // Round trip: a peer reading this frame names the same block we do.
  const decoded = decodeGetData(message);
  assert.equal(decoded.hash, PARENT_DISPLAY);
  witness('getdata', `carried ${hex.encode(message.slice(5, 13))}`, `decoded ${decoded.hash.slice(0, 16)}`);
});

test('getcfilters carries the stop hash in internal order and decodes back', () => {
  const message = encodeGetCfilters({ startHeight: 0, stopHash: PARENT_DISPLAY });
  assert.equal(message.length, 37);
  assert.equal(hex.encode(message.slice(5)), PARENT_INTERNAL);
  assert.equal(decodeGetCfilters(message).stopHash, PARENT_DISPLAY);
  witness('getcfilters', `carried ${hex.encode(message.slice(5, 13))}`);
});

test('cfilter carries the block hash in internal order and decodes back', () => {
  const filter = Uint8Array.of(0x01, 0x02, 0x03);
  const message = encodeCfilter({ blockHash: PARENT_DISPLAY, filter });
  assert.equal(hex.encode(message.slice(1, 33)), PARENT_INTERNAL);
  const decoded = decodeCfilter(message);
  assert.equal(decoded.blockHash, PARENT_DISPLAY);
  assert.equal(hex.encode(decoded.filter), hex.encode(filter));
  witness('cfilter', `carried ${hex.encode(message.slice(1, 9))}`, `decoded ${decoded.blockHash.slice(0, 16)}`);
});

test('a count written in a padded form is refused, because no peer would send one', () => {
  // The same three-byte filter, spelled two ways. 0x03 is the canonical
  // CompactSize; 0xfd 0x03 0x00 says the same number in a form Bitcoin Core
  // refuses. If this wallet accepts both, one sender decides how many encodings
  // of a message exist.
  const filter = Uint8Array.of(0x01, 0x02, 0x03);
  const canonical = encodeCfilter({ blockHash: PARENT_DISPLAY, filter });
  assert.equal(canonical[33], 3);
  assert.equal(decodeCfilter(canonical).filter.length, 3);

  const padded = new Uint8Array([...canonical.slice(0, 33), 0xfd, 0x03, 0x00, ...filter]);
  assert.throws(() => decodeCfilter(padded), /padded form/);

  // getdata's transaction count is the same kind of count, read the same way.
  const getdata = encodeGetData({ hash: PARENT_DISPLAY });
  assert.equal(getdata[0], 1);
  assert.throws(() => decodeGetData(new Uint8Array([0xfd, 0x01, 0x00, ...getdata.slice(1)])), /padded form/);
  witness('padded counts', 'cfilter refused', 'getdata refused');
});

test('a hash written in the wrong order does not survive a round trip', () => {
  // The mutation this pin exists for: if the conversion is removed from both
  // sides symmetrically, a round trip still passes — so the assertion above on
  // the raw bytes is the one that catches it. This case shows that the bytes
  // really do change, so "it round trips" is never mistaken for "it is right".
  const message = encodeGetData({ hash: PARENT_DISPLAY });
  assert.notEqual(hex.encode(message.slice(5)), PARENT_DISPLAY);
  // And a hash that is not 32 bytes is refused rather than half-converted.
  assert.throws(() => encodeGetData({ hash: 'ab'.repeat(31) }), /32 bytes/);
  assert.throws(() => encodeGetCfilters({ startHeight: 0, stopHash: '' }), /32 bytes/);
  // Not hex at all is refused by the decoder, not by the length check.
  assert.throws(() => encodeCfilter({ blockHash: 'zz'.repeat(32), filter: Uint8Array.of(1) }), /Unknown letter/);
});

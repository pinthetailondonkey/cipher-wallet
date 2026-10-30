// Reading one Monero block: what this file is, said first because a caller will
// read this line before any other.
//
// IT DOES NOT READ BLOCK BODIES. It parses a block HEADER, and it REFUSES every
// block body, out loud, because the body model this file used to carry was not
// Monero's. The refusal is the point of the file: a reader that refuses cannot
// mislead the next lane, and a reader that emits a confident wrong identity can.
//
// Two defects were found after the first version of this file shipped green
// (commit 80ba48d, reviewed by ADJUDICATOR, both EXECUTED):
//
//   F1 — THE BODY IS NOT THE SHAPE THIS REPOSITORY MODELLED. Monero's block
//   blob is `header || miner_tx || varint(tx_hash_count) || 32-byte hash ×
//   count`. The first version read a FULL TRANSACTION after the count, and its
//   own test writer built that same fictional layout, so 382 green tests passed
//   against bytes no node emits. The fixtures and the parser were written by the
//   same hand; that is exactly why the suite could not see it.
//
//   F2 — THE TRANSACTION ID RULE WAS NEVER MONERO'S for version 2. A v2 id is
//   `cn_fast_hash(prefix_hash || base_rct_hash || prunable_or_null_hash)`. The
//   first version hashed the prefix alone and included the RingCT type byte in
//   it. Every real miner transaction is version 2, so every id it would have
//   emitted was wrong — and its test checked only that the id was 64 hex
//   characters. A shape check is not a value check.
//
// SO THIS DOOR REFUSES. Not because refusing is useful — it is not — but
// because the alternative is a wrong identity wearing the shape of a fact. The
// fix is not more prose: it is one real (bytes, hash) pair pinned against
// Monero's own output, and then a body model built to it. Until that pair
// exists, nothing here may gate a payment, and no fixture written by this
// repository may stand in for it.
//
// The header parser below is kept because the header layout is not in dispute
// (two version varints, a timestamp, the previous id, a four-byte nonce) and
// because it is what a future body model will start from. It proves nothing
// about which block it belongs to: Monero's header carries no height, and the
// block id rule is unpinned.

import { hex } from '@scure/base';
import { readVarint } from './keys.js';

class Cursor {
  constructor(bytes, label = 'block header') {
    if (!(bytes instanceof Uint8Array)) throw new Error('A header is read from bytes.');
    this.bytes = bytes;
    this.at = 0;
    this.label = label;
  }

  get left() {
    return this.bytes.length - this.at;
  }

  take(length, what) {
    const n = Number(length);
    if (this.at + n > this.bytes.length) {
      throw new Error(`That ${this.label} is cut short: ${what} needs ${n} bytes and ${this.left} are left.`);
    }
    const out = this.bytes.slice(this.at, this.at + n);
    this.at += n;
    return out;
  }

  varint(what) {
    let read;
    try {
      read = readVarint(this.bytes, this.at);
    } catch {
      throw new Error(`That ${this.label} is cut short: ${what} is not a complete varint.`);
    }
    this.at += read.length;
    return read.value;
  }

  hex(length, what) {
    return hex.encode(this.take(length, what));
  }
}

// The header Monero uses: two versions, a timestamp, the parent id and a
// four-byte nonce. It has no height field, which is why heights are counted by
// a walk rather than read from a block.
export function parseBlockHeader(bytes) {
  const cursor = new Cursor(bytes);
  const major = cursor.varint('header major version');
  const minor = cursor.varint('header minor version');
  const timestamp = cursor.varint('header timestamp');
  const prevId = cursor.hex(32, 'header previous id');
  const nonceBytes = cursor.take(4, 'header nonce');
  const nonce = BigInt(nonceBytes[0]) | (BigInt(nonceBytes[1]) << 8n)
    | (BigInt(nonceBytes[2]) << 16n) | (BigInt(nonceBytes[3]) << 24n);
  return {
    major: Number(major),
    minor: Number(minor),
    timestamp,
    prevId,
    nonce,
    headerBytes: cursor.bytes.slice(0, cursor.at),
  };
}

// Every block body is refused. There is no flag that opens this, on purpose: a
// caller who wants the body is asking for a model this repository does not have,
// and an opt-in would be the same trap with a better-sounding name.
export function parseBlock(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('A block is read from bytes.');
  throw new Error(
    'This build will not read a block body: its byte model is not Monero\'s. '
    + 'A real block carries one miner transaction and then the hashes of the other transactions, '
    + 'not full transactions; and the transaction id rule this build carried was never correct for version 2. '
    + 'Nothing here may gate a payment until a real (bytes, hash) pair is pinned.',
  );
}

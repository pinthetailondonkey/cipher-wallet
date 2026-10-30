// Reading one Monero block, strictly.
//
// WHAT THIS FILE DOES NOT DO, said first because a caller will read this line
// before any other: it does not prove that a block is the block you asked for.
// The block id rule needs one real (bytes, hash) pair to be pinned against, and
// this repository has none — pinning our own writer's output would only prove
// that our arithmetic agrees with itself, which the README already names as the
// trap. So `parseBlock` returns `identity: { proven: false }`, and a caller that
// asks for verification is REFUSED rather than quietly given something weaker.
// Until that vector exists, nothing this file returns may gate a payment.
//
// The rest of the strictness is real, and it is deliberate:
//
//   A BLOCK IS REFUSED, NEVER A TRANSACTION SKIPPED. A transaction this build
//   cannot frame might be the one that pays this wallet. Skipping it is
//   indistinguishable from "no payment", and "no payment" is a money verdict.
//
//   AN AMOUNT IS PICONERO OR IT IS NULL. RingCT transactions carry 0 in each
//   output on the wire and put the real value in an encrypted field. A 0 read
//   as a number is not zero coins — it is an amount that was NOT DECODED, and
//   it must never be able to confirm anything. Amounts leave this file as BigInt
//   or as null; never as a JavaScript number, never rounded.
//
//   AN IDENTITY IS (TRANSACTION ID, OUTPUT INDEX). A bare transaction id, an
//   array of ids, or two ids joined into one string name more than one transfer
//   between them. This project has paid for that already.
//
//   HEIGHT IS NOT IN THE BYTES. Monero's block header carries no height, so a
//   node's claim about where a block sits cannot be checked against the block
//   itself. Count heights from a anchor, as chain.js does for Bitcoin.

import { keccak_256 } from '@noble/hashes/sha3.js';
import { hex } from '@scure/base';
import { readVarint } from './keys.js';

// The largest amount one output can carry on Monero's wire.
export const MAX_AMOUNT = 2n ** 64n - 1n;
// The highest height four bytes hold, for the same reason wire.js bounds it.
export const MAX_HEIGHT = 0xffffffffn;

const TXIN_GEN = 0n;
const TXIN_TO_KEY = 1n;
const TXOUT_TO_KEY = 2n;
const TXOUT_TO_TAGGED_KEY = 3n;

const RCT_NULL = 0n;

class Cursor {
  constructor(bytes, label = 'block') {
    if (!(bytes instanceof Uint8Array)) throw new Error('A block is read from bytes.');
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

  // A count is a claim about how many things follow. Every thing this file reads
  // is at least one byte, so a count larger than the bytes left is a lie and is
  // refused before a loop can be made to run on it.
  count(what) {
    const value = this.varint(what);
    if (value > BigInt(this.left)) {
      throw new Error(`That ${this.label} claims ${value} ${what} and has ${this.left} bytes left, so it is cut short.`);
    }
    return Number(value);
  }

  hex(length, what) {
    return hex.encode(this.take(length, what));
  }
}

function checkAmount(value, what) {
  if (value > MAX_AMOUNT) {
    throw new Error(`${what} is larger than one output can hold, so it is refused rather than wrapped.`);
  }
  return value;
}

// One transaction, from `version` through `extra`. The bytes it consumed are the
// transaction's prefix, which is what Monero hashes for the transaction id.
function readTransaction(cursor) {
  const start = cursor.at;
  const version = cursor.varint('transaction version');
  if (version !== 1n && version !== 2n) {
    throw new Error(`That transaction names version ${version}, which this build does not read.`);
  }
  cursor.varint('unlock time');

  const vinCount = cursor.count('transaction inputs');
  for (let i = 0; i < vinCount; i += 1) {
    const type = cursor.varint(`input ${i} type`);
    if (type === TXIN_GEN) {
      const height = cursor.varint(`input ${i} height`);
      if (height > MAX_HEIGHT) throw new Error(`Input ${i} names a height four bytes do not hold.`);
    } else if (type === TXIN_TO_KEY) {
      checkAmount(cursor.varint(`input ${i} amount`), `Input ${i} amount`);
      const offsets = cursor.count(`input ${i} key offsets`);
      for (let o = 0; o < offsets; o += 1) cursor.varint(`input ${i} key offset ${o}`);
      cursor.take(32, `input ${i} key image`);
    } else {
      throw new Error(`Input ${i} is a shape this build cannot read, so the block is refused rather than guessed at.`);
    }
  }

  const voutCount = cursor.count('transaction outputs');
  const outputs = [];
  for (let i = 0; i < voutCount; i += 1) {
    const amount = checkAmount(cursor.varint(`output ${i} amount`), `Output ${i} amount`);
    const target = cursor.varint(`output ${i} target type`);
    if (target !== TXOUT_TO_KEY && target !== TXOUT_TO_TAGGED_KEY) {
      throw new Error(`Output ${i} is not a one-time key, so this build cannot tell whose it is.`);
    }
    const key = cursor.take(32, `output ${i} one-time key`);
    const viewTag = target === TXOUT_TO_TAGGED_KEY ? cursor.take(1, `output ${i} view tag`)[0] : null;
    outputs.push({ index: i, key, viewTag, amountPiconero: amount, encrypted: false });
  }

  const extraLength = cursor.varint('extra field length');
  const extra = cursor.take(extraLength, 'extra field');

  // Version 2 carries a RingCT section after the prefix. Only the null type is
  // read here: it means "amounts are in the clear", and it is what a coinbase
  // transaction uses. Every encrypted type needs its proof sizes pinned to a
  // real block before this file may frame one, because a wrong size would shift
  // every following transaction without a word.
  if (version === 2n) {
    const type = cursor.varint('RingCT type');
    if (type !== RCT_NULL) {
      throw new Error(
        `That transaction uses RingCT type ${type}. This build reads type 0 only, so the block is refused — `
        + 'an encrypted amount has not been decoded, and an undecoded amount is not zero coins.',
      );
    }
  }

  const prefix = cursor.bytes.slice(start, cursor.at);
  return {
    version: Number(version),
    txid: hex.encode(keccak_256(prefix)),
    outputs,
    extra,
    prefixBytes: prefix.length,
  };
}

// The 80-byte-shaped header Monero uses: two versions, a timestamp, the parent
// id and a four-byte nonce. It has no height field, and that absence is the
// reason heights are counted by a walk rather than read from a block.
export function parseBlockHeader(bytes) {
  const cursor = new Cursor(bytes, 'block header');
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

// Parse one block blob. See the header of this file for what is NOT proven.
//
// `expectHash` exists so a caller cannot ask this file to check an identity it
// cannot check: passing one is REFUSED, on purpose. When the block id rule is
// pinned, this is the line that changes, and the test named for the gap is the
// one that will say so.
export function parseBlock(bytes, { expectHash } = {}) {
  if (expectHash !== undefined) {
    throw new Error('This build cannot prove a block is the block you asked for, so it will not claim to. The block id rule needs a real sample pinned first.');
  }
  const cursor = new Cursor(bytes);
  const header = parseBlockHeader(bytes);
  cursor.at = header.headerBytes.length;

  const miner = readTransaction(cursor);
  const count = cursor.count('transactions');
  const transactions = [miner];
  for (let i = 0; i < count; i += 1) transactions.push(readTransaction(cursor));

  if (cursor.left !== 0) {
    throw new Error(`That block has ${cursor.left} bytes left after its last transaction, so its shape is not one this build reads.`);
  }

  const seen = new Set();
  for (const tx of transactions) {
    if (seen.has(tx.txid)) {
      throw new Error(`Transaction ${tx.txid} appears twice in one block, so an identity here names more than one transfer.`);
    }
    seen.add(tx.txid);
  }

  return {
    header,
    miner,
    transactions: transactions.slice(1),
    // The gap, where a caller will hit it rather than in a README.
    identity: {
      proven: false,
      because: 'The block id rule is not pinned to a real sample yet, so this block has no proven identity.',
    },
  };
}

// What a caller must do with a parsed block before it may act on it.
export function assertBlockIdentityProven(block) {
  if (!block?.identity?.proven) {
    throw new Error('This block has no proven identity. It may be parsed, but nothing it says can move a payment.');
  }
  return block;
}

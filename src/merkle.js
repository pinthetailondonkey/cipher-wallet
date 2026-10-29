// A block body against its own header: the merkle root.
//
// A header is 80 bytes and names two things about the body that follows it: the
// previous block, and a merkle root that the body's transactions must produce.
// Hashing the header tells you the header is the block you asked for. It says
// nothing at all about whether the body is that block's body. Without this
// check a peer keeps a real, public header, attaches any transactions it likes,
// and every other check passes: the header hashes to the advertised hash, and a
// filter built from the forged body matches the filter built from the forged
// body.
//
// That is the difference between "the block is a third witness" and a sentence
// that sounds like it. With the body checked, two peers that agree on a
// fabricated filter cannot produce a body that both pays our script and hashes
// to the header's root.
//
// The txid is computed from the bytes that arrived, with the witness cut out at
// the offsets the parser reports — not by re-serializing the parsed fields.
// Re-serializing would make the answer depend on this build's encoder agreeing
// with the sender's, and a disagreement would read as a lie by the peer.

import { hex } from '@scure/base';
import { parseTx, readVarint, reverseBytes, sha256d } from './tx.js';

const HEADER_SIZE = 80;

function concat(left, right) {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

// The hash a transaction is named by, from its own bytes, in display order.
// The non-witness serialization is version, the inputs, the outputs and the
// locktime: the two-byte marker/flag and the witness stacks come out. Removing
// only the stacks and leaving the marker/flag in produces a well-formed hash of
// a transaction that does not exist — which is how this was written first, and
// the published BIP-158 vectors caught it.
export function txidOf(bytes, offset, tx) {
  const start = offset;
  const end = offset + tx.size;
  // With a witness the marker sits at start+4; without one, the inputs begin
  // there. For a transaction with no witness, bodyEnd and lockTimeStart are the
  // same offset, so the tail is the locktime and nothing else.
  const body = tx.witness
    ? concat(bytes.slice(start, start + 4), bytes.slice(start + 6, start + tx.bodyEnd))
    : bytes.slice(start, start + tx.bodyEnd);
  const tail = bytes.slice(start + tx.lockTimeStart, end);
  return hex.encode(reverseBytes(sha256d(concat(body, tail))));
}

// The merkle root a list of transaction ids produces, in display order.
//
// An odd node at the end of a level is paired with itself — that is the
// protocol, and it is also why a block containing the same transaction twice is
// refused below rather than silently hashing to the same root as a shorter
// block (CVE-2012-2459).
export function merkleRootOf(txids) {
  if (!Array.isArray(txids) || txids.length === 0) throw new Error('A block has at least one transaction.');
  let level = txids.map((id) => {
    const text = String(id ?? '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(text)) throw new Error('A transaction id is 64 hex characters.');
    return reverseBytes(hex.decode(text));
  });
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? left;
      next.push(sha256d(concat(left, right)));
    }
    level = next;
  }
  return hex.encode(reverseBytes(level[0]));
}

// The root the header names, in display order (bytes 36..68 are internal order).
export function headerMerkleRoot(header) {
  if (!(header instanceof Uint8Array) || header.length < HEADER_SIZE) {
    throw new Error('A block header is 80 bytes.');
  }
  return hex.encode(reverseBytes(header.slice(36, 68)));
}

// Read a block's body, check it against the header it arrived under, and refuse
// if they disagree. Returns the transactions for callers that need them, but
// only after the body has been shown to be the body the header names.
export function verifyBlockBody(blockBytes) {
  if (!(blockBytes instanceof Uint8Array) || blockBytes.length < HEADER_SIZE + 1) {
    throw new Error('A block is at least a header and a transaction count.');
  }
  const header = blockBytes.slice(0, HEADER_SIZE);
  const count = readVarint(blockBytes, HEADER_SIZE);
  if (count.value === 0) throw new Error('A block has at least one transaction.');

  const transactions = [];
  const txids = [];
  const seen = new Set();
  let at = count.offset;
  for (let i = 0; i < count.value; i += 1) {
    const tx = parseTx(blockBytes, { offset: at, exact: false });
    const id = txidOf(blockBytes, at, tx);
    if (seen.has(id)) {
      throw new Error(`That block carries transaction ${id} twice, which is not a block this wallet will read.`);
    }
    seen.add(id);
    txids.push(id);
    transactions.push(tx);
    at += tx.size;
  }
  if (at !== blockBytes.length) throw new Error('That block has bytes after its last transaction.');

  const root = merkleRootOf(txids);
  const named = headerMerkleRoot(header);
  if (root !== named) {
    throw new Error(`That block's transactions produce merkle root ${root}, and its header names ${named}, so the body is not the body that header commits to.`);
  }
  return { blockHash: hex.encode(reverseBytes(sha256d(header))), txids, merkleRoot: root, transactions };
}

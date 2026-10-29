// Walking a chain of blocks, where every link is checked.
//
// A peer is asked for a block by hash and answers with bytes. The bytes are
// hashed here; if they do not hash to the hash that was asked for, they are not
// that block, whatever the peer called them. And a block names the block before
// it, so a walk can also check that the chain joins: a peer that serves a valid
// block with a valid hash for the wrong position is caught by the link, not by
// the label.
//
// Nothing here trusts a height. Heights come from the chain; a peer that lies
// about one is corrected by the next link or the walk stops.

import { hex } from '@scure/base';
import { reverseBytes, sha256d } from './tx.js';
import { verifyBlockBody } from './merkle.js';

const HEADER_SIZE = 80;

export function blockHeader(block) {
  if (!(block instanceof Uint8Array) || block.length < HEADER_SIZE) {
    throw new Error('A block is at least an 80-byte header.');
  }
  return block.slice(0, HEADER_SIZE);
}

// The hash a block is named by, in display order (the order a peer and a
// person write it in).
export function blockHash(block) {
  return hex.encode(reverseBytes(sha256d(blockHeader(block))));
}

export function headerHash(header) {
  if (!(header instanceof Uint8Array) || header.length !== HEADER_SIZE) {
    throw new Error('A block header is 80 bytes.');
  }
  return hex.encode(reverseBytes(sha256d(header)));
}

// The block a header points back to, in display order.
export function previousBlockHash(block) {
  return hex.encode(reverseBytes(blockHeader(block).slice(4, 36)));
}

// Does `block` name `previous.header` as its predecessor? Checked on the header
// bytes, so it works for a header whose block body is not at hand.
export function headerConnects(previousHeader, block) {
  return headerHash(previousHeader) === previousBlockHash(block);
}

export function blockConnects(previousBlock, block) {
  return headerConnects(blockHeader(previousBlock), block);
}

// Walk backwards from a tip hash, one block at a time, until `stopHash`,
// `maxSteps`, or a link that does not hold. Every block is re-hashed and every
// link is checked; the walk returns blocks newest first.
//
// `fetchBlock(peer, hash)` is `client.fetchBlock` from peerClient.js: it returns
// { bytes }. The hash check lives here rather than in the transport, because it
// is this module that knows which block it asked for.
export async function walkBack({ fetchBlock, peer, tipHash, stopHash = null, maxSteps = 1000, onBlock } = {}) {
  if (typeof fetchBlock !== 'function') throw new Error('A walk needs a way to fetch a block.');
  const tip = String(tipHash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(tip)) throw new Error('A tip hash is 64 hex characters.');
  const stop = stopHash ? String(stopHash).trim().toLowerCase() : null;

  const blocks = [];
  let asked = tip;
  let previous = null;
  for (let step = 0; step < maxSteps; step += 1) {
    const { bytes } = await fetchBlock(peer, asked);
    const actual = blockHash(bytes);
    if (actual !== asked) {
      throw new Error(`That peer served block ${actual}, not ${asked}.`);
    }
    // The hash above says the header is the block that was asked for. It says
    // nothing about the body: a real header travels with whatever body the peer
    // attaches. Checked here so a walk never carries a body its header does not
    // commit to.
    const body = verifyBlockBody(bytes);
    if (previous && !blockConnects(bytes, previous)) {
      // The block we already accepted says its parent is X; this block hashes
      // to X but is not the parent on that same header check only if the bytes
      // disagree. Kept as a separate refusal so a walk bug cannot hide behind
      // the hash check above.
      throw new Error(`Block ${actual} does not connect to ${blockHash(previous)}.`);
    }
    blocks.push({ hash: actual, bytes, body });
    await onBlock?.({ hash: actual, bytes, body });
    if (stop && actual === stop) return blocks;
    const parent = previousBlockHash(bytes);
    if (parent === '0'.repeat(64)) return blocks;
    previous = bytes;
    asked = parent;
  }
  throw new Error(`The walk did not reach a stop after ${maxSteps} blocks.`);
}

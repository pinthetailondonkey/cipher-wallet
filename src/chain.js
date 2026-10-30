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

// Walk FORWARD through headers from an anchor, counting heights from it.
//
// getheaders only answers forwards: a locator names a block the wallet already
// has, and a peer sends what comes after. So a header-first walk cannot be a
// cheaper version of walkBack — it has to start somewhere this wallet already
// believes, and that place is the anchor.
//
// `anchorHash` and `anchorHeight` are required and have no default. That is
// deliberate, not an oversight: a pinned checkpoint is this wallet asserting
// which chain is real, and no line of code here is allowed to make that choice.
// The founder names a block by hand or this walk does not run.
//
// Heights are COUNTED from the anchor. A peer never supplies one, and a count
// that would pass what four bytes hold is refused rather than wrapped — the
// same bound the wire writers carry, checked before it can be written.
export async function walkHeadersForward({ fetchHeaders, peer, anchorHash, anchorHeight, tipHash = null, maxSteps = 2000, onHeader } = {}) {
  if (typeof fetchHeaders !== 'function') throw new Error('A header walk needs a way to fetch headers.');
  const anchor = String(anchorHash ?? '').trim().toLowerCase();
  // Two refusals, two sentences. Sharing one sentence made the pair
  // indistinguishable to a test — removing the hash check left the height check
  // throwing the same words, and the mutation came back green.
  if (!/^[0-9a-f]{64}$/.test(anchor)) {
    throw new Error('A header walk starts from the hash of a block this wallet already trusts. There is no default anchor.');
  }
  if (!Number.isInteger(anchorHeight) || anchorHeight < 0) {
    throw new Error('A header walk starts from the height the anchor sits at, so heights can be counted rather than believed.');
  }
  const tip = tipHash ? String(tipHash).trim().toLowerCase() : null;
  if (tip && !/^[0-9a-f]{64}$/.test(tip)) throw new Error('A tip hash is 64 hex characters.');

  const walked = [];
  let previous = anchor;
  let height = anchorHeight;
  for (let step = 0; step < maxSteps; step += 1) {
    const answer = await fetchHeaders(peer, {
      locator: [previous],
      stopHash: tip ?? '00'.repeat(64),
    });
    const headers = Array.isArray(answer?.headers) ? answer.headers : [];
    if (headers.length === 0) {
      if (tip) throw new Error(`The headers stopped short of ${tip}, so this walk did not reach the tip it was told to reach.`);
      return walked;
    }
    for (const header of headers) {
      // Counted before it is used: a height past 0xffffffff would wrap, and a
      // wrapped height is the genesis question in another coat.
      if (height + 1 > 0xffffffff) {
        throw new Error('That walk counted past the highest height four bytes hold, so it stopped instead of wrapping.');
      }
      const hash = headerHash(header);
      const parent = previousBlockHash(header);
      if (parent !== previous) {
        throw new Error(`Header ${hash} does not connect to ${previous}, so the chain this peer served has a gap.`);
      }
      height += 1;
      walked.push({ hash, height, header });
      await onHeader?.({ hash, height, header });
      previous = hash;
      if (tip && hash === tip) return walked;
    }
  }
  throw new Error(`The walk did not reach a stop after ${maxSteps} header batches.`);
}

// Walk backwards from a tip hash, one block at a time, until `stopHash`,
// `maxSteps`, or a link that does not hold. Every block is re-hashed and every
// link is checked; the walk returns blocks newest first.
//
// `fetchBlock(peer, hash)` is `client.fetchBlock` from peerClient.js: it returns
// { bytes }. The hash check lives here rather than in the transport, because it
// is this module that knows which block it asked for.
export async function walkBack({ fetchBlock, peer, tipHash, tipHeight, stopHash = null, maxSteps = 1000, onBlock } = {}) {
  if (typeof fetchBlock !== 'function') throw new Error('A walk needs a way to fetch a block.');
  const tip = String(tipHash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(tip)) throw new Error('A tip hash is 64 hex characters.');
  const stop = stopHash ? String(stopHash).trim().toLowerCase() : null;
  // A walk steps its parent's parent, so it knows one height per block, and it
  // is the only thing in this wallet that does. Required, not defaulted: a walk
  // that guesses a height hands a filter question the wrong range.
  if (!Number.isInteger(tipHeight) || tipHeight < 0) {
    throw new Error('A walk starts from the height of its tip. Without it, no block it finds can be asked for a filter.');
  }

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
    blocks.push({ hash: actual, height: tipHeight - step, bytes, body });
    await onBlock?.({ hash: actual, bytes, body });
    if (stop && actual === stop) return blocks;
    const parent = previousBlockHash(bytes);
    if (parent === '0'.repeat(64)) return blocks;
    previous = bytes;
    asked = parent;
  }
  throw new Error(`The walk did not reach a stop after ${maxSteps} blocks.`);
}

// The node driver for a block scan: fetch, then prove, then look for our own
// outputs. The layer that was missing between nodeClient and ownOutputs.
//
// The division is deliberate and each half owes the other nothing it cannot
// check. nodeClient fetches bytes and refuses to believe the node's own claims;
// ownOutputsInBlock proves the block and every transaction before a pocket sees
// anything. This module's only job is to call them in that order, and to hand
// the block's identity from the fetch (what was ASKED for) into the proof as the
// thing the bytes must equal.
//
// WHAT IS PASSED AS `expectHash`. When the caller asked by hash, that hash. When
// they asked by height, the id is not known yet, so the block is fetched, its id
// is proven, and THEN the proof is re-run against the proven id — a height read
// is a request for "whatever block is at N", and the node's own height claim is
// only a claim. The fetch already refuses a height disagreement, so the two
// checks together mean a node cannot serve a different block than either one.
//
// WHAT THIS DOES NOT DO, said plainly:
//   - it scans ONE block. Walking a range, and deciding which chain is the real
//     one when peers disagree, is not here and is not in this build at all.
//   - it takes no pool by default. A caller that cares about node rotation
//     passes one; the nodeClient rules for a pool are unchanged.
//   - it does not decide whether a found output is spendable, or what it is
//     worth in fiat; those are later layers.

import { getBlock, getTransactions } from './nodeClient.js';
import { ownOutputsInBlock } from './ownOutputs.js';
import { parseBlock } from './block.js';

// Fetch one block and scan it for `pockets`.
//
// `hash` or `height`, exactly one, as nodeClient's own door requires.
export async function scanBlockFromNode(node, {
  hash, height, pockets, trustViewTags = true, ...options
} = {}) {
  if (!Array.isArray(pockets)) throw new Error('A node scan takes the pockets as a list.');

  const fetched = await getBlock(node, { hash, height }, options);
  const blob = fetched.blob;

  // The transaction bytes. The daemon's hash list is only a claim, so the walk
  // will prove every one of them; the list is used here solely to know WHAT to
  // ask for, and a count mismatch is caught by the walk.
  const hashes = fetched.txHashes;
  const txBytesList = hashes.length === 0
    ? []
    : (await getTransactions(node, hashes, options)).bytes;

  // A hash request is proved against the hash that was asked for.
  if (fetched.askedByHash !== null) {
    return {
      ...ownOutputsInBlock({
        blockBytes: blob, txBytesList, pockets, trustViewTags, expectHash: fetched.askedByHash,
      }),
      node: fetched.address,
      askedByHash: fetched.askedByHash,
      askedByHeight: null,
    };
  }

  // A height request: prove the id from the bytes first, then prove the scan
  // against that id, so nothing downstream rides on the node's height claim.
  const proven = parseBlock(blob);
  const out = ownOutputsInBlock({ blockBytes: blob, txBytesList, pockets, trustViewTags, expectHash: proven.id });
  return {
    ...out,
    node: fetched.address,
    askedByHash: null,
    askedByHeight: fetched.askedByHeight,
    nodeClaimedHeight: fetched.claimedHeight,
  };
}

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
// WHAT A HEIGHT REQUEST CAN AND CANNOT ANCHOR. A Monero block HEADER carries no
// height field, so one block's bytes cannot prove they are at height N — the
// only link to N is the fetching node's `block_header.height`, which getBlock
// already cross-checks. So a height scan is anchored by the node, and a block
// scan is anchored by nothing but itself, unless the caller passes `expectHash`
// (or asks by hash, which is the same anchor for free). That is a property of one
// block, not a defect, and it is why `anchored` exists in the result. What a later range walk would
// add — linking each block to its parent, and so pinning a height by counting —
// is not in this build.
//
// So the height branch parses ONCE. Taking the parsed id and passing it back as
// `expectHash` (the obvious reading of "re-prove") is a tautology: parseBlock is
// deterministic, so the second parse re-derives the same id from the same bytes
// and cannot fail. Proven once is enough; the result is labelled self-consistent.
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

// Fetch one block and scan it for `pockets`.
//
// `hash` or `height`, exactly one, as nodeClient's own door requires.
//
// `expectHash` is the optional outside anchor for a HEIGHT request: the block id
// the caller already believes belongs there. A height alone anchors nothing (see
// the header), so a caller who knows which block they mean should pass it, or
// ask by hash and get the same anchor for free. On a HASH request it is allowed
// and simply loses: the asked-for hash is already the anchor, and two anchors
// would need a rule for disagreeing with each other.
export async function scanBlockFromNode(node, {
  hash, height, pockets, expectHash, trustViewTags = true, ...options
} = {}) {
  if (!Array.isArray(pockets)) throw new Error('A node scan takes the pockets as a list.');

  const fetched = await getBlock(node, { hash, height }, options);

  // The anchor, if there is one. An asked-for hash IS the anchor; otherwise the
  // caller must supply one, or the scan is self-consistent only.
  let anchor = fetched.askedByHash;
  if (anchor === null && expectHash !== undefined) {
    anchor = String(expectHash).trim().toLowerCase();
    if (anchor !== '' && !/^[0-9a-f]{64}$/.test(anchor)) throw new Error('A block anchor is 64 hex characters.');
    if (anchor === '') anchor = null;
  }

  const blob = fetched.blob;

  // The transaction bytes. The list here is the DAEMON's claim about which
  // transactions the block holds; it decides only what to ask for. The block's
  // own list is derived from its bytes inside ownOutputsInBlock, and the walk
  // compares the fetched bytes against THAT, so a wrong claim is caught there
  // and not believed here.
  const hashes = fetched.txHashes;
  const txAnswer = hashes.length === 0 ? { bytes: [], outputIndices: [] } : await getTransactions(node, hashes, options);
  const txBytesList = txAnswer.bytes;

  const out = ownOutputsInBlock({
    blockBytes: blob,
    txBytesList,
    pockets,
    trustViewTags,
    // The daemons' global output indices for each transaction's outputs, aligned
    // with txBytesList order. A found output whose transaction has a served list
    // gets its absolute chain position attached (the number rings are relative
    // to), which is what makes the row spendable without a second query.
    outputIndicesPerTx: txAnswer.outputIndices,
    ...(anchor !== null ? { expectHash: anchor } : {}),
  });

  return {
    ...out,
    node: fetched.address,
    askedByHash: fetched.askedByHash,
    askedByHeight: fetched.askedByHeight,
    nodeClaimedHeight: fetched.claimedHeight,
    expectHash: anchor,
    // True only when the id was proved against something outside the block.
    anchored: anchor !== null,
  };
}

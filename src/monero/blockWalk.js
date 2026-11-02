// The block walk: a block's own hash list, checked against its transactions'
// real bytes. LANE B of the L4 work order.
//
// What this module owns: given a parsed block (parseBlock's output: its
// computed id, its hash list, its tree root) and the real bytes of the block's
// non-miner transactions, read every transaction from its bytes and prove that
// the id computed from those bytes equals the block's own hash-list entry at
// that index. Then prove the tree root still matches: the block's txTreeRoot,
// computed from miner id + hash list, must also be reproducible from the ids
// the bytes proved. No node claim is trusted anywhere: the hash list is read
// from the block's bytes, and each entry is re-proved from transaction bytes.
//
// Refusals are named, per the law:
//   - "bytes and list do not agree" - a tx id disagrees with its hash-list slot
//   - "the count and the list do not agree" - a count mismatch
//   - missing bytes for a listed hash: "the walk is missing transaction bytes"

import { readTransaction, transactionIdOf, txTreeRootOf } from './block.js';
import { hex } from '@scure/base';

export function walkBlockTxs(block, txBytesList) {
  if (!block || !Array.isArray(block.txHashes)) {
    throw new Error('A walk needs a parsed block with its own hash list.');
  }
  if (!Array.isArray(txBytesList)) {
    throw new Error('A walk needs the transaction bytes as an array.');
  }
  if (txBytesList.length !== block.txHashes.length) {
    throw new Error(
      `the count and the list do not agree: the block lists ${block.txHashes.length} transactions, ${txBytesList.length} were fetched`,
    );
  }

  const provenIds = [];
  for (let i = 0; i < txBytesList.length; i += 1) {
    const bytes = txBytesList[i];
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      throw new Error(`the walk is missing transaction bytes for hash-list index ${i}`);
    }
    const tx = readTransaction(bytes, 0, `block transaction ${i}`);
    if (tx.end !== bytes.length) {
      throw new Error(
        `block transaction ${i}: the walk ended at byte ${tx.end} of ${bytes.length}; a leftover byte is a framing lie`,
      );
    }
    const id = transactionIdOf(tx);
    const listed = block.txHashes[i];
    if (id !== listed) {
      throw new Error(
        `bytes and list do not agree: hash-list index ${i} claims ${listed}, the bytes prove ${id}`,
      );
    }
    provenIds.push(id);
  }

  // The tree root from the ids the bytes proved must equal the root the block
  // itself carries. The block's txTreeRoot was computed from minerId + hash
  // list; here the same miner id is reused (it was proved from the block's own
  // bytes inside parseBlock), and the tx ids now carry byte-level proof.
  const rootFromProven = hex.encode(txTreeRootOf([
    hex.decode(block.minerTxId),
    ...provenIds.map((id) => hex.decode(id)),
  ]));
  if (rootFromProven !== block.txTreeRoot) {
    throw new Error(
      `bytes and list do not agree: the proven ids build tree root ${rootFromProven}, the block claims ${block.txTreeRoot}`,
    );
  }
  return { ids: provenIds, txTreeRoot: rootFromProven };
}

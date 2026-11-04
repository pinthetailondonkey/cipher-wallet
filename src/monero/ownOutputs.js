// Lane C: the wallet's own outputs, found in a scan that was PROVED first.
//
// This is the join of four things that each existed and refused to trust the
// next: parseBlock proves a block's id from its bytes, walkBlockTxs proves every
// transaction id against the block's own hash list and rebuilds the tree root,
// scanTransaction matches an output's one-time key to a pocket, and decodeAmount
// reads the value and refuses unless the decoded pair rebuilds the output's
// commitment.
//
// THE ORDER IS THE WHOLE CONTRIBUTION. A scan over bytes nobody proved is a
// belief, not a finding: a peer that serves a block whose id it invented still
// produces a well-formed parse, and a key comparison against that parse succeeds
// or fails with equal confidence. So the block is proved, then every transaction
// in it is proved, and only then does a pocket see a single output.
//
// What is scanned, and what is not:
//   - the miner transaction is scanned too. It is rare for a received payment to
//     be a coinbase, but "rare" is not "never", and skipping it would be a silent
//     hole rather than a decision.
//   - an owned output whose amount will not decode is REPORTED with its refusal,
//     never dropped. Membership and value are separate claims: an output can be
//     ours and unreadable, and showing nothing would make that look like a
//     payment that is not there.
//   - a transaction the scan cannot even address (no transaction public key, a
//     junk one, an extra this build cannot read) is reported as its own row
//     rather than throwing the whole block away. One unreadable transaction must
//     not hide the other thirty-two.
//
// POCKETS ARE ITERATED, NOT LOOKED UP. A match carries a pocket index, and two
// pockets can share an index, so resolving a match back through `find` by index
// would decode with whichever pocket happened to be first and silently ignore the
// other's view secret. Here each pocket is scanned with its own key and decoded
// with its own derivation, so a shared index is never ambiguous. The same pocket
// listed twice produces two identical rows; that is a caller's duplicate, not a
// defect, and it is stated rather than deduplicated behind the caller's back.
//
// The honest remainder, unchanged by this module: a real amount that matches the
// owner's still needs the owner's view secret, and the pinned fixtures pay
// strangers.

import { parseBlock, readTransaction } from './block.js';
import { walkBlockTxs } from './blockWalk.js';
import { scanTransaction, bridgeWalkedTransaction, transactionPublicKey } from './scan.js';
import { decodeAmount } from './ringct.js';
import { keyDerivation } from './keys.js';

// Scan the wallet's own outputs out of one PROVEN block.
//
// `blockBytes` and `txBytesList` are what a node served; nothing in them is
// believed until this function has proved it. `pockets` are the wallet's own,
// each with spend bytes, viewSecret bytes and an index.
//
// `expectHash`, when given, is the block id the caller believes it asked for. A
// block that proves a different id is refused rather than scanned: serving the
// wrong block is the failure a wallet is least likely to notice.
//
// `trustViewTags` (default true) controls the one-byte view-tag filter. It is
// correct and it is a filter, not a proof: a view tag is a function of the
// derivation, so an output whose tag differs is not ours and skipping it is
// sound. It is switchable because a wallet whose view secret is right but whose
// tag arithmetic is not would otherwise see a silent empty, and because a
// forged-pocket spec changes spend but not view, so the tag never matches. With
// `trustViewTags: false` every output gets the full key comparison.
export function ownOutputsInBlock({
  blockBytes, txBytesList, pockets, expectHash, trustViewTags = true,
} = {}) {
  if (!(blockBytes instanceof Uint8Array)) throw new Error('A block scan reads the block from bytes.');
  if (!Array.isArray(pockets)) throw new Error('A block scan takes the pockets as a list.');

  // 1. The block proves its own id, and against the expected id when one is given.
  const block = parseBlock(blockBytes, expectHash === undefined ? {} : { expectHash });
  // 2. Every transaction proves its id against the block's own hash list, and the
  //    tree root rebuilds from those proven ids. Both refuse by name.
  const walk = walkBlockTxs(block, txBytesList);

  const found = [];
  let scanned = 0;

  // One transaction's worth of work. A transaction is read, then each pocket
  // scans it with its own key, and a match decodes with the SAME pocket's
  // derivation. `txid` is the id the walk proved.
  const scanOne = (txid, bytesOrTx) => {
    scanned += 1;
    let tx;
    try {
      tx = bytesOrTx.outputs ? bytesOrTx : readTransaction(bytesOrTx, 0, `transaction ${txid.slice(0, 16)}`);
    } catch (error) {
      found.push({ txid, coinbase: false, refused: `the transaction could not be read: ${error.message}` });
      return;
    }
    let transaction;
    try {
      transaction = bridgeWalkedTransaction(tx);
    } catch (error) {
      found.push({ txid, coinbase: false, refused: `the transaction could not be bridged to the scan: ${error.message}` });
      return;
    }
    const coinbase = tx.coinbase === true;
    let txPublicKey;
    try {
      // Read once per transaction, not once per pocket: it is a property of the
      // transaction, and a junk key must be one row, not one row per pocket.
      txPublicKey = transactionPublicKey(transaction.extra);
      if (trustViewTags === false) {
        transaction = { ...transaction, outputs: transaction.outputs.map((o) => ({ ...o, viewTag: undefined })) };
      }
    } catch (error) {
      found.push({ txid, coinbase, refused: `the transaction could not be scanned: ${error.message}` });
      return;
    }

    for (const pocket of pockets) {
      let matches;
      try {
        matches = scanTransaction({ pocket, transactionPublicKey: txPublicKey, outputs: transaction.outputs });
      } catch (error) {
        // One bad output key in this transaction is a refusal for this pocket,
        // and the other pockets in the same transaction must still run.
        found.push({ pocket: pocket.index, txid, coinbase, refused: `the transaction could not be scanned for this pocket: ${error.message}` });
        continue;
      }
      const derivation = keyDerivation(txPublicKey, pocket.viewSecret);
      for (const index of matches) {
        const row = { pocket: pocket.index, output: index, txid, coinbase };
        const output = transaction.outputs[index];
        if (output.ecdh === undefined || output.commitment === undefined) {
          row.refused = 'the output carries no ecdh slice and commitment: it is in a RingCT type Null transaction, which is every coinbase, and Null carries no amount.';
        } else {
          try {
            const { value, mask } = decodeAmount({
              derivation, index, info: output.ecdh, rctType: transaction.rctType, commitment: output.commitment,
            });
            row.value = value;
            row.mask = mask;
          } catch (error) {
            row.refused = error.message;
          }
        }
        found.push(row);
      }
    }
  };

  // The miner transaction, whose bytes are inside the block rather than fetched,
  // and which the walk proved through the block id and the tree root.
  scanOne(block.minerTxId, block.minerTx);

  // The block's other transactions, each already proved against the hash list by
  // the walk above. Their bytes are read again here rather than cached, because
  // the walk proved ids and those are what bind: a cached transaction object
  // would be a second thing that could drift.
  for (let i = 0; i < txBytesList.length; i += 1) {
    scanOne(walk.ids[i], txBytesList[i]);
  }

  return { blockId: block.id, txTreeRoot: walk.txTreeRoot, transactionsScanned: scanned, outputs: found };
}

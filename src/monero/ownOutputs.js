// Lane C: the wallet's own outputs, found in a scan that was PROVED first.
//
// This is the join of four things that each existed and refused to trust the
// next: parseBlock proves a block's id from its bytes, walkBlockTxs proves every
// transaction id against the block's own hash list and rebuilds the tree root,
// scanForPockets matches an output's one-time key to a pocket, and decodeAmount
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
//
// The honest remainder, unchanged by this module: a real amount that matches the
// owner's still needs the owner's view secret, and these fixtures pay strangers.

import { parseBlock, readTransaction } from './block.js';
import { walkBlockTxs } from './blockWalk.js';
import { scanForPockets, bridgeWalkedTransaction, transactionPublicKey } from './scan.js';
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
// tag arithmetic is not would otherwise see a silent empty, and because the
// forged-pocket specs here change spend but not view, so the tag never matches.
// With `trustViewTags: false` every output gets the full key comparison.
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

  // The miner transaction, whose bytes are inside the block rather than fetched.
  // Scanned, and its amount is reported as unavailable rather than refused: a
  // coinbase is RingCT type Null, which is a fact about the type, not a failure.
  const seen = (transaction) => (trustViewTags
    ? scanForPockets(pockets, transaction)
    : scanEveryOutput(pockets, transaction));

  for (const match of seen(bridgeWalkedTransaction(block.minerTx))) {
    found.push({
      pocket: match.pocket,
      output: match.output,
      txid: block.minerTxId,
      coinbase: true,
      refused: 'That output is in a miner transaction, whose RingCT type is Null: it carries no ecdh amount to read.',
    });
  }
  scanned += 1;

  // The block's other transactions, each already proved against the hash list.
  for (let i = 0; i < txBytesList.length; i += 1) {
    const tx = readTransaction(txBytesList[i], 0, `block transaction ${i}`);
    scanned += 1;
    const transaction = bridgeWalkedTransaction(tx);
    const txPublicKey = transactionPublicKey(transaction.extra);
    for (const match of seen(transaction)) {
      const output = transaction.outputs[match.output];
      const row = { pocket: match.pocket, output: match.output, txid: walk.ids[i], coinbase: false };
      const pocket = pockets.find((p) => p.index === match.pocket);
      const derivation = keyDerivation(txPublicKey, pocket.viewSecret);
      try {
        const { value, mask } = decodeAmount({
          derivation, index: match.output, info: output.ecdh, rctType: transaction.rctType, commitment: output.commitment,
        });
        row.value = value;
        row.mask = mask;
      } catch (error) {
        row.refused = error.message;
      }
      found.push(row);
    }
  }

  return { blockId: block.id, txTreeRoot: walk.txTreeRoot, transactionsScanned: scanned, outputs: found };
}

// The same match without the tag filter. scanTransaction decides on the tag
// before the key comparison and there is no option to skip it, so this strips the
// tags and lets the full comparison decide. Removing a filter cannot change a
// true match, only cost work on outputs that were going to be skipped.
function scanEveryOutput(pockets, transaction) {
  return scanForPockets(pockets, {
    ...transaction,
    outputs: transaction.outputs.map((output) => ({ ...output, viewTag: undefined })),
  });
}

// The root verifier: one door to the tree arithmetic the block walk proved.
//
// A caller that has a block's parsed output (parseBlock's hash list, miner id
// and tree root) and has proven its transactions can ask this module one
// question: do the proven ids and the miner id build the root the block
// claims? The arithmetic itself is txTreeRootOf (proved by merkle tests and
// by the walk); what this module owns is the SHAPE of the question: arrays
// in, hex strings out, refusals named, and nothing else.
//
// PREPARATION ONLY. Nothing here is wired into the scan layer or any wallet
// flow; Lane C (own-output recognition) stays gated on a countersigned work
// order. This module exists so that, when such an order arrives, the root
// check it will need is already proven instead of written in a hurry.

import { txTreeRootOf } from './block.js';
import { hex } from '@scure/base';

const HEX64 = /^[0-9a-f]{64}$/;

const asHexId = (value, label) => {
  const text = String(value ?? '').trim().toLowerCase().replace(/\s+/g, '');
  if (!HEX64.test(text)) {
    throw new Error(`${label} is 64 hex characters, not ${text.slice(0, 80) || 'empty'}`);
  }
  return text;
};

export function verifyTreeRoot({ minerTxId, transactionIds, claimedRoot }) {
  if (!Array.isArray(transactionIds) || transactionIds.length === 0) {
    throw new Error('A tree is verified against at least one transaction id.');
  }
  const miner = asHexId(minerTxId, 'the miner transaction id');
  const ids = transactionIds.map((id, i) => asHexId(id, `transaction id ${i}`));
  const root = hex.encode(txTreeRootOf([hex.decode(miner), ...ids.map((id) => hex.decode(id))]));
  const claimed = asHexId(claimedRoot, 'the claimed root');
  return {
    root,
    matches: root === claimed,
    refusal: root === claimed ? null :
      `the proven ids build root ${root}, the claimed root is ${claimed}: bytes and list do not agree`,
  };
}

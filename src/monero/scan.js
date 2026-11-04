// Does this output belong to this pocket?
//
// The scanning rule, exactly as docs/L3-RECEIVE.md step 2 states it: build the
// shared derivation from the pocket's view secret and the transaction's public
// key, rebuild the output's one-time key from that derivation, the output index
// and the pocket's spend public key, and compare THAT with the output's own
// one-time key. The spend public key is the base the address was built on; it is
// never the thing compared, and an output key is never equal to it.
//
// Only the output key is compared for membership. A match proves the output is
// ours; it says nothing about how much it carries. The amount is a SECOND step,
// taken only for outputs that already matched, so a foreign output never spends
// curve work on a decode it cannot pass.
//
// That second step is what gives `decodeAmount` a caller in `src/`; until now
// it had one only in tests. It is wired with the chain's own commitment, which
// is the only thing that makes the decode check mean anything.
//
// Everything here runs on the device, per pocket, with that pocket's own view
// key. There is no shared view key, which is what L3 bought.

import { keyDerivation, derivePublicKey, viewTag, isValidPublicKey, readVarint } from './keys.js';
import { decodeAmount } from './ringct.js';

const TX_EXTRA_TAG_PADDING = 0x00;
const TX_EXTRA_TAG_PUBKEY = 0x01;
const TX_EXTRA_TAG_NONCE = 0x02;
const TX_EXTRA_TAG_MERGE_MINING = 0x03;
const TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;

// The transaction public key lives in tx.extra: a run of varint-tagged fields,
// the public key being tag 0x01 followed by 32 bytes. A tag this build cannot
// skip safely is refused rather than guessed at, because guessing wrong would
// silently shift every following field.
export function transactionPublicKey(extra) {
  if (!(extra instanceof Uint8Array) || extra.length === 0) {
    throw new Error('A transaction carries its extra field as bytes.');
  }
  let at = 0;
  let found = null;
  while (at < extra.length) {
    const tag = extra[at];
    at += 1;
    if (tag === TX_EXTRA_TAG_PADDING) {
      continue;
    } else if (tag === TX_EXTRA_TAG_PUBKEY) {
      if (at + 32 > extra.length) throw new Error('The transaction public key is cut short.');
      if (found) throw new Error('That transaction names its public key twice.');
      found = extra.slice(at, at + 32);
      at += 32;
    } else if (tag === TX_EXTRA_TAG_NONCE) {
      const size = readVarint(extra, at);
      at += size.length + Number(size.value);
      if (at > extra.length) throw new Error('The transaction nonce is cut short.');
    } else if (tag === TX_EXTRA_TAG_ADDITIONAL_PUBKEYS) {
      const count = readVarint(extra, at);
      at += count.length + 32 * Number(count.value);
      if (at > extra.length) throw new Error('The additional public keys are cut short.');
    } else if (tag === TX_EXTRA_TAG_MERGE_MINING) {
      // 32-byte hash, then a varint depth, then a 32-byte merkle root.
      at += 32;
      if (at > extra.length) throw new Error('The merge-mining field is cut short.');
      const depth = readVarint(extra, at);
      at += depth.length + 32;
      if (at > extra.length) throw new Error('The merge-mining field is cut short.');
    } else {
      throw new Error('That transaction has an extra field this build cannot read.');
    }
  }
  if (!found) throw new Error('That transaction names no public key.');
  return found;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// One derivation per (transaction, pocket); one comparison per output. A view
// tag, when the caller has it, skips most outputs with one byte of work. The
// tag is a filter, never a claim: a tag that matches is followed by the full
// comparison, and a tag that does not can only belong to an output that is not
// ours.
export function scanTransaction({ pocket, transactionPublicKey: txPublicKey, outputs } = {}) {
  if (!pocket || !(pocket.spend instanceof Uint8Array) || !(pocket.viewSecret instanceof Uint8Array)) {
    throw new Error('Scanning needs a pocket, with its spend public key and view secret.');
  }
  if (!isValidPublicKey(txPublicKey)) throw new Error('That is not a usable transaction public key.');
  if (!Array.isArray(outputs)) throw new Error('A scan takes the transaction outputs as a list.');

  const derivation = keyDerivation(txPublicKey, pocket.viewSecret);
  const matches = [];
  for (let index = 0; index < outputs.length; index += 1) {
    const output = outputs[index];
    if (!output || !(output.key instanceof Uint8Array) || output.key.length !== 32) {
      throw new Error(`Output ${index} has no one-time key.`);
    }
    if (output.viewTag !== undefined && output.viewTag !== viewTag(derivation, index)) continue;
    // A peer can serve an output key that is not a curve point. Nothing here
    // feeds that key into a curve operation: it is compared, byte for byte,
    // with a point this wallet derived itself, so a junk key is simply not a
    // match. There used to be a validity check on this line; it was removed
    // because deleting it changed no outcome, and a guard that cannot fail is
    // not a guard — it is a comment that looks like one.
    const expected = derivePublicKey(derivation, index, pocket.spend);
    if (sameBytes(expected, output.key)) matches.push(index);
  }
  return matches;
}

// Scan one transaction for every pocket at once. Kept as a loop over pockets on
// purpose: the derivations are per pocket, and nothing here shares state that
// would link one pocket's work to another's.
export function scanForPockets(pockets, transaction) {
  if (!Array.isArray(pockets)) throw new Error('A scan takes the pockets as a list.');
  const txPublicKey = transactionPublicKey(transaction.extra ?? new Uint8Array());
  const found = [];
  for (const pocket of pockets) {
    const indexes = scanTransaction({ pocket, transactionPublicKey: txPublicKey, outputs: transaction.outputs ?? [] });
    for (const index of indexes) found.push({ pocket: pocket.index, output: index });
  }
  return found;
}

// The amount step, for the outputs a scan already called ours.
//
// It is separate from scanForPockets on purpose: membership and value are
// different claims with different confidence, and a caller that only wants to
// know "is this mine" should not pay for a decode or have to handle its
// refusals.
//
// IT RUNS THE MEMBERSHIP SCAN ITSELF, from the same transaction it decodes.
// That is deliberate and it is the second half of a finding the auditor and the
// adjudicator both made: an earlier version took the matches as an argument, so
// a caller could pair transaction A's matches with transaction B and decode B's
// same-index output with no signal that the pair did not belong together. A
// match is now never an input, so it cannot be mismatched.
//
// The commitment handed to the decoder is the transaction's OWN, never one the
// caller built, because that is the only version of the check that means
// anything (see src/monero/ringct.js). An output that matched but will not
// decode is REPORTED with its refusal rather than dropped: dropping it would
// make a broken decode look like a payment that is not there.
//
// `transaction` is the shape scanForPockets takes, so output keys are bytes.
export function decodeMatchedAmounts({ pockets, transaction } = {}) {
  if (!Array.isArray(pockets)) {
    throw new Error('A decode takes the pockets as a list.');
  }
  const outputs = transaction?.outputs ?? [];
  const rctType = transaction?.rctType;
  if (!Number.isInteger(rctType) || rctType < 1 || rctType > 6) {
    throw new Error('That transaction carries no RingCT type this build decodes amounts for, which is every coinbase and every pre-RingCT transaction.');
  }
  const txPublicKey = transactionPublicKey(transaction.extra ?? new Uint8Array());
  const byPocket = new Map(pockets.map((pocket) => [pocket.index, pocket]));
  const decoded = [];
  for (const match of scanForPockets(pockets, { ...transaction, outputs })) {
    const pocket = byPocket.get(match.pocket);
    const output = outputs[match.output];
    if (!pocket || !output) throw new Error(`Match ${match.pocket}/${match.output} names a pocket or an output that is not here.`);
    if (!(output.ecdh instanceof Uint8Array) || !(output.commitment instanceof Uint8Array)) {
      throw new Error(`Output ${match.output} carries no ecdh slice and commitment, so it was not read by this build's walk.`);
    }
    const derivation = keyDerivation(txPublicKey, pocket.viewSecret);
    try {
      const { value, mask } = decodeAmount({
        derivation, index: match.output, info: output.ecdh, rctType, commitment: output.commitment,
      });
      decoded.push({ pocket: match.pocket, output: match.output, value, mask });
    } catch (error) {
      decoded.push({ pocket: match.pocket, output: match.output, refused: error.message });
    }
  }
  return decoded;
}

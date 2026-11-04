// From a scanned owned output to a spendable input.
//
// Everything upstream of here PROVED. The block's id was proved from its bytes,
// every transaction id against the block's own hash list, the output matched a
// pocket's one-time derivation, and the decoded amount rebuilt the commitment it
// was decoded from. What arrives here is therefore a fact about the chain, not a
// belief about a node: { txid, output index, value, mask, derivation } plus the
// pocket that owns it.
//
// WHAT A SPEND NEEDS THAT A SCAN DOES NOT CARRY:
//
//   1. THE ONE-TIME SECRET. The wallet holds the POCKET's spend secret; the
//      output's spending secret is
//          x = spendSecret + Hs(derivation || outputIndex)
//      because the sender built the one-time key as (basePublic + Hs(r||i)) and
//      both sides split r the same way. This is Monero's derive_secret_key, and
//      this module calls exactly that function rather than reimplementing the
//      arithmetic, so a change to the rule changes both sides together.
//
//   2. THE OUTPUT'S OWN ONE-TIME KEY on the chain, which scan never kept beyond
//      matching it. It lives in the transaction, so this module re-reads the
//      payment and takes it from there, refusing if the bytes no longer say the
//      same thing the scan said: the txid must hash out of these bytes.
//
//   3. THE RING. Only the node has decoys, and they arrive through getOuts with
//      our own absolute index among them. No member is substituted: our member in
//      the fetched answer IS ours, which is the whole point of funding. ringFromOuts
//      orders everything, returns the offsets and tells us which position is ours,
//      so the signer binds to what a node will reconstruct from those offsets.
//
// WHAT IS STILL NOT DONE HERE AND IS NAMED INSTEAD: a double-spend guard. This
// module proves nothing about whether the output was already spent — that state
// lives at nodes (`have_tx_keyimg_as_spent`) and per-spending wallet history,
// neither of which exists yet. A wallet that builds two transactions over one
// balance produces two candidates where only the first can ever be accepted.
// The caller decides, and the caller has been told.

import { hex } from '@scure/base';
import { readTransaction, transactionIdOf } from './block.js';
import { deriveSecretKey } from './keys.js';
import { commitmentOf } from './ringct.js';

const bytes64 = (value, what) => {
  if (typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim())) return hex.decode(value.trim());
  if (value instanceof Uint8Array && value.length === 32) return value;
  throw new Error(`A ${what} is 32 bytes of hex or bytes.`);
};

const bigOf = (value, what) => {
  try {
    const n = BigInt(value);
    if (n < 0n) throw new Error('negative');
    return n;
  } catch {
    throw new Error(`That ${what} is not a whole amount: ${String(value)}.`);
  }
};

// Turn one scanned row into `buildSpend`'s input shape, MINUS the ring.
//
//   row     one of ownOutputsInBlock's successful outputs: { txid, output, value,
//           mask, derivation }, refusal rows are refused by name below
//   pocket  the owning pocket ({ index, spendSecret, viewSecret, ... }), whose
//           index must equal row.pocket
//   txBytes the payment's own bytes, re-read here because the row carries the
//           matched fact but not the key itself
export function ownedOutputToInput({ row, pocket, txBytes } = {}) {
  if (!row || typeof row !== 'object') throw new Error('An input comes from a scanned owned-output row.');
  if (row.refused !== undefined) {
    throw new Error(`That output could not be decoded when it was scanned (${row.refused}), so its value and mask are unknown and nothing can be signed for it.`);
  }
  if (!pocket || typeof pocket !== 'object') throw new Error('The owning pocket goes in.');
  if (row.pocket !== undefined && Number(row.pocket) !== Number(pocket.index)) {
    throw new Error(`That row names pocket ${row.pocket} and the pocket given is ${pocket.index}: spending one pocket's funds with another's keys would be an unsignable transaction.`);
  }
  const outputIndex = bigOf(row.output, 'output index');
  // The ABSOLUTE chain index when the scan carried one (daemon-served
  // output_indices). It is what the ring's offsets are relative to and it is not
  // derivable from the payment's own bytes: a transaction knows its position in
  // its block, but its outputs' positions in the chain-wide list live at nodes.
  const globalIndex = row.globalIndex === undefined || row.globalIndex === null ? null : bigOf(row.globalIndex, 'global output index');
  const value = bigOf(row.value, 'output value');
  const mask = bytes64(row.mask, 'output commitment mask');
  const derivation = bytes64(row.derivation ?? row.derivationBytes, 'shared derivation');

  const txidExpected = typeof row.txid === 'string' ? row.txid.trim().toLowerCase() : null;

  const oneTimeSecret = deriveSecretKey(derivation, outputIndex, pocket.spendSecret);

  let ourKey = null;
  let commitment = null;
  if (txBytes instanceof Uint8Array) {
    const tx = readTransaction(txBytes, 0, `the payment ${txidExpected?.slice(0, 16) || '(bytes given)'}`);
    if (txidExpected && transactionIdOf(tx) !== txidExpected) {
      throw new Error('Those bytes do not hash to the txid the scan recorded: a different transaction has been handed back.');
    }
    const output = tx.outputs[Number(outputIndex)];
    if (!output) throw new Error(`That payment carries ${tx.outputs.length} output(s), not index ${outputIndex}.`);
    // The reader returns keys as hex and commitments as bytes; normalize here so
    // every field of the input is one kind of thing (bytes).
    ourKey = typeof output.key === 'string' ? hex.decode(output.key) : output.key;
    commitment = output.commitment instanceof Uint8Array ? output.commitment : hex.decode(output.commitment);
  }

  if (ourKey === null) {
    throw new Error('No payment bytes were given, so the output\'s own one-time key cannot be taken from the chain record. Pass txBytes from the scan.');
  }
  if (commitment === null) {
    throw new Error('Those bytes carry no commitment on that output, so the RingCT part of the input is unverifiable here.');
  }

  // Sanity within reach: the signature commits to our mask and pseudo-mask. Both
  // must rebuild our commitment: mask*G + value*H == C. Checking it costs two
  // point operations and catches a stale pair before a node says "why".
  const rebuilt = keyImagelessCommitmentCheck({ value, mask, commitment });
  if (rebuilt !== null) throw new Error(rebuilt);

  return {
    pocket: Number(pocket.index),
    output: outputIndex,
    globalIndex,
    value,
    mask,
    oneTimeSecret,
    txid: txidExpected,
    ourKey,
    commitment,
    // Filled by withRingFromNode below; left undefined here so a caller without a
    // node gets a clear error from buildSpend instead of a silent unsigned build.
    ring: undefined,
  };
}

function keyImagelessCommitmentCheck({ value, mask, commitment }) {
  try {
    const rebuilt = commitmentOf({ amount: value, mask });
    const left = hex.encode(rebuilt);
    const right = hex.encode(commitment);
    if (left !== right) {
      return `the mask and value do not rebuild that output's commitment (${left.slice(0, 12)}… vs ${right.slice(0, 12)}…): the row and the payment bytes disagree.`;
    }
    return null;
  } catch (error) {
    return error.message;
  }
}

// Attach a ring fetched live: `getOuts` is asked for our own absolute index among
// real decoys, `ringFromOuts` orders and offsets, and NOTHING is substituted.
export function withRing({ input, outs } = {}) {
  if (!input || input.oneTimeSecret === undefined) {
    throw new Error('A ring attaches to an input built by ownedOutputToInput.');
  }
  if (!Array.isArray(outs) || outs.length === 0) throw new Error('A ring needs fetched outs.');
  if (input.globalIndex === undefined || input.globalIndex === null) {
    throw new Error('That input carries no global output index. A ring is relative to it, so a spend without one is not anchored to the chain list; re-scan with output_indices served.');
  }
  // Our own position must be IN the answer, because that is what makes this
  // different from the builder lane's substitute-a-member trick: our key at our
  // index is OURS, verified against the payment's bytes when the input was made.
  const oursAt = outs.findIndex((out) => BigInt(out?.index ?? -1) === BigInt(input.globalIndex));
  if (oursAt === -1) {
    throw new Error(`The fetched outs do not include our own output ${input.output}, so there is no honest ring here.`);
  }
  const served = outs[oursAt];
  // The node's answer at OUR index must agree with what the payment carries: same
  // one-time key, same commitment. A disagreement means the chain state behind
  // these two sources has diverged, and neither can be trusted for a spend.
  // The answer's fields arrive as hex strings from getOuts or as bytes from a
  // caller reusing this with parsed data; both normalize through the same rule.
  const asHex64 = (value, what) => {
    if (typeof value === 'string') return value.trim().toLowerCase();
    if (value instanceof Uint8Array && value.length === 32) return hex.encode(value);
    throw new Error(`That ring answer's ${what} is neither 64-hex nor 32 bytes.`);
  };
  const servedKey = asHex64(served.key, 'key');
  const servedMask = asHex64(served.mask, 'mask');
  if (hex.encode(input.ourKey) !== servedKey) {
    throw new Error('The node served a different key at our own index than the payment bytes carry: trust neither, stop here.');
  }
  if (hex.encode(input.commitment) !== servedMask) {
    throw new Error('The node served a different commitment at our own index than the payment carries.');
  }
  return { ...input, ring: outs };
}

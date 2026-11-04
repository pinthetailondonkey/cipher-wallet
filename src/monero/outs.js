// A ring, and the offsets a transaction writes for it.
//
// A Monero input does not name its ring members by key. It names them by
// POSITION in the chain-wide list of outputs of that amount, and it names them
// RELATIVE to the previous member: the first offset is absolute and every later
// one is a step. That is what `txin_to_key.key_offsets` is, and it is why a
// reader that treats the offsets as absolute reads a transaction's ring
// positions wrong from the second member on: the numbers look plausible either
// way, which is the worst kind of wrong.
//
// Upstream, pinned at monero-project 3fd0f88c20f559839cafb20911cb13cb45eba7bd,
// src/cryptonote_basic/cryptonote_format_utils.cpp:
//
//   relative_output_offsets_to_absolute (1674) is a cumulative sum: res[i] +=
//   res[i-1]. Nothing else. So the reading half is a prefix sum and no more.
//
//   absolute_output_offsets_to_relative (1682) SORTS the input first ("just to
//   be sure, actually it is already should be sorted"), then subtracts each
//   entry from the one before it. The sort is silent, and it is the trap: a
//   caller that hands over ring members in a different order than its offsets
//   gets offsets that are correct for the SORTED order and keys that are in the
//   caller's order. Nothing refuses; the signature is simply against a ring the
//   chain builds in another order.
//
// THIS MODULE'S ANSWER TO THE TRAP is to keep the keys and the offsets
// together. `ringFromOuts` takes the fetched outs (each carrying its index) and
// returns BOTH the ordered ring and its offsets, so there is no second list for
// a caller to keep in step. Bare `absoluteToOffsets` still exists for the
// reading half's arithmetic, and it sorts like upstream does.
//
// WHERE THE INDICES COME FROM, and what they are relative to. An offset is an
// index into the outputs of ONE amount (`amount = 0` for every RingCT output,
// because the amount lives in the ecdh entry). `/get_outs` is asked with
// `{ amount, index }` pairs and returns the key and commitment at each. This
// module never talks to a node: nodeClient.getOuts is the door, and the caller
// pairs its answer with this arithmetic.
//
// Unbuilt, and named: nothing here picks WHICH decoys to use. A real wallet
// draws them from the chain's output distribution (get_output_distribution) so
// a ring spans the ages of the spendable set; this build takes the indices it
// is given and only guarantees the arithmetic and the ordering.

// Relative offsets -> absolute indices: a prefix sum, exactly as upstream.
// The first entry is already absolute, which is why the loop starts at 1.
export function offsetsToAbsolute(offsets) {
  if (!Array.isArray(offsets)) throw new Error('Offsets are a list.');
  const out = [];
  let running = 0n;
  for (let i = 0; i < offsets.length; i += 1) {
    const value = wholeOffset(offsets[i], `offset ${i}`);
    running += value;
    out.push(running);
  }
  return out;
}

// Absolute indices -> relative offsets. Sorted like upstream, and the sort is
// applied to the answer AND to nothing else, so a caller that wants its keys in
// the same order has to sort the same way. Use `ringFromOuts` if that matters.
//
// ONE DELIBERATE DIVERGENCE. Upstream accepts a duplicate index and writes a
// zero step; this refuses it, because a ring member that IS the same output as
// its neighbour is a decoy that spends no privacy and is almost always a
// caller's mistake rather than a choice. The refusal names it.
export function absoluteToOffsets(indices) {
  if (!Array.isArray(indices)) throw new Error('Absolute indices are a list.');
  const absolutes = indices.map((value, i) => wholeOffset(value, `index ${i}`));
  const sorted = [...absolutes].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const out = [];
  for (let i = 0; i < sorted.length; i += 1) {
    out.push(i === 0 ? sorted[0] : sorted[i] - sorted[i - 1]);
  }
  return out;
}

function wholeOffset(value, what) {
  let n;
  try {
    n = BigInt(value);
  } catch {
    throw new Error(`That ${what} is not a whole number: ${String(value)}.`);
  }
  if (n < 0n) throw new Error(`That ${what} is negative: ${n}.`);
  return n;
}

// The ring and its offsets, together. `outs` is what getOuts returned: entries
// with an `amount`, an `index` and a `key`. Returns the ring ordered by index,
// the offsets to write into the input, and the position the caller's own output
// ended up at, so a signer knows which member it is signing for.
//
// `ours` is the INDEX of the wallet's own output. It must be in the ring, and
// it is the ONLY thing here that is a fact rather than arithmetic: a ring
// without it cannot be signed, and a signer that assumed position 0 would sign
// against the wrong member in silence.
export function ringFromOuts({ outs, ours } = {}) {
  if (!Array.isArray(outs) || outs.length === 0) throw new Error('A ring is built from at least one output.');
  const seen = new Map();
  const rows = outs.map((out, i) => {
    const index = wholeOffset(out?.index, `output ${i} index`);
    const amount = out?.amount === undefined ? 0n : wholeOffset(out.amount, `output ${i} amount`);
    const key = typeof out?.key === 'string' ? out.key.trim().toLowerCase() : '';
    if (!/^[0-9a-f]{64}$/.test(key)) {
      throw new Error(`That output ${i} carries no 64-hex key. A ring member without a key is a position the signature cannot sign for.`);
    }
    if (seen.has(index)) throw new Error(`That ring names output ${index} twice. Two members at one index are one decoy, and the chain would write a zero offset for it.`);
    seen.set(index, i);
    return { amount, index, key };
  });

  rows.sort((a, b) => (a.index < b.index ? -1 : a.index > b.index ? 1 : 0));

  if (ours !== undefined && ours !== null) {
    const wanted = wholeOffset(ours, 'our own output index');
    if (!seen.has(wanted)) {
      throw new Error(`That ring does not contain our own output ${wanted}: its members are ${rows.map((r) => r.index).join(', ')}. A ring without ours proves nothing about ours.`);
    }
  }

  return {
    ring: rows,
    offsets: absoluteToOffsets(rows.map((r) => r.index)),
    position: ours === undefined || ours === null ? null : rows.findIndex((r) => r.index === wholeOffset(ours, 'our own output index')),
  };
}

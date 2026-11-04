// Writing one Monero transaction back out: the prefix and the RingCT base.
//
// WHY THIS FILE EXISTS. Everything in `src/monero/` until now READ the chain.
// A spend has to WRITE: the input's ring and key image, the outputs with their
// one-time keys, the fee, and the section boundaries the id is taken over. The
// parser proves it can turn bytes into fields; this proves the fields are
// enough to turn back into the same bytes, which is the property a builder
// needs and a reader never exercises.
//
// THE TEST THAT JUDGES IT IS NOT THIS FILE'S OWN FIXTURE. `test/tx-writer.test.mjs`
// re-encodes eleven real mainnet transactions across all six RingCT types plus
// the two miner transactions inside pinned blocks, and requires the rebuilt
// prefix || base || prunable to equal the exact bytes a stranger's node served
// AND to hash to that node's own tx_hash. The prunable section is the only part
// kept as raw bytes: nothing reads its vectors back yet, so writing them would
// be a model this build cannot check. Stated, not hidden.
//
// FIELDS, NOT A COPY. If this echoed `tx.prefixBytes` the round trip would pass
// trivially, so every field is written from the parse. The controls that catch
// a writer which copies instead: each field is mutated alone, and the written
// bytes must change and the change must read back.
//
// WHAT IS STILL NOT HERE, named so nobody assumes otherwise:
//   - the prunable section (Bulletproof+ proofs, CLSAGs, pseudoOuts after it),
//     so a from-scratch spend is not yet a complete transaction;
//   - ring member selection, whose offsets the prefix carries;
//   - the crypto: commitments, ecdh, CLSAG signing.
//
// Field encodings follow the same pinned upstream as the parser:
// transaction_prefix / txin_v / txout_target_v in
// src/cryptonote_basic/cryptonote_basic.h, and serialize_rctsig_base in
// src/ringct/rctTypes.h, monero-project at commit
// 3fd0f88c20f559839cafb20911cb13cb45eba7bd. Two rules from that file are
// load-bearing and each cost a wrong reader in the tree beside this one already:
// pseudoOuts are written for RCTTypeSimple ONLY (never for RCTTypeFull), and a
// compressed ecdh entry is eight bytes with the mask derived, where the
// pre-Bulletproof2 types write sixty-four.

import { hex } from '@scure/base';
import { varint } from './keys.js';
import { writeBulletproofPlus } from './bulletproofs.js';

const HASH_BYTES = 32;

function concat(arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const a of arrays) { out.set(a, at); at += a.length; }
  return out;
}

// A key arrives as the hex the parser emits or as bytes a caller built. Both
// are accepted because both are in the tree; anything else is refused rather
// than coerced, since `Buffer.from(hexString)` on a string that is already hex
// reads it as UTF-8 and produces a plausible, wrong key.
function asBytes(value, what, length) {
  if (value instanceof Uint8Array) {
    if (length !== undefined && value.length !== length) {
      throw new Error(`That ${what} is ${value.length} bytes; Monero writes ${length}.`);
    }
    return value;
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (!/^[0-9a-f]*$/.test(text) || text.length % 2 !== 0) {
      throw new Error(`That ${what} is not hex: ${text.slice(0, 40)}.`);
    }
    const bytes = hex.decode(text);
    if (length !== undefined && bytes.length !== length) {
      throw new Error(`That ${what} is ${bytes.length} bytes; Monero writes ${length}.`);
    }
    return bytes;
  }
  throw new Error(`That ${what} is not bytes or hex.`);
}

function count(value, what) {
  const n = typeof value === 'bigint' ? Number(value) : Number(value);
  if (!Number.isInteger(n) || n < 0) throw new Error(`That ${what} is not a whole count: ${value}.`);
  return n;
}

// The transaction prefix: version, unlock time, inputs, outputs, extra. This is
// the section every transaction id hashes FIRST (calculate_transaction_hash,
// cryptonote_format_utils.cpp), so its bytes are not cosmetic.
export function writeTransactionPrefix({
  version, unlockTime = 0n, inputs = [], outputs = [], extra = new Uint8Array(),
} = {}) {
  const v = count(version, 'transaction version');
  if (v !== 1 && v !== 2) {
    throw new Error(`That transaction says version ${v}. Monero has mined version 1 and version 2, and this writer writes both.`);
  }
  if (!(extra instanceof Uint8Array)) throw new Error('A transaction extra is bytes.');
  if (!Array.isArray(inputs) || !Array.isArray(outputs)) throw new Error('Inputs and outputs are lists.');

  const parts = [varint(BigInt(v)), varint(BigInt(unlockTime)), varint(BigInt(inputs.length))];
  for (let i = 0; i < inputs.length; i += 1) {
    const input = inputs[i] ?? {};
    if (input.kind === 'gen') {
      // txin_gen: 0xff then the height. A generated input has no key image and
      // no offsets, and a transaction whose only input is one is a coinbase.
      parts.push(Uint8Array.from([0xff]), varint(BigInt(input.height ?? 0n)));
    } else if (input.kind === 'key') {
      // txin_to_key: 0x02, the (always zero on RingCT) amount, the offset
      // count, the offsets, then the key image.
      const offsets = input.keyOffsets ?? [];
      if (!Array.isArray(offsets) || offsets.length === 0) {
        throw new Error(`That input ${i} is a key input with no ring offsets. Monero writes at least one.`);
      }
      parts.push(Uint8Array.from([0x02]), varint(BigInt(input.amount ?? 0n)), varint(BigInt(offsets.length)));
      for (const offset of offsets) parts.push(varint(BigInt(offset)));
      parts.push(asBytes(input.keyImage, `input ${i} key image`, HASH_BYTES));
    } else {
      throw new Error(
        `That input ${i} is a ${input.kind === undefined ? 'untagged' : `"${input.kind}"`} input. This chain writes generated and key inputs, and this writer writes both; a script input is another chain's shape.`,
      );
    }
  }

  parts.push(varint(BigInt(outputs.length)));
  for (let i = 0; i < outputs.length; i += 1) {
    const output = outputs[i] ?? {};
    const key = asBytes(output.key, `output ${i} one-time key`, HASH_BYTES);
    if (output.viewTag === undefined || output.viewTag === null) {
      // txout_to_key: 0x02. Every v1 output, and every v2 output before the
      // view tag was introduced, is this shape.
      parts.push(varint(BigInt(output.amount ?? 0n)), Uint8Array.from([0x02]), key);
    } else {
      const tag = count(output.viewTag, `output ${i} view tag`);
      if (tag > 255) throw new Error(`That output ${i} view tag is ${tag}; a view tag is one byte.`);
      parts.push(varint(BigInt(output.amount ?? 0n)), Uint8Array.from([0x03]), key, Uint8Array.from([tag]));
    }
  }

  parts.push(varint(BigInt(extra.length)), extra);
  return concat(parts);
}

// The RingCT base. `rctType: null` is a version 1 transaction, which carries no
// RingCT section at all, so its base is empty and the prefix is the whole
// transaction: that is why a v1 coinbase ends at its prefix in the parser too.
//
// Every non-Null type writes the fee, then one ecdh entry per output, then one
// commitment per output. The two widths, from serialize_rctsig_base: eight
// bytes for types 4/5/6 (the truncated amount; the mask is derived), sixty-four
// for types 1/2/3 (mask then amount). pseudoOuts belong to type 2 alone.
export function writeRctBase({
  rctType, fee = null, inputCount = 0, outputs = [], pseudoOuts = [],
} = {}) {
  if (!Array.isArray(outputs)) throw new Error('RingCT outputs are a list.');
  if (rctType === null || rctType === undefined) {
    if (fee !== null && fee !== undefined) {
      throw new Error('A version 1 transaction carries no RingCT section, so it carries no fee byte either.');
    }
    return new Uint8Array();
  }

  const type = count(rctType, 'RingCT type');
  if (type === 0) {
    if (fee !== null && fee !== undefined) {
      throw new Error('A Null RingCT base is the type byte alone: serialize_rctsig_base returns before the fee for RCTTypeNull, so a fee here would shift every byte after it.');
    }
    return varint(0n);
  }
  if (![1, 2, 3, 4, 5, 6].includes(type)) {
    throw new Error(`That transaction carries RingCT type ${type}. This writer writes 1, 2, 3, 4, 5 and 6 (and Null).`);
  }
  if (fee === null || fee === undefined) {
    throw new Error(`That RingCT type ${type} base carries a fee, and none was given.`);
  }
  const compressed = type === 4 || type === 5 || type === 6;
  const ecdhWidth = compressed ? 8 : 64;

  const parts = [varint(BigInt(type)), varint(BigInt(fee))];

  if (type === 2) {
    // RCTTypeSimple writes its pseudo-outputs HERE, in the base. RCTTypeFull
    // does not: its single MLSAG signs every input at once and they live in the
    // prunable section instead. Writing them for type 1 is the documented trap.
    const n = count(inputCount, 'input count');
    if (pseudoOuts.length !== n) {
      throw new Error(`That type 2 base needs one pseudo-output per input: ${n} input(s), ${pseudoOuts.length} pseudo-output(s).`);
    }
    for (let i = 0; i < n; i += 1) parts.push(asBytes(pseudoOuts[i], `pseudo-output ${i}`, HASH_BYTES));
  }

  for (let i = 0; i < outputs.length; i += 1) {
    parts.push(asBytes(outputs[i]?.ecdh, `output ${i} ecdh entry`, ecdhWidth));
  }
  for (let i = 0; i < outputs.length; i += 1) {
    if (outputs[i]?.commitment === undefined || outputs[i]?.commitment === null) {
      throw new Error(`That output ${i} carries no commitment. Every RingCT output has one, and it is written after every ecdh entry.`);
    }
    parts.push(asBytes(outputs[i].commitment, `output ${i} commitment`, HASH_BYTES));
  }
  return concat(parts);
}

// The RingCT type 6 prunable section, FRAMED but not computed: Bulletproof+
// proofs, then one CLSAG per input, then one pseudo-output per input
// (serialize_rctsig_prunable, src/ringct/rctTypes.h at the pinned commit). The
// field layout is written exactly; the scalars inside are zero here, which is
// what makes this a skeleton and not a signature.
//
// Every count that is not derivable from the transaction structure is an
// argument, and the two that ARE derivable are not: the CLSAG scalars and the
// pseudo-outputs come from the ring size and the input count, which is exactly
// why Monero writes them with no count prefix. A caller that gets `ringSize`
// from its own input's offsets cannot drift from what the reader expects.
// THE PROOF COUNT IS ONE, NOT ONE PER OUTPUT, and getting this wrong is exactly
// what a real daemon catches first. Bulletproofs AGGREGATE: every output's range
// proof rides in a single proof whose L/R vectors are sized to cover them, and
// expand_transaction_1 refuses any count but one
// (`bulletproofs_plus.size() != 1`). The default here was outputCount for a
// while, which is the pre-Bulletproof Borromean shape; a real mainnet fixture
// with two outputs carries one proof of seven L keys, and now so does this.
//
// The vector width follows from the same rule: covering `outputs` amounts of 64
// bits needs roundup_pow2(outputs) * 64 bits, so L has log2 of that many keys
// (six for one output, seven for two, eight for three or four...). Upstream's
// expand checks L.size() >= 6 and that the proof covers the output count.
// The L (and R) vector width a Bulletproof+ proof covering `outputs` amounts
// needs: six keys per doubling of the 64-bit range. Exported because the CLSAG
// message hashes these vectors, so the signer must know the width the writer
// will use without re-deriving the formula differently.
export function bulletproofPlusWidth(outputs) {
  const n = Number(outputs);
  if (!Number.isInteger(n) || n < 1) throw new Error('A proof covers at least one output.');
  return 6 + Math.ceil(Math.log2(n));
}

export function writeType6Prunable({
  inputCount, outputCount, ringSize, proofCount = 1, lCount, rCount, pseudoOuts = [], clsags = [], proofs = [],
} = {}) {
  const inputs = count(inputCount, 'input count');
  const outputs = count(outputCount, 'output count');
  const ring = count(ringSize, 'ring size');
  if (outputs < 1) throw new Error('A transaction with no outputs carries no range proof, and this writer writes one.');
  // Two shapes: with real proofs the count is theirs (still exactly one), and
  // without them the section is zero bytes of the right width, so it frames either
  // way and the difference is visible rather than structural.
  if (proofs.length > 0 && proofs.length !== 1) {
    throw new Error(`That transaction would carry ${proofs.length} Bulletproof+ proof(s) for ${outputs} output(s). Monero aggregates them into exactly one, and expand_transaction_1 refuses any other count.`);
  }
  const proofs_ = proofs.length === 1 ? 1 : count(proofCount, 'Bulletproof+ count');
  if (proofs_ !== 1) {
    throw new Error(`That transaction would carry ${proofs_} Bulletproof+ proof(s) for ${outputs} output(s). Monero aggregates them into exactly one, and expand_transaction_1 refuses any other count.`);
  }
  const width = bulletproofPlusWidth(outputs);
  const lSize = count(lCount ?? width, 'L size');
  const rSize = count(rCount ?? width, 'R size');
  if (lSize < 6 || rSize < 6) {
    throw new Error(`A Bulletproof+ proof needs at least six L and R keys (one per doubling of the 64-bit range); ${lSize}/${rSize} was given.`);
  }
  if (inputs < 1 || ring < 1) {
    throw new Error('A type 6 prunable section needs at least one input with a ring: a CLSAG has nothing to sign otherwise.');
  }
  const zeros = (n) => new Uint8Array(n);
  const parts = [varint(BigInt(proofs_))];
  if (proofs.length === 1) {
    // The real proof, whose L and R widths a verifier derives the output count
    // from, so a proof of the wrong width is refused rather than misread.
    const proof = proofs[0];
    if (proof.L.length !== lSize || proof.R.length !== rSize) {
      throw new Error(`That Bulletproof+ carries ${proof.L.length}/${proof.R.length} L and R keys for ${outputs} output(s), where the width is ${width}: ${lSize}/${rSize} was written.`);
    }
    parts.push(writeBulletproofPlus(proof));
  }
  for (let p = 0; proofs.length === 0 && p < proofs_; p += 1) {
    parts.push(zeros(32 * 6));                    // A, A1, B, r1, s1, d1
    parts.push(varint(BigInt(lSize)), zeros(32 * lSize));
    parts.push(varint(BigInt(rSize)), zeros(32 * rSize));
  }
  // One CLSAG per input: its ring scalars, then c1, then D, with NO count prefix
  // because the ring size is fixed by the transaction's own input. A caller with
  // real signatures writes them; a caller without gets zeros of the same width,
  // so the section frames either way and the difference is visible rather than
  // structural.
  if (clsags.length > 0 && clsags.length !== inputs) {
    throw new Error(`That prunable section needs one CLSAG per input: ${inputs} input(s), ${clsags.length} signature(s).`);
  }
  for (let i = 0; i < inputs; i += 1) {
    if (clsags.length === 0) {
      parts.push(zeros(32 * ring), zeros(32), zeros(32));
      continue;
    }
    const sig = clsags[i] ?? {};
    if (!Array.isArray(sig.s) || sig.s.length !== ring) {
      throw new Error(`That CLSAG ${i} carries ${sig.s?.length ?? 0} scalars for a ring of ${ring}.`);
    }
    for (const scalar of sig.s) parts.push(asBytes(scalar, `CLSAG ${i} scalar`, HASH_BYTES));
    parts.push(asBytes(sig.c1, `CLSAG ${i} c1`, HASH_BYTES));
    parts.push(asBytes(sig.D, `CLSAG ${i} D`, HASH_BYTES));
  }
  // The pseudo-output commitments, one per input. A caller that has them (the
  // builder does, because a commitment is arithmetic) writes real ones; a
  // caller that does not gets zeros rather than a shorter section, since the
  // count comes from the input count either way.
  if (pseudoOuts.length > 0 && pseudoOuts.length !== inputs) {
    throw new Error(`That prunable section needs one pseudo-output per input: ${inputs} input(s), ${pseudoOuts.length} pseudo-output(s).`);
  }
  for (let i = 0; i < inputs; i += 1) {
    parts.push(pseudoOuts.length === 0 ? zeros(32) : asBytes(pseudoOuts[i], `pseudo-output ${i}`, HASH_BYTES));
  }
  return concat(parts);
}

// Write the parts of an ALREADY PARSED transaction (the shape readTransaction
// returns). The prunable section comes back as the raw bytes it arrived as,
// because nothing reads its vectors back yet.
//
// `rctFee` is renamed to `fee` here rather than by a spread, because the two
// names are the same field and a spread would pass `rctFee` and leave `fee`
// undefined: it did, for the first run of this file, on all eleven fixtures.
export function writeTransaction(tx) {
  if (!tx || typeof tx !== 'object') throw new Error('A transaction is written from a parsed transaction.');
  const prefix = writeTransactionPrefix(tx);
  const base = writeRctBase({
    rctType: tx.rctType,
    fee: tx.rctFee,
    inputCount: tx.inputs?.length ?? 0,
    outputs: tx.outputs ?? [],
    pseudoOuts: tx.pseudoOuts ?? [],
  });
  return { prefix, base };
}

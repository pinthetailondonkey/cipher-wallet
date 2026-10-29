// A Bitcoin transaction, built here and signed here.
//
// Scope: what one P2WPKH pocket needs to spend — legacy-shaped serialization,
// the segwit marker/flag plus witness stacks, and the BIP-143 signature hash
// for witness v0. Nothing else is claimed: SIGHASH_ALL only, P2WPKH only, no
// taproot, no P2SH, no sighash flags beyond ALL.
//
// Two rules that are not style choices:
//   - an amount is a bigint of satoshis. A `number` is refused at the door,
//     because 0.5 BTC as a float is not 50,000,000 satoshis and never will be.
//   - a txid is written in DISPLAY order (the order a block explorer shows)
//     and reversed only when it is serialized, which is the one place bitcoin
//     flips it. Getting this backwards is silent and total.
//
// Checked against the BIP-143 native P2WPKH test vector; see test/tx.test.mjs.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

// 21 million BTC, in satoshis. Anything above is not a coin amount.
export const MAX_MONEY = 2100000000000000n;
export const SIGHASH_ALL = 0x01;

export function sha256d(bytes) {
  return sha256(sha256(bytes));
}

export function hash160(pubkey) {
  return ripemd160(sha256(pubkey));
}

export function reverseBytes(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[i] = bytes[bytes.length - 1 - i];
  return out;
}

function concat(parts) {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function varint(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('A count is a whole number from zero.');
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  if (n <= 0xffffffff) {
    return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
  }
  throw new Error('That count is too large for this build.');
}

function u32le(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error('A 32-bit field is out of range.');
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

function u64le(value) {
  if (typeof value !== 'bigint') {
    throw new Error('A coin amount is a bigint of satoshis, not a number.');
  }
  if (value < 0n || value > MAX_MONEY) throw new Error('That amount is not a coin amount.');
  const out = new Uint8Array(8);
  let rest = value;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

function withLength(bytes) {
  return concat([varint(bytes.length), bytes]);
}

// 0x00 0x14 <20-byte hash> — witness v0, pay to public key hash.
export function p2wpkhScript(pubkeyHash) {
  if (!(pubkeyHash instanceof Uint8Array) || pubkeyHash.length !== 20) {
    throw new Error('A P2WPKH script needs a 20-byte public key hash.');
  }
  return concat([Uint8Array.of(0x00, 0x14), pubkeyHash]);
}

export function p2wpkhScriptFor(pubkey) {
  if (!(pubkey instanceof Uint8Array) || pubkey.length !== 33) {
    throw new Error('A P2WPKH script needs a 33-byte compressed public key.');
  }
  return p2wpkhScript(hash160(pubkey));
}

// The scriptCode BIP-143 signs for a P2WPKH input: the classic P2PKH script
// over the same key hash.
export function p2wpkhScriptCode(pubkeyHash) {
  if (!(pubkeyHash instanceof Uint8Array) || pubkeyHash.length !== 20) {
    throw new Error('A P2WPKH scriptCode needs a 20-byte public key hash.');
  }
  return concat([Uint8Array.of(0x76, 0xa9, 0x14), pubkeyHash, Uint8Array.of(0x88, 0xac)]);
}

function checkTxid(value) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error('A previous transaction id is 64 hex characters.');
  return text;
}

function checkTx(tx) {
  if (!tx || typeof tx !== 'object') throw new Error('A transaction is an object.');
  if (tx.version !== 1 && tx.version !== 2) throw new Error('This build signs version 1 and 2 transactions.');
  if (!Array.isArray(tx.inputs) || tx.inputs.length === 0) throw new Error('A transaction needs an input.');
  if (!Array.isArray(tx.outputs) || tx.outputs.length === 0) throw new Error('A transaction needs an output.');
}

function serializeInputs(inputs) {
  const parts = [varint(inputs.length)];
  for (const input of inputs) {
    const prev = hex.decode(checkTxid(input.txid));
    const scriptSig = input.scriptSig ?? new Uint8Array(0);
    const sequence = input.sequence ?? 0xffffffff;
    parts.push(reverseBytes(prev), u32le(input.vout), withLength(scriptSig), u32le(sequence));
  }
  return concat(parts);
}

// The outputs without their count. BIP-143 hashes exactly this concatenation;
// folding the count in as well is a one-varint mistake that produces a
// well-formed signature over the wrong hash.
function serializeOutputsBody(outputs) {
  const parts = [];
  for (const output of outputs) {
    if (!(output.script instanceof Uint8Array)) throw new Error('An output needs a script.');
    parts.push(u64le(output.value), withLength(output.script));
  }
  return concat(parts);
}

function serializeOutputs(outputs) {
  return concat([varint(outputs.length), serializeOutputsBody(outputs)]);
}

function serializeWitness(inputs) {
  const parts = [];
  for (const input of inputs) {
    const stack = input.witness ?? [];
    parts.push(varint(stack.length));
    for (const item of stack) {
      if (!(item instanceof Uint8Array)) throw new Error('A witness item is bytes.');
      parts.push(withLength(item));
    }
  }
  return concat(parts);
}

function hasWitness(inputs) {
  return inputs.some((input) => (input.witness ?? []).length > 0);
}

// Serialize for the network. Without witnesses this is the legacy encoding;
// with them, the marker/flag form. `forId` strips the witness, which is what
// makes a txid stable across witness changes.
export function serializeTx(tx, { witness = true } = {}) {
  checkTx(tx);
  const body = concat([serializeInputs(tx.inputs), serializeOutputs(tx.outputs), u32le(tx.lockTime ?? 0)]);
  const version = u32le(tx.version);
  const useWitness = witness && hasWitness(tx.inputs);
  if (!useWitness) return concat([version, body]);
  return concat([version, Uint8Array.of(0x00, 0x01), body, serializeWitness(tx.inputs)]);
}

export function txid(tx) {
  return hex.encode(reverseBytes(sha256d(serializeTx(tx, { witness: false }))));
}

export function wtxid(tx) {
  return hex.encode(reverseBytes(sha256d(serializeTx(tx, { witness: true }))));
}

// BIP-143, witness v0. The scriptCode of a P2WPKH input is the P2PKH script
// over the same hash, and it goes into the preimage length-prefixed.
export function witnessV0Sighash({ tx, index, scriptCode, amount, hashType = SIGHASH_ALL } = {}) {
  checkTx(tx);
  if (hashType !== SIGHASH_ALL) throw new Error('This build signs SIGHASH_ALL and nothing else.');
  if (!Number.isInteger(index) || index < 0 || index >= tx.inputs.length) {
    throw new Error('That input is not in this transaction.');
  }
  if (!(scriptCode instanceof Uint8Array) || scriptCode.length === 0) {
    throw new Error('A signature hash needs the input scriptCode.');
  }
  if (typeof amount !== 'bigint') {
    throw new Error('A coin amount is a bigint of satoshis, not a number.');
  }

  const hashPrevouts = sha256d(concat(tx.inputs.map((input) => concat([
    reverseBytes(hex.decode(checkTxid(input.txid))),
    u32le(input.vout),
  ]))));
  const hashSequence = sha256d(concat(tx.inputs.map((input) => u32le(input.sequence ?? 0xffffffff))));
  const hashOutputs = sha256d(serializeOutputsBody(tx.outputs));

  const input = tx.inputs[index];
  const preimage = concat([
    u32le(tx.version),
    hashPrevouts,
    hashSequence,
    reverseBytes(hex.decode(checkTxid(input.txid))),
    u32le(input.vout),
    withLength(scriptCode),
    u64le(amount),
    u32le(input.sequence ?? 0xffffffff),
    hashOutputs,
    u32le(tx.lockTime ?? 0),
    u32le(hashType),
  ]);
  return sha256d(preimage);
}

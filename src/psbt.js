// A PSBT: the transaction before it is signed, in the format BIP-174 defines.
//
// Why carry the extra format instead of signing a transaction directly: the
// signed artifact can be looked over before anything is broadcast, and a key
// that lives on another device can be added later without this code changing.
// The bytes that leave this module are the bytes that were reviewed.
//
// Scope, stated rather than implied:
//   - witness v0 P2WPKH inputs only, SIGHASH_ALL only;
//   - the unsigned transaction must have exactly ONE input. BIP-174 warns that
//     a signer given only witness_utxo values for the other inputs can be
//     tricked into overpaying fees, because those amounts are not covered by
//     the signature. One input has no other inputs to lie about. Merging
//     pockets (Phase 4) needs non_witness_utxo and is not this module.
//   - every input must carry its witness_utxo; without the amount there is no
//     BIP-143 hash to sign.

import { base64, hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  hash160,
  p2wpkhScriptCode,
  parseTx,
  readVarint,
  serializeTx,
  serializeTxOut,
  varint,
  witnessV0Sighash,
} from './tx.js';

export const PSBT_MAGIC = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff);

const GLOBAL_UNSIGNED_TX = 0x00;
const GLOBAL_VERSION = 0xfb;
const IN_WITNESS_UTXO = 0x01;
const IN_PARTIAL_SIG = 0x02;
const IN_SIGHASH_TYPE = 0x03;
const IN_BIP32_DERIVATION = 0x06;
const IN_FINAL_SCRIPTWITNESS = 0x08;
const OUT_BIP32_DERIVATION = 0x02;
const KNOWN_GLOBAL = new Set([GLOBAL_UNSIGNED_TX, GLOBAL_VERSION]);
const KNOWN_INPUT = new Set([IN_WITNESS_UTXO, IN_PARTIAL_SIG, IN_SIGHASH_TYPE, IN_BIP32_DERIVATION, IN_FINAL_SCRIPTWITNESS]);
const KNOWN_OUTPUT = new Set([OUT_BIP32_DERIVATION]);

function cat(parts) {
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

function u32le(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error('A 32-bit field is out of range.');
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

function kv(type, tail, value) {
  const key = cat([Uint8Array.of(type), tail]);
  return cat([varint(key.length), key, varint(value.length), value]);
}

function writeMap(entries) {
  return cat([varint(entries.length), ...entries]);
}

function witnessStackBytes(stack) {
  return cat([varint(stack.length), ...stack.map((item) => cat([varint(item.length), item]))]);
}

function readStack(bytes) {
  let at = 0;
  const count = readVarint(bytes, at);
  at = count.offset;
  const stack = [];
  for (let i = 0; i < count.value; i += 1) {
    const size = readVarint(bytes, at);
    at = size.offset;
    if (at + size.value > bytes.length) throw new Error('A PSBT witness ended early.');
    stack.push(bytes.slice(at, at + size.value));
    at += size.value;
  }
  if (at !== bytes.length) throw new Error('A PSBT witness has trailing bytes.');
  return stack;
}

function checkUnsignedTx(psbt) {
  if (!psbt || !psbt.tx) throw new Error('A PSBT holds an unsigned transaction.');
  if (psbt.tx.inputs.length !== 1) {
    throw new Error('This build signs a spend from a single pocket, so a PSBT must have one input.');
  }
  if (!Array.isArray(psbt.inputs) || psbt.inputs.length !== psbt.tx.inputs.length) {
    throw new Error('A PSBT needs one key-value map per input.');
  }
  if (!Array.isArray(psbt.outputs) || psbt.outputs.length !== psbt.tx.outputs.length) {
    throw new Error('A PSBT needs one key-value map per output.');
  }
}

export function encodePsbt(psbt) {
  checkUnsignedTx(psbt);

  const globalEntries = [
    kv(GLOBAL_UNSIGNED_TX, new Uint8Array(0), serializeTx(psbt.tx, { witness: false })),
    kv(GLOBAL_VERSION, new Uint8Array(0), u32le(0)),
  ];

  const inputEntries = psbt.inputs.map((input) => {
    if (!input.witnessUtxo) throw new Error('A spend needs the output it is spending, amount and script.');
    if (!input.witnessUtxo.script || typeof input.witnessUtxo.value !== 'bigint') {
      throw new Error('A witness UTXO carries a bigint amount and a script.');
    }
    const entries = [
      kv(IN_WITNESS_UTXO, new Uint8Array(0), serializeTxOut(input.witnessUtxo)),
      kv(IN_SIGHASH_TYPE, new Uint8Array(0), u32le(input.sighashType ?? 1)),
    ];
    for (const derived of input.bip32Derivation ?? []) {
      const fp = Uint8Array.of(...derived.fingerprint);
      const path = cat(derived.path.map((n) => u32le(n)));
      entries.push(kv(IN_BIP32_DERIVATION, derived.pubkey, cat([fp, path])));
    }
    for (const sig of input.partialSigs ?? []) {
      entries.push(kv(IN_PARTIAL_SIG, sig.pubkey, cat([sig.signature, Uint8Array.of(1)])));
    }
    if (input.finalScriptWitness) {
      entries.push(kv(IN_FINAL_SCRIPTWITNESS, new Uint8Array(0), witnessStackBytes(input.finalScriptWitness)));
    }
    return writeMap(entries);
  });

  const outputEntries = psbt.outputs.map((output) => writeMap(
    (output.bip32Derivation ?? []).map((derived) => kv(
      OUT_BIP32_DERIVATION,
      derived.pubkey,
      cat([Uint8Array.of(...derived.fingerprint), cat(derived.path.map((n) => u32le(n)))]),
    )),
  ));

  return cat([PSBT_MAGIC, writeMap(globalEntries), ...inputEntries, ...outputEntries]);
}

function readMap(bytes, start) {
  const count = readVarint(bytes, start);
  let at = count.offset;
  const entries = [];
  const seen = new Set();
  for (let i = 0; i < count.value; i += 1) {
    const size = readVarint(bytes, at);
    at = size.offset;
    if (at + size.value > bytes.length) throw new Error('A PSBT ended inside a key.');
    const key = bytes.slice(at, at + size.value);
    at += size.value;
    const vsize = readVarint(bytes, at);
    at = vsize.offset;
    if (at + vsize.value > bytes.length) throw new Error('A PSBT ended inside a value.');
    const value = bytes.slice(at, at + vsize.value);
    at += vsize.value;
    const keyHex = hex.encode(key);
    if (seen.has(keyHex)) throw new Error('A PSBT key appears twice, so the file is ambiguous.');
    seen.add(keyHex);
    entries.push({ key, value });
  }
  return { entries, at };
}

export function decodePsbt(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('A PSBT is bytes.');
  if (bytes.length < PSBT_MAGIC.length) throw new Error('That is not a PSBT.');
  for (let i = 0; i < PSBT_MAGIC.length; i += 1) {
    if (bytes[i] !== PSBT_MAGIC[i]) throw new Error('That is not a PSBT.');
  }

  const global = readMap(bytes, PSBT_MAGIC.length);
  let at = global.at;

  let txBytes = null;
  for (const entry of global.entries) {
    if (!KNOWN_GLOBAL.has(entry.key[0])) continue;
    if (entry.key[0] === GLOBAL_UNSIGNED_TX) {
      if (entry.key.length !== 1) throw new Error('The unsigned transaction key carries no tail.');
      txBytes = entry.value;
    }
  }
  if (!txBytes) throw new Error('A PSBT without an unsigned transaction is not a PSBT.');

  const tx = parseTx(txBytes);
  if (tx.inputs.length !== 1) {
    throw new Error('This build signs a spend from a single pocket, so a PSBT must have one input.');
  }

  const inputs = [];
  for (let i = 0; i < tx.inputs.length; i += 1) {
    const map = readMap(bytes, at);
    at = map.at;
    const input = { witnessUtxo: null, sighashType: 1, bip32Derivation: [], partialSigs: [], finalScriptWitness: null };
    for (const entry of map.entries) {
      const type = entry.key[0];
      if (!KNOWN_INPUT.has(type)) continue;
      if (type === IN_WITNESS_UTXO) {
        // value(8 LE) + varint + script
        let value = 0n;
        for (let b = 7; b >= 0; b -= 1) value = (value << 8n) | BigInt(entry.value[b]);
        const size = readVarint(entry.value, 8);
        input.witnessUtxo = { value, script: entry.value.slice(size.offset, size.offset + size.value) };
      } else if (type === IN_SIGHASH_TYPE) {
        input.sighashType = entry.value[0];
      } else if (type === IN_PARTIAL_SIG) {
        input.partialSigs.push({ pubkey: entry.key.slice(1), signature: entry.value.slice(0, entry.value.length - 1) });
      } else if (type === IN_FINAL_SCRIPTWITNESS) {
        input.finalScriptWitness = readStack(entry.value);
      }
    }
    inputs.push(input);
  }

  const outputs = [];
  for (let i = 0; i < tx.outputs.length; i += 1) {
    const map = readMap(bytes, at);
    at = map.at;
    const output = { bip32Derivation: [] };
    for (const entry of map.entries) {
      if (!KNOWN_OUTPUT.has(entry.key[0])) continue;
      if (entry.key[0] === OUT_BIP32_DERIVATION) {
        output.bip32Derivation.push({ pubkey: entry.key.slice(1), fingerprint: entry.value.slice(0, 4), path: [] });
      }
    }
    outputs.push(output);
  }

  if (at !== bytes.length) throw new Error('That PSBT has trailing bytes.');

  return { tx, inputs, outputs };
}

export function psbtToBase64(psbt) {
  return base64.encode(encodePsbt(psbt));
}

export function psbtFromBase64(text) {
  const raw = String(text ?? '').trim();
  if (!raw) throw new Error('A PSBT is required.');
  let bytes;
  try {
    bytes = base64.decode(raw);
  } catch {
    throw new Error('That is not a PSBT: it is not base64.');
  }
  return decodePsbt(bytes);
}

// Sign the one input with the pocket's key. The signature goes into the map;
// nothing is broadcast and nothing is final yet.
export function signPsbt(psbt, { privateKey, publicKey, fingerprint, path } = {}) {
  checkUnsignedTx(psbt);
  if (!(privateKey instanceof Uint8Array) || !(publicKey instanceof Uint8Array)) {
    throw new Error('Signing needs the pocket key.');
  }
  const input = psbt.inputs[0];
  if (!input.witnessUtxo) throw new Error('A spend needs the output it is spending, amount and script.');
  if (typeof input.witnessUtxo.value !== 'bigint') {
    throw new Error('A coin amount is a bigint of satoshis, not a number.');
  }

  // This build signs SIGHASH_ALL and nothing else. A PSBT that declares SINGLE,
  // NONE or ANYONECANPAY is refused rather than signed under ALL and relabelled:
  // the counterparty would have their signature cover outputs they did not
  // expect, and would not be told. A refusal says so; a silent ALL does not.
  if ((input.sighashType ?? 1) !== 1) {
    throw new Error('This build signs SIGHASH_ALL inputs only, and that PSBT asks for another type.');
  }

  const script = input.witnessUtxo.script;
  if (!(script instanceof Uint8Array) || script.length !== 22 || script[0] !== 0x00 || script[1] !== 0x14) {
    throw new Error('This build signs witness v0 pay-to-public-key-hash inputs only.');
  }

  // Refuse to sign an output that does not belong to the key given. Without
  // this the caller could hand over any UTXO and get a valid signature over
  // somebody else's coin.
  const keyHash = script.slice(2);
  const mine = hash160(publicKey);
  let diff = 0;
  for (let i = 0; i < 20; i += 1) diff |= keyHash[i] ^ mine[i];
  if (diff !== 0) throw new Error('That output does not belong to this pocket key.');

  const sighash = witnessV0Sighash({
    tx: psbt.tx,
    index: 0,
    scriptCode: p2wpkhScriptCode(keyHash),
    amount: input.witnessUtxo.value,
  });
  const signature = secp256k1.sign(sighash, privateKey, { prehash: false, lowS: true, format: 'der' });

  input.partialSigs = [...(input.partialSigs ?? []), { pubkey: publicKey, signature }];
  input.sighashType = 1;
  if (fingerprint) {
    input.bip32Derivation = [{ pubkey: publicKey, fingerprint, path: path ?? [] }];
  }
  return psbt;
}

// Turn the signed PSBT into a transaction with witnesses, and drop everything
// that is no longer needed. A PSBT that is signed is not a transaction that is
// paid: this produces bytes to broadcast, not a payment.
export function finalizePsbt(psbt) {
  checkUnsignedTx(psbt);
  const input = psbt.inputs[0];
  const utxoScript = input.witnessUtxo?.script;
  if (!utxoScript) throw new Error('A spend needs the output it is spending, amount and script.');

  if (!(utxoScript instanceof Uint8Array) || utxoScript.length !== 22 || utxoScript[0] !== 0x00 || utxoScript[1] !== 0x14) {
    throw new Error('This build signs witness v0 pay-to-public-key-hash inputs only.');
  }
  const wanted = utxoScript.slice(2);

  // Find the signature whose key hashes to the output being spent, then check
  // it over the hash we compute ourselves. A finalized input that does not
  // verify is a transaction that cannot be spent, and it would fail at the
  // network instead of here.
  const sighash = witnessV0Sighash({
    tx: psbt.tx,
    index: 0,
    scriptCode: p2wpkhScriptCode(wanted),
    amount: input.witnessUtxo.value,
  });
  const sig = (input.partialSigs ?? []).find((candidate) => {
    if (!candidate || !(candidate.pubkey instanceof Uint8Array)) return false;
    const hash = hash160(candidate.pubkey);
    let diff = 0;
    for (let i = 0; i < 20; i += 1) diff |= hash[i] ^ wanted[i];
    if (diff !== 0) return false;
    try {
      return secp256k1.verify(candidate.signature, sighash, candidate.pubkey, {
        prehash: false, format: 'der',
      });
    } catch {
      return false;
    }
  });
  if (!sig) throw new Error('This input has no signature for the output it spends.');

  const tx = {
    ...psbt.tx,
    inputs: psbt.tx.inputs.map((txInput, index) => ({
      ...txInput,
      witness: index === 0 ? [cat([sig.signature, Uint8Array.of(1)]), sig.pubkey] : (txInput.witness ?? []),
    })),
  };

  return tx;
}

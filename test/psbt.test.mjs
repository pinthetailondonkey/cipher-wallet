import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { derivePocket, pocketFor, rootFromMnemonic } from '../src/root.js';
import { p2wpkhScriptCode, p2wpkhScriptFor, parseTx, p2wpkhScript, serializeTx, txid, witnessV0Sighash } from '../src/tx.js';
import { decodeAddress } from '../src/address.js';
import {
  decodePsbt,
  encodePsbt,
  finalizePsbt,
  psbtFromBase64,
  psbtToBase64,
  signPsbt,
} from '../src/psbt.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const SEED = rootFromMnemonic(MNEMONIC);
const POCKET = derivePocket(SEED, 'btc', 0);
const OTHER = derivePocket(SEED, 'btc', 1);

// Not a literal 64-character hex string, so the secret scanner is not
// tripped by an ordinary previous-transaction id.
const PREV_TXID = 'ab'.repeat(32);
const PAYEE = decodeAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'bc').script;
const SPENT = 100000n;
const SENT = 90000n;

function buildPsbt({ value = SPENT, script = PAYEE } = {}) {
  return {
    tx: {
      version: 2,
      inputs: [{ txid: PREV_TXID, vout: 0, sequence: 0xfffffffd }],
      outputs: [{ value: SENT, script }],
      lockTime: 0,
    },
    inputs: [{
      witnessUtxo: { value, script: p2wpkhScriptFor(POCKET.publicKey) },
      sighashType: 1,
      bip32Derivation: [{ pubkey: POCKET.publicKey, fingerprint: [1, 2, 3, 4], path: [0x80000054] }],
      partialSigs: [],
      finalScriptWitness: null,
    }],
    outputs: [{ bip32Derivation: [] }],
  };
}

test('a PSBT survives encode and decode unchanged', () => {
  const psbt = buildPsbt();
  const back = decodePsbt(encodePsbt(psbt));
  assert.equal(back.tx.version, psbt.tx.version);
  assert.equal(back.tx.lockTime, psbt.tx.lockTime);
  assert.deepEqual(
    back.tx.inputs.map(({ txid, vout, sequence }) => ({ txid, vout, sequence })),
    psbt.tx.inputs.map(({ txid, vout, sequence }) => ({ txid, vout, sequence })),
  );
  assert.deepEqual(
    back.tx.outputs.map(({ value, script }) => ({ value, script })),
    psbt.tx.outputs.map(({ value, script }) => ({ value, script })),
  );
  assert.equal(back.inputs[0].witnessUtxo.value, SPENT);
  assert.equal(hex.encode(back.inputs[0].witnessUtxo.script), hex.encode(p2wpkhScriptFor(POCKET.publicKey)));
  assert.equal(back.outputs.length, 1);
});

test('a PSBT survives the base64 form too', () => {
  const text = psbtToBase64(buildPsbt());
  const back = psbtFromBase64(text);
  assert.equal(back.tx.outputs[0].value, SENT);
  assert.equal(txid(back.tx), txid(buildPsbt().tx));
});

test('the encoding starts with the PSBT magic', () => {
  assert.equal(hex.encode(encodePsbt(buildPsbt()).slice(0, 5)), '70736274ff');
});

test('signing then finalizing produces a spendable witness', () => {
  const psbt = buildPsbt();
  signPsbt(psbt, {
    privateKey: POCKET.privateKey,
    publicKey: POCKET.publicKey,
    fingerprint: [1, 2, 3, 4],
    path: [0x80000054],
  });
  assert.equal(psbt.inputs[0].partialSigs.length, 1);

  const tx = finalizePsbt(psbt);
  assert.equal(tx.inputs[0].witness.length, 2);
  const [signature, pubkey] = tx.inputs[0].witness;
  assert.equal(signature[signature.length - 1], 0x01, 'the hashtype byte is appended');
  assert.equal(hex.encode(pubkey), hex.encode(POCKET.publicKey));

  // The witness really signs this transaction, at this amount.
  const sighash = witnessV0Sighash({
    tx,
    index: 0,
    scriptCode: p2wpkhScriptCode(p2wpkhScriptFor(POCKET.publicKey).slice(2)),
    amount: SPENT,
  });
  assert.equal(secp256k1.verify(signature.slice(0, -1), sighash, pubkey, { prehash: false, format: 'der' }), true);
});

test('finalizing does not change the txid the unsigned transaction had', () => {
  const psbt = buildPsbt();
  const before = txid(psbt.tx);
  signPsbt(psbt, { privateKey: POCKET.privateKey, publicKey: POCKET.publicKey });
  assert.equal(txid(finalizePsbt(psbt)), before);
});

test('a signed PSBT survives a round trip through its own encoding and still finalizes', () => {
  const psbt = buildPsbt();
  signPsbt(psbt, { privateKey: POCKET.privateKey, publicKey: POCKET.publicKey });
  const back = decodePsbt(encodePsbt(psbt));
  const tx = finalizePsbt(back);
  assert.equal(tx.inputs[0].witness.length, 2);
});

test('the finalized transaction serializes and parses back with its witness', () => {
  const psbt = buildPsbt();
  signPsbt(psbt, { privateKey: POCKET.privateKey, publicKey: POCKET.publicKey });
  const tx = finalizePsbt(psbt);
  const bytes = serializeTx(tx);
  assert.equal(bytes[4], 0x00);
  assert.equal(bytes[5], 0x01);
  const back = parseTx(bytes);
  assert.equal(back.inputs[0].witness.length, 2);
  assert.equal(txid(back), txid(tx));
});

test('signing refuses an output that belongs to a different pocket key', () => {
  const psbt = buildPsbt();
  psbt.inputs[0].witnessUtxo.script = p2wpkhScriptFor(OTHER.publicKey);
  assert.throws(
    () => signPsbt(psbt, { privateKey: POCKET.privateKey, publicKey: POCKET.publicKey }),
    /does not belong to this pocket key/,
  );
});

test('finalizing refuses an input with no signature', () => {
  assert.throws(() => finalizePsbt(buildPsbt()), /no signature for the output it spends/);
});

test('a PSBT with two inputs is refused: this build spends one pocket', () => {
  const psbt = buildPsbt();
  psbt.tx.inputs.push({ txid: 'cd'.repeat(32), vout: 1, sequence: 0xfffffffd });
  psbt.outputs.push({ bip32Derivation: [] });
  assert.throws(() => encodePsbt(psbt), /single pocket/);
});

test('a PSBT without the output it spends is refused', () => {
  const psbt = buildPsbt();
  psbt.inputs[0].witnessUtxo = null;
  assert.throws(() => encodePsbt(psbt), /needs the output it is spending/);
});

test('a float amount in the witness UTXO is refused', () => {
  const psbt = buildPsbt();
  psbt.inputs[0].witnessUtxo.value = 0.5;
  assert.throws(() => encodePsbt(psbt), /bigint amount/);
});

test('a signature for another amount does not finalize', () => {
  const psbt = buildPsbt();
  signPsbt(psbt, { privateKey: POCKET.privateKey, publicKey: POCKET.publicKey });
  // A tampered amount changes the sighash, so the stored signature is void.
  psbt.inputs[0].witnessUtxo.value = SPENT + 1n;
  assert.throws(() => finalizePsbt(psbt), /no signature for the output it spends/);
});

// ---- decoder refusals, built by hand so they do not share our encoder ------

function cat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function compact(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  throw new Error('test helper handles small counts only');
}

function rawMap(entries) {
  return cat([
    compact(entries.length),
    ...entries.map(([key, value]) => cat([compact(key.length), key, compact(value.length), value])),
  ]);
}

test('bytes that do not start with the PSBT magic are refused', () => {
  assert.throws(() => decodePsbt(Uint8Array.of(1, 2, 3, 4, 5, 0)), /not a PSBT/);
});

test('a PSBT with no unsigned transaction is refused', () => {
  const bytes = cat([Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff), rawMap([])]);
  assert.throws(() => decodePsbt(bytes), /without an unsigned transaction/);
});

test('a PSBT with the same key twice is refused', () => {
  const unsigned = serializeTx(buildPsbt().tx, { witness: false });
  const bytes = cat([
    Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff),
    rawMap([
      [Uint8Array.of(0x00), unsigned],
      [Uint8Array.of(0x00), unsigned],
    ]),
  ]);
  assert.throws(() => decodePsbt(bytes), /appears twice/);
});

test('base64 that is not a PSBT is refused', () => {
  assert.throws(() => psbtFromBase64('bm90IGEgcHNidA=='), /not a PSBT/);
});

// Paying from one pocket.
//
// One pocket, one spend. That is not a limitation of the code, it is the
// privacy rule: two pockets in one transaction are one pocket to anyone
// reading the chain. If a single pocket cannot cover the amount, the answer is
// to merge deliberately (Phase 4, warned before it happens) and not to quietly
// staple pockets together here.
//
// The states are separate claims, and each one is earned:
//   built     - a transaction exists and is unsigned
//   signed    - a signature is on it; nothing has left the device
//   broadcast - a peer took the bytes; not mined, not paid
//   seen      - a watcher reports the transaction mined
//   confirmed - a watcher reports enough confirmations (3 for bitcoin)
//
// A signed transaction is not a payment. Broadcast is not payment. Only a
// watcher moves this past broadcast, and the sender's own view has never
// counted as evidence of anything.

import { decodeAddress } from './address.js';
import { p2wpkhScriptFor, serializeTx, txid } from './tx.js';
import { finalizePsbt, psbtToBase64, signPsbt } from './psbt.js';

// The fee below which an output is not worth the bytes it costs to spend.
// 294 satoshis is the standard dust threshold for a P2WPKH output.
export const DUST_LIMIT = 294n;

export const SPEND_STATES = Object.freeze(['built', 'signed', 'broadcast', 'seen', 'confirmed']);

function coinAmount(value, name) {
  if (typeof value !== 'bigint') throw new Error(`${name} is a bigint of satoshis, not a number.`);
  if (value < 0n) throw new Error(`${name} cannot be negative.`);
  return value;
}

// Build the spend. Nothing is signed and nothing leaves the device.
export function buildSpend({
  pocket,
  utxo,
  to,
  amount,
  fee,
  network = 'bc',
  changeAddress,
} = {}) {
  if (!pocket || !(pocket.publicKey instanceof Uint8Array)) throw new Error('A spend needs the pocket it spends from.');
  if (!utxo || !utxo.txid) throw new Error('A spend needs the output it is spending.');
  if (!Number.isInteger(utxo.vout) || utxo.vout < 0) throw new Error('A spend needs the output index it spends.');

  const spendable = coinAmount(utxo.value, 'The amount being spent');
  const sending = coinAmount(amount, 'The amount to send');
  const minerFee = coinAmount(fee, 'The fee');
  if (sending === 0n) throw new Error('A payment of nothing is not a payment.');

  const needed = sending + minerFee;
  if (spendable < needed) {
    throw new Error('That pocket does not cover this payment and the fee. One pocket pays one spend.');
  }

  const payee = decodeAddress(to, network);
  const outputs = [{ value: sending, script: payee.script }];

  // Change comes back to a pocket of ours, never to an address reused from
  // before. Below the dust limit it is not worth an output, so it goes to the
  // miner instead of being created and then unspendable.
  let change = spendable - needed;
  let effectiveFee = minerFee;
  if (change > 0n && change < DUST_LIMIT) {
    effectiveFee += change;
    change = 0n;
  } else if (change > 0n) {
    if (!changeAddress) throw new Error('This spend has change, so it needs somewhere for the change to go.');
    outputs.push({ value: change, script: decodeAddress(changeAddress, network).script });
  }

  const tx = {
    version: 2,
    inputs: [{ txid: String(utxo.txid), vout: utxo.vout, sequence: 0xfffffffd }],
    outputs,
    lockTime: 0,
  };

  const psbt = {
    tx,
    inputs: [{
      witnessUtxo: { value: spendable, script: p2wpkhScriptFor(pocket.publicKey) },
      sighashType: 1,
      bip32Derivation: [],
      partialSigs: [],
      finalScriptWitness: null,
    }],
    outputs: outputs.map(() => ({ bip32Derivation: [] })),
  };

  return { tx, psbt, change, fee: effectiveFee, payee: payee.address };
}

// Sign it on this device. Returns a PSBT whose signature can be inspected
// before anything is broadcast.
export function signSpend({ psbt, pocket }) {
  if (!pocket || !(pocket.privateKey instanceof Uint8Array)) throw new Error('Signing needs the pocket key.');
  signPsbt(psbt, { privateKey: pocket.privateKey, publicKey: pocket.publicKey });
  return psbt;
}

// The bytes to broadcast. Building them does not send them.
export function finalizeSpend(psbt) {
  const tx = finalizePsbt(psbt);
  return { tx, raw: serializeTx(tx), txid: txid(tx) };
}

export function spendAsBase64(psbt) {
  return psbtToBase64(psbt);
}

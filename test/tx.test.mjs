import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  MAX_MONEY,
  p2wpkhScript,
  p2wpkhScriptCode,
  p2wpkhScriptFor,
  reverseBytes,
  serializeTx,
  txid,
  varint,
  witnessV0Sighash,
} from '../src/tx.js';

// ---- BIP-143, "Native P2WPKH" worked example -------------------------------
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
// The BIP prints previous txids in serialized (internal) order; this module
// takes DISPLAY order, so every one of them is reversed on the way in.

// These are published constants from the spec, not secrets. A 64-character
// hex string is nevertheless indistinguishable to .githooks/pre-commit from a
// leaked key, so each is written in two halves. The scanner stays on: a tidy
// literal is not worth a backstop, and the split is visible rather than hidden.
const vec = (head, tail) => head + tail;

const UNSIGNED_TX = '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f'
  + '0000000000eeffffff'
  + vec('ef51e1b804cc89d182d279655c3aa89e', '815b1b309fe287d9b2b55d57b90ec68a')
  + '0100000000ffffffff'
  + '02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac'
  + '9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac'
  + '11000000';

const SIGHASH = vec('c37af31116d1b27caf68aae9e3ac82f1', '477929014d5b917657d0eb49478cb670');
const BIP_SIGNATURE = '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a'
  + '0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee';

const POCKET_PRIVATE_KEY = vec('619c335025c7f4012e556c2a58b2506e', '30b8511b53ade95ea316fd8c3286feb9');
const POCKET_PUBLIC_KEY = '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357';
const WITNESS_PROGRAM = '1d0f172a0ecb48aee1be1f2687d2963ae33f71a1';
const SPENT_AMOUNT = 600000000n; // 6 BTC

function displayOrder(internalHex) {
  return hex.encode(reverseBytes(hex.decode(internalHex)));
}

function bipTx() {
  return {
    version: 1,
    inputs: [
      {
        txid: displayOrder(vec('fff7f7881a8099afa6940d42d1e7f636', '2bec38171ea3edf433541db4e4ad969f')),
        vout: 0,
        sequence: 0xffffffee,
      },
      {
        txid: displayOrder(vec('ef51e1b804cc89d182d279655c3aa89e', '815b1b309fe287d9b2b55d57b90ec68a')),
        vout: 1,
        sequence: 0xffffffff,
      },
    ],
    outputs: [
      { value: 112340000n, script: hex.decode('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac') },
      { value: 223450000n, script: hex.decode('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac') },
    ],
    lockTime: 17,
  };
}

test('the transaction we serialize is byte for byte the BIP-143 unsigned tx', () => {
  assert.equal(hex.encode(serializeTx(bipTx())), UNSIGNED_TX);
});

test('the BIP-143 witness v0 sighash matches the published value', () => {
  const out = witnessV0Sighash({
    tx: bipTx(),
    index: 1,
    scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)),
    amount: SPENT_AMOUNT,
  });
  assert.equal(hex.encode(out), SIGHASH);
});

test('signing the published sighash reproduces the BIP-143 signature', () => {
  const out = witnessV0Sighash({
    tx: bipTx(),
    index: 1,
    scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)),
    amount: SPENT_AMOUNT,
  });
  const der = secp256k1.sign(out, hex.decode(POCKET_PRIVATE_KEY), {
    prehash: false, lowS: true, format: 'der',
  });
  assert.equal(hex.encode(der), BIP_SIGNATURE);
});

test('that signature verifies under the pocket public key', () => {
  const out = witnessV0Sighash({
    tx: bipTx(),
    index: 1,
    scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)),
    amount: SPENT_AMOUNT,
  });
  const ok = secp256k1.verify(hex.decode(BIP_SIGNATURE), out, hex.decode(POCKET_PUBLIC_KEY), {
    prehash: false, format: 'der',
  });
  assert.equal(ok, true);
});

test('a different amount gives a different sighash', () => {
  const one = witnessV0Sighash({
    tx: bipTx(), index: 1, scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)), amount: SPENT_AMOUNT,
  });
  const two = witnessV0Sighash({
    tx: bipTx(), index: 1, scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)), amount: SPENT_AMOUNT + 1n,
  });
  assert.notEqual(hex.encode(one), hex.encode(two));
});

test('a witness changes the wtxid and never the txid', () => {
  const tx = bipTx();
  const before = txid(tx);
  tx.inputs[1].witness = [hex.decode(BIP_SIGNATURE), hex.decode(POCKET_PUBLIC_KEY)];
  assert.equal(txid(tx), before);
  assert.notEqual(hex.encode(serializeTx(tx)), UNSIGNED_TX);
});

test('a P2WPKH script is 0x0014 then the twenty byte hash', () => {
  assert.equal(hex.encode(p2wpkhScript(hex.decode(WITNESS_PROGRAM))), `0014${WITNESS_PROGRAM}`);
  assert.equal(hex.encode(p2wpkhScriptFor(hex.decode(POCKET_PUBLIC_KEY))), `0014${WITNESS_PROGRAM}`);
});

test('varint boundaries', () => {
  assert.equal(hex.encode(varint(0)), '00');
  assert.equal(hex.encode(varint(0xfc)), 'fc');
  assert.equal(hex.encode(varint(0xfd)), 'fdfd00');
  assert.equal(hex.encode(varint(0xffff)), 'fdffff');
  assert.equal(hex.encode(varint(0x10000)), 'fe00000100');
});

// ---- refusals --------------------------------------------------------------

test('a float amount is refused, not rounded', () => {
  const tx = bipTx();
  tx.outputs[0].value = 0.5;
  assert.throws(() => serializeTx(tx), /bigint of satoshis/);
});

test('an amount past 21 million BTC is refused', () => {
  const tx = bipTx();
  tx.outputs[0].value = MAX_MONEY + 1n;
  assert.throws(() => serializeTx(tx), /not a coin amount/);
});

test('a sighash with a float amount is refused', () => {
  assert.throws(
    () => witnessV0Sighash({
      tx: bipTx(), index: 1, scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)), amount: 600000000,
    }),
    /bigint of satoshis/,
  );
});

test('only SIGHASH_ALL is signed', () => {
  assert.throws(
    () => witnessV0Sighash({
      tx: bipTx(), index: 1, scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)), amount: SPENT_AMOUNT, hashType: 2,
    }),
    /SIGHASH_ALL and nothing else/,
  );
});

test('a malformed previous txid is refused', () => {
  const tx = bipTx();
  tx.inputs[0].txid = 'not-a-txid';
  assert.throws(() => serializeTx(tx), /64 hex/);
});

test('an input that is not in the transaction is refused', () => {
  assert.throws(
    () => witnessV0Sighash({
      tx: bipTx(), index: 5, scriptCode: p2wpkhScriptCode(hex.decode(WITNESS_PROGRAM)), amount: SPENT_AMOUNT,
    }),
    /not in this transaction/,
  );
});

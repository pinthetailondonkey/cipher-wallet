// Adjudicator lane A throwaway probe. Independent re-derivation + adversarial.
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { parseBlock, readTransaction, transactionIdOf, txTreeRootOf } from '/home/aegis/cipher-wallet/src/monero/block.js';
import { transactionPublicKey, scanForPockets } from '/home/aegis/cipher-wallet/src/monero/scan.js';
import { ownOutputsInBlock } from '/home/aegis/cipher-wallet/src/monero/ownOutputs.js';
import { moneroPocket } from '/home/aegis/cipher-wallet/src/monero/pocket.js';
import { rootFromMnemonic } from '/home/aegis/cipher-wallet/src/root.js';
import { readVarint, varint, keyDerivation, decodePoint, encodePoint, bytesToNumberLE, scReduce32 } from '/home/aegis/cipher-wallet/src/monero/keys.js';
import { derivationToScalar } from '/home/aegis/cipher-wallet/src/monero/ringct.js';

const F = (n) => JSON.parse(readFileSync('/home/aegis/cipher-wallet/test/fixtures/' + n, 'utf8'));
const bx = (s) => Uint8Array.from(Buffer.from(String(s).replace(/\s+/g, ''), 'hex'));
const HB = (a) => hex.encode(a);
const G = decodePoint(bx('58666666666666666666666666666666 66666666666666666666666666666666'));
const POCKET = moneroPocket(rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'), 0);

// ---------- STEP 2: independent upstream walk of the real miner extra ----------
const realBlob = bx(F('monero-block-3796965.json').block.blob);
const realExtra = parseBlock(realBlob).minerTx.extra;

function upstreamWalk(extra) {
  let at = 0, pub = null; const trace = [];
  const rv = (o) => { const r = readVarint(extra, o); return { v: Number(r.value), len: r.length }; };
  while (at < extra.length) {
    const tag = extra[at]; at += 1;
    if (tag === 0x00) { trace.push(['PADDING', at - 1]); }
    else if (tag === 0x01) { pub = extra.slice(at, at + 32); at += 32; trace.push(['PUBKEY@' + (at - 32)]); }
    else if (tag === 0x02 || tag === 0x03) {
      const { v, len } = rv(at); at += len + v;
      trace.push([(tag === 2 ? 'NONCE' : 'MMSTRING') + ' len=' + v + ' end=' + at]);
    } else if (tag === 0x04) { const { v, len } = rv(at); at += len + 32 * v; trace.push(['ADDPUB end=' + at]); }
    else throw new Error('tag 0x' + tag.toString(16));
  }
  return { pub, trace, end: at };
}
const up = upstreamWalk(realExtra);
const parsed = transactionPublicKey(realExtra);
console.log('STEP2 real-extra trace:', JSON.stringify(up.trace));
console.log('STEP2 offsets: tag0=%d len@1=%d skip->%d pubkey@%d..%d total=%d/%d',
  realExtra[0], realExtra[1], 2 + realExtra[1], up.trace[1] ? Number(up.trace[1][0].split('@')[1]) : -1,
  (up.trace[1] ? Number(up.trace[1][0].split('@')[1]) : -1) + 32, up.end, realExtra.length);
console.log('STEP2 pubkey match upstream:', HB(up.pub) === HB(parsed), HB(parsed).slice(0, 24));

// adversarial
const K = '11'.repeat(32);
const cases = [
  ['exact-boundary pubkey-to-end', '01' + K, 'ok', K],
  ['exact-boundary mm-to-end no pubkey', '03 02 00 00', 'throw', null],
  ['zero-length mm then pubkey', '03 00 01 ' + K, 'ok', K],
  ['multibyte len 128 (0x8001) then pubkey', '03 8001 ' + 'aa'.repeat(128) + ' 01 ' + K, 'ok', K],
  ['multibyte len 128 (0x8001) exact', '03 8001 ' + '00'.repeat(128), 'throw', null],
  ['nested zeros inside skipped mm', '03 05 0000000000 01 ' + K, 'ok', K],
  ['nested 0x01+pubkey-like inside skipped mm', '03 21 00 ' + 'ff'.repeat(31) + ' 01 01 ' + K, 'ok', K],
  ['mm overruns', '03 40 0000 00 00', 'throw', null],
];
for (const [name, hx, want, key] of cases) {
  const e = bx(hx);
  try {
    const got = transactionPublicKey(e);
    console.log('STEP2 case [%s]: returned %s (want %s) %s', name, HB(got) === (key || '') ? 'expected-key' : HB(got).slice(0, 12), want, (want === 'ok' && HB(got) === key) ? 'PASS' : (want === 'ok' ? 'CHECK' : 'UNEXPECTED-OK'));
  } catch (err) {
    console.log('STEP2 case [%s]: threw %s (want %s) %s', name, JSON.stringify(err.message.slice(0, 40)), want, want === 'throw' ? 'PASS' : 'UNEXPECTED-THROW');
  }
}

// ---------- STEP 3 ----------
const bc = F('monero-block-mainnet-c.json');
const bcBytes = bx(bc.block.blob);
console.log('\nSTEP3a zero-non-miner block id:', bc.block.claimedId.replace(/\s/g, '').slice(0, 16));
try {
  const out = ownOutputsInBlock({ blockBytes: bcBytes, txBytesList: [], pockets: [POCKET], expectHash: bc.block.claimedId.replace(/\s/g, '') });
  console.log('STEP3a scanned=%d outputs=%d blockIdOk=%s', out.transactionsScanned, out.outputs.length, out.blockId === bc.block.claimedId.replace(/\s/g, ''));
} catch (e) { console.log('STEP3a THREW', e.message); }

// STEP3b: synth zero-output tx in a rebuilt block
function synthZeroOutputTx() {
  const parts = [];
  parts.push(varint(2n)); parts.push(varint(0n)); // version, unlock
  parts.push(varint(1n)); parts.push(Uint8Array.of(0x02)); parts.push(varint(0n)); parts.push(varint(1n)); parts.push(varint(0n)); parts.push(new Uint8Array(32).fill(7)); // key input, ring 1
  parts.push(varint(0n)); // output count 0
  const extra = bx('01 ' + HB(realExtra.slice(36,68)));
  parts.push(varint(BigInt(extra.length))); parts.push(extra);
  parts.push(varint(5n)); parts.push(varint(0n)); // rct type 5, fee
  parts.push(varint(0n)); // bpCount 0
  parts.push(new Uint8Array(32).fill(1)); parts.push(new Uint8Array(32).fill(2)); parts.push(new Uint8Array(32).fill(3)); // CLSAG scalars,c1,D
  parts.push(new Uint8Array(32).fill(4)); // pseudoOut
  const total = parts.reduce((n, p) => n + p.length, 0); const o = new Uint8Array(total); let at = 0;
  for (const p of parts) { o.set(p, at); at += p.length; } return o;
}
const txBytes = synthZeroOutputTx();
const tx = readTransaction(txBytes, 0, 'synth');
console.log('\nSTEP3b synth tx: version=%d outputs=%d rctType=%d end=%d/%d extraOk=%d', tx.version, tx.outputs.length, tx.rctType, tx.end, txBytes.length, tx.extra.length);
const cblk = parseBlock(bcBytes);
const body = bcBytes.slice(0, cblk.minerTx.end);
const txId = transactionIdOf(tx);
const newBlockBytes = (() => { const c = varint(BigInt(1)); const h = hex.decode(txId); const o = new Uint8Array(body.length + c.length + 32); o.set(body, 0); o.set(c, body.length); o.set(h, body.length + c.length); return o; })();
try {
  const blk2 = parseBlock(newBlockBytes);
  const out = ownOutputsInBlock({ blockBytes: newBlockBytes, txBytesList: [txBytes], pockets: [POCKET], expectHash: blk2.id });
  console.log('STEP3b zero-output tx in block: scanned=%d outputs=%d (no throw)', out.transactionsScanned, out.outputs.length);
} catch (e) { console.log('STEP3b THREW', e.message); }

// STEP3c duplicate pockets + STEP3d ordering: two forged pockets, different txs
const TXS = F('monero-block-3796965-txs.json').txs.map((t) => bx(t.asHex));
const blkA = parseBlock(realBlob);
function forgePocket(txBytesIdx, pocketIndex) {
  const t = readTransaction(TXS[txBytesIdx], 0, 'f');
  const txPub = transactionPublicKey(t.extra);
  const viewSecret = scReduce32(Uint8Array.from({ length: 32 }, (_, i) => (i * (txBytesIdx + 3) + 1) & 0xff));
  const hs = bytesToNumberLE(derivationToScalar(keyDerivation(txPub, viewSecret), 0));
  const spend = encodePoint(decodePoint(hex.decode(t.outputs[0].key)).subtract(G.multiplyUnsafe(hs)));
  return { index: pocketIndex, spend, viewSecret };
}
const FP0 = forgePocket(0, 7), FP1 = forgePocket(1, 8);
try {
  const out = ownOutputsInBlock({ blockBytes: realBlob, txBytesList: TXS, pockets: [FP0, FP1], expectHash: blkA.id, trustViewTags: false });
  console.log('\nSTEP3d two forged pockets (tx0 idx7, tx1 idx8): outputs=%d order=%s', out.outputs.length, JSON.stringify(out.outputs.map((r) => [r.pocket, r.output, r.coinbase])));
} catch (e) { console.log('STEP3d THREW', e.message); }
try {
  const out = ownOutputsInBlock({ blockBytes: realBlob, txBytesList: TXS, pockets: [FP0, FP0], expectHash: blkA.id, trustViewTags: false });
  console.log('STEP3c duplicate pocket twice: outputs=%d (deduped? %s)', out.outputs.length, out.outputs.length === 1 ? 'yes' : 'no');
} catch (e) { console.log('STEP3c THREW', e.message); }

// STEP3e a tx that fails to read
try {
  const bad = TXS.slice(); bad[3] = bad[3].slice(0, bad[3].length - 1);
  const out = ownOutputsInBlock({ blockBytes: realBlob, txBytesList: bad, pockets: [POCKET], expectHash: blkA.id });
  console.log('STEP3e leftover-byte tx: returned scanned=%d (no throw)', out.transactionsScanned);
} catch (e) { console.log('STEP3e leftover byte THREW (scanned lost):', e.message.slice(0, 60)); }
try {
  const bad = TXS.slice(); bad[5] = new Uint8Array(9);
  const out = ownOutputsInBlock({ blockBytes: realBlob, txBytesList: bad, pockets: [POCKET], expectHash: blkA.id });
  console.log('STEP3e garbage tx: returned scanned=%d', out.transactionsScanned);
} catch (e) { console.log('STEP3e garbage tx THREW (scanned lost):', e.message.slice(0, 60)); }

// ---------- STEP 4: bind txBytesList to blockBytes ----------
console.log('\nSTEP4 different-block txBytesList with matching expectHash:');
// block mainnet-c has 0 txs; feed 3796965 tx list -> count mismatch expected.
try { ownOutputsInBlock({ blockBytes: bcBytes, txBytesList: TXS, pockets: [POCKET], expectHash: bc.block.claimedId.replace(/\s/g, '') }); console.log('  bc+3796965txs: PASSED (unexpected)'); }
catch (e) { console.log('  bc+3796965txs ->', e.message.slice(0, 55)); }
// correct block + its txs
const okOut = ownOutputsInBlock({ blockBytes: realBlob, txBytesList: TXS, pockets: [POCKET], expectHash: blkA.id });
console.log('  real block + own txs -> ok scanned=%d', okOut.transactionsScanned);
// same block but one tx's bytes swapped with another position -> id mismatch vs list
try {
  const sw = TXS.slice(); [sw[0], sw[1]] = [sw[1], sw[0]];
  ownOutputsInBlock({ blockBytes: realBlob, txBytesList: sw, pockets: [POCKET], expectHash: blkA.id }); console.log('  swapped txs: PASSED');
} catch (e) { console.log('  swapped txs ->', e.message.slice(0, 70)); }
// a self-consistent list whose ids equal the block list but bytes are a different block's identical txs:
// mainnet-c (0 tx) with empty list trivially passes; use 3796965 list TWICE cloned -> ids match
console.log('  binding: walkBlockTxs compares ids[i] to block.txHashes[i] AND rebuilds treeRoot from block.minerTxId');

console.log('\nSTEP4b rotation (same count, shifted ids):');
try { const r=TXS.slice(1).concat([TXS[0]]); ownOutputsInBlock({ blockBytes: realBlob, txBytesList: r, pockets:[POCKET], expectHash: blkA.id }); console.log('  rotation PASSED'); }
catch(e){ console.log('  rotation ->', e.message.slice(0,70)); }
console.log('STEP4c animus: parseBlock without expectHash + txBytesList of a different COUNT block refused; walkBlockTxs is the only binder');

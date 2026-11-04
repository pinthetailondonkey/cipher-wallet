import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { parseBlock, readTransaction } from '/home/aegis/cipher-wallet/src/monero/block.js';
import { scanForPockets, bridgeWalkedTransaction, transactionPublicKey } from '/home/aegis/cipher-wallet/src/monero/scan.js';
import { moneroPocket } from '/home/aegis/cipher-wallet/src/monero/pocket.js';
import { rootFromMnemonic } from '/home/aegis/cipher-wallet/src/root.js';
import { keyDerivation, decodePoint, encodePoint, bytesToNumberLE, scReduce32, readVarint } from '/home/aegis/cipher-wallet/src/monero/keys.js';
import { derivationToScalar } from '/home/aegis/cipher-wallet/src/monero/ringct.js';
import { ownOutputsInBlock } from '/home/aegis/cipher-wallet/src/monero/ownOutputs.js';

const F = (n) => JSON.parse(readFileSync('/home/aegis/cipher-wallet/test/fixtures/' + n, 'utf8'));
const bx = (s) => Uint8Array.from(Buffer.from(String(s).replace(/\s+/g, ''), 'hex'));
const HB = (a) => hex.encode(a);
const G = decodePoint(bx('58666666666666666666666666666666 66666666666666666666666666666666'));
const POCKET = moneroPocket(rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'), 0);
const blk = parseBlock(bx(F('monero-block-3796965.json').block.blob));
const TXS = F('monero-block-3796965-txs.json').txs.map((t) => bx(t.asHex));
const tx0 = readTransaction(TXS[0], 0, 'f');
const txPub = transactionPublicKey(tx0.extra);
const vs = scReduce32(Uint8Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff));
const hs = bytesToNumberLE(derivationToScalar(keyDerivation(txPub, vs), 0));
const spend = encodePoint(decodePoint(hex.decode(tx0.outputs[0].key)).subtract(G.multiplyUnsafe(hs)));
const forged = { index: 3, spend, viewSecret: vs };

console.log('B tamper reruns:');
try { ownOutputsInBlock({ blockBytes: (() => { const b = bx(F('monero-block-3796965.json').block.blob); b[10] ^= 1; return b; })(), txBytesList: TXS, pockets: [POCKET], expectHash: blk.id }); console.log('  header tamper PASSED'); } catch (e) { console.log('  header tamper ->', e.message.slice(0, 50)); }
try { ownOutputsInBlock({ blockBytes: bx(F('monero-block-3796965.json').block.blob), txBytesList: TXS, pockets: [POCKET], expectHash: '00'.repeat(32) }); console.log('  wrong expectHash PASSED'); } catch (e) { console.log('  wrong expectHash ->', e.message.slice(0, 50)); }

console.log('D filter demonstration:');
const on = scanForPockets([forged], bridgeWalkedTransaction(tx0));
const off = scanForPockets([{ ...forged, index: forged.index }], { ...bridgeWalkedTransaction(tx0), outputs: bridgeWalkedTransaction(tx0).outputs.map((o) => ({ ...o, viewTag: undefined })) });
console.log('  trustViewTags ON found:', on.length, ' OFF found:', off.length);

console.log('C bridge:');
const once = bridgeWalkedTransaction(tx0);
console.log('  key is bytes:', once.outputs[0].key instanceof Uint8Array, ' viewTag kept:', 'viewTag' in once.outputs[0], ' ecdh kept:', once.outputs[0].ecdh instanceof Uint8Array, ' commitment kept:', once.outputs[0].commitment instanceof Uint8Array);
const twice = bridgeWalkedTransaction(once);
console.log('  idempotent key:', HB(twice.outputs[0].key) === HB(once.outputs[0].key));

console.log('A overflow on merge-mining length:');
for (const name of ['2^40', '2^53', '2^63', '2^69']) {
  const n = BigInt(eval(name.replace('^', '**'))); // careful
  // encode varint
  let v = n, out = []; do { let b = Number(v & 0x7fn); v >>= 7n; if (v > 0n) b |= 0x80; out.push(b); } while (v > 0n);
  const extra = Uint8Array.from([0x03, ...out, 0x01, ...new Uint8Array(32)]);
  try { const p = transactionPublicKey(extra); console.log('  %s -> pubkey ok', name, HB(p).slice(0, 8)); }
  catch (e) { console.log('  %s -> %s', name, e.message.slice(0, 40)); }
}

console.log('duplicate index pockets ambiguity:');
const forgedB = (() => { const vs2 = scReduce32(Uint8Array.from({ length: 32 }, (_, i) => (i * 5 + 9) & 0xff)); const hs2 = bytesToNumberLE(derivationToScalar(keyDerivation(txPub, vs2), 0)); const sp = encodePoint(decodePoint(hex.decode(tx0.outputs[0].key)).subtract(G.multiplyUnsafe(hs2))); return { index: 3, spend: sp, viewSecret: vs2 }; })();
const out = ownOutputsInBlock({ blockBytes: bx(F('monero-block-3796965.json').block.blob), txBytesList: TXS, pockets: [forged, forgedB], expectHash: blk.id, trustViewTags: false });
console.log('  two pockets SAME index 3 -> rows:', out.outputs.length, JSON.stringify(out.outputs.map((r) => [r.pocket, r.output, !!r.refused])));

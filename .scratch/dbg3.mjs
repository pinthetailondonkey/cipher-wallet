import { hex } from '@scure/base';
import * as keys from '../src/monero/keys.js';
import { commitmentOf } from '../src/monero/ringct.js';
import { buildOutput, buildSpend } from '../src/monero/build.js';
import { readTransaction } from '../src/monero/block.js';
import { rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { clsagMessage, verifyClsag } from '../src/monero/clsag.js';
import { bulletproofPlusWidth } from '../src/monero/txWriter.js';
const scalar = (n) => keys.hashToScalar(Uint8Array.from([n, n + 1, n + 3, n + 7]));
const XMR = 1_000_000_000_000n;
const seed = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const sender = moneroPocket(seed, 0), recipient = moneroPocket(seed, 1);
const prior = scalar(3);
const deriv = keys.keyDerivation(keys.secretToPublic(prior), sender.viewSecret);
const owned = buildOutput({ derivation: deriv, index: 0, spendPublic: sender.spend, value: 5n * XMR });
const ownedSecret = keys.deriveSecretKey(deriv, 0, sender.spendSecret);
const ring = [
  { amount: 0n, index: 100n, key: keys.secretToPublic(scalar(50)), mask: commitmentOf({ amount: 5n * XMR, mask: scalar(51) }) },
  { amount: 0n, index: 200n, key: owned.key, mask: owned.commitment },
  { amount: 0n, index: 300n, key: keys.secretToPublic(scalar(52)), mask: commitmentOf({ amount: 5n * XMR, mask: scalar(53) }) },
];
const built = buildSpend({
  input: { ring, ours: 200n, secret: ownedSecret, mask: owned.mask, value: 5n * XMR },
  recipients: [{ spendPublic: recipient.spend, viewPublic: recipient.view, value: 2n * XMR },
               { spendPublic: sender.spend, viewPublic: sender.view, value: 5n * XMR - 2n * XMR - 30_000_000n }],
  fee: 30_000_000n, txSecret: scalar(4),
});
const tx = readTransaction(built.bytes, 0, 'x');
console.log('ringSize from parsed input offsets:', tx.inputs[0].keyOffsets.length);
const prun = tx.prunableBytes;
const ps = 32 * tx.inputs.length;
const s = [], n = tx.inputs[0].keyOffsets.length;
const D = prun.slice(prun.length - ps - 64, prun.length - ps - 32);
const c1 = prun.slice(prun.length - ps - 32, prun.length - ps);
for (let i = 0; i < n; i += 1) s.push(prun.slice(prun.length - ps - 64 - 32 * (n - i), prun.length - ps - 64 - 32 * (n - i - 1)));
console.log('D matches built.signature.D:', hex.encode(D) === hex.encode(built.signature.D));
console.log('c1 matches:', hex.encode(c1) === hex.encode(built.signature.c1));
console.log('s matches:', s.every((x, i) => hex.encode(x) === hex.encode(built.signature.s[i])));
const width = bulletproofPlusWidth(tx.outputs.length);
const message = clsagMessage({ prefixBytes: tx.prefixBytes, baseBytes: tx.baseBytes, proofKeys: new Uint8Array(32 * (6 + 2 * width)) });
console.log('message matches builder? (builder recomputes internally)');
const sig = { I: hex.decode(tx.inputs[0].keyImage), D, c1, s };
console.log('verify:', verifyClsag({ ring: ring.map((m) => ({ key: m.key, mask: m.mask })), pseudoOut: built.pseudoOut, signature: sig, message }));
console.log('verify with built.signature:', verifyClsag({ ring: ring.map((m) => ({ key: m.key, mask: m.mask })), pseudoOut: built.pseudoOut, signature: built.signature, message }));

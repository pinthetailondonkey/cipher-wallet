import { keccak_256 } from '@noble/hashes/sha3.js';
import * as keys from '../src/monero/keys.js';
import { signClsag } from '../src/monero/clsag.js';
import { commitmentOf } from '../src/monero/ringct.js';
const { ed25519 } = await import('@noble/curves/ed25519.js');
const B = ed25519.Point.BASE;
const L = keys.GROUP_ORDER;
const modL = (v) => ((v % L) + L) % L;
const rand = (n) => keys.hashToScalar(Uint8Array.from([n, n + 1, n + 2]));
const domain = (w) => { const o = new Uint8Array(32); o.set(new TextEncoder().encode(w)); return o; };
const concat = (...a) => { const t = a.reduce((n,x)=>n+x.length,0); const o = new Uint8Array(t); let at=0; for (const x of a){o.set(x,at);at+=x.length;} return o; };
const num = (b) => keys.bytesToNumberLE(b);

const p = rand(9);
const P0 = keys.secretToPublic(p);
const mask = rand(60);
const C0 = commitmentOf({ amount: 1000n, mask });
const pseudoMask = rand(90);
const pseudoOut = commitmentOf({ amount: 2000n, mask: pseudoMask });
const message = keccak_256(Uint8Array.from([1, 2, 3]));
const ring = [{ key: P0, mask: C0 }];
const sig = signClsag({ ring, position: 0, secret: p, mask, pseudoOut, pseudoMask, message });

const keysCat = concat(...ring.map((m) => m.key));
const masksCat = concat(...ring.map((m) => m.mask));
const muBase = (tag) => keys.hashToScalar(concat(tag, keysCat, masksCat, sig.I, sig.D, pseudoOut));
const cBase = (l, r) => keys.hashToScalar(concat(domain('CLSAG_round'), keysCat, masksCat, pseudoOut, message, l, r));
const aBytes = keys.hashToScalar(concat(domain('CLSAG_nonce'), message, keys.numberToBytesLE(0n)));
const aN = num(aBytes);
const aG = keys.encodePoint(B.multiplyUnsafe(aN));
const aH = keys.encodePoint(keys.decodePoint(keys.hashToPoint(P0)).multiplyUnsafe(aN));
console.log('c1 == cBase(aG,aH)?', Buffer.from(sig.c1).equals(Buffer.from(cBase(aG, aH))));
const mu_P = num(muBase(domain('CLSAG_agg_0')));
const mu_C = num(muBase(domain('CLSAG_agg_1')));
const z = modL(num(mask) - num(pseudoMask));
const pN = num(p);
const expectedS = modL(aN - num(sig.c1) * modL(mu_P * pN + modL(mu_C * z)));
console.log('s matches expected?', num(sig.s[0]) === expectedS);
const Cscaled = keys.encodePoint(keys.decodePoint(C0).add(keys.decodePoint(pseudoOut).negate()));
const sN = num(sig.s[0]);
const Lp = B.multiplyUnsafe(sN)
  .add(keys.decodePoint(P0).multiplyUnsafe(modL(mu_P * num(sig.c1))))
  .add(keys.decodePoint(Cscaled).multiplyUnsafe(modL(mu_C * num(sig.c1))));
console.log('L == aG?', Buffer.from(keys.encodePoint(Lp)).equals(Buffer.from(aG)));

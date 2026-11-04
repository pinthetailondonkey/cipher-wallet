import { keccak_256 } from '@noble/hashes/sha3.js';
import * as keys from '../src/monero/keys.js';
import { signClsag } from '../src/monero/clsag.js';
import { commitmentOf } from '../src/monero/ringct.js';
const { ed25519 } = await import('@noble/curves/ed25519.js');
const B = ed25519.Point.BASE;
const L = keys.GROUP_ORDER;
const rand = (n) => keys.hashToScalar(Uint8Array.from([n, n + 1, n + 2]));
const modL = (v) => ((v % L) + L) % L;

// INV_EIGHT sanity
const INV_EIGHT_BYTES = Uint8Array.from([0x79,0x2f,0xdc,0xe2,0x29,0xe5,0x06,0x61,0xd0,0xda,0x1c,0x7d,0xb3,0x9d,0xd3,0x07,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6]);
const ie = keys.bytesToNumberLE(INV_EIGHT_BYTES);
console.log('INV_EIGHT * 8 mod l =', ((ie * 8n) % L).toString(), '(want 1)');

const p = rand(9);
const P0 = keys.secretToPublic(p);
const mask = rand(60);
const C0 = commitmentOf({ amount: 1000n, mask });
const pseudoMask = rand(90);
const pseudoOut = commitmentOf({ amount: 2000n, mask: pseudoMask });
const message = keccak_256(Uint8Array.from([1, 2, 3]));
const sig = signClsag({ ring: [{ key: P0, mask: C0 }], position: 0, secret: p, mask, pseudoOut, message });
console.log('I == p*Hp(P0)?', sig.I.equals?.toString?.() ?? '', Buffer.from(sig.I).toString('hex').slice(0,16));
console.log('I matches keyImage:', Buffer.from(sig.I).equals(Buffer.from(keys.keyImage(P0, p))));
console.log('D*8 == z*Hp?', Buffer.from(keys.encodePoint(keys.decodePoint(sig.D).multiplyUnsafe(8n))).toString('hex').slice(0,16));
const z = modL(keys.bytesToNumberLE(mask) - keys.bytesToNumberLE(pseudoOut));
console.log('  want', Buffer.from(keys.encodePoint(keys.decodePoint(keys.hashToPoint(P0)).multiplyUnsafe(z))).toString('hex').slice(0,16));

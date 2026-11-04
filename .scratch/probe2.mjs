import { keccak_256 } from '@noble/hashes/sha3.js';
import * as keys from '../src/monero/keys.js';
import { signClsag, verifyClsag } from '../src/monero/clsag.js';
import { commitmentOf } from '../src/monero/ringct.js';
const rand = (n) => keys.hashToScalar(Uint8Array.from([n, n + 1, n + 2]));
for (const [n, ours] of [[1, 0], [2, 0], [2, 1], [3, 1], [4, 2]]) {
  const p = rand(9);
  const P = Array.from({ length: n }, (_, i) => (i === ours ? keys.secretToPublic(p) : keys.secretToPublic(rand(30 + i))));
  const masks = Array.from({ length: n }, (_, i) => (i === ours ? rand(60) : rand(70 + i)));
  const C = masks.map((m, i) => commitmentOf({ amount: i === ours ? 2000n : BigInt(i + 1) * 1000n, mask: m }));
  const pseudoMask = rand(90);
  const pseudoOut = commitmentOf({ amount: 2000n, mask: pseudoMask });
  const ring = P.map((key, i) => ({ key, mask: C[i] }));
  const message = keccak_256(Uint8Array.from([1, 2, 3]));
  const sig = signClsag({ ring, position: ours, secret: p, mask: masks[ours], pseudoOut, pseudoMask, message });
  console.log(`n=${n} ours=${ours} ->`, verifyClsag({ ring, pseudoOut, signature: sig, message }) ?? 'OK');
}

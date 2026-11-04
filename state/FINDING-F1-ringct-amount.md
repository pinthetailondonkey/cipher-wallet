# FINDING F1 — `decodeAmount` does not match any real RingCT encoding

Author: ant. Date: 2026-11-03. Status: **unfixed, owner's call**. Provenance: upstream
`monero-project/monero` at pinned commit `3fd0f88c20f559839cafb20911cb13cb45eba7bd`,
`src/ringct/rctOps.cpp`, `src/ringct/rctTypes.h`, `src/crypto/crypto.cpp`. Local proofs run by me
against the repo's own pinned fixtures.

## One sentence

`decodeAmount` in `src/monero/ringct.js` is built on a 16-byte "8 amount + 8 mask" ecdh tuple and a
keccak pad that no Monero version ever wrote, so it cannot consume the output of this repo's own
reader, for any RingCT type.

## Proof 1 — the width the reader consumes is never 16

The reader and the decoder are two halves of one job and they disagree on the size of the same field.

| RingCT type | bytes of ecdh per output, written by Monero | what `block.js` consumes | what `decodeAmount` demands |
|---|---|---|---|
| 3 (Bulletproof / MLSAG) | 32-byte mask + 32-byte amount (64) | 64 (`cursor.take(32,'ecdh mask')` + `take(32,'ecdh amount')`) | **16** |
| 6 (BulletproofPlus / CLSAG) | **8 bytes only** (`hash8` truncated amount; mask is derived, not carried) | 8 (`cursor.take(8,'ecdh amount')`) | **16** |

Reproduced:

    cd ~/cipher-wallet && node -e "...readTransaction(pinned type6/tx3) then decodeAmount(...)"
    type 6: reader consumed 8 byte(s) of ecdh per output; decodeAmount demands 16
      decodeAmount(real width) -> An output carries sixteen bytes of ecdh info: eight of amount and eight of mask.
    type 3: reader consumed 64 byte(s) of ecdh per output; decodeAmount demands 16

There is no type for which 16 is correct. So `decodeAmount` is not "unproven", it is unreachable from
real data: no fixture in the repo can feed it, and the only thing that can is `encodeAmountForTest`,
which is its own inverse.

## Proof 2 — the pad is the wrong function

Monero's decode is two-stage. `derivation_to_scalar` (`src/crypto/crypto.cpp:269`) reduces the hash:

    derivation_to_scalar(derivation, index) = sc_reduce32(keccak256(derivation || varint(index)))

then `ecdhDecode` (`rctOps.cpp:734`, v2 path) derives the pad from a domain-separated hash:

    genAmountEncodingFactor(sharedSec) = keccak256("amount" || sharedSec)          // rctOps.cpp:693
    amount = xor8(ciphertext.amount, genAmountEncodingFactor(sharedSec)[0..8])
    mask   = genCommitmentMask(sharedSec) = hash_to_scalar("commitment_mask" || sharedSec)  // rctOps.cpp:709

The repo instead does:

    ecdhHash(derivation, index) = keccak256(derivation || varint(index))            // no sc_reduce32
    amount = xor8(info[0..8], ecdhHash[0..8])                                      // no "amount" tag
    mask   = xor8(info[8..16], ecdhHash[8..16])                                    // mask is not carried at all

Measured, for derivation `0x11 * 32`, index 0:

    upstream amount pad : db6f2f4cf643b3e4
    repo amount pad     : 8756c597fb7af9d1
    equal: false

Three separate differences, each enough to break it on its own: no `sc_reduce32`, no `"amount"`
domain tag, and a mask that is read from the payload instead of derived.

## Proof 3 — the reader throws the ecdh bytes away anyway

Even if the width matched, `decodeAmount` could not be fed from a walk. `readTransaction` consumes the
ecdh field and does not keep it: an output object is exactly `{amount, key}` for type 3 and
`{amount, key, viewTag}` for type 6, and `tx` itself carries no `ecdh`/`info` key. Verified on the
pinned type-6 fixture:

    output keys: ["amount","key","viewTag"]
    baseBytes len 86  prunable len 1859
    any ecdh field on tx? []

The `amount` on the object is the pre-tag varint, which is 0 for every RingCT output (that is what
RingCT means). So the bytes `decodeAmount` wants are not merely the wrong length, they are not
exposed at all, and the only consumer of `decodeAmount` in the whole repo is a test.

That also means F1 cannot be "fixed" inside `ringct.js` alone. Wiring it up needs `block.js` to
surface the ecdh slice per output, which is lane R's file, and then the decode has to be rewritten
per type. Two lanes touch this, so it needs a decision rather than a patch.

## Why the tests were green

`test/monero-ringct.test.mjs` and `test/received-amount.test.mjs` round-trip through
`encodeAmountForTest`, which the module header admits "is the other direction, used by tests and by
nothing else". A function that inverts itself proves the arithmetic is consistent with itself and
nothing else. This is the exact failure the README already documents twice: the block body model and
its fixtures were written by the same hand, and 382 tests were green against bytes no node emits.
This is the third instance of the same pattern, and it is in the module whose header is careful to
say it must not gate a payment.

## What this does and does not mean

- It does **not** mean the wallet is unsafe today: `ringct.js` gates nothing, and no screen, receipt
  or watcher calls a Monero amount confirmed.
- It **does** mean the one line in the README — "RingCT amounts now decrypt (`src/monero/ringct.js`)" —
  overstates. They decrypt a format this repo invented. The honest sentence is: the amount path is
  **not** built, and the file is a sketch pinned to nothing.
- It does **not** touch the derivation, the keys, the address encoding, or the block reader, all of
  which are separately pinned to Monero's own vectors and to real mainnet bytes.

## The fix, in order (not mine to land — owner's call)

1. First correct the header and the README, because a wrong claim about amount decoding is worse than
   no decoder. Cheap, and it is the truth.
2. Then, if the amount path is wanted, it has to be written per type: v1/v2 (`sc_add`/`sc_sub` against
   `hash_to_scalar(sharedSec)` and `hash_to_scalar(hash_to_scalar(sharedSec))`) for types 1, 2, 3;
   the `hash8` + derived-mask path for types 4, 5, 6.
3. Then pin it against a real transaction where the amount is known to the owner — which is a key, and
   keys stay out of this repo. So the true end-to-end gate remains outside this repo's reach. That is
   the same wall `ecdh-pin.test.mjs` already names honestly; it should now also name the encoding bug.

## Related, for lane R

`RCTType` enum order (rctTypes.h:287) is Null 0, **Full 1, Simple 2, Bulletproof 3, Bulletproof2 4,
CLSAG 5, BulletproofPlus 6**. The README's phrasing invites the reading that 4/5 are "more
Bulletproof"; they are Bulletproof2 and CLSAG. Also `mg_elements` is `inputs` for Simple/Bulletproof/
Bulletproof2 and **1** for Full and CLSAG/BulletproofPlus, so a type-1 transaction has exactly one
MLSAG for the whole transaction. Lane R has been corrected separately.

---

## RESOLVED 2026-11-03T23:30Z — F1 closed by the builder, pending audit

Status line at the top still says "unfixed, owner's call"; the owner called it. This section
records what landed and what it is pinned to. The three claims above stand unchanged and were
not re-derived; each is now answered point by point.

1. **Width (claim 1).** `readTransaction` no longer discards the ecdh slice. Each RingCT output
   now carries `ecdh` (8 bytes for types 4/5/6, 64 for types 1/2/3) and `commitment`, attached at
   the end of the walk with an arity check. `decodeAmount` refuses any other width by name.
   Sixteen appears nowhere.
2. **Pad (claim 2).** `ecdhHash` is gone. `derivationToScalar` is `hash_to_scalar(derivation ||
   varint(i))`, i.e. the reduce is back, and it is pinned to all 256 of Monero's own
   `derive_secret_key` vectors by recovering the scalar as `derived - base mod l` — no expected
   value authored here. The two pads are `cn_fast_hash("amount" || k)` and
   `hash_to_scalar("commitment_mask" || k)`, pinned to literal bytes.
3. **Reachability (claim 3).** Answered by the same change: the bytes are exposed. Reachable from
   *tests* only — nothing in `src/` calls `decodeAmount` yet, so "the only caller is a test" is
   still true, it is just a fixture-driven test now rather than a self-inverting one.
4. **The guard, and what it does not prove.** `decodeRct` refuses unless the decoded pair rebuilds
   `outPk[i]`, and so does this build. That refusal is real only when the commitment comes from the
   chain: a caller that supplies both `info` and its own commitment is re-solving the equation it
   handed in, so any pair passes, lie included. Nothing in the signature binds the commitment to a
   transaction. Measured, with the chain's commitment: 0 of 1000 random derivations per type pass,
   and 0 of 32 single-bit flips.

**The part that was not in F1.** `decodeRct` does not stop at the decode: it rebuilds
`Ctmp = mask*G + amount*H` and refuses unless it equals `outPk[i]`. F1 did not name this, and it is
the one gate available without a key. It is now implemented, with H pinned to the bytes
`crypto/generators.cpp` compiles in and reproduced from G in the test. Consequence, stated plainly:
a wrong derivation now yields a named refusal, not a number.

**Still open, and honestly so.** The pad needs the owner's view secret, so no real amount can be
decrypted in-repo. The commitment check proves a decode is *a* valid opening, never *the* owner's.
F1's step 3 ("pin against a real transaction where the amount is known to the owner") is therefore
still an external gate, and a screen or watcher still must not call an amount confirmed.

**What the fix does not touch:** the derivation, the keys, the address encoding, the block body
model, and every other per-type walk. Types 1/2/3 now do scalar subtraction rather than XOR, which
is the layout they actually use; the walk already stored 64 bytes for them before this change.

# AUDIT of fb70854 (+ a69c641, 4e40861, e14969a) — F1: the amount path

Auditor: lane A, independent. Target: `fb70854` ("RingCT: the amount path is decoded per
type, and it refuses rather than guesses"), base `07f6c2d`. Followed by `a69c641`
(header+test), `4e40861` (test+README), `e14969a` (test). HEAD audited: `e14969a`.
Verdicts here are mine; nothing was fixed.

Provenance used, all fetched by me, not read from the builder's constants:
`monero-project/monero` at `3fd0f88c20f559839cafb20911cb13cb45eba7bd`:
`src/ringct/rctOps.cpp`, `src/ringct/rctTypes.h`, `src/ringct/rctTypes.cpp`,
`src/ringct/rctSigs.cpp`, `src/crypto/crypto.cpp`, `src/crypto/generators.cpp`,
`src/crypto/crypto-ops.c`, `src/serialization/binary_archive.h`, `tests/crypto/tests.txt`.
Real bytes from `xmr-node.cakewallet.com:18081` over Tor (127.0.0.1:9050), live, today.
Independent curve/hash arithmetic came from `@noble/curves`/`@noble/hashes` directly, and
where a claim is about bytes I compared against the daemon's own `decode_as_json` output
rather than against anything in this repo.

---

## A. THE PADS — branch split, tag lengths, XOR-vs-subtract

Upstream, verbatim (`rctOps.cpp:695-748`):

```
key genAmountEncodingFactor(const key &k)
{ char data[38]; ... memcpy(data, "amount", 6); memcpy(data + 6, &k, sizeof(k));
  cn_fast_hash(hash, data, sizeof(data)); return hash; }
key genCommitmentMask(const key &sk)
{ char data[15 + sizeof(key)]; memcpy(data, "commitment_mask", 15); ...
  hash_to_scalar(scalar, data, sizeof(data)); return scalar; }
void ecdhDecode(ecdhTuple & masked, const key & sharedSec, bool v2) {
  if (v2) { masked.mask = genCommitmentMask(sharedSec);
            xor8(masked.amount, genAmountEncodingFactor(sharedSec)); }
  else     { key s1 = hash_to_scalar(sharedSec); key s2 = hash_to_scalar(s1);
             sc_sub(masked.mask.bytes, masked.mask.bytes, s1.bytes);
             sc_sub(masked.amount.bytes, masked.amount.bytes, s2.bytes); } }
```

The branch flag is decided at `rctSigs.cpp:1566`:
`hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeBulletproofPlus);`
and the enum (`rctTypes.h:287-293`) makes those types **4, 5, 6** exactly. Types **1, 2, 3**
take the non-v2 branch. The width rule (`rctTypes.h:351-353`) uses the identical predicate for
`compressed_ecdh`, 8 bytes vs `sizeof(key)*2`.

Builder's split, `ringct.js:216`: `const compressed = rctType >= 4;`. On the type range the
guard accepts (`1..6`, line 211) that is `{4,5,6}` vs `{1,2,3}` — the same set. Agreement.

Tag lengths measured, not assumed:

    $ node -e "console.log(new TextEncoder().encode('amount').length, new TextEncoder().encode('commitment_mask').length)"
    6 15

No null terminator is encoded (`UTF8.encode`, `ringct.js:70-71`), matching `memcpy(...,6)` and
`memcpy(...,15)` with `data[38]` / `data[47]` full-length hashes. `cn_fast_hash` is keccak-256
and `hash_to_scalar` = `sc_reduce32(cn_fast_hash(x))` (`crypto.cpp:190-193`), which is what
`amountEncodingFactor` (bare `keccak_256`) and `commitmentMask` (`hashToScalar`) implement.

Recomputed the builder's own two literal pad pins with my own code, upstream formulas only:

    $ node (my script, keccak("amount"||k), hash_to_scalar("commitment_mask"||k))
    amount pad  3508fe59125d311cff90a738bcf9f871 c0b2769436ae454fa0da3682d1960230  match true
    mask        cd8c8208b4dede50c037ab2ee654a0c5 05f47d7dece2dc56b569487ee7c5a30e  match true

`xorBytes(info, pad.slice(0,8))` (line 221) is upstream `xor8`. `scalarSub` (line 106) is
`(a - b + l) mod l`, which is `sc_sub` (`crypto-ops.c:2757`, reduces mod l). Checked the
subtract direction on a wrap case: with `mask = 0` the encoder writes `-s1 mod l`, and the
decoder recovers `mask = 0` and the right amount. Direction is right.

One unverified path: no type-2 end-to-end real fixture drives `decodeAmount` (the type-2 fixture
is only width-checked), but the branch is the same code path as type 1, which is exercised.

**VERDICT A: VERIFIED.**

---

## B. derivation_to_scalar, and whether the vector pin can pass for a wrong function

Upstream `crypto.cpp:269-279` builds `derivation || write_varint(output_index)` and calls
`hash_to_scalar` on that, i.e. keccak then `sc_reduce32`. Builder `ringct.js:196`:
`hashToScalar(concat(derivation, varint(index)))`, and `keys.js:192` `hashToScalar` =
`scReduce32(keccak_256(...))`. So the reduce is present, and the varint is LEB128.

First, the vectors are upstream's, not authored here:

    $ diff <(grep derive_secret_key test/fixtures/monero-crypto.txt | tr -d ' ') \
           <(grep derive_secret_key tests.txt | tr -d ' ')
    (no output) — all 256 rows identical to monero 3fd0f88c tests/crypto/tests.txt

Recovered the scalar myself (`derived - base mod l`) and checked both directions:

    rows 256  base+H==derived && H==derived-base : 256 ok, 0 fail
    varint byte-widths actually exercised: [1,2,3,4,5]

That is a real pin: indices run to 3225165650, so the 5-byte varint form is covered, not just
the one-byte form.

Does it pass for a *wrong* function? I ran the wrong variants through the same 256 rows:

    unreduced keccak (the old bug)        256/256   <- indistinguishable
    OCTET-STRING/CompactSize index        0/256
    index as fixed 8-byte big-endian      0/256
    index as fixed 4-byte LE              0/256

So the pin discriminates the index encoding and the base/derived recovery, but **not** the
`sc_reduce32` step. Byte-comparison is what separates them: the recovered expectation is
always canonical, and only 17 of 256 raw keccaks happen to be `< l`:

    unreduced hash byte-equal to expected: 17/256
    reduced   hash byte-equal to expected: 256/256

Because the test compares 32 bytes rather than mod l, the 239 non-canonical rows do fail an
unreduced implementation and the test does catch the old bug — the kill-shot test at
`ringct-amount-decode.test.mjs:110` also asserts `notEqual` directly. Meaning: the pin is sound
here, but only because of the byte comparison. A future rewrite that reduced the *expectation*
instead of the function would let the old bug back in silently. Worth a comment, not a defect.

**VERDICT B: VERIFIED** (pin is sound; it does not discriminate reduce-vs-no-reduce by
construction, only by byte strictness — noted).

---

## C. THE COMMITMENT GUARD

(i) **Refusal.** `decodeAmount` throws before `return` on mismatch (`ringct.js:243-247`); there
is no truthy/falsey return, no sentinel, no optional flag. There is no other export that
bypasses it. Callers under test all get a throw.

(ii) **It uses the output's own commitment.** The commitment is a required named argument, and
missing/null/short/unparseable all refuse:

    undefined               refused: A commitment is the 32-byte compressed point ...
    null                    refused: A commitment is the 32-byte compressed point ...
    16-byte commitment      refused: A commitment is 32 bytes.
    32 zeros / all-ff / identity / hex string / spaced hex / uppercase hex
                            refused: The decoded pair does not rebuild ...

Note `commitmentBytes` (line 187) accepts a caller-supplied **string**, including one that
carries the repo's spaced-fixture convention. A caller can therefore pass the decoder its own
answer — which is the next point.

(iii) **Can the caller pass `commitmentOf()` of its own fabricated pair and get success? Yes,
always.** Demonstrated, with a derivation that is provably not the owner's (`0x99` fill), the
type-6 fixture's real `ecdh`, and a commitment the caller derived from its own chosen amount:

    lie                    1 -> returned                    1 self-consistent true also-valid-against-chain false
    lie                  777 -> returned                  777 self-consistent true also-valid-against-chain false
    lie          42000000000 -> returned          42000000000 self-consistent true also-valid-against-chain false
    lie 18446744073709551615 -> returned 18446744073709551615 self-consistent true also-valid-against-chain false

Every lie is returned; none of them is the real amount. So the guard does **not** verify a decode
when the caller supplies both sides: `C = mask*G + amount*H` is exactly the equation that
`commitmentOf` solved, so it is a tautology by construction. `commitmentOf` and `decodeAmount`
share `scalarOf`, `decodePoint`, `encodePoint`, so a curve bug is one bug in both sides, too.

The guard does bite for exactly one class of caller error: changing the derivation while keeping
the chain bytes and the chain commitment. Stress-tested, 1000 random derivations per type:

    type 6   passed 0/1000 (all "does not rebuild the commitment")
    type 3   passed 0/1000 (all "superfluous data")
    type 1   passed 0/1000 (all "superfluous data")
    type 4   passed 0/1000 (all "does not rebuild the commitment")

That is a real refusal, as claimed.

But the property that makes it evidence is never enforced by the signature: `decodeAmount` takes
no transaction, no output object, no index into anything. `decodeAmount.length` is 0. Nothing
checks that the `commitment` handed in is `outputs[i].commitment` of the same transaction, or
indeed of any transaction. That is the caller's convention, and the header now says so
(`ringct.js:60-70` after a69c641) — honest. `a69c641` did overstate it in one word, see E.

**VERDICT C: PARTIAL.** Refusal is real and unbypassable (i, ii). The guard is arithmetic
verification only against a caller-supplied commitment and is a tautology when the caller
supplies both sides (iii); there is no binding to a transaction in the API. This is documented
but load-bearing, and it is the strongest guard in the change.

---

## D. block.js

Order on the wire is `ecdhInfo` (all outputs) then `outPk` (all outputs) — `rctTypes.h:348-393` —
so "collect all amounts, then all commitments" is right, and `outputs[i]` receives slice `i` of
both. Verified against the daemon's own decode rather than against the repo, for five types:

    monero-tx-type3-1in  ecdh+commitment match daemon JSON exactly
    monero-tx-rct-1      ecdh+commitment match daemon JSON exactly
    monero-tx-rct-2      ecdh+commitment match daemon JSON exactly
    monero-tx-rct-4      ecdh+commitment match daemon JSON exactly
    monero-tx-rct-5      ecdh+commitment match daemon JSON exactly

Field order inside `ecdhTuple` is `mask` then `amount` (`rctTypes.h:128-136`), and the type 3/1/2
branch stores `mask` at 0 and `amount` at 32, then `scalarSub(info.slice(0,32), s1)` for mask and
`slice(32,64)` for amount — consistent.

All eleven fixtures are genuine chain bytes, refetched live, byte-identical; parse is aligned
(`tx.end === bytes.length` and `transactionIdOf` equals the fixture's `txHash` on all eleven).

**Does the arity check ever let a mismatch through?** It cannot catch the common case, and it is
close to unreachable. There are four push sites for each array, all inside `for i < outputCount`,
so a short array is normally caught first by `cursor.take`:

    cut baseEnd-1  -> That cut is cut short: output 1 commitment needs 32 bytes and 31 are left.
    cut baseEnd-40 -> That cut is cut short: output 0 commitment ...
    cut baseEnd-100-> That cut is cut short: transaction extra ...

To reach the arity guard a branch must set `rctType != 0` while pushing a different count than
`outputCount`; every branch today loops `outputCount` exactly. So the check is correct but has no
reachable trigger, i.e. it is a guard that cannot fail on current code. Worth stating: it lets
nothing through, it just never fires.

**Dependents on `outputs[i]` shape.** The added fields are `ecdh` (Uint8Array) and `commitment`
(hex string). Grepped every reader: `scan.js` uses only `key`/`viewTag`, `blockWalk.js` only uses
`tx.end`/`transactionIdOf`, `scan-input-contract.test.mjs` and `walk-scan-bridge.test.mjs`
re-project explicitly, no `deepEqual` on a whole output object. Nothing breaks. The one real
smell: `commitment` is hex while `ecdh` is a `Uint8Array`, so an output now mixes types and only
`decodeAmount`'s loose `commitmentBytes` papering over it accepts both. A caller doing
`Buffer.from(output.commitment)` will read a hex string as UTF-8 and get the wrong 64 bytes
silently.

**VERDICT D: PARTIAL.** Wire order, slicing, and daemon agreement are correct; output shape
changes break nothing today. The arity check is correct but unreachable, and the
Uint8Array/hex mix on the same object is a trap (silent, not a throw).

---

## E. HONESTY

Overclaims found, all prose, all minor but each implies more than is true:

1. `README.md:37-40`: "Then the guard that matters: `decodeRct` rebuilds ... and so does this
   build. A wrong derivation therefore produces a named refusal instead of a plausible number."
   True for a *wrong derivation with the chain's commitment*. False for what a wallet will
   actually wire: supply both sides and every amount is "right", including a lie (C.iii, above).
   The README drops the qualifier the header keeps.
2. `state/FINDING-F1-ringct-amount.md:137`: "the only caller is no longer a test." No `src/`
   file calls `decodeAmount` — grep gives one hit, the definition. `received-amount.test.mjs`
   does not import it either (its two live tests are width/bytes only, and the header of that
   file still narrates an inverse that is no longer there). The reachability claim is true only
   in the sense "tests now call it from fixtures", which the next clause says; the first clause
   is wrong.
3. Same finding, line 143: "a wrong derivation now yields a named refusal, not a number." Same
   missing qualifier as (1).
4. `ringct.js:33`: the amount bound is cited to `src/ringct/rctOps.cpp decodeRct`. `decodeRct`
   has 0 occurrences in rctOps.cpp and 6 in rctSigs.cpp; `h2d` is defined in rctTypes.cpp:144.
   Wrong file cited for the one claim in that block.
5. `ringct.js` header claims each rule is "taken from ... file by file, and named where used",
   but the amount-bound citation (#4) is wrong, and the h2d refusal is cited to a name
   (`decodeRct`) rather than the definition. Cosmetic, but it is the header that advertises the
   provenance discipline.

Correct and not overclaimed: "Sixteen appears nowhere", "no real amount can be decrypted
in-repo", "the commitment check proves a decode is *a* valid opening, never *the* owner's",
"a screen or watcher still must not call an amount confirmed", the `a69c641` paragraph in the
header (that one is accurately worded), and the `types 1/2/3 do scalar subtraction` note. The
type 3 nbp claim holds too: it is `FIELD(nbp)` not `VARINT_FIELD` (`rctTypes.h:457`),
`serialize_int` is fixed-width (`binary_archive.h:109-127`), and the fixture's four bytes at 401
are `01000000`.

**VERDICT E: PARTIAL.** No false statement about a decrypted amount; four sentences imply the
guard verifies a decode without saying whose commitment made it so, and "the only caller is no
longer a test" is false in `src/`.

---

## OVERALL

The arithmetic is faithful to upstream on every point that was checkable — tags, split, widths,
subtract direction, reduce, H, refusal set — and no real bug was found in the code path; the
guard is a tautology when the caller supplies both commitment and info, prose hides that
qualifier in two places, `decodeAmount` still has no `src/` caller, and F1's end-to-end gate
(the owner's amount) remains open exactly as the tail of the finding admits.

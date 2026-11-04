# AUDIT-3 - key material and derivation path

Lane A3, independent adjudicator. Scope: `src/root.js`, `src/monero/keys.js`,
`src/monero/base58.js`, `src/monero/address.js`, `src/monero/pocket.js`,
`src/address.js`. Method: prove by execution (`state/findings/probe-A3.mjs`),
pinning every primitive to Monero's own vendored vectors or a published vector,
and re-deriving the wallet by hand from the phrase with an independent BIP32.

## Verdicts (FALSE first)

| # | area | verdict |
|---|---|---|
| 5 | hex-vs-bytes coercion | **FALSE** (latent): `hashToScalar` silently eats a hex string |
| 1 | non-canonical scalars / zero secret | **PARTIAL**: reduction is right; zero secret refused where Monero accepts |
| 2 | `xmrPocketEntropy` well-defined / collision-free | **VERIFIED** |
| 3 | `encodeAddress` (checksum, prefix, refusal) | **VERIFIED** |
| 4 | derivation frozen, re-derivable | **VERIFIED** |

**OVERALL:** the money path is sound and externally pinned - no normal-path
funds-loss - with two edge defects: `hashToScalar` returns a wrong-but-valid
scalar for a hex string, and a zero secret is refused where Monero's `sc_check`
accepts it.

Run: `node state/probes/probe-A3.mjs`.

---

## 5. Hex string vs bytes - FALSE

`hashToScalar(data)` does `new Uint8Array(data ?? [])`. A hex *string* is not a
byte array: `new Uint8Array('aabb')` is length **0**, so the function hashes zero
bytes and returns a canonical, plausible, wrong scalar. Every other door
(`scReduce32`, `secretToPublic`, the byte readers) requires a `Uint8Array` and
refuses a string loudly; this one does not.

```
$ node -e "const u=new Uint8Array('aabb');console.log('len',u.length)"
len 0
  new Uint8Array("aabb") ->  (not aabb)
  hashToScalar("aabb") = 4a078e76...5d85a400  hashToScalar(bytes) = eae48a42...c740080c
  FAIL hashToScalar(hexstring) matches bytes: false
  ok   scReduce32(hexstring) refused
  ok   secretToPublic(hexstring) refused
```

No in-repo caller passes a string today (all callers feed `Uint8Array`), so it is
latent, but `hashToScalar` is exported and documented as "keccak-256 of the
data". A caller that hands it a hex literal gets a valid 32-byte key that is not
the one it asked for. Verdict **FALSE** for the area's proposition.

## 1. Non-canonical scalars / zero secret - PARTIAL

All reduction boundaries are correct and canonical after reduction: `l-1`, `l`,
`l+1`, `2^255-1`, `2^255+1`, `2^256-1` all return `value mod l` and pass
`isCanonicalScalar`. `keyDerivation`/`secretToPublic`/`keyImage`/`deriveSecretKey`
refuse a non-reduced secret rather than silently using it. Every positive secret
in every pinned section (`generate_key_derivation` 32, `generate_key_image` 32,
`derive_secret_key` 256) is canonical, and all 48 refusal vectors are the
non-canonical or off-curve cases Monero refuses, so there is **no** vector where
Monero reduces and we do not.

```
  ok   l-1: reduced=ecd3f55c...0000  canonical=true
  ok   l:   reduced=0000...0000      canonical=true
  ok   l+1: reduced=0100...0000      canonical=true
  ok   2^256-1: reduced=1c95988d...ff0f canonical=true
  non-canonical positive secrets (Monero may accept where we refuse): {}
  ok   refuses l+1: A secret key is not reduced mod l...
```

The one divergence is the reverse direction and is deliberate: `keyScalar`
refuses zero, but Monero's `sc_check(0)` is true and `secret_key_to_public_key(0)`
returns the identity `0x01||0…`. Since `scReduce32(l) == 0`, a pocket whose
entropy is `≡ 0 mod l` (or a `deriveSecretKey` call with a zero base) throws here
where Monero would produce a wallet. Probability ~`2^-252`, so real but rare.

```
  identity encoding: 010000...0000
  our secretToPublic(0): throws -> A secret key of zero is not a key.
  ok   scReduce32(l)=0, so entropy==l yields a zero secret
```

PARTIAL: the vector-backed behaviour is exact; the zero case diverges.

## 2. `xmrPocketEntropy` - VERIFIED

It is `derivePocket(seed,'xmr',index).privateKey`, a BIP32-hardened leaf. Three
thousand consecutive indices yield 3000 distinct, 32-byte values; it returns the
same `derivePocket` bytes; it is not the bitcoin leaf at the same index; it
returns fresh bytes.

```
  ok   3000 indices: collisions=0 badLen=0
  ok   entropy is the derived xmr pocket key
  ok   xmr entropy != btc key at same index
```

Two indices cannot collide except by a BIP32 break; "one wallet shown twice" is
excluded across the practical range. Well-defined and collision-free.

## 3. `encodeAddress` - VERIFIED

Pinned to Monero's own `keys_addr` account vector, and the checksum is exactly
`keccak(prefix||payload)[0..4]` recomputed independently from the decoded bytes.
The prefix is the mainnet standard byte 18; a subaddress (42) is a different
string and decodes back to `kind:'subaddress'`. Bad keys (all-zero point of order
four, identity, `0xff*32`) are refused via `isValidPublicKey` (on-curve, not
identity, prime-order subgroup). Tampering the checksum is refused.

```
  ok   matches Monero keys_addr vector
  ok   checksum is keccak(prefix||payload)[0..4]
  ok   mainnet standard prefix byte is 18 (got 18)
  ok   tampered checksum refused
  ok   standard vs subaddress distinguishable
  ok   refuses bad spend zero / identity / ff*32
```

Swept the whole `monero-base58.txt` address corpus externally as well:
`encode/encode_block` 46 ok, `decode_pos` 33 ok, `addr` 21 ok, `addr_neg` 16
refused, `decode_neg` **85 of 85** refused (56 string-level plus 29 block-level).
This is a strong external pin, and it holds.

```
  decode_neg refused 85 of 85 accepted-wrongly 0
```

## 4. Derivation frozen - VERIFIED

Re-derived the first three addresses *by hand*, not by calling the module's
composition: BIP39 seed from `node:crypto` PBKDF2 matches the published Trezor
vector for `abandon…about`; a hand-rolled BIP32 (HMAC-SHA512, node crypto)
reproduces `xmrPocketEntropy` at `m/44'/128'/0'/0'/i'`; a hand Monero account
(spend = `scReduce32(entropy)`, view = `scReduce32(keccak(spend))`, base58 with
prefix 18 and a keccak checksum) reproduces `moneroPocket`'s keys and address
exactly for i = 0,1,2.

```
  ok   BIP39 seed matches the published Trezor vector
  ok   hand BIP32 m/44'/128'/0'/0'/0' == xmrPocketEntropy
  ok   hand-built wallet 0 == moneroPocket   (1, 2 likewise)
```

The README's "first three addresses pinned by a test" are therefore not
self-confirming: they agree with an independent derivation. Value counts backing
the primitives: `biased_hash_to_ec` 64, `derive_secret_key` 256, others 32/16
each, base58 202 rows, plus 1 external address pin. `scReduce32` has no direct
vector but is pinned transitively by `hash_to_scalar` (32) and the mod in
`derive_secret_key` (256).

## root.js, read by hand (A1 glances; A3 owns the verdict)

- `rootFromMnemonic` normalizes case and whitespace, then `validateMnemonic`
  refuses rather than repairs. Pinned: the seed for `abandon…about` equals the
  published Trezor BIP39 vector byte for byte.
- Paths are fully hardened and out of range is refused, not wrapped:
  `m/84'/0'/0'/0'/i'` and `m/44'/128'/0'/0'/i'`, index `0..2^31-1`.
- `derivePocket` refuses an empty or non-bytes seed. A 32-byte seed is accepted
  (BIP32-legal), so a caller cannot pass entropy where seed bytes belong and get
  a silent result, though nothing in the string labels the two apart.
- `pocketFor(coin:'xmr')` returns `address: null`; the Monero address lives in
  `src/monero/pocket.js`. Correct one-way dependency, no import cycle.
- `btcPocketAddress` requires 33 compressed bytes and rejects a 32-byte key.

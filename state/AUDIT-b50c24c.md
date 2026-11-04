# AUDIT b50c24c - Lane A, independent

Target: `b50c24c` ("Lane C: own outputs, found in a scan that was proved first").
Scope audited: the commit's own diff (`git show b50c24c`, parent 8a90679):
new `src/monero/ownOutputs.js`, `src/monero/scan.js` (merge-mining skip + bridge),
`test/own-outputs.test.mjs`. Upstream truth fetched at pin
`3fd0f88c20f559839cafb20911cb13cb45eba7bd` (raw.githubusercontent), file by file.

Gate reproduced, then attacked: suite 637/637, build "32 modules resolved",
lint 0 errors / 15 warnings. A green gate was not treated as a verdict.

## A. The merge-mining fix - VERIFIED

Claim (both halves): upstream length-prefixes the merge-mining field; the old
fixed `32 + varint + 32` read was wrong; the new length-prefixed skip is right
and exact.

(i) Upstream mechanism, fetched at the pin:
`src/cryptonote_basic/tx_extra.h` - `tx_extra_merge_mining_tag::member_do_serialize`
reads/writes a `std::string field` via `do_serialize(ar, field)`, then parses an
inner helper (`VARINT_FIELD_N("depth")`, then `FIELD_N("merkle_root")`).
`src/serialization/string.h` - `do_serialize(Archive<false>, std::string&)` does
`ar.serialize_varint(size); ar.serialize_blob(buf, size)`. `src/serialization/variant.h`
+ `binary_archive.h` - the variant tag is one `uint8_t` written by
`write_variant_tag`/`read_variant_tag` (`serialize_int`). So the wire is
`0x03 || varint(len) || len bytes`, and the old fixed read is wrong twice: order
(`depth` then `merkle_root`, not a leading 32B hash) and both are inside the
prefixed string.

(ii) Exact consumption on the real miner extra:

```
$ node ... parseBlock(block) ; print minerTx.extra
real extra len 87  bytes[0..2]=03 21 00  (tag, len=33, depth=0)
new parser pubkey: 6b5d26cf172676a0d41a8d80fcccd210 07e0aa258333725d29a8e9c418882450
byte@35 = 01 ; expected pubkey region 36..68 = 6b5d26cf...82450  -> same
old code (32+varint+32) -> threw: "tag 36"
```

New skip: tag@0, varint@1 -> 33 (len 1), at = 1+1+33 = 35, pubkey tag@35,
pubkey@36..68. Inner shape is exactly `00`(depth) + 32B root = 33 bytes, so the
skip lands on the next field, no over/under-skip. `transactionPublicKey` then
walks the remaining fields to end (the whole-block test passes).

Overflow: `readVarint` is bounded to 10 bytes (`shift > 63`). `Number` of a
<=2^70 length is a safe double; all huge lengths refuse by overrun:

```
length=2^40 -> "The merge-mining field is cut short."
2^53, 2^63, 2^69, 2^70-1 -> all "cut short", no crash, no accept
```

Refusal test `03 40 ...` (len 64, 4 bytes) names the cut. VERIFIED.

## B. The proof order - VERIFIED

Traced `ownOutputsInBlock`: `parseBlock(blockBytes, {expectHash})` -> `walkBlockTxs`
-> only then the miner-tx scan and the tx-list scan. No pocket sees bytes before
both calls return.

Does the walk prove everything the scan trusts? The non-miner txs are id-proved
against `block.txHashes` (from the served block) and the root is rebuilt from the
proven ids. Tamper/reorder before any scan:

```
tampered tx byte   -> threw before scan (parse refused)
wrong expectHash   -> threw
swapped two txs    -> "bytes and list do not agree: hash-list index 0 ..."
```

The miner tx is NOT in `txBytesList`; it is proved transitively: `parseBlock`
computes `minerId` from the miner-tx bytes and `treeRoot` from `minerId + txHashes`,
and the block id hashes that treeRoot. With `expectHash` the miner-tx bytes are
therefore committed; a tamper inside the miner tx is caught by the id proof:

```
miner tx byte flipped -> "That block proves the id dac92e18... not <expected>"
```

The scanned `block.minerTx` is the same object `parseBlock` proved, so no
unproved bytes reach a pocket. Caveat, documented in the module: with
`expectHash` omitted the block is only self-consistent (no external anchor).
VERIFIED.

## C. The bridge - VERIFIED

`bridgeWalkedTransaction` spreads each output, so `viewTag`, `ecdh` and
`commitment` ride through unchanged (same object identity for the byte slices),
and only `key` is converted. Probe:

```
viewTag kept: true   ecdh kept: true   commitment kept: true
key -> Uint8Array(32)
idempotent: second bridge produces identical key bytes
re-bridge from a hex string after mutation: converts again -> true
```

Wrong-length key: `hex.decode` does not length-check, but `scanTransaction`
does, with a named refusal and no crash:

```
key = Uint8Array(30) -> "Output 0 has no one-time key."
null / odd hex       -> "hex: string expected" / "odd-length string"
```

From real bytes `readTransaction` always emits 32-byte keys, so the unchecked
decode is only reachable by hand-fed input, and it still refuses. Idempotence is
true for the tested mutation (bytes pass through, string re-decodes). VERIFIED.

## D. trustViewTags - VERIFIED

Filter is a function of the same derivation used for the key: with the filter ON
the tag decides before the key compare; OFF (`scanEveryOutput` strips `viewTag`)
every output gets the full byte compare. Removing the filter cannot drop a true
match - demonstrated on a forged pocket whose key matches but whose derivation is
bogus (so its tag does not):

```
trustViewTags=true  (ON)  found: 0   <- tag filter skips the forged match
trustViewTags=false (OFF) found: 1   <- full compare finds it, amount refused
```

`keys.viewTag` vs upstream `crypto.cpp::crypto_ops::derive_view_tag`: identical
construction - `cn_fast_hash("view_tag"[8] || derivation || write_varint(index))`,
first byte. Vendored vectors all pass:

```
$ node --test test/monero-keys.test.mjs  -> ok 10 "view tags match Monero for every vector" (16/16)
```

So the filter-ON path rests on arithmetic that is proven against Monero's own
generated vectors; a true output is not skipped by a wrong-tag derivation. Note
(not a defect): with a wrong pocket viewSecret a true output is skipped by the
filter, because the tag is derived from that same wrong derivation. VERIFIED.

## E. Honesty - VERIFIED

`ownOutputs.js` header and commit message checked for overclaim. Header states
membership and value are separate, that the miner tx refusal is a type fact (Null
has no ecdh), that a refused amount is reported not dropped, and the honest
remainder: "a real amount that matches the owner's still needs the owner's view
secret, and these fixtures pay strangers." That the join's value path is only
exercised via synth-encoded round trips (no chain-decoded value) is stated, not
hidden. No claim that a found output is spendable (no key-image/spend path here),
no claim that a value is produced on these fixtures. Commit "offset 35" and
"length 0x21 / depth 0x00" both reproduce exactly. The gate string
"637/637, build 32, lint 0e (15w)" reproduces. VERIFIED.

## OVERALL

VERIFIED - no FALSE or PARTIAL; every claim in the target was re-run or
recomputed against upstream at the pin, and the sole caveats (no expectHash =
self-consistent only; join value path untested on-chain) are the ones the module
already states.

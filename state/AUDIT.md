# AUDIT — cipher-wallet, append-only

Adjudicator: lane A. One section per landed commit. Re-run the gate yourself; re-derive the needle
from the fixture bytes yourself. A lane's word is not acceptance; this file's verdict is.

Base: f1fcd6f. Baseline gate measured by ant: 544 tests / 544 pass / 0 fail, build 31 modules,
lint 0 errors 18 warnings.

Verdict scale: VERIFIED / PARTIAL / FALSE / UNPROVABLE.

## 2026-11-03 — base gate, f1fcd6f (lane A, independent)

Environment: clean `git archive f1fcd6f` into a scratch dir, repo `node_modules` symlinked.
(Current worktree is not clean: lane N has 4 modified + 1 untracked file. Base was measured off the
archive, not the dirty tree.)

    node --test test/   -> 1..544, tests 544, pass 544, fail 0  (137.6s)
    npm run build       -> build: 31 modules resolved
    npm run lint        -> 18 warnings, 0 errors (93 files)

VERIFIED — base gate reproduces ant's numbers exactly.

## 2026-11-03 — FINDING F1 (ant) adjudicated

Upstream pinned at `3fd0f88c20f559839cafb20911cb13cb45eba7bd`, fetched raw, read locally:
`src/ringct/rctTypes.h`, `src/ringct/rctOps.cpp`, `src/ringct/rctSigs.cpp`, `src/crypto/crypto.cpp`.
No line numbers from the finding were trusted; each was re-located.

### Claim 1 — WIDTH: decodeAmount demands 16; no Monero type writes 16. **VERIFIED**

Upstream serialization, `rctTypes.h:348-382`:
- `compressed_ecdh = (type == Bulletproof2(4) || CLSAG(5) || BulletproofPlus(6))`
- compressed: `FIELD_N("amount", crypto::hash8)` only, mask is NOT serialized -> **8 bytes/output**
  (`rctTypes.h:364-377`; `min_size = sizeof(hash8)` at :354)
- uncompressed (types 1 Full, 2 Simple, 3 Bulletproof): `FIELDS(ecdhInfo[i])` = `key mask; key amount`
  -> **64 bytes/output** (`rctTypes.h:105-106, :378`)
- Null (0): returns before ecdhInfo (`rctTypes.h:324-326`).
So the upstream set of widths is {0, 8, 64}. 16 is absent.

Local reader matches upstream widths, and neither is 16:
- `src/monero/block.js:237` type 6: `take(8, 'ecdh amount')` = 8.
- `src/monero/block.js:257-258` type 3: `take(32,'ecdh mask')` + `take(32,'ecdh amount')` = 64.
- `src/monero/ringct.js:81` demands `info.length !== 16` -> refuse.

Reproduced on pinned real bytes (`test/fixtures/monero-tx-ringct-type6.json`,
`monero-tx-type3-2in.json`, read via `readTransaction(bytes, 0, ...)`):

    type 6 rctType=6 outputs=2: reader consumed 8 byte(s) of ecdh per output
      decodeAmount(real width) -> An output carries sixteen bytes of ecdh info: eight of amount and eight of mask.
    type 3 rctType=3 outputs=2: reader consumed 64 byte(s) of ecdh per output
      decodeAmount(real width) -> An output carries sixteen bytes of ecdh info: eight of amount and eight of mask.

No fixture in the repo can feed `decodeAmount`. Only `encodeAmountForTest` can, and it is its inverse
(`ringct.js:93-102`).

### Claim 2 — PAD: upstream reduces and domain-separates; repo does neither. **VERIFIED**

Upstream, re-read:
- `crypto.cpp:269-278` `derivation_to_scalar` = `hash_to_scalar(derivation || write_varint(index))`.
- `rctOps.cpp:608-612` `hash_to_scalar` = `keccak` then `sc_reduce32`. So the shared secret IS reduced.
- `rctOps.cpp:695-703` `genAmountEncodingFactor(k) = keccak("amount" || k)` (6+32 = data[38]).
- `rctOps.cpp:709-717` `genCommitmentMask(sk) = hash_to_scalar("commitment_mask" || sk)` (15+32 = 47).
- `rctOps.cpp:734-745` `ecdhDecode(..., v2)`: v2 (types 4,5,6) derives the mask, never reads it,
  and xor8's amount with the "amount"-tagged pad; v1 (types 1,2,3) is `sc_sub` with
  `hash_to_scalar(sharedSec)` / `hash_to_scalar(hash_to_scalar(sharedSec))`.
- v2 flag wiring `rctSigs.cpp:1093,1228,1566`: v2 only for types 4/5/6.

Repo (`ringct.js:56-61, 80-86`): `ecdhHash = keccak(derivation || varint)`; no `sc_reduce32`, no
"amount" tag, mask XOR'd from payload bytes 8..16.

Reproduced (`node padcheck.mjs`, derivation = 0x11*32, index 0, sc_reduce32 = LE mod l,
l = 2^252 + 27742317777372353535851937790883648493):

    upstream derivation_to_scalar : d306ee2392eeaf7147fb6cd1329f0a61 5a189eb5a3fea39c58052a20d05d7e04
    repo ecdhHash                 : 8756c597fb7af9d1a06e4b5dad8686b4 5a189eb5a3fea39c58052a20d05d7e44
    upstream amount pad : db6f2f4cf643b3e4
    repo amount pad     : 8756c597fb7af9d1
    equal: false        (matches the finding's two values exactly)

Three independent defects, each sufficient: no reduce, no "amount" tag, mask carried vs derived.

### Claim 3 — UNREACHABLE: reader discards ecdh, sole caller is a test. **VERIFIED**

    grep -rn decodeAmount --include=*.js --include=*.mjs .   -> src/monero/ringct.js:80 def;
      test/received-amount.test.mjs:32,61,67,76,86; test/monero-ringct.test.mjs:16,59,69,79,82
    any src import of './ringct.js'                          -> none
So `ringct.js` has zero runtime importers at all, stronger than the finding claimed.

On pinned bytes: output object keys are exactly
    type 6 -> ["amount","key","viewTag"]; type 3 -> ["amount","key"]
and `readTransaction` returns no `ecdh`/`info` key (grep `ecdh` in block.js hits only the three
`cursor.take` discards at :237,:257,:258). The `amount` on an output is the pre-RingCT varint, 0.
Verdict: VERIFIED. (Fix necessarily spans `block.js` (lane R) and `ringct.js`, as the finding says:
`decodeAmount` cannot be fixed inside ringct.js alone.)

### README sentence: "RingCT amounts now decrypt (`src/monero/ringct.js`)" — **FALSE**

README.md:72. It decrypts a 16-byte 8+8 format this repo invented; no Monero output of any type has
that width, and the pad is wrong in three ways. The trailing hedge ("pinned only to keccak's vectors
... not to a real transaction") concedes unproven provenance, not a wrong algorithm, so it does not
rescue the sentence. Also README.md:25-28 "pinned to published vectors": the published vectors pin
keccak and varint only, not the encoding — PARTIAL at best.
Honest sentence: the amount path is not built.

Note (not part of F1's charges, added by lane A): `ringct.js:17` says "the modern encoding is 8+8
bytes". Upstream v2 is 8 bytes of amount only with the mask derived; 8+8 is wrong even as a
description of the invented format's upstream cousin. `ringct.js` header should be corrected with
the README.

## 2026-11-03 — Lane N, c22e6a7 "Node source: CIPHER_XMR_NODE is read at runtime" — **PARTIAL**

Scope check: touches only lane-N files (`nodes.js`, new `test/node-source.test.mjs`); no
block.js/ringct.js/fixtures/README. OK.

Gate at c22e6a7, clean archive: `node --test test/` -> 552 tests, 552 pass, 0 fail. Matches claim.

VERIFIED mechanics:
- `git grep -n nodeSourceFromEnv -- src/` -> only its definition at `nodes.js:160`; no src reader
  at f1fcd6f. After c22e6a7, `nodeOverride()` (`nodes.js:148-152`) reads `process.env` at CALL time;
  `node --input-type=module -e "..."` with a v3 onion in `CIPHER_XMR_NODE` -> `nodeSourceFromEnv().pick()`
  returns it; with it unset -> "No Monero node is configured..." named refusal.
- Override beats list, list still ships `PUBLIC_NODES = []`, malformed override refused at the door
  (`nodes.js:56-72`). Clearnet override allowed by design; shipped clearnet row refused. Tests 8/8 real.

PARTIAL, one defect of claim:
- `grep -rn "nodeSourceFromEnv\|createNodePool" --include=*.js src/` -> definitions only; **zero
  callers in src**. `grep "from './nodes.js'" src/` -> none. `nodeClient.js` still does not import
  `nodes.js`. So "The one entry point a scan uses" (`nodes.js:154`) is a door no scan opens. O1's
  substance ("a scan has no node to ask") is unchanged: a caller that does not pass an injected pool
  still gets no enforcement, and no src caller passes one. README.md:110-112 ("nodes.js is not
  imported by [nodeClient.js]") remains literally true after this commit, and README.md:109-110
  ("Nothing reads the variable at runtime yet") is now stale. README is not lane N's file; ant owns
  that correction. Named as PARTIAL, not FALSE: the commit does what its own sentence says for the
  module, and the lack of a scan orchestrator is structural in this repo.

## 2026-11-03 — Lane N, 74b7c91 "O6: the pinned node is checked BEFORE the socket" — **VERIFIED**

Scope check: `nodeClient.js`, `test/monero-node-client.test.mjs`, `test/pool-door.test.mjs`. OK.

Gate at 74b7c91: 558 tests / 558 pass / 0 fail; build 31 modules; lint 18 warnings 0 errors. Matches.

O6 red-first reproduced independently, not from the commit body. Script imports `getBlock`,
`getTransactions`, `getInfo` from base `f1fcd6f` vs HEAD, with a fetchImpl that logs and a pool whose
`assertCurrent` records and throws:

    BASE f1fcd6f
      getBlock        log ["http://peer.example:18081/json_rpc","assert"]   network-before-refusal 1
      getTransactions log ["http://peer.example:18081/get_transactions"]    network-before-refusal 1
      getInfo         log ["http://peer.example:18081/json_rpc"]            network-before-refusal 1
    HEAD 74b7c91
      getBlock / getTransactions / getInfo -> log ["assert"], network-before-refusal 0

The new regression tests are real guards, not tautologies: served HEAD's
`test/pool-door.test.mjs` to the base tree -> 5 of 9 fail (the three O6 door tests, the ordering
control, the dead-node test); all pass at HEAD.

No failover, with the REAL `createNodePool` (not a test double):
    pool = createNodePool({nodes:['first...','second...'],allowClearnet:true}); getBlock(first,...,{fetchImpl:throw})
    -> "The Monero node first.example:18081 did not answer: ECONNREFUSED..."
    attempts: 1; next pick: second.example:18081; assertCurrent(first) now refuses.
`call()` asserts at `nodeClient.js:68` before URL construction; `getTransactions` asserts at :269
before its own fetch at :290; the two after-the-fact asserts are deleted. Both network sites
(`:86`, `:290`) are guarded. No defect found.

Residual (not a lane N defect): `pool.abandon?.(address)` at :97/:300 is optional-call, so a pool
without `abandon` silently loses the next-scan rotation. Only the real pool is used, and it has
`abandon` (`nodes.js:120-124`). Noted, not counted against.

## 2026-11-03 — 326898c "ringct: the amount path is a sketch, not a decoder" (docs, F1 response) — **VERIFIED**

Scope: README.md + `src/monero/ringct.js` comments only. `git show --stat`: 32 insertions, 13
deletions, no executable line changed (every hunk in ringct.js is inside the header comment).
Gate at HEAD: 558/558 pass, build 31 modules, lint 18 warnings 0 errors.

Content check against F1: README now says amounts "do **not** yet decrypt", names the 16-byte
shape, the wrong pad and the unexposed bytes, and points at the finding. ringct.js:17 now says
"EIGHT bytes of amount and no mask at all; the mask is derived", which is upstream-accurate
(`rctTypes.h:364-377`). The earlier overstatement is gone; no new overclaim introduced. No code
change, so no regression surface. VERIFIED.

Note: this is ant's commit, not lane R. Lane R still has no commit: HEAD 326898c, no
`test/fixtures/monero-tx-rct-*.json`, no `test/rct-type-*.test.mjs`.

## 2026-11-03 — 19689f3 "README: the node door is open but no scan walks through it" (docs) — **VERIFIED**

Docs only (README.md, 7+/4-). Gate at HEAD: 558/558 pass, 0 fail.
Content check: states both halves correctly — the variable is read at runtime via
`nodeOverride`/`nodeSourceFromEnv`, and `nodeClient.js` does not import `nodes.js` / no src caller
passes a pool, so a caller omitting one gets no pre-socket enforcement. This matches lane A's
PARTIAL evidence at c22e6a7 exactly. No overclaim. VERIFIED.

Lane R status: still none. HEAD 19689f3; `ls test/fixtures/monero-tx-rct-*` empty; no
`test/rct-type-*.test.mjs`.

## 2026-11-03 — pre-existing corpus, independent re-capture over Tor (lane A) — **PARTIAL (index convention only)**

Node: xmr-node.cakewallet.com:18081 via 127.0.0.1:9050. Script fetches get_block(height), reads
json.tx_hashes, fetches /get_transactions for the entry, compares bytes to the fixture.

    monero-tx-ringct-type6.json  h3796965 tx_hashes[0]  bytes_equal true  2220B  block hash match
    monero-tx-type3-1in.json     h1750000 tx_hashes[1]  bytes_equal true  1911B  block hash match
    monero-tx-type3-2in.json     h1750000 tx_hashes[5]  bytes_equal FALSE 1885 vs 2707
    monero-tx-type3-2in.json     h1750000 tx_hashes[4]  bytes_equal true  2707B  (tx id d2e04… is at index 4)

The bytes of type3-2in are real (direct /get_transactions by its txHash returns the identical 2707
bytes); the finding is the index convention. `scripts/pin-tx.mjs` uses 1-based index with "index 0
is the miner tx" (`pin-tx.mjs:171-175`), so its `--index 5` = `tx_hashes[4]`. The fixture's
`source.txIndexInBlock: 5` follows that convention, while `monero-tx-type3-1in.json` records 1 and
sits at `tx_hashes[1]` (0-based). Both files are real; the corpus does not use one convention for
`txIndexInBlock`. A re-deriver following index 5 as a 0-based tx_hashes index gets a different
transaction (id 97192238…). Not a fabricated fixture. Recommendation: state the convention in
test/fixtures/README.md, or store `txHashesIndex` explicitly. This is a pre-existing fixture, not a
lane R commit.

## 2026-11-03 — mainnet availability of RingCT types 1/2/4/5 (lane A survey) — **VERIFIED**

Independent survey through the same node/Tor path, first 3 non-miner txs per height, type read by
`readTransaction`'s own dispatch/refusal:

    1230000  1,1,2      1250000  2,1      1280000  1,1,2
    1800000  4,4        2100000  4,4,4
    2250000  5,5,5      2400000  5,5,5    2600000  5,5,5

All four types are present on mainnet and findable in minutes. "Not found on mainnet" is not
available as a reason for any of types 1, 2, 4, 5. Lane R must capture, or state a different reason.

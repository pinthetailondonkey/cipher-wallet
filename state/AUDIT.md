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

## 2026-11-03 — Lane N, 3116cbc "Node selection: a door with no pool walks the environment itself" — **PARTIAL**

Scope: nodeClient.js, nodes.js, monero-node-client.test.mjs, monero-nodes.test.mjs, pool-door.test.mjs.
All lane-N files. Gate at the commit: 572/572 pass, 0 fail; build 31 modules; lint 0 errors. Matches.

VERIFIED core claim, independently, against base 19689f3 and HEAD:
    env={CIPHER_XMR_NODE:'named.example:18081'}, getBlock('stranger.example:18081', ..., {env})
      19689f3: 1 network call to http://stranger.example:18081/json_rpc (accepted the stranger)
      HEAD   : refusal "A scan runs against one Monero node...", 0 network calls
Same 0-call refusal on getTransactions and getInfo. Env-set path reaches the named host; process-env
path does too; createPinnedPool seeds `session` so the no-env fallback does not refuse everything
(the bug I flagged pre-commit is fixed and its regression test is real). `configured.pick()` at
nodeClient.js:73 fixes the fresh-pool assert.

TWO DEFECTS, both reproduced (hence PARTIAL not VERIFIED):

1. NO NEXT SCAN AFTER ABANDON. `configuredPool()` caches the pool and `pick()` is called only at
   build time (nodeClient.js:73). After a transport failure `pinned.abandon(address)` nulls the
   session; every later no-pool call returns the same cached pool and `assertCurrent` throws, with
   no `pick()` and no network call, forever:

       env={CIPHER_XMR_NODE:'dead.example:18081'}; call1 fetch throws; call2/3/4 use a 200 fetch
       call 1 REFUSED "did not answer: ECONNREFUSED"
       call 2,3,4 REFUSED "A scan runs against one Monero node. Refusing to stitch..."
       network calls total: 1   (the node coming back is never re-asked)

   This contradicts nodes.js:9-12 and the commit's own "the NEXT scan starts on the next node, from
   the start": nothing starts a next scan. For a one-node override the remaining refusal should at
   least be `pick()`'s named "No configured Monero node answered. This is a failed read..." rather
   than the stitching sentence. With a multi-node shipped list (once the founder fills it), rotation
   through the doors never happens at all. Missing test: a two-call sequence across an abandon.

2. IN-PLACE ENV CHANGE DOES NOT REBUILD. For an injected env object the cache key is object identity
   (`POOLS_BY_ENV` WeakMap, nodeClient.js:61-66), so changing `env.CIPHER_XMR_NODE` in place reuses
   the stale pool:

       env={CIPHER_XMR_NODE:'first...'}; getBlock(first) OK; env.CIPHER_XMR_NODE='second';
       getBlock(second) -> "Refusing to stitch", 0 calls to second

   The commit says "a changed value builds a new pool" and the test of that name uses two different
   env objects, so it does not cover the in-place case. The process-env path (keyed by the value
   string) is correct.

## 2026-11-03 — Lane R, 8b4fc6a "pin-tx: capture the shapes the reader refuses, and pin one of each" — **PARTIAL**

Fixture authenticity: all four PROVEN against live mainnet, not taken on trust. Method: independent
re-capture over Tor by height -> block hash -> the block's own tx_hashes -> /get_transactions, byte
compare. Provenance block read independently of the fixture's own `source`.

    rct-1 h1600000 tx_hashes[0] blockHash match true bytes_equal true 13192B
    rct-2 h1500000 tx_hashes[0] blockHash match true bytes_equal true 13524B
    rct-4 h1800000 tx_hashes[0] blockHash match true bytes_equal true  2629B
    rct-5 h2300000 tx_hashes[0] blockHash match true bytes_equal true  1451B

Not hand-written: every byte equals what the node serves today. Type claim corroborated by the
node's own `as_json` rct_signatures.type = 1/2/4/5 on all four, and each `declared byteLength`
equals the actual `asHex` length. `txHashListIndex` 0 matches the live listing index for each, and
the newly recorded `txIndexConvention` closes the 1-based/0-based ambiguity I raised at 1750000.

Gate at 8b4fc6a: 592 tests / 592 pass / 0 fail; build 31 modules; lint 18 warnings 0 errors. Matches
the claim; 572 -> 592 is the 20 corpus tests the four new files add (each gets a needle + 4 controls
entry points, all taking the refusal branch).

Same-pattern check (fixture not self-consistent-only): the needle here asserts the refusal regex, and
the 4 mutated controls are skipped because `probe === null`
(test/monero-tx-corpus.test.mjs:58-70). So for these four commits nothing is proven by a computed
id. The id is evidenced only by the block's hash list. That is correct for a red-first pin, but it is
weaker than the type-3 and type-6 pins and must not be described as node-proven until a reader
computes the id.

PARTIAL, three reasons:

1. NO READER YET. Deliverable is capture + refusal + read + needle + controls. Only steps 1-2
   landed; `readTransaction` still refuses all four and no `test/rct-type-*.test.mjs` exists. The
   fixture bytes are committed with `rctType: null`, so nothing in the tree can test them beyond the
   refusal sentence.
2. PROVENANCE SCHEMA GAP. `source` carries node, transport, capturedAt, blockHeight, blockHash,
   rederive, index fields (good) but no `endpoint`; the ladder in the work order names it. Mixed:
   `rederive` names pin-tx.mjs, which implies get_block + /get_transactions, so it is derivable
   rather than absent. Same gap exists in five pre-existing fixtures.
3. NO LEDGER ENTRY. test/fixtures/README.md is where this repo records each fixture's source,
   checksum, transformation and re-derivation. None of the four files is listed, and their sha256s
   are not recorded anywhere. For a corpus whose whole argument is provenance, an undocumented file
   is the weakest link.

`refusedByReader` is a genuine improvement and is honest: it records the exact sentence and leaves
`version`/`rctType`/`shape` null instead of guessing. Commit message byte counts and tx-prefix
digests match what I measured.

## 2026-11-03 — Lane N, 5d2917c "Node selection: re-pick a cached pool, and key it on the value" — **VERIFIED**

Scope: nodeClient.js + pool-door.test.mjs. Gate on a clean archive of the commit: 595/595 pass,
build 31 modules, lint 18 warnings 0 errors. Matches. (Commit body says "Previous was 572/572"; the
parent 8b4fc6a was 592. Bookkeeping typo only, not a gate discrepancy.)

D1 reproduced fixed. Same script as at 3116cbc, env={CIPHER_XMR_NODE:'dead.example:18081'}:
    call1 fetch throws      -> "did not answer: ECONNREFUSED"
    call2,3 with a 200 fetch -> "No configured Monero node answered. This is a failed read..."
    network calls total: 1
The wrong "stitching" sentence is gone; the honest exhausted-pool refusal is `pick()`'s.

D2 reproduced fixed:
    env.CIPHER_XMR_NODE='first...'; getBlock(first) OK
    env.CIPHER_XMR_NODE='second...' (same object); getBlock(second) OK
    calls: first JSON-RPC, second JSON-RPC
Both new tests are real guards: served 5d2917c's pool-door.test.mjs to 3116cbc -> 2 fail
("O1/D1" and "O1/D2"), 21 pass; at 5d2917c all pass.

RESIDUAL, named for when the shipped list is filled (not observable today, because PUBLIC_NODES is
empty and an override is one address): re-picking on every no-pool call means a second call after an
abandon silently moves to the next node in a multi-node list. With a caller-held pool the scan is
still pinned per pool, but a no-pool caller has no scan boundary, so "a dead node refuses the scan
rather than stitching two operators" holds only for callers who inject a pool. Recommend: no-pool
calls either never rotate (single-shot) or a scan must hold a pool. Recorded as a risk, not a
regression: at 3116cbc the same path refused forever, which was fail-closed but for the wrong
reason, and the shipped list is currently empty.

## 2026-11-03 — Lane R, b24389f "RingCT: read types 1, 2, 4 and 5" — **VERIFIED**

Fixture bytes re-verified against live mainnet AFTER the commit: all four still byte_equal true,
declared byteLength == actual, provenance now complete (endpoint added), `refusedByReader` removed,
`rctType` numeric, ledger sha256s in test/fixtures/README.md match `sha256sum` of each file exactly
(276ed43f…, 6441afed…, 1a9cfa97…, d784ee94…). Gate on a clean archive: 611/611 pass, build 31,
lint 18w/0e. Matches the claim.

Reader correctness, checked against upstream `rctTypes.h` at the pinned commit rather than against
the author's own words:
- compressed ecdh for 4/5 (`min_size = sizeof(hash8)`, mask not serialized) matches `block.js`
  8-byte take; 1/2/3 use `FIELDS(ecdhInfo)` = 64 bytes. Correct.
- type 2 pseudoOuts in the BASE before ecdhInfo (`rctTypes.h:331-346`); prunable pseudoOuts only for
  3/4/5/6 (`:586-600`); type 1 none. `block.js` places they exactly so.
- Borromean `rangeSig` = 64+64+1+64 = 193 keys/output (`rctTypes.h:192-196`), unprefixed, one per
  output. Match.
- Version 2 type-1 really is emitted: `cryptonote_tx_utils.cpp:549`
  `use_simple_rct = sources.size() > 1 || range_proof_type != RangeProofBorromean`, so a 1-input
  pre-Bulletproof tx is Full. The walker's Full branch is one matrix of `ring x (inputs+1)` then one
  cc. Hand arithmetic on rct-1: prunLen 12832 == outs*193*32 + ring*(ins+1)*32 + 32 = 12832. type-2
  base decodes as type byte 1 + a 6-byte fee varint + 256 == Ins*32+outs*64+outs*32; prunLen 13056
  == outs*193*32 + ins*(ring*2*32+32). Both land exactly on the last byte.

Controls now execute (probe non-null): 4 per fixture, 16 in all, and I re-ran them independently.
Each flip lands inside its named section and every one either refuses or changes the id; none keeps
the node's id. The recorded "base flip refuses on the two compressed types and changes the id on the
other two" is accurate.

Two nits, neither blocking:
1. `version` stays null on all four fixtures though the reader parses it (always 2). The field is
   nullable by contract, so not false, but now knowable.
2. The type-1 fixture is ONE input, so the Full-only `inputs + 1` column term is exercised only as
   `1 + 1`. A multi-input type-1 tx is rare under `use_simple_rct` (only pre-Bulletproof, and only
   when all real inputs share an index) and my mainnet sweep of 1230000-1300000 found none; say so
   rather than imply the 2-input Full case is pinned. Note the prunable is 12832 bytes for only 2
   outputs: 2 proofs x 193 x 32 = 12352, i.e. 6162 bytes per output, because Borromean proofs carry
   no aggregate compression. That is the real cost of the pre-Bulletproof types, not a sizing error.

## 2026-11-03 — d5447c1 "README: every RingCT type a transaction carries is read" — **PARTIAL**

Docs only. Gate at HEAD: 611/611, build 31, lint 0e.

The RingCT half is TRUE and now correctly scoped: "every RingCT type a real transaction can carry
is now read: 1..6", all nine corpus fixtures reproduce their node ids from bytes
(needle-all.mjs: 9/9 idmatch true, every walk ends at the last byte), and the two layout traps are
named. Types 4/5 are given their rctTypes.h names. Types 1, 2, 4 and 5 are no longer described as
refusing. Correct.

The node half is now STALE, and this is the same class of defect F1 was about — a sentence that
outlived its code, in the opposite direction:

    README.md:121  "`nodeClient.js` does not import `nodes.js`"
    README.md:123  "nothing opens the door yet"

    reality: nodeClient.js:31 `import { createPinnedPool, nodeSourceFromEnv, OVERRIDE_ENV } from
             './nodes.js'`; :111 poolFor(); :155 and :367 `const pinned = poolFor(...)`

Also stale by implication: "a caller that omits one gets no pre-socket enforcement" — 3116cbc and
5d2917c made exactly that caller enforced. The paragraph was correct at 19689f3 and was not revisited
when the door was wired. PARTIAL: the RingCT claim VERIFIED, the node paragraph FALSE as written.

Verdict on the README as a whole: of the two sentences this audit was asked about, `RingCT amounts
now decrypt` (F1) was FALSE and is now corrected; `every RingCT type ... is read` is now VERIFIED.
The node-door paragraph needs the same correction it got once already.

## 2026-11-03 — 04358d0 "README: the node door is walked, and what is left is only the list" — **VERIFIED**

Docs only; gate at HEAD 611/611, build 31, lint 0e. Every factual clause re-tested rather than
read:

    "a caller that injects a pool keeps it unchanged"      -> injected pool. assertCurrent called: true
    "with no override and no list, the refusal is named
     at the wallet boundary"                              -> /No Monero node is configured/: true
    "falls back to the node it named"                      -> getBlock returned the named address: true
    nodeClient.js imports nodes.js; poolFor at :111; checks at :155 and :367  -> all true

The residual I raised is now stated in the README ("a no-pool caller has no scan boundary, so it
rotates after an abandon where a pool-holding caller would refuse") and points at this file. That is
the honest framing; the underlying design choice is still open but it is no longer a hidden one.

The remaining claim of absence is accurate: `PUBLIC_NODES` is still `[]` (`nodes.js:41-46`), so a scan
still needs the variable or a hand-passed node.

Also corrects the count in 19689f3's own paragraph without dropping it: the door is walked, only the
list is missing. VERIFIED.

## 2026-11-03 — 6edf861 "fixtures: record the knowable version, and say which term is not pinned" — **VERIFIED**

Both of my nits addressed, and the fixture bytes are unchanged in substance (only `version` null -> 2).

- `version` is 2 on all four; the reader agrees; the ledger sha256s were recomputed and all four
  `sha256sum`s match the new values exactly (006e9a25…, 05c36979…, 3a205e1e…, e374e63f…).
- The input-count hole is stated as a hole in test/fixtures/README.md:381-390, with the ranges swept
  and the `cryptonote_tx_utils.cpp:549` line, and "Do not read this fixture as pinning the column
  term." Accurate.

Re-verified after the change: all four still byte_equal true against live mainnet (13192 / 13524 /
2629 / 1451), all four ids still compute from bytes and match. Gate 611/611, lint 0e.

Spot-check of the sweep claim: my own independent sweep of 1230000-1300000 found no multi-input
type 1 either; their 1180000-1340000 and 1390000-1700000 ranges are wider than mine, so the
statement stands as far as it is testable without a full-chain scan.

One correction to their reasoning, not the result: the README says "`use_simple_rct` goes false only
for a single source, so Full is emitted". Upstream is the reverse polarity —
`use_simple_rct = sources.size() > 1 || range_proof_type != RangeProofBorromean` — so Simple is taken
when there is more than one source, and Full only for exactly one source under a Borromean proof
config. The conclusion (Full exists, is single-input by construction in that branch) is right; only
"goes false only for a single source" is loose about which side of the test it means. Cosmetic.

## 2026-11-03 — closing index (lane A)

Sections above are append-ordered, not commit-ordered. Chronology of the commits landed after the
base, with the verdict each carries:

    c22e6a7  N  PARTIAL     74b7c91  N  VERIFIED
    326898c  docs VERIFIED  19689f3  docs VERIFIED
    8b4fc6a  R  PARTIAL     b24389f  R  VERIFIED
    3116cbc  N  PARTIAL     5d2917c  N  VERIFIED
    d5447c1  docs PARTIAL   6edf861  fixtures VERIFIED
    04358d0  docs VERIFIED
    (0c03cb5, cb98797, c138f9a are state/ commits of this file, not code)

F1: three claims VERIFIED, README sentence FALSE and corrected at 326898c.
Final gate at c138f9a / working tree: 611 tests, 611 pass, 0 fail; build 31 modules; lint 18w/0e.

Open after close, none blocking: PUBLIC_NODES empty (founder), no-pool rotation residual (design,
stated in README), no multi-input type-1 witness, decodeAmount still an unbuilt sketch (F1).

## 2026-11-03 — fba917b "fixtures: the type-1 polarity was inverted, and the hole is smaller" — **VERIFIED**

Docs only; gate 611/611, build 31, lint 0e (re-measured).

Corrects the sentence I flagged: `use_simple_rct = sources.size() > 1 || range_proof_type !=
RangeProofBorromean` (`cryptonote_tx_utils.cpp:549`), so Full is chosen only for exactly ONE source
under Borromean. The new text states the polarity correctly and draws the right conclusion: Full is
single-input in practice, the `inputs + 1` serializer term is always 2 on chain, and only a
hand-built tx could exercise `> 2`. That is stronger than what it replaces.

The 185-type-1 sweep count is taken as reported, not re-run (a partial re-run is not evidence for a
negative); the conclusion does not depend on it, because the upstream branch makes a multi-input
Full impossible for a wallet-built transaction. The distinguishing term is still unwitnessed, and
the text now says exactly that rather than implying a chain sample exists.

## 2026-11-04 — 46db7eb "audit: fb70854, findings A-E" — **PARTIAL**

Adjudicating the auditor. Fetched `rctTypes.cpp`, `rctSigs.cpp`, `rctOps.cpp` at the pinned
`3fd0f88c20f559839cafb20911cb13cb45eba7bd` again and re-ran the numbers; none of the report's
figures were accepted from prose.

A reproduces: tag lengths 6/15; both pad pins match `keccak("amount"||k)` and
`hash_to_scalar("commitment_mask"||k)` for two independent fills; H reproduced from G and
`clearCofactor()` equals the pinned `8b655970…`. B reproduces exactly: 256/256 rows byte-equal
after `sc_reduce32`, 17/256 for the unreduced keccak, and 256/256 if the comparison were mod l.
That is the audit's own caveat, and it is correct: the byte comparison, not the vectors, is what
kills the old bug.

D reproduces by cutting, not by reading. Cut every byte of the base on six fixtures (362 / 402 /
361 / 469 / 355 / 265 cuts): `arity fires: 0` in every case. A short base is caught by
`cursor.take` ("output 1 commitment needs 32 bytes and 31 are left") or by the prunable varint;
the arity guard is correct and has no reachable trigger. The audit's "close to unreachable" is if
anything generous: on current code it is unreachable.

C.iii: **the conclusion is right, the demonstration is false.** At the API level, own `info` plus
own commitment is still a tautology: 100/100 lies pass per type (1..6), and 200/200 over runs of
200. The audit's thesis stands. But the printed table claims the type-6 fixture's real `ecdh` plus
a self-chosen commitment returns every lie. It does not. Re-ran it with the 0x99 fill, the chain's
`ecdh`, and `commitmentOf({amount: lie, mask: derived})`:

    lie 1 / 777 / 42000000000 / 18446744073709551615   all REFUSED
    "The decoded pair does not rebuild the output's commitment"

With the chain's `ecdh`, only the decoded value rebuilds the commitment; a caller has to supply
its own `info` as well to make the lie pass, which is a different setup from the one printed. The
audit overstated its evidence, not its result. That is the one thing in 46db7eb that is quietly
wrong, and it is recorded here because a false demonstration is worse than a harsh verdict.

E was correct at audit time: `git grep decodeAmount e14969a -- src/` returns the definition only,
so "the only caller is no longer a test" was false then.

**VERDICT on the audit: PARTIAL.** Four of five sections reproduce exactly; C's verdict is right;
C.iii's table cannot have been produced by the code it names.

## 2026-11-04 — 3249ef5, C fix (the qualifier) — **VERIFIED**

The qualifier is present in `README.md:39-45` and `state/FINDING-F1-ringct-amount.md:139-144`, and
it is accurate, not an overcorrection: it says the refusal is real only when the commitment comes
from the chain, and that a caller supplying its own `info` and its own commitment re-solves the
equation. Both halves re-measured:

    chain commitment, wrong derivation, real fixtures, types 1..6:  0/1000 pass, 0/32 flips pass
    own info + own commitment:                                       100/100 pass per type

The 0/1000 and 0/32 hold for all six types, not just the two the test drives. The audit's bucket
split is also right: 1000/1000 of the type 1/2/3 refusals are the superfluous-data bound, and
1000/1000 of the type 4/5/6 refusals are the commitment. See the gap section for what that means.

No overcorrection: the text still says the guard matters, and it does when the commitment is the
transaction's.

## 2026-11-04 — 3249ef5, D fix (byte shape and arity) — **VERIFIED**

`outputs[i].commitment` is now a `Uint8Array` of exactly 32 on all six type families;
`Buffer.from(output.commitment).length` is 32, so the UTF-8 trap is closed. Both forms still decode
identically, and not only on a refusal: a self-consistent pair returns 123456789 through bytes,
lowercase hex, spaced hex and uppercase hex. The new test only compares the two refusal messages
(it uses a wrong derivation), so it proves parity of the refusal path, not of an accepted decode;
the accepted path is correct anyway (re-derived here).

The arity check is unchanged in logic and still correct: it compares the number of entries, and
`cursor.take` now yields 32-byte entries, so its meaning did not shift from hex characters. The
new comment states the unreachability plainly and gives the right reason. Cut sweep as above:
0 firings, every short read caught earlier.

## 2026-11-04 — 3249ef5, E fix (citations and callers) — **PARTIAL**

1. README qualifier: fixed, accurate (see C).
2. "the only caller is a test": **not fixed; now false in the other direction.** At HEAD
   `src/monero/scan.js:160` calls `decodeAmount`, yet `README.md:46` says "`decodeAmount` also has
   no caller in `src/` yet; the tests drive it" and `state/FINDING-F1-ringct-amount.md:137` says
   "nothing in `src/` calls `decodeAmount` yet". The same commit's own header
   (`src/monero/scan.js:15`) says it "gives `decodeAmount` a caller in `src/`". The commit message
   says both. The correction is stale on arrival.
3. FINDING line "a wrong derivation now yields a named refusal, not a number": the sentence is
   unchanged, but point 4 immediately above now carries the qualifier, so it is mitigated rather
   than fixed in place.
4. Citation: fixed and now correct. `h2d` is defined at `src/ringct/rctTypes.cpp:144`;
   `decodeRct` has 0 occurrences in `rctOps.cpp` and 6 in `rctSigs.cpp`, and calls `h2d` at
   `rctSigs.cpp:1582`. The header names the definition file and the caller file correctly.
5. Header provenance claim: resolved for the one citation that was wrong. Every other cited file
   re-checked and correct.

**VERDICT E: PARTIAL.** Citation and README fixed; the reachability sentence is still false at
HEAD and contradicts the caller added in the same commit.

## 2026-11-04 — 3249ef5, the new caller `decodeMatchedAmounts` — **PARTIAL**

Answers to the three questions:

- It uses the transaction's own commitment: yes, `outputs[match.output].commitment`, never one the
  caller built, and it refuses a match whose output lacks `ecdh`/`commitment`.
- A refusal is reported, not dropped: yes, it pushes `{pocket, output, refused}` and no `value`.
  Driven on the type-6 fixture with a forged pocket whose one-time key lands on the chain's, the
  result carries the reason and no number. Re-ran; gate 628/628.
- Can it attach the wrong `ecdh` to the wrong output? Not inside one call: `outputs[match.output]`
  and `index: match.output` are the same index, so the derivation index, the `ecdh` and the
  commitment are all the output the match names. The residual hole is one level up: `matches` is
  an argument and nothing binds it to `transaction`, and the result carries no transaction id. A
  match taken from transaction A and passed with transaction B decodes B's same-index output with
  no error (demonstrated; it returns a refusal only because the derivation does not fit). The
  binding the C finding names is moved, not closed.

**VERDICT: PARTIAL.** The wiring is real and the refusal is honest; the function still accepts a
match set it cannot verify belongs to the transaction it decodes.

## 2026-11-04 — the four builder commits, re-derived

    fb70854  VERIFIED   branch, widths, pads, H, refusal set all re-derived; 0/1000, 0/32
    a69c641  VERIFIED   header and test; caller-own pair passes, chain pair refuses
    4e40861  VERIFIED   eleven fixtures, width 8/64, every output, bytes after D
    e14969a  VERIFIED   near-misses: 0/32 flips, wrong index and swapped ecdh refused

No arithmetic defect in the amount path was found by me either.

## 2026-11-04 — what neither lane caught

1. **The commit contradicts itself on reachability.** 3249ef5 adds the `src/` caller and in the
   same diff writes that no `src/` caller exists, in both the README and the finding. The audit
   could not see this (it audited e14969a); the builder wrote it while adding the caller; the
   commit message states both versions.
2. **The new caller does not bind its matches to its transaction.** `decodeMatchedAmounts` takes
   `matches` as an argument and returns records with no transaction identity, so a caller can pair
   transaction A's matches with transaction B and get B's same-index output decoded, or a refused
   entry, with no signal that the pair belongs to a different transaction. This is the same
   convention the C finding names, one layer up.
3. **The 0/1000 figure is not evidence for the commitment guard on types 1/2/3.** On the
   uncompressed types the `h2d` bound runs before `commitmentOf`, and 1000/1000 random wrong
   derivations are refused as "superfluous data"; the commitment check never runs. The number is
   true but measures the bound there, and both the README and the finding present it as the
   chain-commitment refusal. The audit printed the bucket split but drew no consequence from it.
4. Minor: the bytes-vs-hex parity test exercises only a refusal, and the new caller test only
   reaches the refusal branch, so `decodeMatchedAmounts` has no positive decode test at all. The
   accepted path is correct (re-derived here), but a broken decode that still refuses would pass
   both tests.

## 2026-11-04 — closing index (lane A, chain base 07f6c2d)

    fb70854  VERIFIED     a69c641  VERIFIED
    4e40861  VERIFIED     e14969a  VERIFIED
    46db7eb  PARTIAL      (audit: A/B/D/E reproduce; C.iii demonstration false)
    3249ef5  PARTIAL      (C VERIFIED, D VERIFIED, E PARTIAL, caller PARTIAL)

Gate at HEAD, re-run by me, not read from the commit message:

    node --test test/   -> 1..628, tests 628, pass 628, fail 0  (23.8s)
    npm run build       -> build: 31 modules resolved
    npm run lint        -> 15 warnings, 0 errors (95 files)

Open, none blocking: the reachability sentence is false at HEAD; matches are not bound to the
transaction; no positive decode of a real amount is possible in-repo (unchanged, the owner's view
secret is external).

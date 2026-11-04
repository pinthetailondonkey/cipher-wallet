# AUDIT-4 — Monero read path + app-wide honesty

Lane A4, independent. Tree clean at `5ecbf6d`. Gate baseline: build 33/33, lint
0e/15w, test 660 pass / 0 fail. Every mutation below: break line, run, restore.

## FALSE first (README sentences the code does not support)

### F-1 `README.md:123-127` — ringct.js "is a sketch on a sixteen-byte shape Monero never writes" — **FALSE (stale)**
The sentence: *"RingCT amounts do **not** yet decrypt: `src/monero/ringct.js` is a
sketch on a sixteen-byte shape Monero never writes ... and its vectors pin keccak
and the varint rather than the encoding."*
Code: `src/monero/ringct.js:14` "There is no type that writes sixteen bytes",
`:254 "It now writes Monero's real layout, per type, instead of the invented
sixteen-byte tuple", and `decodeAmount` follows `ecdhDecode` per type 1-6.
Evidence: fixtures pin six types across eleven mainnet txs
(`test/fixtures/monero-tx-rct-*.json`, `monero-tx-ringct-type6.json`,
`monero-tx-type3-*.json`), and the README's OWN "What is still open" bullet says
decoding "is built per type". Two README sections contradict; the Derivation one
is stale. `decodeAmount` also does return a value for a known derivation, so
"amounts do not yet decrypt" is stale too.

### F-2 `README.md:151` — "What is still not built: the scan wired to a block walk" — **FALSE**
`src/monero/ownOutputs.js` calls `walkBlockTxs` and then scans
(`scanOne`); `src/monero/scanFromNode.js` wires node -> fetch -> prove -> scan.
The README itself says at `:57` "Lane C is built" and `:68` "A node driver
fetches and scans one block". The `:151` sentence is a leftover.

### F-3 `README.md:137` — "Every real miner transaction is version 2" — **FALSE**
`test/fixtures/monero-block-v1-early.json` is real mainnet block 100
(`majorVersion: 1`) and its coinbase is a version-1 miner transaction;
`src/monero/block.js:148` reads it and `test/monero-block.test.mjs` pins it as a
v1 exception. True only for the RingCT-era blocks, not "every".

### F-4 `README.md:203` — "the IDB adapter itself is exercised by the UI layer" — **FALSE here**
There is no UI directory in this repo (`ls` -> docs/src/test/scripts/state
only), and `indexedDbKv` (`src/pocketStore.js:30`) has no caller anywhere:
`grep -rn indexedDbKv src test` returns the definition line only. Nothing in
this repository exercises it.

## OVERCLAIM

### O-1 `README.md:99` "Merging pockets is possible" vs `:13` "no merging" — **OVERCLAIM / contradiction**
`src/spend.js` builds exactly one input, and its own header `:6` defers merging
to "Phase 4". So merging is *designed*, not built; the top line's "no merging"
is the accurate one.

### O-2 `README.md:149` "The live path runs that whole chain over Tor against a real node" — **OVERCLAIM (conditional)**
`scripts/scan-live.mjs` uses `--socks5-hostname` only when `CIPHER_TOR_SOCKS` is
set; over clearnet it is not Tor. And the live path is explicitly not in the
gate (`:163` "The gates are offline"), so "runs" is by hand.

### O-3 `README.md:8` "the tree root re-proven from the proven ids" — **OVERCLAIM (mild)**
The walk's root comparison is `txTreeRootOf([miner, ...provenIds])` vs
`block.txTreeRoot`, which `parseBlock` computed as
`txTreeRootOf([miner, ...txHashes])`. Once the per-slot check proves
`provenIds == txHashes` elementwise, the root check can only fail on a mutated
miner id (control 2) — true guard, but it is not an independent anchor.

### Everything else in README that is falsifiable: **TRUE**
Body layout `header||miner_tx||varint(count)||hash×count` (`block.js:598`);
"no public explorer / http local only / child token / signed fresh echo"
(`watcher.js`); `PUBLIC_NODES` ships empty (`nodes.js:41`); hook shipped but a
clone lacks `core.hooksPath` (`.githooks/pre-commit`); five pinned mainnet blocks
+ block 100 + block 202612 exist; `pin-tx.mjs` exists; "no tx building, no
recovery shards".

## Item 1 — Is `rootVerify.js` "unwired and redundant"? — **VERDICT: TRUE (with a shape note)**
`grep -rn verifyTreeRoot src test` -> only `src/monero/rootVerify.js:28` and
`test/root-verify.test.mjs`: no `src/` caller => **unwired TRUE**.
`walkBlockTxs` does rebuild the root from proven ids and refuses on mismatch
(`blockWalk.js:60-66`), and both use the same `txTreeRootOf` and the same
`parseBlock`-supplied miner id, so the walk performs `verifyTreeRoot`'s check
inline => **redundant TRUE**. The one thing the task asks about — a
*caller-supplied* claimed root the walk never sees — exists in the signature
(`claimedRoot`), but the walk's `block.txTreeRoot` is itself computed, never a
peer's, and no in-repo caller passes an external one. README is not wrong.

## Item 2 — exported symbols with no external caller
`grep -rn <sym> src test` per symbol (excluded own file):
- `verifyTreeRoot` (rootVerify.js) — no src caller, test-only.
- `decodeMatchedAmounts` (scan.js) — no src caller; `ownOutputs.js`
  re-implements the decode loop instead of calling it.
- `fromFieldElement` (keys.js), `cleanNode` (nodeClient.js) — exported but only
  called from their own file (no external ref anywhere, no test).
- Constants with no external ref: `ADDRESS_KINDS`, `PAYMENT_ID_LENGTH`,
  `ENCODED_BLOCK_SIZES`, `MAX_HEIGHT`, `DEFAULT_NETWORK`, `COMMITMENT_H_BYTES`.
Verdict: **real dead doors** are `verifyTreeRoot` and `decodeMatchedAmounts`; the
other two are needless `export`s. Nothing in `src/monero` is fully unreferenced.

## Item 3 — fetch doors: failed read vs finding, "reachability is not no"
`nodeClient` never returns empty where it should refuse: `getTransactions` throws
on `txs.length !== asked.length`, on `missed_tx`, on a bad `status`, on non-hex;
`readTxHashes` throws on a missing/non-array list; `getBlock` throws on an empty
or odd blob. `scanFromNode` with an empty daemon hash list passes `[]`, and the
walk's count check refuses any real mismatch. A died node abandons + refuses,
never empties (`nodes.js` "No configured Monero node answered"). Verdict:
**consistent**; the one asymmetry is documented: on a *hash* request `expectHash`
is silently ignored (hash wins) — `scanFromNode.js:53`.

## Item 4 — comparison direction / comment-vs-code drift
Every `claimed` use compares claim-vs-asked or claim-vs-list and is named:
`nodeClient.js:311-315` (claimed hash/height vs asked), `:266` (num_txes vs list
length), `blockWalk.js:50,66` (bytes-proved vs block list), `rootVerify.js:38`
(`root === claimed`). No wrong-direction compare found. Drafts:
- **code drift in the stray test** (see item 6): its header says a height scan
  "proves the id from the bytes" and a title repeats it, while the committed
  `scanFromNode.js`/`scan-from-node.test.mjs` were reworded to "self-consistent
  only" (commits `10d75b4`, `28b713e`). The stray file still reads as an anchor.
- `scan.js:105-110` comment about the removed validity check matches the code.

## Item 5 — README claim walk
See F-1..F-4, O-1..O-3 above and the TRUE list. Commands: `grep -n` on the cited
lines, plus `ls`, `grep -rn indexedDbKv`, and fixture inventory. Verdict: **four
FALSE, three OVERCLAIM; the rest supported.**

## Item 6 — `test/zz-audit-committed.test.mjs` — **VERDICT: redundant + divergent, not load-bearing**
It is a frozen pre-audit snapshot of `scan-from-node.test.mjs`: 7 tests, all
superseded by the 13 in `scan-from-node.test.mjs`. It is divergent: its stub
keeps the old shapes (`num_txes` inside the `json` string, tx field named
`hash`, always-empty `missed_tx`) that commits `10d75b4`/`28b713e` explicitly
corrected, and its wording is the pre-fix "proves the id from the bytes". It
adds no unique coverage. `git log -- test/zz-audit...` -> one commit, then never
touched again. It does not belong as a permanent peer; fold or delete.

## Item 7 — mutation tests (all restored; tree clean after)
WATCHED (test fails on break):
- `ringct.js` decodeAmount commitment rebuild compare -> **6 fail**.
- `scan.js` `sameBytes(expected, output.key)` -> **4 fail**.
- `block.js` block-202612 id exception -> **1 fail**.
- `blockWalk.js` root check -> **2 fail** (control 2 miner flip, reorder).
- `blockWalk.js` slot check -> **3 fail**.
- `keys.js` `isValidPublicKey` identity guard -> **2 fail**; `spend.js`
  change-to-payee guard -> **2 fail**; `nodes.js` clearnet refusal -> **1 fail**.
UNWATCHED (break leaves the suite green):
- `ringct.js` `commitmentOf` zero-amount / zero-mask branches (`amount === 0n`,
  `maskScalar === 0n`) -> **19 pass / 0 fail** on
  `test/ringct-amount-decode.test.mjs`; no test distinguishes them.
- `keys.js` `viewSecretFromSpend` 32-byte guard -> **0 fail**.
- `keys.js` `numberToBytesLE` "does not fit" overflow guard -> **0 fail**.

## Item 8 — does the gate gate?
- `npm run build` imports every `src/**/*.js` (recursive). Broken syntax ->
  exit 1; unresolved import -> `FAIL ... Cannot find module` exit 1.
- `npm test` runs `node --test test/`; unresolved import -> `ERR_MODULE_NOT_FOUND`
  exit 1; behavioral break -> failing test.
- `npm run lint` (`oxlint`): **exit 0 on an unresolved import** (it does not
  resolve imports) and exit 0 with 15 warnings; only syntax errors flip it.
Verdict: build+test gate for real, lint is advisory. But a broken *uncovered*
line does not fail any gate (see item 7 unwatched) — "a guard that cannot fail
is a comment" holds for those three.

## OVERALL
No money/identity direction bug in the fetch or scan path and no cross-module
hole found; the defects are honesty defects: four README sentences are false
(three stale against the code's own newer sections) and the stray
`zz-audit-committed.test.mjs` is a divergent pre-fix copy, while three
money/identity guards have no test watching them.

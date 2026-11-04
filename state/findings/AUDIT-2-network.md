# AUDIT-A2: Bitcoin network and scan side

Independent adjudication. Scope: `src/wire.js`, `src/peerClient.js`, `src/peers.js`,
`src/filters.js`, `src/chain.js`, `src/merkle.js`, `src/blockScan.js`, and the
header/walk tests. HEAD `436fb9d`. Probe: `state/findings/probe-A2.mjs`
(`node state/findings/probe-A2.mjs`, 24 checks, all PASS; raw run in
`state/findings/probe-A2.out`). Nothing fixed.

OVERALL: header+merkle checks are real and honest, but the load-bearing "two
independent peers agree" is unwired from every live scan path and is defeatable
by a single peer, which can invent a payment on a never-mined private chain.

---

## Area 1 (FALSE) — "two independent peers agree"

Hypothesis: filter data is believed only when two independent peers agree, so
one lying peer cannot hide or invent a payment. Claims quoted from README
"two-peers-agree paragraph" (lines 252-255) and the `src/peers.js` header.

Command: `node state/findings/probe-A2.mjs` sections 1 and 6.

Breaking facts:

- `verifiedFilter`/`agreedFilter` have **no caller in `src/`**; only tests call
  them (`grep -rn 'agreedFilter|verifiedFilter' src/`). The live scan,
  `scanBack`, takes `fetchFilter` from a **single** `peer` and never consults a
  pool. The agreement the README describes is not on the path the wallet uses.
- The same physical peer listed twice satisfies the quorum:
  `[A2 PASS] 1a one physical peer listed twice satisfies "two peers"` with
  `agreed peers=2 | server-A hits=2`. Two pool entries can be one operator:
  `[A2 PASS] 1b two pool entries (one operator) are counted as two agreeing peers`.
- A single peer invents a payment. A never-mined chain (arbitrary 80-byte
  headers, self-consistent merkle) is walked and its fabricated body produces a
  payment: `[A2 PASS] 1c one peer invents a payment` /
  `single-peer fabricated payments | 2 | amount=123456789`. No second peer, no
  work check (Area 4).
- Anchor-first, second-is-veto confirmed: `[A2 PASS] 6a` (first-answering liar
  vetoed -> refusal), `[A2 PASS] 6b` (anchor on a liar discards an honest 2-of-3
  majority -> refusal), `[A2 PASS] 6c` (liar-first + one colluder carries a
  false filter). So the anchor's identity decides the outcome and the second
  peer can only veto, exactly as the code comment says. A single honest peer
  never outvotes the anchor.

Verdict: FALSE as applied to the product. VERIFIED only as a description of the
dead `agreedFilter` function.

## Area 5 (PARTIAL) — is a height trusted or counted; tip-hash door / anchor

Hypothesis (README line 280-294, `src/chain.js` line 10-11): "Nothing here
trusts a height"; the tip hash is the open door and the anchor is founder-named.

Command: `node state/findings/probe-A2.mjs` sections 5 and 7.

- `walkBack` stamps `height = tipHeight - step` and never proves it:
  `[A2 PASS] 5 walkBack stamps heights from the tipHeight CLAIM (777)`. A wrong
  claim is fail-closed downstream: inflated `[A2 PASS] 5 inflated height is
  refused`, deflated `[A2 PASS] 5 deflated height is refused` (fetch refuses on
  the first `cfilter` whose block hash is not the asked one). So heights are
  trusted claims, caught by the fetch, not counted from bytes.
- `walkHeadersForward` never fetches or hashes the anchor: a fabricated anchor
  hash that a header names as parent walks clean
  (`[A2 PASS] 7a an anchor that is not a real block is still walked`). Two
  competing forks off one anchor both pass every check and neither is chosen
  (`[A2 PASS] 7b` / `A=cd47005d B=be845899`). A wrong `anchorHeight` silently
  renumbers and is passed straight into `getcfilters`
  (`[A2 PASS] 7c`, `[A2 PASS] 7d height -> getcfilters startHeight | 800001`).
- README admits forks are undecided ("Deciding which chain is the real one is
  not in this build"), but "Nothing here trusts a height" is imprecise:
  `tipHeight` and `anchorHeight` are trusted, and only the Bitcoin
  `getcfilters` hash echo happens to catch a lie. There is no in-code height
  proof.

Verdict: PARTIAL (fail-closed, but heights and the anchor are trusted inputs;
fork selection absent, as admitted).

## Area 2 (VERIFIED) — checks on the exact believed bytes

Hypothesis: header hash AND merkle root are checked on the block that is
accepted; any copy/re-parse/fetch is a hole.

Command: `node state/findings/probe-A2.mjs` section 2.

- The block is fetched once: `[A2 PASS] 2 verifiedFilter fetches the block
  exactly once (no second copy)`. The returned `block` is byte-identical to what
  was merkle-checked, and re-derives the asked hash:
  `... byte-identical ...`, `... still hashes to the asked hash`.
- A single body-byte flip is refused by the merkle root; a header flip is
  refused by the hash-vs-asked check:
  `[A2 PASS] 2 a mutated body is refused` (merkle-root message),
  `[A2 PASS] 2 a mutated header is refused` (served-block message).
- `fetchFilter` compares the echoed block hash to the asked hash before an
  answer counts; `verifiedFilter` re-checks `actual !== asked`. The merkle check
  and the returned block are the same `bytes` object; no re-parse hole.

Verdict: VERIFIED for `verifiedFilter` and `walkBack`/`scanHeaderFirst` body
handling.

## Area 3 (VERIFIED) — omitted script under header-first

Hypothesis (README lines 281-287): header-first loses an omitted payment and
says so; the backwards walk keeps it.

Command: `node state/findings/probe-A2.mjs` section 3.

- `[A2 PASS] 3 header-first LOSES the omitted payment` (`payments=0 bodies=0`),
  `[A2 PASS] 3 backwards walk FINDS it (reads every body)`. `scanHeaderFirst`
  records the block in `skipped`. The README admission is exact, not hedged.
- Also matches `test/header-scan.test.mjs`, which prints the same number.

Verdict: VERIFIED (the admission is exact; header-first is unwired, README
says so).

## Area 4 (VERIFIED) — proof of work

Hypothesis (README proof-of-work paragraph, lines 269-272): no header work is
checked, so a peer-mined private chain links and hashes cleanly.

Command: `node state/findings/probe-A2.mjs` section 4, plus
`grep -n 'target|nBits|difficulty' src/*.js`.

- A header with `nBits = 0` (impossible target) is accepted and merkle-checked:
  `[A2 PASS] 4 a block with nBits=0 (impossible target) is accepted`.
- No target/difficulty code exists (only `bits` in the filter BitWriter).
- Cost: `[A2 WITNESS] 4 private-chain cost | each block: 1 arbitrary 80-byte
  header + self merkle root; 0 leading zeros required`. Demoed live in Area 1c:
  arbitrary `0xe...`/`0xf...` headers were walked and believed.

Verdict: VERIFIED (the README admission is exact; no work is verified).

---

## Residuals a fixer should see (not fixed)

1. Wire one live scan to `verifiedFilter`/a pool, or state plainly that
   `scanBack`'s filter provider is single-peer.
2. The spurious-false-positive surface is the *body*, not the filter, once the
   tip is peer-supplied: `scanBack` trusts one peer's chain end to end.
3. Anchor-first means an honest 2-of-3 majority is discarded if the anchor lies
   (Area 6b): DoS, fail-closed, not a false answer.

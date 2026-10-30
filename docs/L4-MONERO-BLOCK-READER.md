# L4 — the Monero block reader: what it refuses, and why

Written while the build box is held, so it is words rather than a run. It
describes `src/monero/block.js` and `src/monero/nodeClient.js` as they stand,
and it is the page a future lane reads before touching either.

The one-sentence version: **a block is refused as a whole, never half-read, and
nothing it returns may gate a payment until the block id rule is pinned.**

## Why refusal is the whole design

A payment verdict is a money verdict. Every shape this build cannot frame is a
shape some transaction might arrive in, and a transaction it cannot frame might
be the one that pays this wallet. Skipping it is indistinguishable from "no
payment", and "no payment" is a verdict the wallet would act on. So the parser
has no tolerant mode: an input it does not recognise stops the block.

Two refusals deserve their own reason because they look like data:

- **A RingCT amount is not zero.** Modern Monero transactions carry `0` in each
  output's amount field and put the real value in an encrypted field. Reading
  that `0` as a number is not reading zero coins; it is reading an amount that
  was never decoded.
- **A count is a claim about what follows.** A varint that says "seven
  transactions" when four bytes remain is a lie, and a loop started on it would
  read past the end of the blob. The count is checked against the bytes left
  before any loop runs.

## The ten refusals

Each row is a thing that can arrive, the sentence the code says, and the test
that names it. The sentences are quoted from `src/monero/block.js`, not
paraphrased, so the page and the code cannot drift apart quietly.

| # | What arrives | What the code says | Test that names it |
|---|---|---|---|
| 1 | Something that is not bytes | `A block is read from bytes.` | every test, via the cursor |
| 2 | A blob that ends inside a field | `That block is cut short: <what> needs N bytes and M are left.` | `a block header parses field by field…` (header path) and the count test below |
| 3 | A count larger than the bytes left | `That block claims N <what> and has M bytes left, so it is cut short.` | `a count larger than the bytes left is refused before any loop runs on it` |
| 4 | A transaction version other than 1 or 2 | `That transaction names version N, which this build does not read.` | `a transaction version this build does not read is refused, not skipped` |
| 5 | An input this build cannot frame (a script input, or a coinbase height wider than four bytes) | `Input N is a shape this build cannot read, so the block is refused rather than guessed at.` | `an input this build cannot frame is refused, so a block is never half-read` |
| 6 | An output that is not a one-time key (a script output) | `Output N is not a one-time key, so this build cannot tell whose it is.` | `an output that is not a one-time key is refused, because this build cannot tell whose it is` |
| 7 | An amount wider than 64 bits | `<what> is larger than one output can hold, so it is refused rather than wrapped.` | `an amount larger than one output can hold is refused rather than wrapped` |
| 8 | An encrypted RingCT amount (type 1 to 5) | `That transaction uses RingCT type N. This build reads type 0 only, so the block is refused — an encrypted amount has not been decoded, and an undecoded amount is not zero coins.` | `an encrypted RingCT transaction is refused, so an undecoded amount is never read as zero coins` |
| 9 | Bytes left after the last transaction | `That block has N bytes left after its last transaction, so its shape is not one this build reads.` | `bytes left after the last transaction are refused, so a shape this build cannot frame is not half-read` |
| 10 | The same transaction id twice in one block | `Transaction <id> appears twice in one block, so an identity here names more than one transfer.` | `the same transaction twice in one block is refused, because an identity would name two transfers` |
| c | **The node client:** the node takes the connection and then says nothing past the deadline | `The Monero node <host> did not answer within N ms. A silent node is a failed read, not a finding about any payment.` | `a node that takes the connection and then says nothing is refused on a deadline, never waited on` |

The last row is the transport's, not the parser's, and it is in this table on
purpose: a stall is the one failure that looks like patience rather than like a
refusal, and a read that never ends is a payment that never moves. It says
*failed read*, never *no payment*, in the same words as every row above it.

**That row was the weakest link on this page, and the weakness is now closed.**
Its first mutation was caught by a hang rather than by a red: the stalled fetch
never settled, the runner saw an empty event loop with a pending promise,
cancelled the file and printed `# fail 0` behind a column of `not ok`. The test
now carries a backstop inside the fake fetch, so removing the deadline fails by
name in under half a second instead of stalling the file. Measured after the
fix: mutant `const timer = null` reddens exactly one test, `not ok 17 - a node
that takes the connection and then says nothing is refused on a deadline, never
waited on`, count 1 of 24. A green summary hiding a live mutant is the same
shape as a test that cannot fail, and it is worth remembering that the first
version of this row was exactly that.

The amount rule has a positive control beside it, not only refusals:
`a version 2 transaction with the null RingCT type reads its amounts in the
clear`, and `a block parses its miner and its transactions, and every amount is
a BigInt of piconero`. A guard that refuses everything passes every refusal
test; only the positive control tells a guard from a wall.

## The boundary: identity is not proven, and the code says so

This is the part that must not live only in a README. It lives in three places,
and the third is the one that matters.

1. **The module header**, first paragraph, before any other claim about the
   file:

   > it does not prove that a block is the block you asked for. The block id
   > rule needs one real (bytes, hash) pair to be pinned against, and this
   > repository has none — pinning our own writer's output would only prove
   > that our arithmetic agrees with itself, which the README already names as
   > the trap. So `parseBlock` returns `identity: { proven: false }`, and a
   > caller that asks for verification is REFUSED rather than quietly given
   > something weaker. Until that vector exists, nothing this file returns may
   > gate a payment.

2. **The return value**, where a caller meets it in an object rather than a
   paragraph:

   ```js
   identity: {
     proven: false,
     because: 'The block id rule is not pinned to a real sample yet, so this block has no proven identity.',
   }
   ```

3. **A test named for the gap, which fails closed.** Not "identity is not
   proven" — a name that says what happens to a caller who asks for more than
   this build can give:

   > `THE GAP: the parser does not prove a block's identity and refuses a caller who asks it to (fails closed until a real sample is pinned)`

   The test passes `expectHash` and asserts a refusal. When the block id rule
   is pinned, that test is the one that must change, and a lane that pins the
   rule without changing it gets a red named for exactly this.

There is also `assertBlockIdentityProven(block)`, which throws
`This block has no proven identity. It may be parsed, but nothing it says can
move a payment.` It exists so the first lane that wires a block into a pocket
scan hits the gap at the call site rather than reading a boolean and deciding
for itself what false means.

**What the boundary costs, said plainly:** this build refuses every modern
mainnet block, because every modern mainnet block contains encrypted amounts.
That is not a bug to be worked around in a hurry. A guessed RingCT proof size
would shift every following transaction by a few bytes and produce a block that
parses cleanly and is wrong, which is the failure shape this repository has
already paid for once (see "What has gone wrong here" in the README).

## What the node client adds

The client's job is that a stranger's answer never arrives wearing the shape of
a fact. It returns bytes, never the daemon's parsed copy. Its refusals are:

- no answer at all, and no answer **within a deadline** — a node that takes the
  connection and then says nothing is a stall, and a read that never ends is a
  payment that never moves;
- an answer that arrived from another host than the one asked;
- a non-2xx status, a body that is not JSON, a body with no `result`;
- a daemon whose chain is on another network, or that is still syncing;
- a daemon whose own claimed hash or height disagrees with what was asked —
  checked as a claim, never as a proof;
- a pinned node that is no longer the pinned node, checked on every answer, so
  one scan cannot straddle two operators.

Every one of these is worded as *a failed read*, never as a finding about a
payment.

## Gaps in this page, named rather than hidden

- Refusals 4 and 5 (a transaction version this build does not read; an input
  shape it cannot frame) are implemented but have no test of their own. A guard
  with no test is a guard a later edit can remove without a red. They are owed
  before this slice is called done.
- `parseBlock` proves nothing about identity, by design, and the test named for
  the gap is the record of that.
- Nothing here has met real mainnet bytes. Every fixture is built by this
  repository's own writer, which is exactly the arrangement the identity
  argument warns about.

## What this page does not claim

- It does not claim the parser is complete. It claims every shape it does not
  frame is a refusal rather than a guess.
- It does not claim the block reader is wired into a scan. It is not.
- It does not claim anything here is part of the shipped messenger. This
  repository is a separate product with its own history.

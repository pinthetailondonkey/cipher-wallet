# Cipher Wallet

A privacy wallet. One root secret, a fresh pocket per payment, and a spend that
never needs a custodian and never needs a node you run.

This repo is a set of well-tested parts with one entry point (`src/index.js`)
that assembles them: the units, the root and pocket derivation, the vault, the
receive path, the Bitcoin spend path, and the Monero keys, base58, address
encoding, block and transaction reading (pinned to real mainnet bytes with
provenance), the block walk (every transaction id proven against the block's own
hash list, the tree root re-proven from the proven ids), the transaction fetch
client (getTransactions with named refusals), and the capture tooling
(pin-tx.mjs: one command from node + height + index to a pinned fixture). The
entry point is a seam, not a UI: it wires what exists and refuses to pretend the
missing parts are there. There is no Monero transaction building, no merging, no
recovery shards, and nothing here has been run against real money.

### What is still open on the Monero read path

- **Every RingCT type a real transaction can carry is now read**: 1 (Full), 2
  (Simple), 3 (Bulletproof), 4 (Bulletproof2), 5 (CLSAG) and 6 (BulletproofPlus).
  Each is pinned on real mainnet bytes with a needle and mutated controls, and
  the per-type layout traps are written down in `test/fixtures/README.md` against
  the pinned `rctTypes.h` — because they are traps: two of them cost a wrong
  reader here already (a matrix read as one row per input, which only disagrees
  on multi-input transactions, and a pseudoOuts array in a section upstream never
  writes it to).
- **RingCT amount decoding is built per type, and it refuses rather than
  guesses.** It was wrong before: it demanded sixteen bytes of ecdh info where
  no RingCT type writes sixteen, padded with a keccak that skipped `sc_reduce32`
  and the `"amount"` domain tag, and read a mask the modern types derive.
  `state/FINDING-F1-ringct-amount.md` holds the proofs, and every fix cites the
  pinned upstream line it follows. What is pinned now, and to what: the
  per-output scalar to Monero's own 256 `derive_secret_key` vectors; the
  commitment generator H to the bytes `crypto/generators.cpp` compiles in,
  recomputed from G in the test; both pads to literal bytes from the quoted
  `ecdhDecode`; the widths (eight for types 4/5/6, sixty-four for 1/2/3) to
  eleven real mainnet transactions across all six types. Then the guard that
  matters: `decodeRct` rebuilds the output's Pedersen commitment from the pair
  it decoded and refuses on a mismatch, and so does this build.
  **The qualifier matters:** the refusal is real only when the commitment comes
  from the chain. Hand `decodeAmount` its own `info` *and* a commitment the
  caller computed, and `C = mask*G + amount*H` is the equation it just solved,
  so any pair passes, including a lie. Nothing in the signature binds the
  commitment to a transaction, so "the chain's" is a caller convention, not an
  enforced one. The one `src/` caller, `decodeMatchedAmounts`, does run the
  membership scan itself and takes the commitment from the same output, so the
  convention holds on the path the wallet would use.
  **Measured, on the chain's commitment:** 0 of 32 single-bit derivation flips
  are accepted for types 4/5/6. For types 1/2/3 the `h2d` bound refuses first
  (1000 of 1000 random wrong derivations die as "superfluous data"), so on those
  types the bound is what bites and the commitment check never runs. Both are
  refusals; they are not the same guard.
  **What is still not pinned, and cannot be from inside this repository:** a
  real amount that matches one the owner knows, because the pad needs the view
  secret and keys stay out. So the commitment check proves a decode is *a* valid
  opening, never *the* owner's. The line that unblocks a screen or a receipt is
  still an external one, and no watcher calls a Monero amount confirmed yet.
- **Lane C is built: the wallet finds its own outputs in a scan, in the right
  order.** `ownOutputsInBlock` proves the block, proves every transaction
  against the block's own hash list and the tree root, and only then lets a
  pocket see an output, because a scan over unproved bytes is a belief.
  Membership and value stay separate: an owned output whose amount will not
  decode is reported with its refusal, and a transaction that cannot be read
  becomes its own row instead of throwing the block away. `state/AUDIT.md`
  records the chain: built, audited, adjudicated, four adjudicator findings
  fixed. The one witness the join lacked (no real fixture pays this wallet, so
  the success branch had no test) is now a synthetic block whose amount must
  come back through the whole path.
- **A node driver fetches and scans one block.** `scanBlockFromNode` is
  getBlock, then getTransactions, then `ownOutputsInBlock`, in that order. It
  adds no trust: the fetch refuses the node's claims and the scan proves the
  bytes. The one thing worth knowing is what a height request cannot anchor. A
  Monero block header carries no height field, so a single block's bytes cannot
  prove they are at height N; a height scan is therefore unanchored unless the
  caller passes `expectHash`, and the result says so in an `anchored` flag. Ask
  by hash, or pass the id you believe, if you want an anchor. `scripts/scan-live.mjs`
  runs the whole path against a real node.
- **`src/monero/rootVerify.js` is still unwired and is now redundant.** It was
  built as preparation for Lane C, but `walkBlockTxs` already rebuilds the tree
  root from proven ids and refuses on a mismatch, so nothing needs the separate
  door. It is kept until someone decides whether to call it or delete it.

## Setup, once per checkout

    git config core.hooksPath .githooks

The pre-commit hook scans staged additions for key-shaped material. It is
committed, but a clone does not carry config, so the line above is what makes it
live. Without it the hook exists and does nothing.

## The shape

- **One root.** A BIP39 phrase is the only secret at rest. Every pocket key is
  derived from it, so recovery is one phrase, not one phrase per payment.
- **A pocket per payment.** Each payment lands on its own derived key and its
  own address. Two pockets share no public relation.
- **A pay handle.** A stable name a customer pays to, which resolves on this
  device to a fresh pocket. It is a pointer, never a chain key.
- **One pocket, one spend.** Paying picks a single pocket that covers the
  amount. Merging pockets is possible and is the one moment the chain can link
  them; the app says so before it happens.

`src/index.js` is the entry point that puts those together on one seed and one
store (`createWallet`), and `package.json` names it, so `import 'cipher-wallet'`
builds a wallet rather than a bag of modules. It is a seam, not a UI: it wires
what exists, and names in its own header the parts that are still unjoined. When
the caller passes a socket `connect`, the wallet builds its own peer transport
(`wallet.peer`) and reaches a peer without hand-passed fetchers; without one it
still takes them from the caller. A scan finding is returned rather than
persisted, because the watcher alone may move a payment; the xmr rail is the
exception a caller opts into, because `src/monero/watch.js` turns a found output
into the same kind of watcher report, so `monero.scan({ record: true })` moves
an xmr pocket through that one path; a pocket issued with `amount` is checked
against that price, so a short xmr payment is refused like a short btc one.

## Derivation (the format, not an implementation detail)

Every segment is hardened:

    btc: m/84'/0'/0'/0'/index'
    xmr: m/44'/128'/0'/0'/index'

Why hardened: a non-hardened child plus a leaked parent xpub derives every
sibling. We never publish an xpub, but hardening removes the class. The cost is
that a standard wallet cannot find a single pocket by scanning; it restores from
the same mnemonic by re-deriving this path, as this app does.

Bitcoin pockets are P2WPKH. Monero has no BIP32 of its own, so the derived 32
bytes are entropy for Monero's key set, reduced in Phase 3. That much is built:
`src/monero/` holds the key operations, base58 and address encoding, all pinned
to Monero's own generated vectors, and `src/monero/pocket.js` turns one pocket
into one whole Monero wallet — its own spend and view keys and a standard
address — with the derivation frozen and its first three addresses pinned by a
test. The matching rule for spotting an output that is ours is built
(`src/monero/scan.js`) and tested against locally built transactions. RingCT
amount decoding is now built per type and refuses rather than guesses — the
earlier sixteen-byte sketch is gone. `src/monero/ringct.js` follows upstream
`ecdhDecode` (`sc_reduce32`, the `"amount"` domain tag, the derived mask) and
re-builds the commitment as a third witness; the proofs are in
`state/FINDING-F1-ringct-amount.md`. Decoding a real owned amount needs a view
secret external to this repo, so its success path is witnessed by a synthetic
block rather than a mainnet fixture.

**The block reader was withdrawn after review, and the withdrawal was the
feature.** `src/monero/nodeClient.js` fetches a block from one pinned node and
refuses every answer it cannot frame. `src/monero/block.js` parses a block
header and, now, its body, because the body model it first shipped with was not
Monero's. Review found two defects that 382 green tests could not see, and the
reason they could not see them is the point: the parser and its fixtures were
written by the same hand. The body is
`header || miner_tx || varint(count) || 32-byte hash × count`, not a list of
full transactions; and a version 2 transaction id is
`cn_fast_hash(prefix_hash || base_rct_hash || prunable_hash)`, not a hash of the
prefix alone. Version 2 is what modern miner transactions are (early blocks carry
version 1, pinned in `monero-block-v1-early.json`), so a v2 id read from the
prefix alone is wrong, and the old reader would have emitted confident, wrong
identities. A wrong identity is worse than none,
so the door refused, there was no flag that opened it, and the tests assert that
the old fictional shape is still refused — a fixture written here may not stand
in for a real sample.

The body was rebuilt against real mainnet bytes, not against a fixture written
to match the parser: the hash list is read from the block, every transaction id
is recomputed from that transaction's own bytes and must equal the block's own
entry for that index, and the tree root is re-derived from the proven ids and
must equal the root the block carries. A block whose bytes and list disagree is
refused by name. A walk that leaves a byte over is a framing lie and refused.
The live path runs that whole chain over Tor against a real node.

What is still not built on the Monero side: building and broadcasting a spend.
The read scan IS wired to the block walk — `ownOutputsInBlock` walks a proven
block and reads our outputs — and `scanBlockFromNode` is the node driver over
it. Nothing on the Monero side has been funded or touched mainnet.

The transport for reading blocks is ruled: a shipped list of public nodes in
`src/monero/nodes.js`, with a private node overriding the list when
`CIPHER_XMR_NODE` is set — one node per scan, sticky, and fail-closed, so a node
that dies mid-scan refuses the scan rather than stitching two operators together.
**The list ships two rows**, `xmr-node.cakewallet.com:18081` and
`nodes.hashvault.pro:18081`, both verified live on 2026-11-04 (a real block
fetched and scanned). So a scan has a node to ask with no configuration at all,
and a failed read moves the wallet to the next row for the next scan rather than
staying on a dead host; only a genuinely empty list refuses. The rows are clearnet
and each carries its own `allowClearnet` allowance on the row, as the rule
requires. Capture scripts still take `CIPHER_XMR_NODE` directly.

The variable is read at runtime, and `nodeClient.js` walks that door itself: a
caller that injects a pool keeps it unchanged, a caller that sets the variable is
checked against it, and a caller that injects none and sets nothing pins the one
node it named. The pinned-node check happens before the socket on every door,
never after the answer; the wallet's own `resolveNode` is what consults the
shipped list when there is no node and no override. With no override and no list,
the refusal is named at the wallet boundary rather than arriving as a socket
error.

What that leaves open: a no-pool caller has no scan boundary, so it rotates after
an abandon where a pool-holding caller would refuse; `state/AUDIT.md` records that
as a risk.

## The vault is two layers

The PIN vault (`src/vault.js`) is the inner layer. The device envelope
(`src/deviceEnvelope.js`) wraps it under a key that only this device holds, so
a copied ciphertext has the PIN layer but not the key. Opening takes both. A
device-key failure is a typed `DeviceKeyError` and is never told to the person
as a wrong PIN.

The header of `src/vault.js` names the Cipher commit it was ported from
(`cipher/src/useIdentity.js @ ec6e98b`). That sha is a surname, not a parent:
this repository is a separate product with its own history, it has copied one
file by hand from Cipher, and it descends from nothing in that tree. A Cipher
commit moving forward does not put this wallet behind it, and nothing here
needs a rebase when Cipher moves. Nor does Cipher depend on this: the arrow
runs one way, wallet ← Cipher, and it is a copy, not an import.

## The receive path

`src/payHandle.js` issues a stable pointer (32 random bytes, never derived from
the root). `src/receive.js` resolves it to the next derived pocket, writes the
pocket and the moved handle in one storage write, and asks the watcher about
that one address. `src/pocketStore.js` keeps the table on disk so it survives a
reload and a history re-fetch; a repeated report is a no-op, never a second
pocket. `src/watcher.js` holds the transport rules: no public explorer, plain
http only on this machine, a per-payment child token, and a signed, fresh
answer that echoes the ask.

Storage is a small key/value interface: IndexedDB in the app, a memory adapter
in tests. The IDB adapter itself has no caller and no test yet (there is no UI
directory), so it is the one storage door this repo does not yet walk.

## The spend path

The transaction is built and signed on this device. Nothing is handed to a
service that could sign for you.

- `src/tx.js` — serialization, the txid that ignores the witness, and the
  BIP-143 signature hash for witness v0. Checked byte for byte against the
  published BIP-143 vector, including the signed transaction.
- `src/address.js` — the payee address, decoded or refused. Witness v0 must use
  bech32 and v1+ bech32m; mixed case is refused; another network is refused.
- `src/psbt.js` — BIP-174. The signed artifact can be read before anything is
  broadcast. Witness v0 P2WPKH, SIGHASH_ALL, and exactly one input.
- `src/filters.js` — BIP-157/158 compact block filters, so the wallet learns
  which blocks mention its own addresses without asking anyone.
- `src/merkle.js` — a block body against its own header. Every transaction id,
  folded into the merkle root the header names; a body that does not hash up to
  its header is refused, so a real header cannot carry a body of a peer's own.
- `src/peers.js` — no explorer, no clearnet peer unless deliberately allowed,
  and filter data believed only when two independent peers agree and the block
  both checks.
- `src/spend.js` — one pocket pays one spend; change returns to a fresh pocket;
  dust goes to the miner instead of becoming an unspendable output.

### What a spend does not prove

Each state is a separate claim and only the last two involve anyone else:

- **built** and **signed** — a transaction exists and a signature is on it.
  Nothing has left the device. A signed transaction is not a payment.
- **broadcast** — a peer took the bytes. Being taken is not being mined.
- **seen** — a watcher reports the transaction mined. For Bitcoin, seen means
  mined; there is no 0-confirmation state in this wallet.
- **confirmed** — a watcher reports three confirmations.

A watcher is the only thing that moves a payment. The wallet's own view of its
own transaction is not evidence, and a vendor's wallet is not a chain
confirmation.

### What it costs in privacy

The peer serving compact block filters learns *which blocks matched your wallet*
over time, because you keep asking for the next filter after a hit. That is the
price of not running a node. The mitigation is several peers, chosen by you,
over Tor, rotating between them — not a claim that the filter is free. A block
explorer would learn the same thing plus your address and your IP in one
request, which is why it is refused.

Filter data is accepted only when two independent peers agree, so one lying peer
cannot hide a payment or invent one. When they disagree nothing is believed.
That agreement anchors on the first peer that answers and is checked against one
more: a compromised peer can force a refusal, and cannot force a false answer.

Two peers that lie together are covered only because the block is checked as a
whole. Agreement is two strangers saying the same thing, and two strangers can
agree on a lie; so the block those peers serve is checked two ways. Its 80-byte
header must hash to the block hash that was asked for, and the transactions in
its body must produce the merkle root the header names (`src/merkle.js`). The
second check is the one that matters: without it a peer keeps a real, public
header, attaches a body of its own choosing that pays whatever it likes, and
both the header check and a filter rebuilt from that body agree with the lie.
With it, a body that does not hash up to its own header is refused outright.
Both checks are exercised by a forged body in `test/filter-drill.test.mjs`,
served over a socket by two agreeing peers.

The quorum is now wired into the scan, not only held as policy. `scanBack` takes
an optional `pool` and a peer `client`; with them, every block's filter comes
from `verifiedFilter`, so two independent peers must agree AND the filter is
rebuilt from the block before the scan uses it. With no pool, the scan still
believes one `fetchFilter` by design; the pool is how a caller stops doing so.
`test/quorum-scan.test.mjs` pins the agreed-over-a-liar path, a disagreement
refused, and a one-peer pool refusing because one peer is not a witness.

Verifying a filter means rebuilding it, which needs the scripts the block's
inputs spend — and a real block spends money from before the walk. When the
peer client can `fetchTx` (it can, over `MSG_WITNESS_TX`), those previous
transactions are fetched once and cached, so a pooled scan of a realistic block
verifies instead of refusing; without it the honest refusal stands.
`test/pooled-prevouts.test.mjs` pins both.

Work is now checked too. `walkBack` and `walkHeadersForward` decode each
header's nBits and require its double-sha256 to be at or below the target the
header names; a header that does not is refused by name. So a never-mined
private chain no longer walks for free — the peer must at least set a target its
hash meets. And a chain is priced by its TOTAL work, not one header: each
header's target is turned into expected hashes (`2^256/(target+1)`, the standard
form) and summed, the total rides back on the walk's array as a non-enumerable
`work`, and an optional `minWork` floor refuses a chain the peer could have
invented cheaply by naming an easy target on every block. Fork choice is now a
primitive: when peers name DIFFERENT tips, `fork.js` prices each tip's chain
and `chooseTip` returns the heavier one — the peers serving it, and the
candidates, go with it. An exact-work tie between distinct tips is refused
rather than broken. It is opt-in (`scanBack` with `forkChoice: true`); the
default path still uses exact `agreedTip`. What remains is that no caller is
forced onto it, and the winner's height rides on the peer's claim like every
other height here.

Header-first walking is built, and it now has a door. `walkHeadersForward`
counts forward from an anchor, checking every link; `scanHeaderFirst` fetches a
body only when its filter matched — the BIP-157 shape, and what makes the filters
save bandwidth. `wallet.scanHeadersFirst` reaches it when the wallet has a
transport. It is still not the default, and it needs a block to start from: this
repository is not allowed to choose an anchor, so the anchor is a required
argument with no default and the founder names a block by hand or the walk does
not run.

What the saving costs is measured rather than described, in
`test/header-scan.test.mjs`: the same block and the same script, run through both
walks. An honest filter finds the payment on either. A filter that omits our
script finds it under the backwards walk, which reads every body, and loses it
under header-first, which never downloads the block that would contradict the
filter. Every walk in this wallet today is the backwards one; `scanBack` remains
what a caller reaches for.

Where that bites is specific, and worth naming rather than hedging: a filter
lookup asks about a block hash the wallet already has, and the header must hash
to exactly that, so a lie on that path needs a second preimage of the asked hash.
The walk was the open door, because its tip hash is peer-supplied: a peer could
hand over a tip of its own making, and every link after it would check out. When
a `pool` and a client are given and the caller pins no tip, the tip itself is
now agreed by two peers (`peers.agreedTip`) before the walk starts, so a lone
peer no longer chooses the whole answer; and when the peers disagree on the tip,
an opt-in `forkChoice` lets the HEAVIER chain win instead of refusing. Deciding
which fork is the real one is still a judgement, but it is now the heaviest-work
judgement rather than no judgement at all.

### What has gone wrong here

Kept in the open because a reader will otherwise assume the code and its tests
were right the first time.

- **Change could be sent to the payee.** The surplus was added to the payee's
  output, so a spend overpaid and the fresh-pocket promise was silently broken.
  The guard that now refuses this is one line. The larger fault was that four
  existing tests were quietly asserting the wrong shape, because their shared
  helper defaulted change to the payee. The guard was missing and the net under
  it was mesh.
- **A transaction was serialized with the locktime before the witness**, and a
  P2PKH script builder dropped a byte. Both were caught on the first run by
  published test vectors, not by review.
- **Monero's hash-to-point map was wrong for half of all inputs**, while
  producing correct points for the other half. Published vectors caught it.
- **The extra-field walker misread the merge-mining tag**, so a merge-mined
  coinbase had an unreadable extra. The walker treated it as a fixed struct;
  upstream serializes it as a length-prefixed string, and the fields inside are
  the other way round from what the comment claimed. Nothing noticed until a
  block scan ran the miner transaction, because every earlier test used a
  non-miner transaction whose extra had no such tag. Writing a lane that had to
  scan a whole block is what surfaced it.
- **The vectors that would have caught it were cut away.** The fixture was made
  by taking the first N lines of each section, and Monero puts its refusal
  vectors at the ends, so all 48 vectors that say "this input must be refused"
  were dropped silently. The suite was green because the negative half had been
  removed. A test that only ever sees inputs that should work cannot tell a
  guard from a missing one, which is the same shape as the four change tests
  above.

That last one is the whole argument for pinned vectors, so it is worth saying
plainly: a map that is wrong half the time looks exactly like a map that is
right, and only a vector knows the difference. Vectors are not ceremony here.

## Gates

    npm run build   # every module parses and resolves
    npm run lint
    npm test

Test vectors are vendored under `test/fixtures`; see the README there for
provenance, the pinned upstream commits, both checksums, and the visible
transformation applied to each file.

The gates are offline. The live path is checked by hand, because a test that
needs the network is a test that fails for reasons unrelated to the code:

    CIPHER_XMR_NODE=xmr-node.cakewallet.com:18081 \
      node scripts/scan-live.mjs --height 3796965

It prints what it found and writes nothing. The other `scripts/` capture
fixtures; they are not part of the gate either.

# Cipher Wallet

A privacy wallet. One root secret, a fresh pocket per payment, and a spend that
never needs a custodian and never needs a node you run.

This repo is Phases 0 to 2 complete, and Phase 3 part-built: the units, the
root and pocket derivation, the vault, the receive path, the Bitcoin spend path,
and the Monero keys, base58 and address encoding. There is no Monero
transaction, no merging and no recovery shards, and nothing here has been run
against real money.

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
amounts now decrypt (`src/monero/ringct.js`), but they are pinned only to
keccak's vectors and Monero's varint, not to a real transaction, so nothing may
gate a payment on them yet. What is not built: reading real Monero blocks from a
node, and anything that spends or broadcasts. Nothing on the Monero side has been
funded or touched mainnet.

The transport for reading blocks is ruled: a shipped list of public nodes in
`src/monero/nodes.js`, with a private node overriding the list when
`CIPHER_XMR_NODE` is set — one node per scan, sticky, and fail-closed, so a node
that dies mid-scan refuses the scan rather than stitching two operators together.
The list ships empty until the founder names addresses. Nothing reads the
variable yet: the selection is built and tested, the reader is not.

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
in tests (the IDB adapter itself is exercised by the UI layer).

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

What this still does not do: it verifies a body against its header, not the
chain's proof of work. A header's own work is not checked here, so a peer that
mines a private header (or is handed one) can build a self-consistent block, and
a short private chain of such blocks links and hashes cleanly.

Header-first walking is built, and it is not wired. `walkHeadersForward` counts
forward from an anchor, checking every link; `scanHeaderFirst` fetches a body
only when its filter matched — the BIP-157 shape, and what makes the filters save
bandwidth. It has no caller because it needs a block to start from and this
repository is not allowed to choose one: the anchor is a required argument with
no default, and the founder names a block by hand or the walk does not run.

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
The walk is the open door, because its tip hash is peer-supplied: a peer can hand
over a tip of its own making, and every link after it will check out. Deciding
which chain is the real one is not in this build.

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

# The L3 receive shape

How a pocket receives Monero. Written before the code because two of these
choices are expensive to change once money is on them.

The founder chose **L3 on 2026-10-29**: every pocket is its own Monero wallet,
so no single view key spans two pockets. On the same day, with the shape on the
table, two follow-on choices were made:

- **Detection happens on the device.** Block data comes from peers; each
  pocket's view key is used locally and never leaves.
- **Keys are derived, not stored.** A pocket's keys are recomputed from its
  index. What is kept on disk is the index and the state, nothing else.

Everything below follows from those three.

## What a pocket is

A pocket is one address, one spend key, one view key, one payment. It is not a
subaddress of a shared account: a subaddress shares the account's view key,
which is exactly the link L3 exists to remove. A subaddress would let one key
see every pocket, and no amount of UI wording changes what the chain shows.

The derivation, frozen from the first commit that writes one:

    entropy_i  = BIP32(m/44'/128'/0'/0'/i')          hardened, as all the segments are
    spend_i    = sc_reduce32(entropy_i)               Monero's own convention: the seed is reduced
    view_i     = sc_reduce32(keccak256(spend_i))      account generation, not a second entropy
    spendPub_i = spend_i * G
    viewPub_i  = view_i * G
    address_i  = encodeAddress({ spend: spendPub_i, view: viewPub_i, kind: 'standard' })

Standard, not subaddress: each pocket is a whole wallet, and the prefix says so.

**Freezing this is a money rule, not a style rule.** If the derivation ever
changes, a restored wallet derives different addresses and the old money is
unreachable — silently, with a zero balance that looks like "never received".
The guard is a pinned test: a known phrase, the first three pockets, their exact
address strings. A change to any line above fails that test.

Storing only the index is the founder's choice, and it is the leaner one: one
secret at rest, the phrase. The cost is that there is no on-disk copy of a
pocket's address to disagree with a changed derivation, which is why the pinned
test is the mitigation and not a decoration.

## How the wallet learns a pocket was paid

There is no shared view key, so there is no scan that covers every pocket at
once. Detection is per pocket, on the device:

1. Ask peers for block data in order. A peer serves blocks; it is not told which
   pockets exist, which transactions matter, or that this device is a wallet.
2. For each transaction output, for each pocket being scanned, build Monero's
   shared derivation from the pocket's view key and the transaction's public
   key, rebuild the output's one-time key from that derivation, the output index
   and the pocket's spend public key, and compare **that** with the output's own
   one-time key. The comparison target is the output's key, not the pocket's
   spend public key: the spend public key is the base the address is built on,
   and an output's key is never equal to it. This is Monero's own
   output-scanning rule; the output is ours when the comparison matches.
   Implemented the other way round the scan matches nothing, and every payment
   reads as never received — the silent-zero class the pinned-address test
   exists to catch.
3. A matched output is a **seen** payment. As with Bitcoin, a peer having the
   bytes is not the money; the confirmation count comes from the chain height
   the same peer reports, and the states stay separate: seen, then confirmed.

What this costs, stated plainly because it is the price of L3:

- **Bandwidth.** The wallet downloads blocks. There is no filter scheme for
  Monero the way BIP-158 gives Bitcoin one, so the honest first sync is heavy
  and the app must say so rather than show a spinner that implies seconds.
- **CPU.** Every output is tested against every scanned pocket. The work is
  linear in pockets times outputs, and it happens on a phone.
- **Sync time.** A restored wallet cannot know which pockets existed, so it
  scans a gap: the first pocket with no history and the next 19 empty ones. The
  same gap limit Bitcoin wallets use, for the same reason.
- **No instant "payment seen".** A payment is seen when a block carrying it has
  been scanned, not when a watcher is asked. The UI must not promise faster.

What it buys: the view keys never leave the device, no service learns which
addresses belong to this wallet, and a breach of any peer or watcher reveals
nothing about pockets it was never told about.

## The trust edges this introduces

- **A peer can hide a payment** by serving fewer blocks or older ones. It
  cannot invent one: inventing an output requires a transaction whose one-time
  key matches a pocket's, which it cannot produce. Hiding is detectable by
  height going backwards or stalling, and that is a thing the wallet can say.
- **A peer learns the wallet's IP** unless the connection is over Tor. The
  existing rule stands: no clearnet peer without an explicit allowance.
- **A peer sees the pattern of requests.** Asking for every block in order is
  the least revealing shape; asking for one block out of twenty is not. This is
  why the scan walks forward rather than jumping.

## What this does not yet cover

- **Amounts.** A matched output proves an output is ours, not how much it
  carries. RingCT amounts have to be decrypted with the same derivation before a
  payment can be shown as an amount, and that is the next piece of work.
- **Spending.** Nothing here builds, signs or broadcasts a Monero transaction.
  Key images, RingCT and CLSAG are unbuilt.
- **Restore.** The gap-limit scan is described, not implemented.
- **No wallet has been funded, and nothing has touched mainnet.** Passing
  vectors prove the arithmetic matches Monero's; they say nothing about safety
  once real money is involved.

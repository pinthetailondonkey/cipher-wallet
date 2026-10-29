# Cipher Wallet

A privacy wallet. One root secret, a fresh pocket per payment, and a spend that
never needs a custodian.

This repo is Phase 0: the units, the root and pocket derivation, and the vault
primitive. No relay, no chain call, no spend. Nothing here talks to a network.

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
bytes are entropy for Monero's key set, reduced in Phase 3 — this build does not
emit a Monero address yet.

## Moved into the derive path from existing code

- `src/units.js` is ported verbatim from `deal-engine/src/units.js` (the
  1-piconero bug class). Bitcoin 8 decimals, Monero 12, round half up, never a
  float.
- `src/vault.js` is ported from the vault half of `cipher/src/useIdentity.js`:
  PBKDF2-SHA256 at 600,000 iterations, per-vault salt, AES-GCM-256.

## The vault is two layers

The PIN vault (`src/vault.js`) is the inner layer. The device envelope
(`src/deviceEnvelope.js`) wraps it under a key that only this device holds, so
a copied ciphertext has the PIN layer but not the key. Opening takes both. A
device-key failure is a typed `DeviceKeyError` and is never told to the person
as a wrong PIN.

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

## Gates

    npm run build   # every module parses and resolves
    npm run lint
    npm test

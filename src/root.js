// The root and the pockets.
//
// One BIP39 seed is the only secret at rest. Every pocket key is derived from
// it on demand, so recovery is one phrase, not one phrase per payment.
//
// Decision (Phase 0 gate 1): BIP32-HARDENED paths, every segment hardened.
// Why hardened: a non-hardened child key plus a leaked parent xpub derives
// every sibling. We never publish an xpub, but hardened removes the whole
// class, and the plan's rule is that two pockets must share no public
// relation. Cost: the leaf index is not the BIP84 convention, so a standard
// wallet cannot restore a single pocket by scanning. It CAN restore from the
// same mnemonic by re-deriving this documented path, and this app does the
// same. The path is part of the format, not an implementation detail.
//
// This module never talks to a chain, never sees an amount, and never
// decides an address is paid. It makes keys and addresses only.

import { HDKey } from '@scure/bip32';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

// One row per coin. purpose/coinType are BIP44/84 numbers; addressKind names
// what the derived key becomes on that rail. Bitcoin is a secp256k1 key we
// turn into a P2WPKH address. Monero has no BIP32 of its own, so the derived
// 32 bytes are ENTROPY for Monero's own key set, reduced to an ed25519 scalar
// in Phase 3 — this module does not pretend to emit a Monero address yet.
export const COINS = Object.freeze({
  btc: Object.freeze({ purpose: 84, coinType: 0, addressKind: 'p2wpkh' }),
  xmr: Object.freeze({ purpose: 44, coinType: 128, addressKind: 'ed25519-entropy' }),
});

// BIP32 hardened indexes are 0 .. 2^31-1. Anything else is a refusal, not a
// wrap.
export const MAX_POCKET_INDEX = 0x7fffffff;

const NETWORK_HRP = Object.freeze({ bc: 'bc', tb: 'tb', bcrt: 'bcrt' });

function coinRow(coin) {
  const row = COINS[String(coin || '').toLowerCase()];
  if (!row) throw new Error(`Unknown coin: ${String(coin)}`);
  return row;
}

function pocketIndex(index) {
  if (!Number.isInteger(index) || index < 0 || index > MAX_POCKET_INDEX) {
    throw new Error('A pocket index is a whole number from 0.');
  }
  return index;
}

// m/purpose'/coinType'/0'/0'/index' — every segment hardened. See the header.
export function pocketPath(coin, index) {
  const row = coinRow(coin);
  const n = pocketIndex(index);
  return `m/${row.purpose}'/${row.coinType}'/0'/0'/${n}'`;
}

// A 12-word root. This is the one secret the circle's shards protect.
export function createRoot() {
  const mnemonic = generateMnemonic(wordlist, 128);
  return { mnemonic, seed: mnemonicToSeedSync(mnemonic) };
}

// The seed for a phrase this build understands. No silent repair: a phrase
// with a typo is refused here, not normalized into a different wallet.
export function rootFromMnemonic(mnemonic) {
  const text = String(mnemonic ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
  if (!validateMnemonic(text, wordlist)) throw new Error('That is not a valid recovery phrase.');
  return mnemonicToSeedSync(text);
}

// The pocket key. Deterministic: same seed, coin and index give the same key
// on every device, which is what makes one phrase enough to recover.
export function derivePocket(seed, coin, index) {
  if (!(seed instanceof Uint8Array) || seed.length === 0) {
    throw new Error('A pocket derives from the root seed bytes.');
  }
  const path = pocketPath(coin, index);
  const node = HDKey.fromMasterSeed(seed).derive(path);
  if (!node.privateKey || !node.publicKey) throw new Error('The pocket key could not be derived.');
  return {
    path,
    privateKey: node.privateKey,
    publicKey: node.publicKey,
    chainCode: node.chainCode,
  };
}

// Monero's key set is built from 32 bytes of entropy, not from a secp256k1
// scalar. Exposed by name so Phase 3 cannot mistake a bitcoin key for it.
export function xmrPocketEntropy(seed, index) {
  const pocket = derivePocket(seed, 'xmr', index);
  return pocket.privateKey;
}

// P2WPKH: hash160(compressed public key), witness v0. Bech32, never a public
// explorer.
export function btcPocketAddress(publicKey, network = 'bc') {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 33) {
    throw new Error('A Bitcoin pocket address needs a 33-byte compressed public key.');
  }
  const hrp = NETWORK_HRP[String(network || 'bc').toLowerCase()];
  if (!hrp) throw new Error('Choose a Bitcoin network.');
  const hash = ripemd160(sha256(publicKey));
  return bech32.encode(hrp, [0, ...bech32.toWords(hash)]);
}

// One call for a receive pocket. Kept here so nothing upstream handles raw
// key material it does not need.
export function pocketFor(seed, { coin, index, network = 'bc' } = {}) {
  const pocket = derivePocket(seed, coin, index);
  if (String(coin).toLowerCase() === 'btc') {
    return { ...pocket, address: btcPocketAddress(pocket.publicKey, network) };
  }
  return { ...pocket, address: null };
}

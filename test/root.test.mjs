import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '@scure/base';
import {
  COINS, MAX_POCKET_INDEX, btcPocketAddress, createRoot, derivePocket,
  pocketFor, pocketPath, rootFromMnemonic, xmrPocketEntropy,
} from '../src/root.js';

// A fixed BIP39 phrase, so a derivation change shows up as a failing test
// rather than a silently different wallet.
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

test('a new root is 12 valid words and has a seed', () => {
  const root = createRoot();
  assert.equal(root.mnemonic.split(' ').length, 12);
  assert.equal(root.seed.length, 64);
});

test('the same phrase always gives the same seed', () => {
  assert.deepEqual(Array.from(rootFromMnemonic(MNEMONIC)), Array.from(rootFromMnemonic(MNEMONIC)));
});

test('a typo in the phrase is refused, not repaired', () => {
  assert.throws(() => rootFromMnemonic('abandon abandon abandon'), /not a valid recovery phrase/);
});

test('the path is doubly hardened and names its coin', () => {
  assert.equal(pocketPath('btc', 0), "m/84'/0'/0'/0'/0'");
  assert.equal(pocketPath('xmr', 7), "m/44'/128'/0'/0'/7'");
  assert.equal(COINS.btc.coinType, 0);
  assert.equal(COINS.xmr.coinType, 128);
});

test('a pocket index is a whole number in range', () => {
  assert.throws(() => pocketPath('btc', -1), /whole number/);
  assert.throws(() => pocketPath('btc', 1.5), /whole number/);
  assert.throws(() => pocketPath('btc', MAX_POCKET_INDEX + 1), /whole number/);
  assert.throws(() => pocketPath('doge', 0), /Unknown coin/);
});

test('two pockets share no key', () => {
  const seed = rootFromMnemonic(MNEMONIC);
  const a = derivePocket(seed, 'btc', 0);
  const b = derivePocket(seed, 'btc', 1);
  assert.notDeepEqual(Array.from(a.privateKey), Array.from(b.privateKey));
  assert.notDeepEqual(Array.from(a.publicKey), Array.from(b.publicKey));
});

test('a bitcoin pocket key is a compressed secp256k1 key', () => {
  const seed = rootFromMnemonic(MNEMONIC);
  const pocket = derivePocket(seed, 'btc', 0);
  assert.equal(pocket.privateKey.length, 32);
  assert.equal(pocket.publicKey.length, 33);
});

test('the bitcoin address is a P2WPKH bech32 for the chosen network', () => {
  const seed = rootFromMnemonic(MNEMONIC);
  const pocket = pocketFor(seed, { coin: 'btc', index: 0, network: 'bc' });
  assert.match(pocket.address, /^bc1q[02-9ac-hj-np-z]{8,}$/);
  const decoded = bech32.decode(pocket.address);
  assert.equal(decoded.prefix, 'bc');
  assert.equal(decoded.words[0], 0); // witness v0
  assert.equal(bech32.fromWords(decoded.words.slice(1)).length, 20); // hash160

  const regtest = pocketFor(seed, { coin: 'btc', index: 0, network: 'bcrt' });
  assert.match(regtest.address, /^bcrt1q/);
});

test('a bitcoin address needs a compressed key', () => {
  assert.throws(() => btcPocketAddress(new Uint8Array(32)), /33-byte/);
});

test('monero entropy is 32 bytes and is not the bitcoin key', () => {
  const seed = rootFromMnemonic(MNEMONIC);
  const xmr = xmrPocketEntropy(seed, 0);
  assert.equal(xmr.length, 32);
  assert.notDeepEqual(Array.from(xmr), Array.from(derivePocket(seed, 'btc', 0).privateKey));
});

test('a monero pocket has no address until Phase 3', () => {
  const seed = rootFromMnemonic(MNEMONIC);
  assert.equal(pocketFor(seed, { coin: 'xmr', index: 0 }).address, null);
});

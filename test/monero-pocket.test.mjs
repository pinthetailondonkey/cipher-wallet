import test from 'node:test';
import assert from 'node:assert/strict';
import { derivePocket, rootFromMnemonic } from '../src/root.js';
import { moneroPocket } from '../src/monero/pocket.js';
import { decodeAddress } from '../src/monero/address.js';
import { viewSecretFromSpend } from '../src/monero/keys.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');

// The derivation is frozen by docs/L3-RECEIVE.md. These three strings are the
// fence: if any line of the derivation changes, a restored wallet derives
// different addresses, shows a zero balance, and looks exactly like a pocket
// that was never paid. This test turns that silent failure into a red one.
//
// It pins BEHAVIOUR, not correctness. These addresses were produced by the code
// below the first time it ran; what makes that code right is Monero's own
// vectors for the primitives underneath, not this list.
const PINNED = [
  '49uPoRx2rTeUrdWJUWgF4W6NrfGaDyYCEVxX4fTAPXFPfm7bn2QvBqd8CzNsCsSuvFFWWsydFYgZ91pEtXFyTCAMN8uAh4T',
  '44Bi2Zu3x9xhSLc4sN71uxNE8NQr97GJDPufXRAdE2br7yPjC8XoBHvisXxXrUioC5iu2M1vEokTnBkfqXedDY58TqT8z9j',
  '43AWJ8kgmu1Ee1nvS9jSRcMyvBKuZ2iUnXoVFBZhmtuuC2Ciq8HjHzq7ygxonAo5Jod8TJyKaHZZfE5vM3YVGW2EJb35XY1',
];

test('the first three pocket addresses are frozen', () => {
  for (const [index, expected] of PINNED.entries()) {
    assert.equal(moneroPocket(SEED, index).address, expected, `pocket ${index} moved`);
  }
});

test('a pocket is deterministic: same seed and index, same wallet', () => {
  const a = moneroPocket(SEED, 7);
  const b = moneroPocket(SEED, 7);
  assert.equal(hex(a.spendSecret), hex(b.spendSecret));
  assert.equal(hex(a.viewSecret), hex(b.viewSecret));
  assert.equal(a.address, b.address);
});

test('two pockets share nothing that would link them', () => {
  const a = moneroPocket(SEED, 0);
  const b = moneroPocket(SEED, 1);
  assert.notEqual(a.address, b.address);
  assert.notEqual(hex(a.spend), hex(b.spend));
  assert.notEqual(hex(a.view), hex(b.view));
  // The point of L3: a view key opened one pocket and no other. If b's address
  // could be recognised with a's view key, this whole shape would be pointless.
  const decoded = decodeAddress(b.address);
  assert.notEqual(hex(a.view), hex(decoded.view));
});

test('a pocket address is a standard address carrying that pocket’s keys', () => {
  const pocket = moneroPocket(SEED, 5);
  const decoded = decodeAddress(pocket.address, { network: 'mainnet' });
  assert.equal(decoded.kind, 'standard');
  assert.equal(decoded.network, 'mainnet');
  assert.equal(hex(decoded.spend), hex(pocket.spend));
  assert.equal(hex(decoded.view), hex(pocket.view));
});

test('the view secret is derived from the spend secret, not stored beside it', () => {
  const pocket = moneroPocket(SEED, 3);
  assert.equal(hex(viewSecretFromSpend(pocket.spendSecret)), hex(pocket.viewSecret));
});

test('the entropy is the Bitcoin path’s sibling, not a second scheme', () => {
  const derivation = derivePocket(SEED, 'xmr', 4);
  assert.equal(derivation.path, "m/44'/128'/0'/0'/4'");
});

test('the network decides the prefix and nothing else', () => {
  const mainnet = moneroPocket(SEED, 0);
  const testnet = moneroPocket(SEED, 0, { network: 'testnet' });
  assert.notEqual(mainnet.address, testnet.address);
  assert.equal(decodeAddress(testnet.address).network, 'testnet');
  // Same wallet, different prefix: the keys must be identical.
  assert.equal(hex(testnet.spend), hex(mainnet.spend));
});

test('a pocket index that is not a hardened index is refused', () => {
  assert.throws(() => moneroPocket(SEED, -1), /whole number/);
  assert.throws(() => moneroPocket(SEED, 1.5), /whole number/);
  assert.throws(() => moneroPocket(SEED, 0x80000000), /whole number/);
});

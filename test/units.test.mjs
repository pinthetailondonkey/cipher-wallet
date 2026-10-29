import test from 'node:test';
import assert from 'node:assert/strict';
import { amountUnits, normalizeAmount, sumAmounts, unitsToAmount, ASSETS } from '../src/units.js';

test('every rail has its decimal power', () => {
  assert.equal(ASSETS.btc.decimals, 8);
  assert.equal(ASSETS.xmr.decimals, 12);
});

test('one satoshi and one piconero are one unit, not a fraction', () => {
  assert.equal(amountUnits('0.00000001', 'btc'), 1n);
  assert.equal(amountUnits('0.000000000001', 'xmr'), 1n);
});

test('a whole coin is the full scale', () => {
  assert.equal(amountUnits('1', 'btc'), 100000000n);
  assert.equal(amountUnits('1', 'xmr'), 1000000000000n);
});

test('round half up, never drop', () => {
  assert.equal(amountUnits('0.123456785', 'btc'), 12345679n);
  assert.equal(amountUnits('0.000000005', 'btc'), 1n);
  assert.equal(amountUnits('0.000000004', 'btc'), 0n);
});

test('a float is refused, not rounded', () => {
  assert.equal(amountUnits(0.1, 'btc'), null);
  assert.throws(() => normalizeAmount(0.1), /float is not a coin amount/);
});

test('commas group digits and are not a decimal point', () => {
  assert.equal(normalizeAmount('1,234'), '1234');
  assert.equal(amountUnits('1,234', 'btc'), 123400000000n);
});

// Upstream limitation, confirmed in deal-engine @ 8870f72 as well: the ported
// rule accepts ONE comma group, so a grouped amount with a fraction, or two
// groups, is refused. It fails CLOSED (refuses rather than mis-parsing), so
// this test pins the safe behaviour and flags the gap. Do not fix it here —
// one source of truth for the units law; raise it against deal-engine.
test('a grouped amount beyond one group fails closed today', () => {
  assert.throws(() => normalizeAmount('1,234.5'), /decimal string/);
  assert.throws(() => normalizeAmount('1,234,567'), /decimal string/);
  assert.equal(amountUnits('1,234,567', 'btc'), null);
});

test('a comma inside the fraction is refused', () => {
  assert.equal(amountUnits('1,5', 'btc'), null);
});

test('units render back without a lost digit', () => {
  assert.equal(unitsToAmount(1n, 'xmr'), '0.000000000001');
  assert.equal(unitsToAmount(12345679n, 'btc'), '0.12345679');
  assert.equal(unitsToAmount(0n, 'btc'), '0');
});

test('sums are BigInt and one currency', () => {
  const sum = sumAmounts([{ amount: '0.1', currency: 'btc' }, { amount: '0.2', currency: 'btc' }]);
  assert.equal(sum.units, 30000000n);
  assert.equal(sum.amount, '0.3');
  assert.throws(() => sumAmounts([{ amount: '1', currency: 'btc' }, { amount: '1', currency: 'xmr' }]), /two currencies/);
});

test('an unknown rail is refused, never guessed', () => {
  assert.equal(amountUnits('1', 'usd'), null);
  assert.throws(() => unitsToAmount(1n, 'usd'), /Unknown currency/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { applyWatcherReport, confirmationsRequired, nextPaymentState } from '../src/paymentState.js';

const report = (extra = {}) => ({ source: 'watcher', txid: 'abc', confirmations: 3, amount: '1', ...extra });

test('the walk is a straight line and nothing skips', () => {
  assert.equal(nextPaymentState('created', 'issue'), 'address_issued');
  assert.equal(nextPaymentState('address_issued', 'see'), 'seen');
  assert.equal(nextPaymentState('seen', 'confirm'), 'confirmed');
  assert.throws(() => nextPaymentState('created', 'see'), /cannot see/);
});

test('a watcher report moves issued to seen, then to confirmed', () => {
  assert.equal(applyWatcherReport({ state: 'address_issued', report: report({ confirmations: 0 }), currency: 'btc', amount: '1' }), 'seen');
  assert.equal(applyWatcherReport({ state: 'address_issued', report: report(), currency: 'btc', amount: '1' }), 'confirmed');
});

test('a report without a transaction moves nothing', () => {
  assert.throws(() => applyWatcherReport({ state: 'address_issued', report: { source: 'watcher' }, currency: 'btc' }), /Only a watcher report/);
  assert.throws(() => applyWatcherReport({ state: 'address_issued', report: { source: 'wallet', txid: 'x' }, currency: 'btc' }), /Only a watcher report/);
});

test('a short payment is refused by unit, not by float', () => {
  assert.throws(
    () => applyWatcherReport({ state: 'address_issued', report: report({ amount: '0.99999999' }), currency: 'btc', amount: '1' }),
    /short of the order/,
  );
  assert.equal(applyWatcherReport({ state: 'address_issued', report: report({ amount: '1.00000001' }), currency: 'btc', amount: '1' }), 'confirmed');
});

test('a demand must be real and a report must carry an amount', () => {
  assert.throws(() => applyWatcherReport({ state: 'address_issued', report: report(), currency: 'btc', amount: '0' }), /no amount/);
  assert.throws(() => applyWatcherReport({ state: 'address_issued', report: report({ amount: null }), currency: 'btc', amount: '1' }), /did not report an amount/);
});

test('the confirmation floor is the coin default and never lowered by junk', () => {
  assert.equal(confirmationsRequired('btc'), 3);
  assert.equal(confirmationsRequired('xmr'), 10);
  assert.equal(confirmationsRequired('btc', 0), 3);
  assert.equal(confirmationsRequired('btc', -1), 3);
  assert.equal(confirmationsRequired('btc', 5), 5);
});

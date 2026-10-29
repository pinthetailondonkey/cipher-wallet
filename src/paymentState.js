// The payment walk and the one amount comparison.
//
// Ported from cipher/src/lib/paymentState.js @ ec6e98b. Four states, a straight
// line, nothing skips: created -> address_issued -> seen -> confirmed.
//
// Only a watcher moves a payment. The vendor's own wallet is never a
// confirmation, and a report that does not name a transaction moves nothing.
// Every amount is an integer unit; a float is not a coin amount.

import { amountUnits } from './units.js';

export const PAYMENT_STATES = Object.freeze(['created', 'address_issued', 'seen', 'confirmed']);

const NEXT = Object.freeze({
  created: Object.freeze({ issue: 'address_issued' }),
  address_issued: Object.freeze({ see: 'seen' }),
  seen: Object.freeze({ confirm: 'confirmed' }),
});

export function nextPaymentState(current, event) {
  const next = NEXT[current]?.[event];
  if (!next) throw new Error(`A payment that is ${current || 'missing'} cannot ${event}.`);
  return next;
}

export function confirmationsRequired(currency, threshold) {
  const fallback = String(currency || '').toLowerCase() === 'xmr' ? 10 : 3;
  const count = Number(threshold);
  if (!Number.isInteger(count) || count < 1) return fallback;
  return count;
}

// Report shape: { source: 'watcher', txid, confirmations, amount?, time? }.
// `amount` is the demand to cover; leave it undefined only when walking the
// states without a price.
export function applyWatcherReport({ state, report, currency, amount, threshold } = {}) {
  if (!report || report.source !== 'watcher' || !report.txid) {
    throw new Error('Only a watcher report can move a payment to seen or confirmed.');
  }
  if (amount !== undefined) {
    const demanded = amountUnits(amount, currency);
    if (demanded == null || demanded <= 0n) {
      throw new Error('The order has no amount to check the payment against.');
    }
    if (report.amount == null || report.amount === '') {
      throw new Error('The watcher did not report an amount.');
    }
    const reported = amountUnits(report.amount, currency);
    if (reported == null || reported < demanded) {
      throw new Error('The payment is short of the order.');
    }
  }
  let current = state;
  if (current === 'address_issued') current = nextPaymentState(current, 'see');
  const need = confirmationsRequired(currency, threshold);
  const confirmed = Number(report.confirmations) >= need;
  if (confirmed) {
    if (current !== 'seen') throw new Error('A payment has to be seen before it can be confirmed.');
    current = nextPaymentState(current, 'confirm');
  }
  if (current === state) throw new Error('The watcher report did not move the payment.');
  return current;
}

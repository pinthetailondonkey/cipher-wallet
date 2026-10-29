import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { checkPayment, childWatcherToken, isPublicExplorer, paymentWatchUrl } from '../src/watcher.js';

const BASE = 'a-long-secret';
const ADDRESS = 'bc1qexample';
const NOW = 1700000000;

async function signedFetch({ address = ADDRESS, currency = 'btc', body, rawBody, ts = NOW, sig, headers = true }) {
  const child = await childWatcherToken(BASE, address, currency);
  const raw = rawBody ?? JSON.stringify(body);
  const good = 'v1=' + createHmac('sha256', child).update(`${ts}:${raw}`).digest('hex');
  let seenUrl = null;
  const impl = async (url) => {
    seenUrl = url;
    return {
      ok: true,
      status: 200,
      async text() { return raw; },
      headers: {
        get(name) {
          if (!headers) return null;
          if (name === 'x-cipher-sig') return sig === undefined ? good : sig;
          if (name === 'x-cipher-ts') return String(ts);
          return null;
        },
      },
    };
  };
  return { impl, child, url: () => seenUrl };
}

const WATCHER = `http://127.0.0.1:8788/payment?token=${BASE}`;
const OK_BODY = { address: ADDRESS, currency: 'btc', txid: 'tx-1', confirmations: 2, amount: '0.5' };

test('a signed, fresh answer that echoes the ask is accepted', async () => {
  const { impl, child } = await signedFetch({ body: OK_BODY });
  const out = await checkPayment({ watcherUrl: WATCHER, address: ADDRESS, currency: 'btc', fetchImpl: impl, nowSec: NOW });
  assert.equal(out.report.txid, 'tx-1');
  assert.equal(out.report.amount, '0.5');
  // the check carried the CHILD token, never the pasted base secret
  assert.match(WATCHER, new RegExp(BASE));
  assert.ok(child.length === 64);
});

test('an unsigned answer moves nothing', async () => {
  const { impl } = await signedFetch({ body: OK_BODY, headers: false });
  await assert.rejects(
    checkPayment({ watcherUrl: WATCHER, address: ADDRESS, currency: 'btc', fetchImpl: impl, nowSec: NOW }),
    /signature check/,
  );
});

test('a stale answer is ignored even when its signature is real', async () => {
  const { impl } = await signedFetch({ body: OK_BODY, ts: NOW - 500 });
  await assert.rejects(
    checkPayment({ watcherUrl: WATCHER, address: ADDRESS, currency: 'btc', fetchImpl: impl, nowSec: NOW }),
    /signature check/,
  );
});

test('an answer for another payment does not answer this one', async () => {
  const { impl } = await signedFetch({ body: { ...OK_BODY, address: 'bc1qsomeoneelse' } });
  await assert.rejects(
    checkPayment({ watcherUrl: WATCHER, address: ADDRESS, currency: 'btc', fetchImpl: impl, nowSec: NOW }),
    /does not name the payment/,
  );
});

test('a pending answer is pending, not a payment', async () => {
  const { impl } = await signedFetch({ body: { address: ADDRESS, currency: 'btc', pending: true } });
  const out = await checkPayment({ watcherUrl: WATCHER, address: ADDRESS, currency: 'btc', fetchImpl: impl, nowSec: NOW });
  assert.equal(out.pending, true);
});

test('a piconero amount keeps every digit', async () => {
  // Written as raw JSON on purpose: an "amount" that is a plain JSON number
  // bigger than 2^53 must survive, and a source literal would lose it first.
  const rawBody = `{"address":"${ADDRESS}","currency":"xmr","txid":"tx-x","confirmations":1,"amount":12345678901234567890}`;
  const { impl } = await signedFetch({ rawBody, currency: 'xmr' });
  const out = await checkPayment({
    watcherUrl: WATCHER, address: ADDRESS, currency: 'xmr', fetchImpl: impl, nowSec: NOW,
  });
  assert.equal(out.report.amount, '12345678901234567890');
});

test('a block explorer is refused before any request', async () => {
  assert.equal(isPublicExplorer('https://mempool.space/api'), true);
  assert.equal(isPublicExplorer('https://xmrchain.net.evil.tld/x'), true);
  assert.equal(isPublicExplorer('https://my-own-watcher.example'), false);
  assert.throws(() => paymentWatchUrl('https://mempool.space/x', { address: ADDRESS, currency: 'btc' }), /block explorer/);
});

test('plain http is allowed only on this machine', () => {
  assert.throws(
    () => paymentWatchUrl('http://watcher.example/payment?token=x', { address: ADDRESS, currency: 'btc' }),
    /must use HTTPS/,
  );
  assert.match(
    paymentWatchUrl('http://127.0.0.1:8788/payment?token=x', { address: ADDRESS, currency: 'btc' }),
    /^http:\/\/127\.0\.0\.1/,
  );
});

test('a watcher URL without a token is refused', () => {
  assert.throws(() => paymentWatchUrl('https://watcher.example/payment', { address: ADDRESS, currency: 'btc' }), /needs a token/);
});

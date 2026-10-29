// The watcher client: the only thing allowed to say a payment arrived.
//
// Ported from cipher/src/lib/paymentWatch.js @ ec6e98b. The rules that cost
// blood to learn, kept:
//   - no public block explorer is ever called, and a lookalike host is refused;
//   - plain http is allowed only on this machine;
//   - the check carries a per-payment CHILD token, never the pasted base one,
//     so a captured token opens exactly one address and one currency;
//   - an answer must be signed over `<ts>:<body>`, be fresh, and echo the
//     address and currency it was asked about, or it moves nothing;
//   - amounts are read as text, never as JSON numbers.
//
// The watcher is a witness the vendor runs or borrows; this module never talks
// to a chain itself.

const EXPLORERS = [
  'mempool.space',
  'blockstream.info',
  'blockchain.info',
  'blockchain.com',
  'blockchair.com',
  'blockcypher.com',
  'xmrchain.net',
  'moneroblocks.info',
  'localmonero.co',
];

const LOCAL_WATCHER_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const CHILD_TOKEN_VERSION = 'cipher-watch-v1';
const WATCHER_SIG_MAX_AGE = 120;

export function isPublicExplorer(value) {
  let host = '';
  try {
    host = new URL(String(value || '')).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return false;
  }
  return EXPLORERS.some((name) => host === name || host.endsWith(`.${name}`) || host.includes(name));
}

export function isLocalWatcherHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  return LOCAL_WATCHER_HOSTS.has(host);
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret || '')),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  let hex = '';
  for (const byte of new Uint8Array(mac)) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

export async function childWatcherToken(baseToken, address, currency) {
  return hmacHex(
    baseToken,
    `${CHILD_TOKEN_VERSION}:${String(currency || '').trim().toLowerCase()}:${String(address || '').trim()}`,
  );
}

export function paymentWatchUrl(watcherUrl, { address, currency, token } = {}) {
  const raw = String(watcherUrl || '').trim();
  if (!raw) throw new Error('No payment watcher is set. This device does not check a block explorer.');
  if (isPublicExplorer(raw)) throw new Error('That host is a block explorer. This device will not call it. Paste a watcher you run.');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('The payment watcher address is not a URL.');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('The payment watcher address is not a URL.');
  }
  if (url.protocol === 'http:' && !isLocalWatcherHost(url.hostname)) {
    throw new Error('A payment watcher on the open internet must use HTTPS. Paste an https watcher, or run this one on this device.');
  }
  const watchToken = token || url.searchParams.get('token') || '';
  if (!watchToken) throw new Error('The payment watcher URL needs a token.');
  url.searchParams.set('address', String(address || '').trim());
  url.searchParams.set('currency', String(currency || '').trim());
  url.searchParams.set('token', watchToken);
  return url.href;
}

// A piconero amount can pass 2^53, where JSON.parse would round it, and a
// bitcoin amount parsed as a number is a binary float. Quote every plain
// number under an "amount" key before parsing.
export function parseExactAmounts(text) {
  return JSON.parse(String(text).replace(/("amount"\s*:\s*)(\d+(?:\.\d+)?)(?![\d.eE])/g, '$1"$2"'));
}

function hexEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function verifyWatcherResponse({ rawBody, sig, ts, token, nowSec } = {}) {
  if (typeof rawBody !== 'string' || rawBody.length === 0) return false;
  if (!/^\d+$/.test(String(ts ?? '').trim())) return false;
  const sent = Number(ts);
  const now = Number(nowSec);
  if (!Number.isInteger(now)) return false;
  if (Math.abs(now - sent) > WATCHER_SIG_MAX_AGE) return false;
  const presented = String(sig ?? '').trim();
  const match = presented.match(/^v1=([0-9a-f]{64})$/);
  if (!match) return false;
  return hexEqual(await hmacHex(token, `${String(ts).trim()}:${rawBody}`), match[1]);
}

// One check for one address. Returns { pending:true } when the watcher has
// not seen a transaction, or { report } when it has. Anything unverified
// throws and moves nothing.
export async function checkPayment({ watcherUrl, address, currency, fetchImpl = globalThis.fetch, nowSec } = {}) {
  const paste = String(watcherUrl || '').trim();
  paymentWatchUrl(paste, { address, currency });
  const baseToken = new URL(paste).searchParams.get('token') || '';
  const child = await childWatcherToken(baseToken, address, currency);
  const endpoint = paymentWatchUrl(paste, { address, currency, token: child });

  let response;
  try {
    response = await fetchImpl(endpoint, { headers: { Accept: 'application/json', Authorization: `Bearer ${child}` } });
  } catch {
    throw new Error('The payment watcher did not answer.');
  }
  const raw = await response.text().catch(() => null);
  if (!response.ok) {
    let body = null;
    try { body = JSON.parse(raw); } catch { body = null; }
    throw new Error(body?.error || `The payment watcher refused the check (${response.status}).`);
  }
  const sig = response.headers?.get?.('x-cipher-sig') ?? null;
  const ts = response.headers?.get?.('x-cipher-ts') ?? null;
  const verified = raw != null && await verifyWatcherResponse({
    rawBody: raw, sig, ts, token: child, nowSec: nowSec ?? Math.floor(Date.now() / 1000),
  });
  if (!verified) {
    throw new Error('The payment watcher tried to answer, but its answer did not pass the signature check. Nothing was marked.');
  }
  let body;
  try { body = parseExactAmounts(raw); } catch { throw new Error('The watcher answer could not be read.'); }

  const asked = String(address || '').trim();
  const askedCurrency = String(currency || '').trim().toLowerCase();
  if (body.address !== asked || String(body.currency || '').trim().toLowerCase() !== askedCurrency) {
    throw new Error('This watcher answer does not name the payment this check asked about.');
  }
  if (body.pending || !body.txid) return { pending: true };

  const report = {
    source: 'watcher',
    txid: String(body.txid),
    confirmations: Number(body.confirmations) || 0,
  };
  if (body.amount != null) report.amount = body.amount;
  if (body.outputAmount != null) report.outputAmount = body.outputAmount;
  if (body.time != null) {
    const now = Math.floor(Date.now() / 1000);
    const time = Number(body.time);
    // A milliseconds value sails past every issuance check as "the future".
    // It carries no weight instead of lying.
    if (Number.isFinite(time) && time >= 1231006505 && time <= now + 7200) report.time = time;
  }
  return { report };
}

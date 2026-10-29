// Bitcoin 8 decimals, Monero 12. Round half up, never drop. A float is not a
// coin amount — every amount crossing into the engine is a decimal string,
// every comparison is BigInt units.
//
// Ported verbatim from deal-engine/src/units.js @ 8870f72 (identical at 27b0b61).
// Do not "improve" this file in the port: it is the one place the 1-piconero
// bug class is barred, and it has already paid for itself in a drill.
//
// The rail pair is a row-per-coin table. decimals is the atomic-unit power —
// the piconero class bug is the thing every future row must get right. chain
// records whether the chain itself shows amounts ('transparent') or hides
// them ('hidden-amount'). Adding a coin is a row plus a watcher, never
// surgery here.
export const ASSETS = {
  btc: { decimals: 8, chain: 'transparent' },
  xmr: { decimals: 12, chain: 'hidden-amount' },
};

// The scale map, by its old name — one decimal power per rail.
export const AMOUNT_SCALE = Object.fromEntries(
  Object.entries(ASSETS).map(([rail, asset]) => [rail, asset.decimals]),
);

function scaleOf(currency) {
  return AMOUNT_SCALE[String(currency || '').toLowerCase()];
}

export function normalizeAmount(value) {
  if (typeof value === 'number') {
    throw new Error('A float is not a coin amount: pass a decimal string.');
  }
  const raw = String(value ?? '').trim();
  if (!raw || /e/i.test(raw) || !/^\d+([,.]\d+)?$/.test(raw) || /,/.test(raw) && !/^(\d{1,3})(,\d{3})*(\.\d+)?$/.test(raw)) {
    throw new Error('The amount must be a decimal string — group digits with commas in threes, or use plain digits.');
  }
  const digits = raw.replace(/,/g, '');
  const [whole, frac = ''] = digits.split('.');
  const wholeDigits = whole.replace(/^0+(?=\d)/, '') || '0';
  const trimmed = frac.replace(/0+$/, '');
  return trimmed ? `${wholeDigits}.${trimmed}` : wholeDigits;
}

export function amountUnits(amount, currency) {
  const scale = scaleOf(currency);
  if (scale == null) return null;
  let text;
  try {
    text = normalizeAmount(amount);
  } catch {
    return null;
  }
  const [whole, frac = ''] = text.split('.');
  const factor = 10n ** BigInt(scale);
  if (frac.length <= scale) {
    return BigInt(whole) * factor + BigInt((frac || '0').padEnd(scale, '0'));
  }
  // round half up, never drop: one extra digit decides, nothing else counts
  let units = BigInt(whole) * factor + BigInt(frac.slice(0, scale) || '0');
  if (Number(frac[scale]) >= 5) units += 1n;
  return units;
}

export function unitsToAmount(units, currency) {
  if (!Number.isInteger(units) && typeof units !== 'bigint') {
    throw new Error('Units are an integer (BigInt). A float is not a coin amount.');
  }
  const value = BigInt(units);
  const scale = scaleOf(currency);
  if (scale == null) throw new Error(`Unknown currency: ${String(currency)}`);
  const factor = 10n ** BigInt(scale);
  const sign = value < 0n ? '-' : '';
  const abs = value < 0n ? -value : value;
  const whole = abs / factor;
  const frac = abs % factor;
  const fracText = frac.toString().padStart(scale, '0').replace(/0+$/, '');
  return `${sign}${fracText ? `${whole}.${fracText}` : `${whole}`}`;
}

// The 1-piconero drill: a value crossing a trust edge carries its units with
// it. Nothing here adds or compares amounts that went through a JavaScript
// float.
export function sumAmounts(pairs) {
  if (!Array.isArray(pairs)) throw new Error('The sum takes a list of amounts.');
  if (pairs.length === 0) return { currency: '', units: 0n, amount: '0' };
  // pairs: [{ amount, currency }] — all entries must share one currency
  let units = 0n;
  let currency = '';
  for (const pair of pairs) {
    const one = amountUnits(pair.amount, pair.currency);
    if (one == null) throw new Error('A refused amount reached the sum.');
    if (!currency) currency = String(pair.currency).toLowerCase();
    else if (currency !== String(pair.currency).toLowerCase()) {
      throw new Error('Amounts of two currencies were summed.');
    }
    units += one;
  }
  return { currency, units, amount: unitsToAmount(units, currency) };
}

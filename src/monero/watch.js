// The bridge from a Monero scan finding to the one place a payment is allowed to
// move: the pocket store, through a watcher report.
//
// The Monero half could read a block and find the wallet's own output, but
// nothing wrote that into the table, so a finding was returned and forgotten.
// This module turns found outputs into the SAME report shape the Bitcoin rail
// uses (`{ source: 'watcher', txid, confirmations, amount }`), so the pocket
// store, the state walk and the "one pocket, one transaction" rule are all
// reused rather than re-implemented for xmr.
//
// Two honest limits, stated rather than hidden:
//
//   DEMAND. The xmr rail tracks no per-pocket price yet, so the found value is
//   passed as the demand too. That makes a found output record as seen/
//   confirmed and never as short — a real short-payment check needs a demand
//   recorded when the pocket is issued, which is a later lane.
//
//   CONFIRMATIONS. A block does not carry its own height, so confirmations are
//   only knowable when the caller gives both the block's height and the tip's.
//   With neither, a finding is one confirmation (seen). With both, the depth is
//   counted and the ordinary threshold (10 for xmr) decides confirmed.

import { unitsToAmount } from '../units.js';

// A found output is only persistable when it decoded a value: a refused output
// (no ecdh, an unreadable amount) is kept in the scan result but cannot name an
// amount, so it is left for a caller that wants to look.
function persistable(row) {
  return row && !row.refused && row.txid != null && row.pocket != null && row.value != null;
}

export function reportsFromScan(outputs, { height = null, tipHeight = null } = {}) {
  if (!Array.isArray(outputs)) throw new Error('A scan report is built from the scan\'s outputs list.');
  const known = Number.isInteger(height) && Number.isInteger(tipHeight) && tipHeight >= height;
  const confirmations = known ? Math.max(tipHeight - height + 1, 1) : 1;
  const reports = [];
  for (const row of outputs) {
    if (!persistable(row)) continue;
    reports.push({
      pocket: row.pocket,
      output: row.output,
      report: {
        source: 'watcher',
        txid: row.txid,
        confirmations,
        amount: unitsToAmount(row.value, 'xmr'),
      },
    });
  }
  return reports;
}

// Which Monero node a scan talks to.
//
// The founder's ruling: a shipped list of public nodes to pick from, and a
// private node that overrides the list when one is configured. The override is
// the CIPHER_XMR_NODE door: set, it is the ONLY node; unset, the list is used.
//
// Four rules, and each one is a way this goes wrong:
//
//   ONE NODE PER SCAN. A scan is coherent only over one chain. If a node dies
//   mid-scan, this wallet REFUSES the scan rather than continuing on the next
//   node and stitching two operators' answers into one result. The user's next
//   scan starts on the next node, from the start.
//
//   FAIL-CLOSED. A node that does not answer is a failed read. It is never "no
//   payments" — those are different sentences and the second is a money verdict.
//
//   STICKY. One node per session, kept until it fails. Choosing per query would
//   hand one user's whole watching pattern to every operator in the list.
//
//   SHIPPED, NOT FETCHED. The list below is a constant. No scraping, no runtime
//   discovery, no list downloaded over the network: a fetched list is a stranger
//   choosing who gets to see this wallet's users.
//
// The list ships EMPTY, the same way the messenger's founder doors ship dark:
// an address this build invented would be a claim about a stranger's server that
// I cannot verify, and a wallet pointed at the wrong host is worse than a wallet
// that says it has nowhere to go. Fill it here, by hand, with addresses the
// founder has named; that is the only way it changes.
//
// What a node learns is written in the README and in docs/L3-RECEIVE.md, not on
// a screen: the founder's copy law is that user-facing text does not frighten a
// user with what servers can see. The machinery's limits still have to be true
// and still have to be written down somewhere a reviewer reads.

export const PUBLIC_NODES = Object.freeze([
  // e.g. 'node.example.onion:18081' — added by hand, never discovered.
]);

// The same two shapes the Bitcoin rail accepts, and the same refusal: an
// address that is not a name, a port outside 1..65535, and — the one that
// matters — a host reachable without Tor unless someone said clearnet is
// allowed. docs/L3-RECEIVE.md states that rule for the whole lane, and a door
// that quietly excepted itself from it would make the document false.
const ONION = /^[a-z2-7]{16,56}\.onion$/;
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

function clean(address, { allowClearnet } = {}) {
  const text = String(address ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!text) return '';
  const at = text.lastIndexOf(':');
  const written = at === -1 ? '' : text.slice(at + 1);
  const port = Number(written);
  if (at === -1 || !/^\d{1,5}$/.test(written) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`That is not a node address: ${text}. An address is host:port, port 1 to 65535.`);
  }
  const host = text.slice(0, at);
  const onion = ONION.test(host);
  if (!onion && !HOSTNAME.test(host)) throw new Error(`That is not a node host: ${host}.`);
  if (!onion && !allowClearnet) {
    throw new Error('A Monero node reachable without Tor would learn where you are. Use an .onion node, or say clearnet is allowed.');
  }
  return `${host}:${port}`;
}

// A pool is the list plus the override, and a sticky choice inside it.
export function createNodePool({ nodes = PUBLIC_NODES, override = '', allowClearnet = false } = {}) {
  const chosen = clean(override, { allowClearnet });
  const list = chosen
    ? [chosen]
    : (Array.isArray(nodes) ? nodes : []).map((node) => clean(node, { allowClearnet })).filter(Boolean);
  if (list.length === 0) {
    throw new Error('No Monero node is configured on this wallet, so the Monero rail cannot read the chain. Bitcoin is unaffected.');
  }

  let cursor = 0;
  let session = null;

  return {
    // The node this session is using. Sticky: the same node every time until it
    // is abandoned.
    pick() {
      if (!session) {
        if (cursor >= list.length) {
          throw new Error('No configured Monero node answered. This is a failed read, not a finding about any payment.');
        }
        session = list[cursor];
      }
      return session;
    },

    // A scan may only ever talk to one node. Called by the scan at each step, so
    // a node that died mid-scan cannot be silently replaced by the next one.
    assertCurrent(node) {
      if (!session || node !== session) {
        throw new Error('A scan runs against one Monero node. Refusing to stitch results from two.');
      }
      return node;
    },

    // The session's node failed. The CURRENT scan must be refused (see above);
    // the next one starts on the next node in the list.
    abandon(node) {
      if (node !== session) return;
      session = null;
      cursor += 1;
    },

    get exhausted() {
      return cursor >= list.length;
    },

    // For tests and for the screen's own count — never for choosing per query.
    get nodes() {
      return list.slice();
    },
  };
}

// The override's name, read by whatever builds this wallet. Exported so the
// name exists in one place: CIPHER_XMR_NODE, one address, host:port.
export const OVERRIDE_ENV = 'CIPHER_XMR_NODE';

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
// The list shipped EMPTY for a long time, the same way the messenger's founder
// doors ship dark: an address this build invented would be a claim about a
// stranger's server it could not verify. One row is now here because it WAS
// verified: `get_info` and a full `getBlock`+scan at a live height were run
// against it on 2026-11-04 (a block was fetched, 59 transactions read). The row
// is still by hand and still never fetched at runtime.
//
// A CLEARNET ROW SAYS SO ON THE ROW. The lane's rule is that no clearnet peer is
// used without an explicit allowance, so the allowance is written where the
// address is: a shipped row that is not an .onion is an object carrying
// `allowClearnet: true`, and a plain string is refused. The override is the
// person's own allowance — they typed the address — so it needs no marker.
//
// What a node learns is written in the README and in docs/L3-RECEIVE.md, not on
// a screen: the founder's copy law is that user-facing text does not frighten a
// user with what servers can see. The machinery's limits still have to be true
// and still have to be written down somewhere a reviewer reads.

export const PUBLIC_NODES = Object.freeze([
  // Clearnet, live-verified 2026-11-04 (see the note above). Carry the allowance
  // on the row. An .onion row is a plain string: 'nodexxx.onion:18081'.
  { address: 'xmr-node.cakewallet.com:18081', allowClearnet: true },
  // The second row exists so a failed read has somewhere to go: the next scan
  // starts on the next node (nodes.js abandon/rotation). Also live-verified
  // 2026-11-04 (get_info + block header read).
  { address: 'nodes.hashvault.pro:18081', allowClearnet: true },
  // A clearnet row has to carry its own allowance, exactly like this:
  //   { address: 'node.example:18081', allowClearnet: true },
  // Never discovered, never fetched.
]);

// The stagenet list, for the funded lane: coins a faucet pays to an address this
// build derived are the only honest way to test acceptance end-to-end, and
// mainnet is no place for that. BOTH rows were live-verified 2026-11-04 against
// a node whose get_info says nettype=stagenet and whose /get_block, /get_outs
// and /get_transactions doors all answered at height 2243680. The funding script
// pins its node anyway; these rows exist so a scan has rotation too.
export const STAGENET_PUBLIC_NODES = Object.freeze([
  { address: 'stagenet.xmr-tw.org:38081', allowClearnet: true },
  { address: 'node.sethforprivacy.com:38089', allowClearnet: true },
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
//
// `allowClearnet` is the caller's blanket allowance, for a build whose transport
// is known to be Tor. A row that carries its own `allowClearnet` needs no
// blanket, which is what keeps one address's allowance from covering the list.
export function createNodePool({ nodes = PUBLIC_NODES, override = '', allowClearnet = false } = {}) {
  const chosen = clean(override, { allowClearnet: true });
  const list = chosen
    ? [chosen]
    : (Array.isArray(nodes) ? nodes : [])
      .map((node) => {
        const row = node && typeof node === 'object' ? node : { address: node };
        return clean(row.address, { allowClearnet: allowClearnet || row.allowClearnet === true });
      })
      .filter(Boolean);
  if (list.length === 0) {
    const none = new Error('No Monero node is configured on this wallet, so the Monero rail cannot read the chain. Bitcoin is unaffected.');
    // A stable name for the one refusal a caller may recover from by pinning
    // the node it was already given. Matching on the sentence would break the
    // first time someone edits the sentence.
    none.code = 'NO_NODE_CONFIGURED';
    throw none;
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

// THE RUNTIME DOOR. The constant above names the variable; this is the only
// function that reads it. The read is a function of an explicit environment
// (defaulting to the process's) rather than a value captured when this module
// was first imported: a captured value would freeze whatever the launcher
// happened to have set, could not be tested without mutating the process, and
// would make "set it and the next scan uses it" untrue. Reading it here is what
// turns OVERRIDE_ENV from a name into a door.
export function nodeOverride(env = globalThis.process?.env) {
  if (!env) return '';
  const raw = env[OVERRIDE_ENV];
  return raw === undefined || raw === null ? '' : String(raw).trim();
}

// The one entry point a scan uses to find its node. The environment decides
// between the person's own node and the shipped list; createNodePool owns the
// refusal when the answer is "nothing is configured", so a wallet with nowhere
// to go says that by name instead of failing somewhere deeper with a socket
// error. An override is the person's own address, so it carries its own
// clearnet allowance; the shipped list needs one written on it.
export function nodeSourceFromEnv({ env = globalThis.process?.env, nodes = PUBLIC_NODES,
  allowClearnet = false } = {}) {
  return createNodePool({ nodes, override: nodeOverride(env), allowClearnet });
}

// A pool of exactly one node that the CALLER pinned, for the doors' fallback
// when no pool was injected and the wallet itself has nothing configured. The
// address is the one the caller wrote into the call, so this invents no default
// and fetches no list: it exists so the pinned-node rule is still a check
// rather than a branch that skips one.
export function createPinnedPool(address) {
  const node = String(address ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!node) throw new Error('A pinned pool needs a node address.');
  let session = node;
  return {
    pick() {
      if (!session) {
        throw new Error('No configured Monero node answered. This is a failed read, not a finding about any payment.');
      }
      return session;
    },
    assertCurrent(candidate) {
      if (!session || candidate !== session) {
        throw new Error('A scan runs against one Monero node. Refusing to stitch results from two.');
      }
      return candidate;
    },
    abandon(candidate) {
      if (candidate === session) session = null;
    },
    get exhausted() {
      return session === null;
    },
    get nodes() {
      return [node];
    },
  };
}

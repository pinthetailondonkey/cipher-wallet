// The socket side of talking to a Bitcoin peer.
//
// peers.js holds the policy and takes `fetchFilter` as a function precisely so
// the policy can be tested against something that lies. This module is that
// function's real body: it shakes hands, frames messages, reads frames back,
// and answers with the thing it was asked for — or refuses.
//
// The connection is injected. This module owns bytes and ordering; the caller
// owns how a socket is opened (a Tor stream in the app, a loopback TCP socket
// in the drill). That keeps the parser testable against bytes a stranger could
// actually send.
//
// Every answer is checked against the question: a cfilter must name the block
// hash that was asked about, and a block's bytes are returned for the caller to
// hash and compare. Nothing here "asks nicely and hopes".

import {
  BASIC_FILTER_TYPE,
  FRAME_HEADER_SIZE,
  MAX_PAYLOAD,
  NODE_COMPACT_FILTERS,
  PROTOCOL_VERSION,
  decodeCfilter,
  decodeFrame,
  decodeVersion,
  encodeCfilter,
  encodeGetCfilters,
  encodeGetData,
  encodeVersion,
  frame,
} from './wire.js';

// The reader must be able to hold any frame the wire will accept: one payload
// at the wire's own cap, plus its header. A smaller cap here would refuse a
// frame that decodeFrame is happy to parse, and the refusal would name the
// reader rather than the peer.
const MAX_BUFFER = MAX_PAYLOAD + FRAME_HEADER_SIZE;
const DEFAULT_TIMEOUT_MS = 8000;

function normalizeHash(blockHash) {
  const text = String(blockHash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error('A block hash is 64 hex characters.');
  return text;
}

// A buffer that hands back whole frames in arrival order. A partial frame waits;
// bytes that cannot be a frame are refused rather than kept for later.
export function frameReader({ network = 'mainnet' } = {}) {
  let buffered = new Uint8Array(0);
  return {
    push(chunk) {
      if (!(chunk instanceof Uint8Array)) throw new Error('A socket gives bytes.');
      if (buffered.length + chunk.length > MAX_BUFFER) throw new Error('That peer sent more than this wallet will hold.');
      const joined = new Uint8Array(buffered.length + chunk.length);
      joined.set(buffered, 0);
      joined.set(chunk, buffered.length);
      buffered = joined;
      const out = [];
      let at = 0;
      while (buffered.length - at >= 24) {
        let decoded;
        try {
          decoded = decodeFrame(buffered, { offset: at, network });
        } catch (error) {
          // A short payload is a wait, not a refusal; anything else is corrupt.
          if (/ends before its payload/.test(error.message)) break;
          throw error;
        }
        out.push(decoded);
        at += decoded.size;
      }
      buffered = buffered.slice(at);
      return out;
    },
    pending: () => buffered.length,
  };
}

// One connected, hand-shaken peer. Frames arrive into a queue; `nextFrame`
// waits for one until the deadline, and refuses rather than hanging.
async function openSession(socket, { network, timeoutMs, userAgent }) {
  const reader = frameReader({ network });
  const queue = [];
  let failure = null;
  let notify = null;
  const wake = () => { const n = notify; notify = null; n?.(); };

  socket.onData((chunk) => {
    let frames;
    try {
      frames = reader.push(chunk);
    } catch (error) {
      failure = error;
      wake();
      return;
    }
    queue.push(...frames);
    wake();
  });
  socket.onClose?.(() => {
    failure = failure ?? new Error('That peer closed the connection before answering.');
    wake();
  });

  const deadline = Date.now() + timeoutMs;

  async function nextFrame() {
    for (;;) {
      if (queue.length) return queue.shift();
      if (failure) throw failure;
      const left = deadline - Date.now();
      if (left <= 0) throw new Error('That peer did not answer in time.');
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, left);
        notify = () => { clearTimeout(timer); resolve(); };
      });
    }
  }

  function send(command, payload = new Uint8Array()) {
    socket.write(frame(command, payload, network));
  }

  // version/verack. A node sends its version as soon as it connects; this
  // replies with its own and answers theirs with a verack. A ping before the
  // handshake is answered rather than ignored.
  send('version', encodeVersion({ userAgent }));
  let gotVersion = false;
  let gotVerack = false;
  let remote = null;
  while (!(gotVersion && gotVerack)) {
    const message = await nextFrame();
    if (message.command === 'version') {
      // One handshake, counted once, in order. A second version would let a peer
      // revise what it claimed after the first claim was checked, and a verack
      // before any version would let it complete a handshake that was never
      // offered — skipping the protocol-version check below entirely.
      if (gotVersion) throw new Error('That peer offered a second version, so the handshake is not one handshake.');
      remote = decodeVersion(message.payload);
      if (remote.version < 70015) throw new Error('That peer speaks a protocol too old to ask for filters.');
      gotVersion = true;
      send('verack');
    } else if (message.command === 'verack') {
      if (!gotVersion) throw new Error('That peer acknowledged a handshake it never offered.');
      gotVerack = true;
    } else if (message.command === 'ping') {
      send('pong', message.payload);
    } else if (message.command === 'reject') {
      throw new Error('That peer rejected the handshake.');
    }
  }

  // After the handshake, another version or verack is the peer opening the
  // handshake again — the one message it cannot send honestly at this point.
  // Checked in the read loops below, which is the only place it can arrive: the
  // handshake loop above exits on the first verack, so a duplicate sent during
  // the handshake lands here instead.
  async function nextAnswer() {
    for (;;) {
      const message = await nextFrame();
      if (message.command === 'version' || message.command === 'verack') {
        throw new Error('That peer re-opened the handshake after it was finished.');
      }
      if (message.command === 'ping') { send('pong', message.payload); continue; }
      return message;
    }
  }

  return { nextFrame, nextAnswer, send, remote, close: () => { try { socket.end?.(); } catch { /* already closed */ } } };
}

export function createPeerClient({ connect, network = 'mainnet', timeoutMs = DEFAULT_TIMEOUT_MS, userAgent } = {}) {
  if (typeof connect !== 'function') throw new Error('A peer client needs a way to open a connection.');

  async function withSession(peer, work) {
    const socket = await connect(peer);
    const session = await openSession(socket, { network, timeoutMs, userAgent });
    try {
      return await work(session);
    } finally {
      session.close();
    }
  }

  // Ask for one block's filter. The answer counts only if it names the block
  // that was asked about; anything else is a refusal naming what happened.
  async function fetchFilter(peer, blockHash) {
    const asked = normalizeHash(blockHash);
    return withSession(peer, async (session) => {
      // A peer that never claimed to serve compact filters is refused before a
      // question is asked of it. Asking anyway gets silence or an unrelated
      // answer, and both look like a broken wallet rather than a wrong peer.
      if ((session.remote.services & NODE_COMPACT_FILTERS) === 0n) {
        throw new Error('That peer does not say it serves compact filters, so it is not asked.');
      }
      session.send('getcfilters', encodeGetCfilters({ startHeight: 0, stopHash: asked }));
      for (;;) {
        const message = await session.nextAnswer();
        if (message.command !== 'cfilter') continue;
        const answer = decodeCfilter(message.payload);
        if (answer.filterType !== BASIC_FILTER_TYPE) {
          throw new Error('That peer answered with a filter type this wallet did not ask for.');
        }
        if (answer.blockHash !== asked) {
          throw new Error(`That peer answered about block ${answer.blockHash}, not ${asked}.`);
        }
        return { filter: answer.filter, blockHash: answer.blockHash };
      }
    });
  }

  // Ask for one block's bytes. The bytes are returned unverified on purpose:
  // the caller hashes them and compares with the hash it asked for, so the
  // check lives with the code that also knows which block it wanted.
  async function fetchBlock(peer, blockHash) {
    const asked = normalizeHash(blockHash);
    return withSession(peer, async (session) => {
      session.send('getdata', encodeGetData({ hash: asked }));
      for (;;) {
        const message = await session.nextAnswer();
        if (message.command !== 'block') continue;
        return { bytes: message.payload };
      }
    });
  }

  return { fetchFilter, fetchBlock };
}

// The framing a loopback peer needs to speak, exported so the drill does not
// re-invent it: a test that lies must lie in the same bytes a peer would send.
export { frame, encodeCfilter, encodeVersion, decodeVersion, PROTOCOL_VERSION, BASIC_FILTER_TYPE };

// The socket side of asking a peer for a block's filter.
//
// peers.js holds the policy and takes `fetchFilter` as a function precisely so
// the policy can be tested against something that lies. This module is that
// function's real body: it frames a getcfilters message, reads frames back, and
// answers with the filter for the block it was asked about — or refuses.
//
// The connection is injected. This module owns bytes and ordering; the caller
// owns how a socket is opened (a Tor stream in the app, a loopback TCP socket
// in the drill). That keeps the parser testable against bytes a stranger could
// actually send.
//
// Not here yet, and stated so nobody assumes it: the Bitcoin version/verack
// handshake. A mainnet node expects it before serving getcfilters, so this
// transport is proven against the drill's peers and not yet against a real
// node. It is the first thing the block-fetch step needs.

import { BASIC_FILTER_TYPE, decodeCfilter, decodeFrame, encodeCfilter, encodeGetCfilters, frame } from './wire.js';

const MAX_BUFFER = 4 * 1024 * 1024;
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

// connect(peer) resolves to a socket-like object: write(bytes), end(), onData(fn),
// onClose(fn). The promise settles with the filter that names the block asked
// about. Anything else — another block, another filter type, a cut stream, a
// timeout — is a refusal naming what happened.
export function createFilterClient({ connect, network = 'mainnet', timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof connect !== 'function') throw new Error('A peer client needs a way to open a connection.');

  return async function fetchFilter(peer, blockHash) {
    const asked = normalizeHash(blockHash);
    const socket = await connect(peer);
    const reader = frameReader({ network });

    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        finish(new Error('That peer did not answer in time.'));
      }, timeoutMs);

      function finish(error, value) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.end?.(); } catch { /* a dead socket is already closed */ }
        if (error) reject(error); else resolve(value);
      }

      socket.onClose?.(() => finish(new Error('That peer closed the connection before answering.')));

      socket.onData((chunk) => {
        let frames;
        try {
          frames = reader.push(chunk);
        } catch (error) {
          finish(error);
          return;
        }
        for (const message of frames) {
          if (message.command !== 'cfilter') continue;
          let answer;
          try {
            answer = decodeCfilter(message.payload);
          } catch (error) {
            finish(error);
            return;
          }
          if (answer.filterType !== BASIC_FILTER_TYPE) {
            finish(new Error('That peer answered with a filter type this wallet did not ask for.'));
            return;
          }
          if (answer.blockHash !== asked) {
            // The one thing the framing cannot catch: a well-formed answer to a
            // different question.
            finish(new Error(`That peer answered about block ${answer.blockHash}, not ${asked}.`));
            return;
          }
          finish(null, { filter: answer.filter, blockHash: answer.blockHash });
          return;
        }
      });

      try {
        socket.write(frame('getcfilters', encodeGetCfilters({ startHeight: 0, stopHash: asked }), network));
      } catch (error) {
        finish(error);
      }
    });
  };
}

// The framing a loopback peer needs to speak, exported so the drill does not
// re-invent it: a test that lies must lie in the same bytes a peer would send.
export { frame, encodeCfilter, BASIC_FILTER_TYPE };

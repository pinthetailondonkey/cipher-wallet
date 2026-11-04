// Fork choice: when two peers name different tips, believe the heavier chain.
//
// `peers.agreedTip` requires the two peers to name the SAME hash. That is the
// right rule for a tip that is merely being confirmed, but it is not a fork
// rule: two honest peers on opposite sides of a fork name different tips and
// exact agreement refuses even though one chain is heavier. The heavier chain
// is the one a miner spent more on, and pricing it is the missing primitive.
//
// Nothing here decides which fork is "real" by fiat. A candidate's work is the
// chain's own cost, read by walking that peer's tip back with the same checks
// as any other walk (hash, link, merkle, proof-of-work). A peer cannot buy a
// heavier vote by naming an easy target on every header: `walkBack` prices what
// the headers actually prove.
//
// A TIE is refused, not broken. Two tips that carry the exact same work are two
// chains a miner spent indistinguishably on, and picking the first would hide
// that. `onTie: 'first'` is the escape hatch for a caller that has a reason.
//
// These functions take a pool and a client, not a socket. The pool supplies the
// peers; the client answers `fetchTip`/`fetchBlock`. The client's `fetchTip`
// must exist here — this path exists precisely because one peer's tip is not a
// witness.

import { walkBack } from './chain.js';
import { MIN_AGREEMENT } from './peers.js';

const HASH = /^[0-9a-f]{64}$/;

// The heaviest of `candidates`, each `{ hash, work }` with a 64-hex hash and a
// non-negative bigint work. Empty input and malformed entries are refused by
// name. If the two heaviest candidates carry EQUAL work but DIFFERENT hashes,
// there is no heavier one to pick, so the refusal says so; `onTie: 'first'`
// returns the earliest such candidate instead.
export function heaviestTip(candidates, { onTie = 'refuse' } = {}) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new Error('A heaviest tip needs at least one candidate.');
  }
  const checked = candidates.map((candidate, index) => {
    if (!candidate || typeof candidate !== 'object') {
      throw new Error(`Candidate ${index} is not a { hash, work } pair.`);
    }
    const hash = String(candidate.hash ?? '').trim().toLowerCase();
    if (!HASH.test(hash)) throw new Error(`Candidate ${index} has no 64-hex tip hash.`);
    if (typeof candidate.work !== 'bigint' || candidate.work < 0n) {
      throw new Error(`Candidate ${index} has no non-negative bigint work.`);
    }
    return { hash, work: candidate.work };
  });

  let best = checked[0];
  for (const candidate of checked) {
    if (candidate.work > best.work) best = candidate;
  }
  const heaviest = checked.filter((candidate) => candidate.work === best.work);
  if (new Set(heaviest.map((candidate) => candidate.hash)).size > 1) {
    if (onTie === 'first') return heaviest[0];
    throw new Error('two tips carry equal work, so nothing here picks between them');
  }
  return best;
}

// Ask the picked peers where their chain ends, price each tip's chain, and hand
// back one candidate per peer that answered: `{ peer, hash, work, height }`.
//
// `client.fetchTip(peer)` must exist. It may answer `{ hash, height }` or a
// bare hash; a bare hash has no height, so `tipHeight` (an option) supplies the
// count the walk starts from. Each candidate is walked back up to `depth`
// blocks by that peer's OWN tip, so the work is that chain's, not a neighbour's.
//
// A peer that errors anywhere (no tip, no block, a broken link) is skipped and
// its error collected on the returned array's non-enumerable `errors`. Unlike
// agreedTip, the survivors need NOT agree on a hash — that is the whole point.
// Fewer than MIN_AGREEMENT survivors is a refusal.
export async function tipCandidates(pool, client, { depth = 10, tipHeight = null } = {}) {
  if (!pool || typeof pool.requireAgreement !== 'function') {
    throw new Error('A fork choice needs a peer pool.');
  }
  if (!client || typeof client.fetchTip !== 'function') {
    throw new Error('A fork choice needs a client with fetchTip.');
  }
  if (!Number.isInteger(depth) || depth < 1) {
    throw new Error('A fork choice walks at least one block back.');
  }
  pool.requireAgreement(MIN_AGREEMENT);
  const asked = pool.pick(Math.min(pool.size(), MIN_AGREEMENT + 1));
  if (asked.length < MIN_AGREEMENT) {
    throw new Error(`This needs ${MIN_AGREEMENT} independent peers and ${asked.length} were asked.`);
  }

  const errors = [];
  const candidates = [];
  for (const peer of asked) {
    try {
      const answer = await client.fetchTip(peer);
      const hash = String(answer?.hash ?? answer?.tipHash ?? answer ?? '').trim().toLowerCase();
      if (!HASH.test(hash)) {
        errors.push({ peer, error: 'no tip' });
        continue;
      }
      const height = Number.isInteger(answer?.height) ? answer.height
        : (Number.isInteger(tipHeight) ? tipHeight : 0);
      // The walk is the price: it re-hashes every block, checks every link and
      // merkle root, and requires every header to prove its own work. `work` is
      // the sum it returns, and it cannot be faked for free because the peer
      // chose every nBits.
      const walked = await walkBack({
        fetchBlock: client.fetchBlock,
        peer,
        tipHash: hash,
        tipHeight: height,
        maxSteps: depth,
      });
      candidates.push({ peer, hash, work: walked.work, height });
    } catch (error) {
      errors.push({ peer, error: error?.message || String(error) });
    }
  }

  if (candidates.length < MIN_AGREEMENT) {
    const who = [...candidates, ...errors]
      .map((entry) => `${entry.peer.host}:${entry.peer.port}${entry.error ? ` (${entry.error})` : ''}`)
      .join(', ');
    throw new Error(`Fewer than ${MIN_AGREEMENT} peers served a tip that could be walked, so no fork was priced. Asked: ${who}.`);
  }
  Object.defineProperty(candidates, 'errors', { value: errors, enumerable: false });
  return candidates;
}

// The heavier tip, and the peers that serve it.
//
// `heaviestTip` alone already refuses a tie, but this also requires the winner
// to be STRICTLY heavier than the heaviest OTHER distinct tip: a bare tie is
// refused here too, and it names the ambiguity rather than returning a winner
// that is no better than its rival. Returns `{ hash, work, height, peers,
// candidates }`, where `peers` are the peers whose tip is the winner.
export async function chooseTip(pool, client, opts = {}) {
  const candidates = await tipCandidates(pool, client, opts);
  const winner = heaviestTip(candidates, { onTie: 'first' });
  let heaviestOther = null;
  for (const candidate of candidates) {
    if (candidate.hash === winner.hash) continue;
    if (!heaviestOther || candidate.work > heaviestOther.work) heaviestOther = candidate;
  }
  if (heaviestOther && winner.work <= heaviestOther.work) {
    throw new Error('two tips carry equal work, so nothing here picks between them');
  }
  // heaviestTip returns only { hash, work }, so the winner's height (a claim
  // that peer made) is read back off the candidate it matched.
  const mined = candidates.find((candidate) => candidate.hash === winner.hash);
  const peers = candidates.filter((candidate) => candidate.hash === winner.hash).map((candidate) => candidate.peer);
  return { hash: winner.hash, work: winner.work, height: mined?.height, peers, candidates };
}

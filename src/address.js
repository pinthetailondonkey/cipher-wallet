// Turning the address a payee gives you into the script that pays them.
//
// This is the edge where a typo becomes money sent to nobody, so it refuses
// rather than guesses:
//   - a mixed-case bech32 address is refused (the case carries the checksum);
//   - witness v0 must use bech32 and v1..16 must use bech32m, as BIP-350 says;
//   - a program outside 2..40 bytes, or a v0 program that is not 20 or 32, is
//     refused;
//   - an address for another network is refused, not reinterpreted.
//
// Checked against the BIP-173/BIP-350 valid and invalid vectors and against
// the genesis coinbase address; see test/address.test.mjs.

import { bech32, bech32m, createBase58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';

const b58check = createBase58check(sha256);

const NETWORK_HRP = Object.freeze({ bc: 'bc', tb: 'tb', bcrt: 'bcrt' });
const P2PKH_VERSION = Object.freeze({ bc: 0x00, tb: 0x6f, bcrt: 0x6f });
const P2SH_VERSION = Object.freeze({ bc: 0x05, tb: 0xc4, bcrt: 0xc4 });

export const MAX_WITNESS_PROGRAM = 40;

function networkRow(network) {
  const key = String(network ?? 'bc').toLowerCase();
  if (!Object.hasOwn(NETWORK_HRP, key)) throw new Error('Choose a Bitcoin network.');
  return key;
}

function segwitScript(version, program) {
  const opcode = version === 0 ? 0x00 : 0x50 + version;
  const script = new Uint8Array(2 + program.length);
  script[0] = opcode;
  script[1] = program.length;
  script.set(program, 2);
  return script;
}

function segwitKind(version, length) {
  if (version !== 0) return 'witness';
  return length === 20 ? 'p2wpkh' : 'p2wsh';
}

function decodeSegwit(raw, lower, network) {
  // Base58 is case-sensitive by design; bech32 is not, but a MIXED-case
  // bech32 string is a checksum failure pretending to be a typo.
  if (raw !== lower && raw !== raw.toUpperCase()) {
    throw new Error('That address mixes upper and lower case, so its checksum cannot be trusted.');
  }
  const ownHrp = NETWORK_HRP[network];
  let prefix;
  let words;
  let encoding;
  try {
    ({ prefix, words } = bech32.decode(lower));
    encoding = 'bech32';
  } catch {
    try {
      ({ prefix, words } = bech32m.decode(lower));
      encoding = 'bech32m';
    } catch {
      throw new Error('That address is not valid. Check it and paste it again.');
    }
  }
  if (prefix !== ownHrp) throw new Error('That address is for a different network.');
  if (words.length === 0) throw new Error('That address carries no witness program.');

  const version = words[0];
  if (version > 16) throw new Error('That address names a witness version this build does not know.');

  let program;
  try {
    program = bech32.fromWords(words.slice(1));
  } catch {
    throw new Error('That address is not valid. Check it and paste it again.');
  }

  // The checksum flavour is part of the address, not a style choice.
  if (version === 0 && encoding !== 'bech32') {
    throw new Error('That address is not valid: a v0 address must use the bech32 checksum.');
  }
  if (version !== 0 && encoding !== 'bech32m') {
    throw new Error('That address is not valid: a v1+ address must use the bech32m checksum.');
  }
  if (version === 0 && program.length !== 20 && program.length !== 32) {
    throw new Error('That address is not valid: a v0 program is 20 or 32 bytes.');
  }
  if (program.length < 2 || program.length > MAX_WITNESS_PROGRAM) {
    throw new Error('That address is not valid: a witness program is 2 to 40 bytes.');
  }

  return {
    address: lower,
    network,
    kind: segwitKind(version, program.length),
    witnessVersion: version,
    program,
    script: segwitScript(version, program),
  };
}

function decodeBase58(raw, network) {
  let bytes;
  try {
    bytes = b58check.decode(raw);
  } catch {
    throw new Error('That address is not valid. Check it and paste it again.');
  }
  if (bytes.length !== 21) throw new Error('That address is not valid. Check it and paste it again.');

  const version = bytes[0];
  const hash = bytes.slice(1);
  // OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
  const p2pkhScript = () => {
    const out = new Uint8Array(25);
    out.set([0x76, 0xa9, 0x14], 0);
    out.set(hash, 3);
    out.set([0x88, 0xac], 23);
    return out;
  };
  // OP_HASH160 PUSH20 <hash> OP_EQUAL
  const p2shScript = () => {
    const out = new Uint8Array(23);
    out.set([0xa9, 0x14], 0);
    out.set(hash, 2);
    out[22] = 0x87;
    return out;
  };

  if (version === P2PKH_VERSION[network]) {
    return { address: raw, network, kind: 'p2pkh', witnessVersion: null, program: hash, script: p2pkhScript() };
  }
  if (version === P2SH_VERSION[network]) {
    return { address: raw, network, kind: 'p2sh', witnessVersion: null, program: hash, script: p2shScript() };
  }
  throw new Error('That address is for a different network.');
}

// One address in, a paying script out. Anything doubtful throws.
export function decodeAddress(text, network = 'bc') {
  const net = networkRow(network);
  const raw = String(text ?? '').trim();
  if (!raw) throw new Error('An address is required.');

  const lower = raw.toLowerCase();
  const isSegwit = Object.values(NETWORK_HRP).some((hrp) => lower.startsWith(`${hrp}1`));
  return isSegwit ? decodeSegwit(raw, lower, net) : decodeBase58(raw, net);
}

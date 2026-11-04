// Probe A3: key material and derivation path. Prove by execution.
// Independent of the code under test where possible: node:crypto HMAC/PBKDF2,
// a hand-rolled BIP32, and the pinned Monero vectors in test/fixtures.
import { readFileSync } from 'node:fs';
import { createHmac, pbkdf2Sync } from 'node:crypto';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';

import {
  FIELD, GROUP_ORDER, scReduce32, isCanonicalScalar, bytesToNumberLE,
  numberToBytesLE, secretToPublic, keyDerivation, keyImage, deriveSecretKey,
  hashToScalar, varint,
} from '../../src/monero/keys.js';
import { encodeAddress, decodeAddress, ADDRESS_PREFIXES } from '../../src/monero/address.js';
import { encode as b58encode, decode as b58decode, decodeAddr, encodeAddr } from '../../src/monero/base58.js';
import { moneroPocket } from '../../src/monero/pocket.js';
import { derivePocket, rootFromMnemonic, xmrPocketEntropy } from '../../src/root.js';

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const le = (v) => numberToBytesLE(v, 32);
const out = (...a) => console.log(...a);
const OK = (c, m) => out(c ? `  ok   ${m}` : `  FAIL ${m}`);

out('== area1: scReduce32 boundaries vs mod l ==');
for (const [name, v] of [
  ['l-1', GROUP_ORDER - 1n],
  ['l', GROUP_ORDER],
  ['l+1', GROUP_ORDER + 1n],
  ['2^255-1', (1n << 255n) - 1n],
  ['topbit+1', (1n << 255n) + 1n],
  ['2^256-1', (1n << 256n) - 1n],
]) {
  const r = bytesToNumberLE(scReduce32(le(v)));
  OK(r === v % GROUP_ORDER && isCanonicalScalar(scReduce32(le(v))), `${name}: reduced=${hex(scReduce32(le(v)))} canonical=${isCanonicalScalar(scReduce32(le(v)))}`);
}
// Are the positive vectors' secrets canonical? (we refuse non-canonical, does Monero accept?)
const cryptoRows = readFileSync(new URL('../../test/fixtures/monero-crypto.txt', import.meta.url), 'utf8')
  .split('\n').map((l) => l.trim()).filter(Boolean);
const nonCanon = {};
for (const line of cryptoRows) {
  const t = line.split(/\s+/);
  if (t.at(-1) === 'false') continue;
  const pick = { generate_key_derivation: [3, 5], generate_key_image: [3, 5], derive_secret_key: [4, 6], derive_public_key: [3, 5] }[t[0]];
  if (!pick) continue;
  const secHex = t.slice(pick[0], pick[1]).join('');
  if (secHex.length !== 64) continue;
  if (!isCanonicalScalar(unhex(secHex))) nonCanon[t[0]] = (nonCanon[t[0]] || 0) + 1;
}
out('  non-canonical positive secrets (Monero may accept where we refuse):', JSON.stringify(nonCanon));

out('== area1b: does a non-reduced scalar reach a value silently ==');
try { secretToPublic(le(GROUP_ORDER + 1n)); out('  FAIL accept l+1'); } catch (e) { OK(/not reduced|zero/.test(e.message), `refuses l+1: ${e.message}`); }
try { keyDerivation(unhex('01'.repeat(32)), le(GROUP_ORDER + 5n)); out('  FAIL accepted non-reduced derivation secret'); } catch (e) { OK(true, 'keyDerivation refuses non-reduced'); }

out('== area2: xmrPocketEntropy well-defined and collision-free ==');
const SEED = rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const seen = new Map();
let coll = 0, badLen = 0;
for (let i = 0; i < 3000; i += 1) {
  const e = xmrPocketEntropy(SEED, i);
  if (e.length !== 32) badLen += 1;
  const h = hex(e);
  if (seen.has(h)) coll += 1;
  seen.set(h, i);
}
OK(coll === 0 && badLen === 0, `3000 indices: collisions=${coll} badLen=${badLen}`);
OK(hex(xmrPocketEntropy(SEED, 0)) === hex(derivePocket(SEED, 'xmr', 0).privateKey), 'entropy is the derived xmr pocket key');
OK(xmrPocketEntropy(SEED, 0) instanceof Uint8Array && xmrPocketEntropy(SEED, 0) !== xmrPocketEntropy(SEED, 0), 'returns fresh bytes');
OK(hex(xmrPocketEntropy(SEED, 0)) !== hex(derivePocket(SEED, 'btc', 0).privateKey), 'xmr entropy != btc key at same index');

out('== area3: address encoding, checksum, prefix, refusal ==');
// Monero's own keys_addr vector: the only external pin.
const b58Rows = readFileSync(new URL('../../test/fixtures/monero-base58.txt', import.meta.url), 'utf8').split('\n');
const keysAddr = b58Rows.map((l) => l.trim().split(/\s+/)).find((t) => t[0] === 'keys_addr');
const pinnedBlob = unhex(keysAddr.slice(1, -1).join(''));
const pinnedSpend = pinnedBlob.subarray(0, 32);
const pinnedView = pinnedBlob.subarray(32, 64);
const pinnedAddr = keysAddr.at(-1);
OK(encodeAddress({ spend: pinnedSpend, view: pinnedView }) === pinnedAddr, 'matches Monero keys_addr vector');
// Independent checksum check on the raw decoded bytes.
const raw = b58decode(pinnedAddr);
const body = raw.subarray(0, raw.length - 4);
const cs = raw.subarray(raw.length - 4);
OK(hex(cs) === hex(keccak_256(body).subarray(0, 4)), 'checksum is keccak(prefix||payload)[0..4]');
OK(body[0] === 18, `mainnet standard prefix byte is 18 (got ${body[0]})`);
OK(pinnedBlob.length === 64, 'payload is spend||view 64 bytes');
// tamper
const tamper = Uint8Array.from(raw); tamper[tamper.length - 1] ^= 1;
try { decodeAddress(b58encode(tamper)); out('  FAIL tampered checksum accepted'); } catch { OK(true, 'tampered checksum refused'); }
// distinct subaddress prefix + standard distinguishability
const sub = encodeAddress({ spend: pinnedSpend, view: pinnedView, kind: 'subaddress' });
OK(sub !== pinnedAddr && decodeAddress(sub).kind === 'subaddress', 'standard vs subaddress distinguishable');
OK(decodeAddress(pinnedAddr).kind === 'standard', 'standard decodes as standard');
// bad keys
for (const [name, k] of [['zero', new Uint8Array(32)], ['identity', unhex('01' + '00'.repeat(31))], ['ff*32', unhex('ff'.repeat(32))]]) {
  try { encodeAddress({ spend: k, view: pinnedView }); out(`  FAIL accepted bad spend ${name}`); }
  catch (e) { OK(true, `refuses bad spend ${name}: ${e.message.slice(0, 40)}`); }
}

out('== area4: freeze the derivation, re-derive by hand ==');
const MN = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = rootFromMnemonic(MN);
const KNOWN_SEED = '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4';
OK(hex(seed) === KNOWN_SEED, 'BIP39 seed matches the published Trezor vector');
// hand BIP32 hardened leaf m/44'/128'/0'/0'/i'
function hmac512(key, data) { return createHmac('sha512', key).update(data).digest(); }
function ckdPriv(node, index) {
  const data = Buffer.concat([Buffer.from([0]), node.k, Buffer.from(index.toString(16).padStart(8, '0'), 'hex')]);
  const I = hmac512(node.c, data);
  const IL = I.subarray(0, 32);
  const n = BigInt('0xfffffffffffffffffffffffffffffffe' + 'baaedce6af48a03bbfd25e8cd0364141');
  const k = ((BigInt('0x' + IL.toString('hex')) + BigInt('0x' + node.k.toString('hex'))) % n);
  return { k: Buffer.from(k.toString(16).padStart(64, '0'), 'hex'), c: I.subarray(32) };
}
function deriveHardened(seedBytes, segments) {
  let I = hmac512(Buffer.from('Bitcoin seed'), Buffer.from(seedBytes));
  let node = { k: I.subarray(0, 32), c: I.subarray(32) };
  for (const s of segments) node = ckdPriv(node, (s | 0x80000000) >>> 0);
  return node.k;
}
for (let i = 0; i < 3; i += 1) {
  const manual = deriveHardened(seed, [44, 128, 0, 0, i]);
  OK(hex(manual) === hex(xmrPocketEntropy(seed, i)), `hand BIP32 m/44'/128'/0'/0'/${i}' == xmrPocketEntropy`);
}
// hand Monero account + base58 + compare to moneroPocket
function moneroFromEntropy(entropy) {
  const spend = scReduce32(entropy);
  const view = scReduce32(keccak_256(spend));
  const spub = secretToPublic(spend);
  const vpub = secretToPublic(view);
  const bodyPt = Buffer.concat([Buffer.from([18]), Buffer.from(spub), Buffer.from(vpub)]);
  const full = Buffer.concat([bodyPt, Buffer.from(keccak_256(bodyPt).subarray(0, 4))]);
  return { spend, view, address: b58encode(full) };
}
for (let i = 0; i < 3; i += 1) {
  const p = moneroPocket(seed, i);
  const m = moneroFromEntropy(xmrPocketEntropy(seed, i));
  OK(hex(m.spend) === hex(p.spendSecret) && hex(m.view) === hex(p.viewSecret) && m.address === p.address, `hand-built wallet ${i} == moneroPocket`);
}

out('== area5: hex-string vs bytes ==');
out('  new Uint8Array("aabb") ->', hex(new Uint8Array('aabb')), '(not aabb)');
const hsString = hashToScalar('aabb');
const hsBytes = hashToScalar(unhex('aabb'));
out('  hashToScalar("aabb") =', hex(hsString), ' hashToScalar(bytes) =', hex(hsBytes));
OK(hex(hsString) === hex(hsBytes), 'hashToScalar(hexstring) matches bytes: ' + (hex(hsString) === hex(hsBytes)));
try { scReduce32('aa'.repeat(32)); out('  scReduce32(hexstring) ACCEPTED'); } catch { OK(true, 'scReduce32(hexstring) refused'); }
try { secretToPublic('aa'.repeat(32)); out('  secretToPublic(hexstring) ACCEPTED'); } catch { OK(true, 'secretToPublic(hexstring) refused'); }
// varint Number vs BigInt
OK(hex(varint(217407)) === hex(varint(217407n)), 'varint number == bigint');

out('== area3b: sweep Monero base58/address vectors externally ==');
{
  const rows = b58Rows.map((l) => l.trim().split(/\s+/)).filter((t) => t.length);
  let enc = 0, dec = 0, addr = 0, neg = 0, addrNeg = 0;
  const failEnc = [], failDec = [], failAddr = [], failNeg = [];
  for (const t of rows) {
    const cmd = t[0];
    const data = t.slice(1, -1).join('');
    const last = t.at(-1);
    if (cmd === 'encode' || cmd === 'encode_block') {
      try { if (b58encode(unhex(data)) === last) enc += 1; else failEnc.push(t.join(' ')); }
      catch { failEnc.push(t.join(' ')); }
    } else if (cmd === 'decode_pos') {
      const text = t[1] === '-' ? '' : t[1];
      const want = t.slice(2).join('') === '-' ? '' : t.slice(2).join('');
      try { if (hex(b58decode(text)) === want) dec += 1; else failDec.push(t.join(' ')); }
      catch { failDec.push(t.join(' ')); }
    } else if (cmd === 'addr') {
      try {
        const got = encodeAddr(BigInt(t[1]), unhex(t.slice(2, -1).join('')));
        if (got === last) addr += 1; else failAddr.push(t.join(' '));
      } catch { failAddr.push(t.join(' ')); }
    }
  }
  OK(failEnc.length === 0 && enc > 0, `encode/encode_block vectors pass: ${enc}, fail ${failEnc.length}`);
  OK(failDec.length === 0 && dec > 0, `decode_pos vectors pass: ${dec}, fail ${failDec.length}`);
  OK(failAddr.length === 0 && addr > 0, `addr vectors pass: ${addr}, fail ${failAddr.length}`);
  // addr_neg: every address Monero refuses, we refuse too.
  for (const t of rows) {
    if (t[0] !== 'addr_neg') continue;
    addrNeg += 1;
    try { decodeAddr(t[1]); failNeg.push(t.join(' ')); } catch { /* refused */ }
  }
  OK(addrNeg > 0 && failNeg.length === 0, `addr_neg vectors refused: ${addrNeg}, fail ${failNeg.length}`);
}

out('== area1c: zero secret divergence from Monero (sc_check accepts 0) ==');
{
  const zero = new Uint8Array(32);
  try { secretToPublic(zero); out('  FAIL our secretToPublic(0) accepted'); }
  catch { out('  note: Monero sc_check(0)=true -> identity 0x01||0..; ours throws'); }
  OK(hex(scReduce32(le(GROUP_ORDER))) === hex(zero), 'scReduce32(l)=0, so entropy==l yields a zero secret');
}

out('== area5b: src/address.js (btc) refusals ==');
{
  const { decodeAddress } = await import('../../src/address.js');
  OK(decodeAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').program.length === 20, 'BIP173 v0 vector decodes');
  try { decodeAddress('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'); OK(true, 'all-upper accepted'); } catch { out('  note: all-upper refused'); }
  try { decodeAddress('bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'); out('  FAIL mixed case accepted'); } catch { OK(true, 'mixed case refused'); }
  try { decodeAddress('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 'bc'); out('  FAIL wrong network accepted'); } catch { OK(true, 'wrong network refused'); }
}

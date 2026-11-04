import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { parseBlock, readTransaction, transactionIdOf } from '/home/aegis/cipher-wallet/src/monero/block.js';
import { transactionPublicKey } from '/home/aegis/cipher-wallet/src/monero/scan.js';
import { ownOutputsInBlock } from '/home/aegis/cipher-wallet/src/monero/ownOutputs.js';
import { moneroPocket } from '/home/aegis/cipher-wallet/src/monero/pocket.js';
import { rootFromMnemonic } from '/home/aegis/cipher-wallet/src/root.js';
import { varint } from '/home/aegis/cipher-wallet/src/monero/keys.js';
const F=(n)=>JSON.parse(readFileSync('/home/aegis/cipher-wallet/test/fixtures/'+n,'utf8'));
const bx=(s)=>Uint8Array.from(Buffer.from(String(s).replace(/\s+/g,''),'hex'));
const HB=(a)=>hex.encode(a);
const K='11'.repeat(32);
const POCKET=moneroPocket(rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),0);
const blob=bx(F('monero-block-3796965.json').block.blob);
const TXS=F('monero-block-3796965-txs.json').txs.map(t=>bx(t.asHex));
const blk=parseBlock(blob);
// more adversarial extras
const more=[
 ['mm last byte of varint=0x80 mid:', '03 80 01 aa'.repeat(0)+'03 8001 '+'aa'.repeat(128)+' 01 '+K, 'ok'],
 ['mm lone 0x80 length (incomplete):', '03 80 01 '+K, 'throw'],
 ['non-shortest varint length 0x80 0x00:', '03 80 00 01 '+K, 'throw?'],
 ['mm len=1 =0x00 then pubkey:', '03 01 00 01 '+K, 'ok'],
 ['pubkey BEFORE mm, mm to exact end:', '01 '+K+' 03 02 00 00', 'ok'],
];
for(const [n,h,want] of more){ try{ const p=transactionPublicKey(bx(h)); console.log('case [%s] -> %s',n, HB(p)===K?'expected-key':HB(p).slice(0,8)); }catch(e){ console.log('case [%s] -> threw %s',n,e.message.slice(0,45)); } }

// item4: alt block, same txs, different miner (header nonce changed) -> same hash list
const alt=new Uint8Array(blob); alt[5]^=0x40; // flip a header byte
try{ const altBlk=parseBlock(alt);
  const out=ownOutputsInBlock({blockBytes:alt,txBytesList:TXS,pockets:[POCKET],expectHash:altBlk.id});
  console.log('item4 alt-block (same tx list, diff header) PASSED id=%s scanned=%d', altBlk.id.slice(0,12), out.transactionsScanned);
}catch(e){ console.log('item4 alt-block ->', e.message.slice(0,60)); }
// item4: no expectHash, self-consistent block + unrelated list count -> refused by count
try{ ownOutputsInBlock({blockBytes:blob,txBytesList:TXS.slice(0,10),pockets:[POCKET]}); console.log('item4 no-expect wrong count PASSED'); }
catch(e){ console.log('item4 no-expect wrong count ->', e.message.slice(0,50)); }

// Attack caveat 1: can the JOIN's positive value branch ever be exercised?
import { readFileSync } from 'node:fs';
import { hex } from '@scure/base';
import { parseBlock, readTransaction, transactionIdOf } from '/home/aegis/cipher-wallet/src/monero/block.js';
import { ownOutputsInBlock } from '/home/aegis/cipher-wallet/src/monero/ownOutputs.js';
import { moneroPocket } from '/home/aegis/cipher-wallet/src/monero/pocket.js';
import { rootFromMnemonic } from '/home/aegis/cipher-wallet/src/root.js';
import { varint, keyDerivation, derivePublicKey, decodePoint } from '/home/aegis/cipher-wallet/src/monero/keys.js';
import { derivationToScalar, commitmentMask, commitmentOf, encodeAmountForTest } from '/home/aegis/cipher-wallet/src/monero/ringct.js';

const F=(n)=>JSON.parse(readFileSync('/home/aegis/cipher-wallet/test/fixtures/'+n,'utf8'));
const bx=(s)=>Uint8Array.from(Buffer.from(String(s).replace(/\s+/g,''),'hex'));
const HB=(a)=>hex.encode(a);
const POCKET=moneroPocket(rootFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),0);
const txPubBytes=bx('58666666666666666666666666666666 66666666666666666666666666666666'); // G
const deriv=keyDerivation(txPubBytes,POCKET.viewSecret);
const outKey=derivePublicKey(deriv,0,POCKET.spend);
const shared=derivationToScalar(deriv,0);
const mask=commitmentMask(shared);
const ecdh=encodeAmountForTest({derivation:deriv,index:0,value:424242n,rctType:5});
const commit=commitmentOf({amount:424242n,mask});
const parts=[];
parts.push(varint(2n),varint(0n));
parts.push(varint(1n),Uint8Array.of(0x02),varint(0n),varint(1n),varint(0n),new Uint8Array(32).fill(9)); // key input ring1
parts.push(varint(1n)); // 1 output
parts.push(varint(0n),Uint8Array.of(0x02),outKey); // amount0, tag key, key
const extra=Uint8Array.from([0x01,...txPubBytes]);
function Graw(){return bx('58666666666666666666666666666666 66666666666666666666666666666666')}
parts.push(varint(BigInt(extra.length)),extra);
parts.push(varint(5n),varint(0n)); // rct type 5, fee
parts.push(ecdh,commit);
parts.push(varint(1n)); // bpCount=1
parts.push(new Uint8Array(32*6)); // A S T1 T2 taux mu
parts.push(varint(6n),new Uint8Array(32*6)); // L count 6, L
parts.push(varint(6n),new Uint8Array(32*6)); // R
parts.push(new Uint8Array(32*3)); // a b t
parts.push(new Uint8Array(32),new Uint8Array(32),new Uint8Array(32)); // CLSAG ring1 scalar,c1,D
parts.push(new Uint8Array(32)); // pseudoOut
const total=parts.reduce((n,p)=>n+p.length,0); const txBytes=new Uint8Array(total); let at=0; for(const p of parts){txBytes.set(p,at);at+=p.length;}
const tx=readTransaction(txBytes,0,'synth');
console.log('synth tx: outputs=%d rctType=%d end=%d/%d ecdh=%s commit=%s',tx.outputs.length,tx.rctType,tx.end,txBytes.length,HB(tx.outputs[0].ecdh),HB(tx.outputs[0].commitment).slice(0,12));
const bc=bx(F('monero-block-mainnet-c.json').block.blob);
const minerEnd=parseBlock(bc).minerTx.end;
const body=bc.slice(0,minerEnd);
const h=hex.decode(transactionIdOf(tx));
const blkBytes=(()=>{const c=varint(1n);const o=new Uint8Array(body.length+c.length+32);o.set(body,0);o.set(c,body.length);o.set(h,body.length+c.length);return o;})();
const blk2=parseBlock(blkBytes);
try{
  const out=ownOutputsInBlock({blockBytes:blkBytes,txBytesList:[txBytes],pockets:[POCKET],expectHash:blk2.id});
  console.log('JOIN RESULT:',JSON.stringify(out.outputs,(k,v)=>typeof v==='bigint'?String(v)+'n':v));
  console.log('value=',out.outputs[0]&&out.outputs[0].value,' maskSet=',!!(out.outputs[0]&&out.outputs[0].mask));
}catch(e){console.log('JOIN THREW',e.message);}

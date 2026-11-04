import assert from 'node:assert/strict';
import { sealVault, openVault, isDamagedVault, MIN_EXISTING_PIN_LENGTH } from '../../src/vault.js';
const pin='12345678';
const secret=new TextEncoder().encode('root');
console.log('== vault: a lower iteration count is unusable ==');
for (const iter of [600000, 599999, 100000, 1]) {
  const env = await sealVault(secret, pin, { iterations: iter });
  let r; try { r = new TextDecoder().decode(await openVault(env, pin)); } catch(e){ r = 'REFUSED '+e.code; }
  console.log('  seal iter', iter, '-> damaged?', isDamagedVault(env), '-> open:', r);
}
console.log('\n== vault: device errors are not wrong-pin ==');
// openVault with pin exactly MIN_EXISTING_PIN_LENGTH but wrong
{
  const env = await sealVault(secret, pin);
  let e; try { await openVault(env, '000000'); } catch(x){ e=x; }
  console.log('  6-digit wrong pin ->', e.code);
  let e2; try { await openVault(env, 12345678); } catch(x){ e2=x; } // number pin
  console.log('  number pin ->', e2.code, '(isPlausiblePin requires string)');
}

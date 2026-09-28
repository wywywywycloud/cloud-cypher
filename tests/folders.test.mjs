import test from 'node:test';
import assert from 'node:assert/strict';
import {createVault, generateRecoveryCode, encryptFolder, decryptFolder} from '../web/crypto.js';

test('folder names encrypt with vault and folder identity binding', async () => {
  const {vault, key} = await createVault(generateRecoveryCode());
  const id = crypto.randomUUID();
  const metadata = await encryptFolder(key, vault.id, id, 'Документы');
  const record = {id, vault_id:vault.id, metadata};
  assert.equal((await decryptFolder(key,vault.id,record)).name, 'Документы');
  assert.equal(JSON.stringify(metadata).includes('Документы'),false);
  await assert.rejects(decryptFolder(key,vault.id,{...record,id:crypto.randomUUID()}));
  await assert.rejects(decryptFolder(key,crypto.randomUUID(),record));
  await assert.rejects(encryptFolder(key,vault.id,id,'../bad'));
  await assert.rejects(encryptFolder(key,vault.id,id,''));
});

// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  CypherError, MAX_METADATA_BYTES, MAX_PLAINTEXT_BYTES, TAG_BYTES,
  assertUuid, createVault, decodeBase64Url, decryptFile, decryptMetadata,
  encodeBase64Url, encryptFile, generateRecoveryCode, parseRecoveryCode,
  rewrapVault, unlockVault, validateEnvelope, validateFileRecord, validateVault,
} from '../web/crypto.js';

if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });

const VAULT_ID = '2aa03e24-471c-4e59-8e32-71eeb48e0a2c';
const OTHER_VAULT_ID = 'fc0326e3-0545-47c4-ac4c-7c7dbb1c3a1d';
const FILE_ID = 'f51581f6-5ef1-4cb0-bc43-29e7f9b915d5';
const OTHER_FILE_ID = 'c17fd1c7-4674-494b-ac18-3eb47974c458';
const utf8 = text => new TextEncoder().encode(text);

async function fixture(content = utf8('Тестовые данные \u0000 🐈')) {
  const secret = generateRecoveryCode();
  const { vault, key } = await createVault(secret, VAULT_ID);
  const file = await encryptFile(key, vault.id, { name: 'Документ 🐈.txt', type: 'text/plain', bytes: content }, FILE_ID);
  return { secret, vault, key, file, content };
}

function changedEnvelope(envelope, index = 0) {
  const raw = decodeBase64Url(envelope.ct);
  raw[index] ^= 1;
  return { ...envelope, ct: encodeBase64Url(raw) };
}

async function metadataEnvelope(key, vaultId, fileId, metadata) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const input = metadata instanceof Uint8Array ? metadata : utf8(JSON.stringify(metadata));
  const ciphertext = await crypto.subtle.encrypt({
    name: 'AES-GCM', iv, tagLength: 128,
    additionalData: utf8(`cloud-cypher:metadata:v1:${vaultId}:${fileId}`),
  }, key, input);
  return { v: 1, iv: encodeBase64Url(iv), ct: encodeBase64Url(ciphertext) };
}

test('vault keys round-trip through a separate 256-bit wrapping secret on a new device', async () => {
  const { secret, vault, key, file, content } = await fixture();
  assert.equal(secret.length, 47);
  assert.equal(parseRecoveryCode(secret).byteLength, 32);
  assert.equal(vault.wrapped_key.v, 1);
  assert.equal(decodeBase64Url(vault.wrapped_key.iv).length, 12);
  assert.equal(decodeBase64Url(vault.wrapped_key.ct).length, 48);
  assert.equal(key.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', key));
  const newDeviceKey = await unlockVault(JSON.parse(JSON.stringify(vault)), secret);
  const restored = await decryptFile(newDeviceKey, vault.id, JSON.parse(JSON.stringify(file)), file.ciphertext);
  assert.deepEqual(restored.bytes, content);
  assert.equal(restored.name, 'Документ 🐈.txt');
  assert.equal(restored.type, 'text/plain');
  assert.equal(restored.size, content.length);
});

test('empty and Unicode files retain their exact bytes and authenticated metadata', async () => {
  const { vault, key } = await fixture();
  for (const content of [new Uint8Array(), utf8('مرحبا · 日本語 · Ёжик · 🧑🏽‍💻\r\n\u0000')]) {
    const name = 'Фото & «<b>» 🦦.txt';
    const encrypted = await encryptFile(key, vault.id, { name, type: '', bytes: content });
    assert.equal(encrypted.ciphertext.length, content.length + TAG_BYTES);
    const result = await decryptFile(key, vault.id, encrypted, encrypted.ciphertext);
    assert.equal(result.name, name);
    assert.equal(result.type, 'application/octet-stream');
    assert.deepEqual(result.bytes, content);
  }
});

test('each encryption uses a distinct key, content nonce and metadata nonce', async () => {
  const { vault, key, content } = await fixture();
  const first = await encryptFile(key, vault.id, { name: 'same.txt', type: 'text/plain', bytes: content }, FILE_ID);
  const second = await encryptFile(key, vault.id, { name: 'same.txt', type: 'text/plain', bytes: content }, FILE_ID);
  const a = await decryptMetadata(key, vault.id, first);
  const b = await decryptMetadata(key, vault.id, second);
  assert.notEqual(a.key, b.key);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(first.metadata.iv, second.metadata.iv);
  assert.notDeepEqual(first.ciphertext, second.ciphertext);
});

test('incorrect wrapping secret, altered wrapped key and changed vault ID are rejected', async () => {
  const { vault, secret } = await fixture();
  await assert.rejects(unlockVault(vault, generateRecoveryCode()), { code: 'AUTH_FAILED' });
  await assert.rejects(unlockVault({ ...vault, wrapped_key: changedEnvelope(vault.wrapped_key) }, secret), { code: 'AUTH_FAILED' });
  await assert.rejects(unlockVault({ ...vault, id: OTHER_VAULT_ID }, secret), { code: 'AUTH_FAILED' });
});

test('changing a password wrapper preserves all existing file keys', async () => {
  const { secret, vault, key, file, content } = await fixture();
  const nextSecret = generateRecoveryCode();
  const wrapped = await rewrapVault(vault, secret, nextSecret);
  assert.notEqual(wrapped.iv, vault.wrapped_key.iv);
  assert.notEqual(wrapped.ct, vault.wrapped_key.ct);
  const updatedVault = { ...vault, wrapped_key: wrapped };
  const restoredKey = await unlockVault(updatedVault, nextSecret);
  assert.deepEqual((await decryptFile(restoredKey, vault.id, file, file.ciphertext)).bytes, content);
  const newFile = await encryptFile(restoredKey, vault.id, { name: 'new.bin', type: '', bytes: content });
  assert.deepEqual((await decryptFile(key, vault.id, newFile, newFile.ciphertext)).bytes, content);
  await assert.rejects(unlockVault(updatedVault, secret), { code: 'AUTH_FAILED' });
  await assert.rejects(rewrapVault(vault, nextSecret, secret), { code: 'AUTH_FAILED' });
  // Old wrapping records still open with the old secret; password changes are not retroactive revocation.
  assert.equal((await unlockVault(vault, secret)).extractable, false);
});

test('ciphertext alterations, tag alterations, reordering, truncation and extension fail closed', async () => {
  const input = Uint8Array.from({ length: 128 }, (_, index) => index);
  const { vault, key, file } = await fixture(input);
  const modified = file.ciphertext.slice();
  modified[0] ^= 1;
  const tagChanged = file.ciphertext.slice();
  tagChanged[tagChanged.length - 1] ^= 1;
  const reordered = file.ciphertext.slice();
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  for (const invalid of [modified, tagChanged, reordered, file.ciphertext.subarray(0, -1), new Uint8Array(file.ciphertext.length + 1)]) {
    await assert.rejects(decryptFile(key, vault.id, file, invalid), CypherError);
  }
});

test('a file from another vault cannot be substituted', async () => {
  const { vault, key, file } = await fixture();
  const other = await createVault(generateRecoveryCode(), OTHER_VAULT_ID);
  await assert.rejects(decryptFile(other.key, other.vault.id, file, file.ciphertext), CypherError);
  await assert.rejects(decryptFile(key, vault.id, { ...file, vault_id: OTHER_VAULT_ID }, file.ciphertext), CypherError);
  await assert.rejects(decryptFile(other.key, other.vault.id, { ...file, vault_id: other.vault.id }, file.ciphertext), { code: 'AUTH_FAILED' });
});

test('metadata authentication binds the vault ID and file ID', async () => {
  const { vault, key, file } = await fixture();
  await assert.rejects(decryptMetadata(key, vault.id, { ...file, id: OTHER_FILE_ID }), { code: 'AUTH_FAILED' });
  await assert.rejects(decryptMetadata(key, OTHER_VAULT_ID, { ...file, vault_id: OTHER_VAULT_ID }), { code: 'AUTH_FAILED' });
  await assert.rejects(decryptMetadata(key, vault.id, { ...file, metadata: changedEnvelope(file.metadata) }), { code: 'AUTH_FAILED' });
});

test('file ciphertext has its own vault and file ID binding, independent from metadata', async () => {
  const { vault, key, file } = await fixture();
  const metadata = await decryptMetadata(key, vault.id, file);
  const rebound = { ...file, id: OTHER_FILE_ID, metadata: await metadataEnvelope(key, vault.id, OTHER_FILE_ID, metadata) };
  await assert.rejects(decryptFile(key, vault.id, rebound, file.ciphertext), { code: 'AUTH_FAILED' });
  const moved = { ...file, vault_id: OTHER_VAULT_ID, metadata: await metadataEnvelope(key, OTHER_VAULT_ID, file.id, metadata) };
  await assert.rejects(decryptFile(key, OTHER_VAULT_ID, moved, file.ciphertext), { code: 'AUTH_FAILED' });
});

test('canonical unpadded base64url is strictly validated', () => {
  const original = Uint8Array.from([0, 1, 127, 128, 254, 255]);
  assert.deepEqual(decodeBase64Url(encodeBase64Url(original), { length: 6 }), original);
  for (const invalid of ['AA==', 'AA ', 'A', '+w', '/w', 'AB', 123, null, '_'.repeat(20000)]) {
    assert.throws(() => decodeBase64Url(invalid), CypherError);
  }
  assert.throws(() => decodeBase64Url('AA', { length: 2 }), CypherError);
  assert.throws(() => decodeBase64Url('', { min: 1 }), CypherError);
  assert.deepEqual(decodeBase64Url(''), new Uint8Array());
});

test('internal wrapping secrets reject malformed, short and non-canonical encodings', () => {
  const valid = generateRecoveryCode();
  for (const invalid of ['', valid + '=', ' ' + valid, valid.slice(0, -1), valid.toUpperCase(), 'cc2-' + valid.slice(4), valid.replace('cc1-', 'cc1- ')]) {
    assert.throws(() => parseRecoveryCode(invalid), CypherError);
  }
});

test('only canonical lowercase UUIDv4 and protocol version 1 are supported', async () => {
  assert.equal(assertUuid(VAULT_ID), VAULT_ID);
  for (const invalid of [VAULT_ID.toUpperCase(), ' ' + VAULT_ID, '../' + VAULT_ID, VAULT_ID.replace('-4e59-', '-3e59-'), VAULT_ID.replace('-8e32-', '-7e32-'), '00000000-0000-0000-0000-000000000000']) {
    assert.throws(() => assertUuid(invalid), CypherError);
  }
  const { vault, key, file, secret } = await fixture();
  for (const invalid of [0, 2, '1', null, true]) {
    assert.throws(() => validateVault({ ...vault, version: invalid }), CypherError);
    await assert.rejects(unlockVault({ ...vault, wrapped_key: { ...vault.wrapped_key, v: invalid } }, secret), CypherError);
    await assert.rejects(decryptFile(key, vault.id, { ...file, metadata: { ...file.metadata, v: invalid } }, file.ciphertext), CypherError);
  }
});

test('envelopes have an exact schema, 96-bit IV and bounded ciphertext', async () => {
  const { vault } = await fixture();
  const envelope = vault.wrapped_key;
  for (const invalid of [null, [], { ...envelope, extra: 1 }, { v: 1, iv: envelope.iv }, { ...envelope, iv: encodeBase64Url(new Uint8Array(11)) }, { ...envelope, ct: encodeBase64Url(new Uint8Array(15)) }, { ...envelope, ct: encodeBase64Url(new Uint8Array(MAX_METADATA_BYTES + 1)) }]) {
    assert.throws(() => validateEnvelope(invalid), CypherError);
  }
  assert.throws(() => validateVault({ ...vault, extra: true }), CypherError);
  assert.throws(() => validateVault({ ...vault, wrapped_key: { ...envelope, ct: encodeBase64Url(new Uint8Array(47)) } }), CypherError);
});

test('authenticated metadata is still treated as untrusted structured input', async () => {
  const { vault, key, file } = await fixture();
  const metadata = await decryptMetadata(key, vault.id, file);
  const bad = [
    { ...metadata, size: -1 }, { ...metadata, size: 1.5 }, { ...metadata, size: MAX_PLAINTEXT_BYTES + 1 },
    { ...metadata, size: metadata.size + 1 }, { ...metadata, size: String(metadata.size) },
    { ...metadata, type: 'text/html\r\nX-Foo: bar' }, { ...metadata, type: 'IMAGE/PNG' },
    { ...metadata, name: '../escape.txt' }, { ...metadata, name: 'a\\b.txt' }, { ...metadata, name: '\u0000' },
    { ...metadata, name: '' }, { ...metadata, name: '..' }, { ...metadata, name: 'ю'.repeat(513) },
    { ...metadata, key: encodeBase64Url(new Uint8Array(31)) }, { ...metadata, iv: encodeBase64Url(new Uint8Array(13)) },
    { ...metadata, extra: 'ignored?' }, null, [], utf8('{oops'), new Uint8Array([0xff, 0xfe]),
  ];
  for (const value of bad) {
    const envelope = await metadataEnvelope(key, vault.id, file.id, value);
    await assert.rejects(decryptMetadata(key, vault.id, { ...file, metadata: envelope }), CypherError);
  }
});

test('declared size limits are enforced before decryption or encryption', async () => {
  const { vault, key, file } = await fixture();
  for (const size of [0, 15, -1, 16.5, '16', MAX_PLAINTEXT_BYTES + 17, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => validateFileRecord({ ...file, ciphertext_bytes: size }, vault.id), CypherError);
  }
  await assert.rejects(encryptFile(key, vault.id, { name: 'oversize.bin', type: '', bytes: new Uint8Array(MAX_PLAINTEXT_BYTES + 1) }), { code: 'FILE_SIZE' });
  await assert.rejects(encryptFile(key, vault.id, { name: 'bad.bin', type: '', bytes: 'not bytes' }), CypherError);
});

test('multi-megabyte file round-trip works without a custom streaming format', async () => {
  const input = new Uint8Array(2 * 1024 * 1024 + 37);
  for (let offset = 0; offset < input.length; offset += 65536) crypto.getRandomValues(input.subarray(offset, offset + 65536));
  const { vault, key, file } = await fixture(input);
  assert.deepEqual((await decryptFile(key, vault.id, file, file.ciphertext)).bytes, input);
});

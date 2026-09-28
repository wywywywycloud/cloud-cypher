// SPDX-License-Identifier: Apache-2.0
// cloud-cypher v1 uses the platform's Web Crypto implementation only.

export const VERSION = 1;
export const MAX_PLAINTEXT_BYTES = 50 * 1024 * 1024;
export const TAG_BYTES = 16;
export const MAX_METADATA_BYTES = 8192;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MIME = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

export class CypherError extends Error {
  constructor(message, code = 'INVALID_DATA') {
    super(message);
    this.name = 'CypherError';
    this.code = code;
  }
}

function webCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new CypherError('Для шифрования откройте сайт по HTTPS или на localhost.', 'UNAVAILABLE');
  }
  return globalThis.crypto;
}

function bytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new CypherError('Ожидались двоичные данные.');
}

function exactObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Object.keys(value).length !== keys.length
      || !keys.every(key => Object.hasOwn(value, key))) {
    throw new CypherError('Неверный формат зашифрованных данных.');
  }
}

export function assertUuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw new CypherError('Неверный идентификатор хранилища или файла.');
  }
  return value;
}

export function encodeBase64Url(value) {
  const input = bytes(value);
  let binary = '';
  for (let offset = 0; offset < input.length; offset += 8192) {
    binary += String.fromCharCode(...input.subarray(offset, offset + 8192));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decodeBase64Url(value, { length, min = 0, max = MAX_METADATA_BYTES } = {}) {
  const limit = length ?? max;
  if (typeof value !== 'string' || value.length > Math.ceil(limit * 4 / 3)
      || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new CypherError('Неверная кодировка зашифрованных данных.');
  }
  let result;
  try {
    const padded = value.replaceAll('-', '+').replaceAll('_', '/');
    result = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  } catch {
    throw new CypherError('Неверная кодировка зашифрованных данных.');
  }
  if (result.length < min || result.length > limit
      || (length !== undefined && result.length !== length)
      || encodeBase64Url(result) !== value) {
    throw new CypherError('Неверная длина или кодировка зашифрованных данных.');
  }
  return result;
}

function randomBytes(size) {
  return webCrypto().getRandomValues(new Uint8Array(size));
}

function aad(kind, vaultId, fileId) {
  assertUuid(vaultId);
  if (fileId !== undefined) assertUuid(fileId);
  return encoder.encode(`cloud-cypher:${kind}:v1:${vaultId}${fileId === undefined ? '' : `:${fileId}`}`);
}

async function importKey(raw) {
  return webCrypto().subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function seal(key, input, iv, additionalData) {
  return new Uint8Array(await webCrypto().subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData, tagLength: 128 }, key, input,
  ));
}

async function open(key, ciphertext, iv, additionalData) {
  try {
    return new Uint8Array(await webCrypto().subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData, tagLength: 128 }, key, ciphertext,
    ));
  } catch {
    throw new CypherError('Не удалось расшифровать данные: ключ не подходит или файл повреждён.', 'AUTH_FAILED');
  }
}

export function validateEnvelope(value, { length, min = TAG_BYTES, max = MAX_METADATA_BYTES } = {}) {
  exactObject(value, ['v', 'iv', 'ct']);
  if (value.v !== VERSION) throw new CypherError('Эта версия формата не поддерживается.', 'VERSION');
  return {
    iv: decodeBase64Url(value.iv, { length: 12 }),
    ciphertext: decodeBase64Url(value.ct, { length, min, max }),
  };
}

export function validateVault(vault) {
  exactObject(vault, ['id', 'version', 'wrapped_key']);
  assertUuid(vault.id);
  if (vault.version !== VERSION) throw new CypherError('Эта версия хранилища не поддерживается.', 'VERSION');
  validateEnvelope(vault.wrapped_key, { length: 48 });
  return vault;
}

export function generateRecoveryCode() {
  const key = randomBytes(32);
  try {
    return `cc1-${encodeBase64Url(key)}`;
  } finally {
    key.fill(0);
  }
}

export function parseRecoveryCode(code) {
  if (typeof code !== 'string' || !/^cc1-[A-Za-z0-9_-]{43}$/.test(code)) {
    throw new CypherError('Не удалось получить ключ шифрования. Войдите повторно.', 'WRAPPING_SECRET');
  }
  return decodeBase64Url(code.slice(4), { length: 32 });
}

export async function createVault(recoveryCode, vaultId = webCrypto().randomUUID()) {
  assertUuid(vaultId);
  const recoveryBytes = parseRecoveryCode(recoveryCode);
  const vaultBytes = randomBytes(32);
  try {
    const recoveryKey = await importKey(recoveryBytes);
    const iv = randomBytes(12);
    const ciphertext = await seal(recoveryKey, vaultBytes, iv, aad('vault', vaultId));
    return {
      vault: { id: vaultId, version: VERSION, wrapped_key: { v: VERSION, iv: encodeBase64Url(iv), ct: encodeBase64Url(ciphertext) } },
      key: await importKey(vaultBytes),
    };
  } finally {
    recoveryBytes.fill(0);
    vaultBytes.fill(0);
  }
}

export async function unlockVault(vault, recoveryCode) {
  validateVault(vault);
  const recoveryBytes = parseRecoveryCode(recoveryCode);
  let vaultBytes;
  try {
    const recoveryKey = await importKey(recoveryBytes);
    const { iv, ciphertext } = validateEnvelope(vault.wrapped_key, { length: 48 });
    vaultBytes = await open(recoveryKey, ciphertext, iv, aad('vault', vault.id));
    if (vaultBytes.length !== 32) throw new CypherError('Неверная длина ключа хранилища.');
    return await importKey(vaultBytes);
  } finally {
    recoveryBytes.fill(0);
    vaultBytes?.fill(0);
  }
}

export async function rewrapVault(vault, oldWrappingSecret, newWrappingSecret) {
  validateVault(vault);
  const oldBytes = parseRecoveryCode(oldWrappingSecret);
  let newBytes;
  let vaultBytes;
  try {
    newBytes = parseRecoveryCode(newWrappingSecret);
    const envelope = validateEnvelope(vault.wrapped_key, { length: 48 });
    vaultBytes = await open(await importKey(oldBytes), envelope.ciphertext, envelope.iv, aad('vault', vault.id));
    if (vaultBytes.length !== 32) throw new CypherError('Неверная длина ключа хранилища.');
    const iv = randomBytes(12);
    const ciphertext = await seal(await importKey(newBytes), vaultBytes, iv, aad('vault', vault.id));
    return { v: VERSION, iv: encodeBase64Url(iv), ct: encodeBase64Url(ciphertext) };
  } finally {
    oldBytes.fill(0);
    newBytes?.fill(0);
    vaultBytes?.fill(0);
  }
}

function validateFileInfo({ name, type, size }) {
  if (typeof name !== 'string' || name.length === 0 || encoder.encode(name).length > 1024
      || /[\u0000-\u001f\u007f/\\]/.test(name) || name === '.' || name === '..') {
    throw new CypherError('Имя файла пустое, слишком длинное или содержит недопустимые символы.');
  }
  if (typeof type !== 'string' || type.length > 127 || !MIME.test(type)) {
    throw new CypherError('Неверный тип файла.');
  }
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_PLAINTEXT_BYTES) {
    throw new CypherError('Размер одного файла не должен превышать 50 МиБ.', 'FILE_SIZE');
  }
}

export function validateFileRecord(record, vaultId) {
  assertUuid(vaultId);
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new CypherError('Неверный формат записи файла.');
  }
  assertUuid(record.id);
  if (record.vault_id !== vaultId) throw new CypherError('Файл относится к другому хранилищу.');
  if (!Number.isSafeInteger(record.ciphertext_bytes)
      || record.ciphertext_bytes < TAG_BYTES || record.ciphertext_bytes > MAX_PLAINTEXT_BYTES + TAG_BYTES) {
    throw new CypherError('Неверный размер зашифрованного файла.');
  }
  validateEnvelope(record.metadata);
  return record;
}

export async function encryptFile(vaultKey, vaultId, file, fileId = webCrypto().randomUUID()) {
  assertUuid(vaultId);
  assertUuid(fileId);
  const input = bytes(file.bytes);
  const name = file.name;
  const type = file.type || 'application/octet-stream';
  validateFileInfo({ name, type, size: input.byteLength });
  const fileBytes = randomBytes(32);
  let metadataBytes;
  try {
    const fileKey = await importKey(fileBytes);
    const iv = randomBytes(12);
    const ciphertext = await seal(fileKey, input, iv, aad('file', vaultId, fileId));
    metadataBytes = encoder.encode(JSON.stringify({ name, type, size: input.byteLength, key: encodeBase64Url(fileBytes), iv: encodeBase64Url(iv) }));
    const metadataIv = randomBytes(12);
    const metadataCiphertext = await seal(vaultKey, metadataBytes, metadataIv, aad('metadata', vaultId, fileId));
    return {
      id: fileId,
      vault_id: vaultId,
      metadata: { v: VERSION, iv: encodeBase64Url(metadataIv), ct: encodeBase64Url(metadataCiphertext) },
      ciphertext_bytes: ciphertext.byteLength,
      ciphertext,
    };
  } finally {
    fileBytes.fill(0);
    metadataBytes?.fill(0);
  }
}

export async function decryptMetadata(vaultKey, vaultId, record) {
  validateFileRecord(record, vaultId);
  const { iv, ciphertext } = validateEnvelope(record.metadata);
  const plaintext = await open(vaultKey, ciphertext, iv, aad('metadata', vaultId, record.id));
  try {
    let metadata;
    try {
      metadata = JSON.parse(decoder.decode(plaintext));
    } catch {
      throw new CypherError('Не удалось прочитать метаданные файла.');
    }
    exactObject(metadata, ['name', 'type', 'size', 'key', 'iv']);
    validateFileInfo(metadata);
    const rawKey = decodeBase64Url(metadata.key, { length: 32 });
    rawKey.fill(0);
    decodeBase64Url(metadata.iv, { length: 12 });
    if (metadata.size + TAG_BYTES !== record.ciphertext_bytes) {
      throw new CypherError('Размер файла не совпадает с зашифрованными метаданными.');
    }
    return metadata;
  } finally {
    plaintext.fill(0);
  }
}

export async function decryptFile(vaultKey, vaultId, record, ciphertext) {
  const input = bytes(ciphertext);
  validateFileRecord(record, vaultId);
  if (input.byteLength !== record.ciphertext_bytes) {
    throw new CypherError('Файл получен не полностью или имеет неверный размер.');
  }
  const metadata = await decryptMetadata(vaultKey, vaultId, record);
  const rawKey = decodeBase64Url(metadata.key, { length: 32 });
  try {
    const fileKey = await importKey(rawKey);
    const plaintext = await open(fileKey, input, decodeBase64Url(metadata.iv, { length: 12 }), aad('file', vaultId, record.id));
    return { name: metadata.name, type: metadata.type, size: metadata.size, bytes: plaintext };
  } finally {
    rawKey.fill(0);
  }
}

export async function encryptFolder(key, vaultId, id, name) {
  validateFileInfo({name, type: 'application/octet-stream', size: 0});
  const iv = randomBytes(12);
  const plaintext = encoder.encode(JSON.stringify({name}));
  try {
    const ct = await seal(key, plaintext, iv, aad('folder', vaultId, id));
    return {v: 1, iv: encodeBase64Url(iv), ct: encodeBase64Url(ct)};
  } finally { plaintext.fill(0); }
}

export async function decryptFolder(key, vaultId, record) {
  assertUuid(record.id);
  if (record.vault_id !== vaultId) throw new CypherError('Папка относится к другому хранилищу.');
  const envelope = validateEnvelope(record.metadata);
  const raw = await open(key, envelope.ciphertext, envelope.iv, aad('folder', vaultId, record.id));
  try {
    const info = JSON.parse(decoder.decode(raw));
    exactObject(info, ['name']);
    validateFileInfo({name: info.name, type: 'application/octet-stream', size: 0});
    return {...info, type: 'folder', size: 0};
  } catch { throw new CypherError('Не удалось проверить имя папки.'); }
  finally { raw.fill(0); }
}

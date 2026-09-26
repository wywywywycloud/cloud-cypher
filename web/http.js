// SPDX-License-Identifier: Apache-2.0
import {CypherError} from './crypto.js';

export async function authJson(response) {
  if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    await response.body?.cancel();
    throw new CypherError('Сервер вернул неожиданный ответ.');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new CypherError('Сервер вернул пустой ответ.');
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 65536) { await reader.cancel(); throw new CypherError('Ответ сервера слишком большой.'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)); }
  catch { throw new CypherError('Неверный формат ответа сервера.'); }
}

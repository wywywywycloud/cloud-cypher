// SPDX-License-Identifier: Apache-2.0
import qrcode from './vendor/qrcode.js';
import {CypherError} from './crypto.js';

export function totpUri(secret, username) {
  if (typeof secret !== 'string' || !/^[A-Z2-7]{32}$/.test(secret)
      || typeof username !== 'string' || !/^[a-z0-9_.-]{3,64}$/i.test(username)) {
    throw new CypherError('Не удалось подготовить QR-код. Повторите настройку TOTP.');
  }
  const params = new URLSearchParams({secret, issuer: 'cloud.nimbus', algorithm: 'SHA1', digits: '6', period: '30'});
  return `otpauth://totp/${encodeURIComponent(`cloud.nimbus:${username}`)}?${params}`;
}

export function clearTotpQr(canvas) {
  // Resizing clears the bitmap, including when the onboarding panel is hidden.
  canvas.width = 0;
  canvas.height = 0;
  canvas.hidden = true;
}

export function drawTotpQr(canvas, secret, username) {
  clearTotpQr(canvas);
  const qr = qrcode(0, 'M');
  qr.addData(totpUri(secret, username), 'Byte');
  qr.make();
  const count = qr.getModuleCount(), quiet = 4, scale = 5;
  canvas.width = canvas.height = (count + 2 * quiet) * scale;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new CypherError('QR-код недоступен. Используйте секрет для ручной настройки.');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) ctx.fillRect((col + quiet) * scale, (row + quiet) * scale, scale, scale);
    }
  }
  canvas.hidden = false;
}

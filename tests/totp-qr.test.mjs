// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {totpUri, drawTotpQr, clearTotpQr} from '../web/totp-qr.js';
const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

test('TOTP QR payload preserves secret, account, issuer and authenticator parameters', () => {
  const value = new URL(totpUri(secret, 'test.user'));
  assert.equal(value.protocol, 'otpauth:');
  assert.equal(value.hostname, 'totp');
  assert.equal(decodeURIComponent(value.pathname), '/cloud.nimbus:test.user');
  assert.deepEqual(Object.fromEntries(value.searchParams), {secret, issuer:'cloud.nimbus', algorithm:'SHA1', digits:'6', period:'30'});
  for (const bad of ['', 'invalid-secret', secret + '&issuer=other']) assert.throws(() => totpUri(bad, 'test.user'));
  assert.throws(() => totpUri(secret, 'user/other'));
});

test('QR uses white quiet zone and clears the bitmap when setup ends', () => {
  const pixels = [];
  const ctx = {fillStyle:'', fillRect(...coordinates) { pixels.push([this.fillStyle, ...coordinates]); }};
  const canvas = {getContext: () => ctx, hidden:true};
  drawTotpQr(canvas, secret, 'test.user');
  assert.equal(canvas.hidden, false);
  assert.equal(canvas.width, canvas.height);
  assert.deepEqual(pixels[0], ['#fff', 0, 0, canvas.width, canvas.height]);
  assert.ok(pixels.length > 100);
  for (const [color, x, y, w, h] of pixels.slice(1)) {
    assert.equal(color,'#000');
    assert.ok(x >= 20 && y >= 20 && x+w <= canvas.width-20 && y+h <= canvas.height-20);
  }
  clearTotpQr(canvas);
  assert.equal(canvas.width, 0);
  assert.equal(canvas.height, 0);
  assert.equal(canvas.hidden, true);
});

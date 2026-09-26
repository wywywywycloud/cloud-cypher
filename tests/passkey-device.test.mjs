// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {enrollPasskey, loginPasskey} from '../web/passkeys.js';

const options = {
  challenge: 'AQID', rp: {id: 'localhost'}, user: {id: 'BAUG', name: 'test'},
  authenticatorSelection: {authenticatorAttachment: 'platform', userVerification: 'discouraged'},
};
const credential = attachment => ({
  id: 'AQID', rawId: Uint8Array.of(1, 2, 3).buffer, authenticatorAttachment: attachment,
  response: {clientDataJSON: Uint8Array.of(4).buffer, attestationObject: Uint8Array.of(5).buffer},
});
function setup(t, publicKey) {
  t.mock.method(globalThis, 'fetch', async url => {
    const result = url.endsWith('/session/') ? {csrf_token: 'test'} :
      url.endsWith('/register/finish/') ? {id: 'AQID'} : {challenge: 'test', publicKey};
    return new Response(JSON.stringify(result), {headers: {'Content-Type': 'application/json'}});
  });
  for (const [name, value] of Object.entries({location: {hostname: 'localhost'}, PublicKeyCredential: function () {}})) {
    const before = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, {value, configurable: true});
    t.after(() => before ? Object.defineProperty(globalThis, name, before) : delete globalThis[name]);
  }
  const before = Object.getOwnPropertyDescriptor(navigator, 'credentials');
  const api = {};
  Object.defineProperty(navigator, 'credentials', {value: api, configurable: true});
  t.after(() => before ? Object.defineProperty(navigator, 'credentials', before) : delete navigator.credentials);
  return api;
}
test('enrollment requests external device and refuses a platform result before sending registration', async t => {
  const api = setup(t, options);
  let count = 0;
  api.create = async ({publicKey}) => {
    count++;
    assert.deepEqual(publicKey.hints, ['hybrid']);
    assert.equal(publicKey.authenticatorSelection.authenticatorAttachment, 'cross-platform');
    assert.equal(publicKey.authenticatorSelection.residentKey, 'required');
    assert.equal(publicKey.authenticatorSelection.userVerification, 'required');
    assert.equal(publicKey.extensions.prf.eval.first.byteLength, 32);
    return credential('platform');
  };
  await assert.rejects(enrollPasskey({}, 'unused'), /локальный passkey/);
  assert.equal(count, 1);
  assert.equal(fetch.mock.calls.some(call => call.arguments[0].endsWith('/register/finish/')), false);
});
test('activation routes the registered credential to external transports and keeps PRF required', async t => {
  const api = setup(t, options);
  const original = fetch;
  t.mock.method(globalThis, 'fetch', async (...args) => args[0].endsWith('/activate/start/') ?
    new Response(JSON.stringify({challenge: 'test', publicKey: {challenge: 'AQID', rpId: 'localhost',
      allowCredentials: [{id: 'AQID', type: 'public-key', transports: ['internal']}]}}), {headers: {'Content-Type': 'application/json'}}) : original(...args));
  api.create = async () => credential('cross-platform');
  api.get = async ({publicKey}) => {
    assert.deepEqual(publicKey.hints, ['hybrid']);
    assert.deepEqual(publicKey.allowCredentials[0].transports, ['hybrid', 'usb', 'nfc', 'ble']);
    assert.deepEqual([...publicKey.allowCredentials[0].id], [1, 2, 3]);
    assert.equal(publicKey.userVerification, 'required');
    return {...credential('cross-platform'), getClientExtensionResults: () => ({})};
  };
  await assert.rejects(enrollPasskey({}, 'unused'), /PRF/);
  assert.equal(fetch.mock.calls.some(call => call.arguments[0].endsWith('/activate/finish/')), false);
});
test('discoverable login requests phone and rejects platform results without posting login proof', async t => {
  const api = setup(t, {challenge: 'AQID', rpId: 'localhost'});
  api.get = async ({publicKey}) => {
    assert.deepEqual(publicKey.hints, ['hybrid']);
    assert.equal(publicKey.allowCredentials, undefined);
    return credential('platform');
  };
  await assert.rejects(loginPasskey(), /локальный passkey/);
  assert.equal(fetch.mock.calls.some(call => call.arguments[0].endsWith('/login/finish/')), false);
});
test('cancelling external device selection does not retry using a local device', async t => {
  const api = setup(t, options);
  let calls = 0;
  api.create = async () => { calls++; throw new DOMException('cancelled', 'NotAllowedError'); };
  await assert.rejects(enrollPasskey({}, 'unused'), /внешнем устройстве/);
  assert.equal(calls, 1);
});

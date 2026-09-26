// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {authJson} from '../web/http.js';
import {publicCredential} from '../web/passkeys.js';
import {CypherError, encodeBase64Url} from '../web/crypto.js';

const encoder = new TextEncoder();
const buffer = (...values) => Uint8Array.from(values).buffer;

test('WebAuthn request whitelist excludes PRF and extension secrets from assertions and attestations', () => {
  const prfSecret = new Uint8Array(32).fill(219).buffer;
  const secretMarker = encodeBase64Url(prfSecret);
  const base = {
    id: 'public-credential-id', rawId: buffer(1, 2, 3), type: 'public-key',
    clientExtensionResults: {prf: {results: {first: prfSecret}}},
    secretMarker,
    getClientExtensionResults() { throw new Error('Must not read PRF while serializing a request'); },
    toJSON() { throw new Error('Generic WebAuthn serialization may expose PRF'); },
  };
  const assertion = publicCredential({...base, response: {
    clientDataJSON: buffer(4, 5), authenticatorData: buffer(6, 7), signature: buffer(8, 9),
    userHandle: buffer(10), secretMarker, extensionResults: base.clientExtensionResults,
  }});
  assert.deepEqual(assertion, {
    id: 'public-credential-id', rawId: 'AQID', type: 'public-key',
    response: {clientDataJSON: 'BAU', authenticatorData: 'Bgc', signature: 'CAk', userHandle: 'Cg'},
  });
  const attestation = publicCredential({...base, response: {
    clientDataJSON: buffer(4, 5), attestationObject: buffer(11, 12), secretMarker,
  }});
  assert.deepEqual(attestation, {
    id: 'public-credential-id', rawId: 'AQID', type: 'public-key',
    response: {clientDataJSON: 'BAU', attestationObject: 'Cww'},
  });
  assert.equal(JSON.stringify([assertion, attestation]).includes(secretMarker), false);
  assert.equal(JSON.stringify([assertion, attestation]).includes('prf'), false);
  const noHandle = publicCredential({...base, response: {
    clientDataJSON: buffer(4), authenticatorData: buffer(6), signature: buffer(8), userHandle: null,
  }});
  assert.equal(noHandle.response.userHandle, null);
});

test('auth JSON accepts chunked UTF-8 and the exact 64 KiB boundary', async () => {
  const value = {username: 'пример', authenticated: true};
  const bytes = encoder.encode(JSON.stringify(value));
  const chunks = new ReadableStream({start(controller) {
    for (const byte of bytes) controller.enqueue(Uint8Array.of(byte));
    controller.close();
  }});
  assert.deepEqual(await authJson(new Response(chunks, {
    headers: {'Content-Type': 'application/json; charset=utf-8'},
  })), value);
  const boundary = '{}'.padEnd(65536, ' ');
  assert.deepEqual(await authJson(new Response(boundary, {headers: {'Content-Type': 'application/json'}})), {});
});

test('auth JSON caps actual streamed bytes and cancels regardless of advertised length', async () => {
  for (const contentLength of [undefined, '2']) {
    let cancelled = false;
    let pulls = 0;
    const stream = new ReadableStream({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array(pulls === 1 ? 65536 : 1).fill(32));
      },
      cancel() { cancelled = true; },
    });
    const headers = {'Content-Type': 'application/json'};
    if (contentLength !== undefined) headers['Content-Length'] = contentLength;
    await assert.rejects(authJson(new Response(stream, {headers})), CypherError);
    assert.equal(cancelled, true);
  }
});

test('auth JSON rejects wrong MIME, absent body, malformed JSON and invalid UTF-8', async () => {
  const wrongMime = new Response('<html>login</html>', {headers: {'Content-Type': 'text/html'}});
  await assert.rejects(authJson(wrongMime), CypherError);
  assert.equal(wrongMime.bodyUsed, true);
  for (const body of [null, '{', Uint8Array.of(0x22, 0xc0, 0xaf, 0x22)]) {
    await assert.rejects(authJson(new Response(body, {headers: {'Content-Type': 'application/json'}})), CypherError);
  }
});

// SPDX-License-Identifier: Apache-2.0
import {CypherError, decodeBase64Url, encodeBase64Url, rewrapVault, unlockVault} from './crypto.js';
import {authJson} from './http.js';

const encoder = new TextEncoder();

async function post(path, payload) {
  const session = await fetch('/api/cypher/session/', {credentials: 'same-origin', cache: 'no-store', redirect: 'error'});
  if (!session.ok) throw new CypherError('Сервер недоступен.');
  const {csrf_token} = await authJson(session);
  const response = await fetch(`/api/passkeys/${path}/`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf_token},
    body: JSON.stringify(payload),
  });
  const result = await authJson(response);
  if (!response.ok) {
    const messages = {
      credential_already_exists: 'Passkey уже подключён. Его замена возможна только со сбросом хранилища.',
      synced_passkey_required: 'Выбран ключ только для этого устройства. Выберите passkey на другом устройстве с поддержкой PRF и резервирования. Обычный несинхронизируемый USB-ключ не подойдёт.',
      passkey_backup_required: 'Менеджер ключей пока не подтвердил резервирование passkey. Проверьте его синхронизацию и повторите настройку.',
      recent_authentication_required: 'Подтвердите действие повторным входом.',
      rate_limited: 'Слишком много попыток. Повторите позднее.',
    };
    throw new CypherError(messages[result.error] || 'Passkey или код не подтверждён. Проверьте данные и повторите действие.');
  }
  return result;
}

async function options(value) {
  const result = {...value, challenge: decodeBase64Url(value.challenge)};
  // Prefer a phone over hybrid/QR, including for discoverable login. Hints
  // guide browser UI; they are not cryptographic proof of the transport.
  result.hints = ['hybrid'];
  const rpId = value.rp?.id || value.rpId;
  // Preserve existing credentials when the app moves to a subdomain of its RP.
  // WebAuthn additionally enforces registrable-domain/public-suffix constraints.
  if (typeof rpId !== 'string' || !rpId ||
      !(location.hostname === rpId || location.hostname.endsWith(`.${rpId}`))) {
    throw new CypherError('Домен passkey не совпадает с текущим сайтом.');
  }
  if (value.user) {
    result.authenticatorSelection = {...value.authenticatorSelection, authenticatorAttachment: 'cross-platform', userVerification: 'required', residentKey: 'required'};
  } else {
    result.userVerification = 'required';
  }
  if (value.user) result.user = {...value.user, id: decodeBase64Url(value.user.id)};
  for (const list of ['allowCredentials', 'excludeCredentials']) {
    if (value[list]) result[list] = value[list].map(item => ({...item, id: decodeBase64Url(item.id),
      ...(list === 'allowCredentials' ? {transports: ['hybrid', 'usb', 'nfc', 'ble']} : {})}));
  }
  // The browser uses a constant, published PRF input. It never accepts an
  // arbitrary server-provided input to the authenticator's PRF.
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode('cloud-cypher:passkey-prf:v1')));
  result.extensions = {prf: {eval: {first: salt}}};
  return result;
}

export function publicCredential(credential) {
  // Deliberately do NOT call credential.toJSON(): that can serialize the PRF
  // output, which is the secret protecting the vault, into a server request.
  const encode = value => encodeBase64Url(new Uint8Array(value));
  const response = {clientDataJSON: encode(credential.response.clientDataJSON)};
  if (credential.response.attestationObject) {
    response.attestationObject = encode(credential.response.attestationObject);
  } else {
    response.authenticatorData = encode(credential.response.authenticatorData);
    response.signature = encode(credential.response.signature);
    response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;
  }
  return {id: credential.id, rawId: encode(credential.rawId), type: 'public-key', response};
}

async function secret(credential) {
  const first = credential.getClientExtensionResults()?.prf?.results?.first;
  if (!first || first.byteLength !== 32) {
    throw new CypherError('Этот браузер или менеджер не поддерживает шифрование через passkey (PRF). Попробуйте совместимый менеджер; доступ к файлам остаётся закрыт.');
  }
  const raw = new Uint8Array(first);
  try {
    const key = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
    const derived = new Uint8Array(await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256',
      salt: encoder.encode('cloud-cypher:passkey-wrap:v1'), info: encoder.encode(credential.id)}, key, 256));
    try { return `cc1-${encodeBase64Url(derived)}`; } finally { derived.fill(0); }
  } finally { raw.fill(0); }
}

async function getCredential(kind, publicKey) {
  if (!globalThis.PublicKeyCredential || !navigator.credentials) {
    throw new CypherError('Этот браузер не поддерживает passkey.');
  }
  try {
    const credential = await navigator.credentials[kind]({publicKey: await options(publicKey)});
    if (!credential) throw new Error('cancelled');
    if (credential.authenticatorAttachment === 'platform') {
      throw new CypherError('Выбран локальный passkey. Выберите «Другое устройство» и подтвердите действие на телефоне, например через QR-код.');
    }
    return credential;
  } catch (error) {
    if (error instanceof CypherError) throw error;
    throw new CypherError('Passkey на внешнем устройстве не выбран или недоступен. Выберите «Другое устройство», отсканируйте QR-код телефоном и включите Bluetooth на обоих устройствах, если браузер попросит. Нужна поддержка PRF и резервирования.');
  }
}

export async function enrollPasskey(vault, wrappingSecret) {
  const registration = await post('register/start', {});
  const created = await getCredential('create', registration.publicKey);
  const stored = await post('register/finish', {challenge: registration.challenge, credential: publicCredential(created)});
  const activation = await post('activate/start', {credential_id: stored.id});
  const assertion = await getCredential('get', activation.publicKey);
  const prfSecret = await secret(assertion);
  const wrapped_key = await rewrapVault(vault, wrappingSecret, prfSecret);
  // Prove the stored wrapper can be opened locally before enabling uploads.
  await unlockVault({...vault, wrapped_key}, prfSecret);
  await post('activate/finish', {challenge: activation.challenge,
    credential: publicCredential(assertion), vault_id: vault.id, wrapped_key});
}

export async function loginPasskey(username = '') {
  const start = await post('login/start', username ? {username} : {});
  const credential = await getCredential('get', start.publicKey);
  const wrappingSecret = await secret(credential);
  const result = await post('login/finish', {challenge: start.challenge, credential: publicCredential(credential)});
  // Reject a swapped wrapper even if the server claims successful login.
  await unlockVault(result.vault, wrappingSecret);
  return {...result, wrappingSecret};
}


export const beginPasskeyReset = username => post('reset/start', {username});
export const finishPasskeyReset = (challenge, code, confirmation) => post('reset/finish', {challenge, code, confirmation});

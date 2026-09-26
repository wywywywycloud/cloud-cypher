// SPDX-License-Identifier: Apache-2.0
import * as opaque from './vendor/opaque.js';
import {CypherError, decodeBase64Url, encodeBase64Url, rewrapVault} from './crypto.js';
import {authJson} from './http.js';

const encoder = new TextEncoder();
const serverIdentifier = 'cloud-cypher-v1';
let codePrompt = null;
export function setCodePrompt(callback) { codePrompt = callback; }

function canonicalUsername(value) {
  const username = String(value).trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_.-]{2,63}$/.test(username)) {
    throw new CypherError('Логин: 3–64 символа, латинские буквы, цифры, точка, дефис или подчёркивание.');
  }
  return username;
}

function checkPassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 256) {
    throw new CypherError('Используйте пароль длиной от 12 до 256 символов.');
  }
}

async function csrfToken() {
  const response = await fetch('/api/cypher/session/', {credentials: 'same-origin', cache: 'no-store', redirect: 'error'});
  if (!response.ok) throw new CypherError('Сервер недоступен. Попробуйте снова.');
  return (await authJson(response)).csrf_token;
}

async function post(path, data, namespace = 'opaque') {
  const response = await fetch(`/api/${namespace}/${path}/`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': await csrfToken()},
    body: JSON.stringify(data),
  });
  const body = await authJson(response);
  if (!response.ok) {
    const messages = {
      authentication_failed: 'Неверный логин или пароль. Либо попытка входа истекла.',
      account_unavailable: 'Этот логин уже используется.',
      rate_limited: 'Слишком много попыток. Повторите позднее.',
      opaque_unavailable: 'Вход временно недоступен: сервер OPAQUE не настроен.',
      recent_authentication_required: 'Подтвердите вход текущим паролем.',
      vault_changed: 'Хранилище изменилось. Войдите заново перед сменой пароля.',
    };
    throw new CypherError(messages[body.error] || 'Операция не выполнена. Обновите страницу и попробуйте снова.');
  }
  return body;
}

export async function deriveWrappingSecret(exportKey, username) {
  // OPAQUE's export key is client-only. Its session key is shared with the
  // server and must never be used to protect stored file keys.
  const raw = decodeBase64Url(exportKey, {length: 64});
  try {
    const material = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
    const output = new Uint8Array(await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256', salt: encoder.encode('cloud-cypher:opaque-wrap:v1'),
      info: encoder.encode(canonicalUsername(username)),
    }, material, 256));
    try { return `cc1-${encodeBase64Url(output)}`; } finally { output.fill(0); }
  } finally { raw.fill(0); }
}

export async function loginAccount(username, password) {
  username = String(username).trim().toLowerCase();
  checkPassword(password);
  await opaque.ready;
  let first = opaque.client.startLogin({password});
  const response = await post('login/start', {username, startLoginRequest: first.startLoginRequest});
  username = canonicalUsername(response.username);
  let result = opaque.client.finishLogin({
    password, clientLoginState: first.clientLoginState, loginResponse: response.loginResponse,
    identifiers: {client: username, server: serverIdentifier}, keyStretching: 'memory-constrained',
  });
  first = null;
  if (!result) throw new CypherError('Неверный логин или пароль.');
  const authenticated = await post('login/finish', {challenge: response.challenge, finishLoginRequest: result.finishLoginRequest});
  if (authenticated.second_factor_required) {
    if (!codePrompt) throw new CypherError('Введите одноразовый код для завершения входа.');
    const code = await codePrompt(authenticated.method);
    await post('login/finish', {challenge: authenticated.challenge, code}, 'otp');
  }
  const wrappingSecret = await deriveWrappingSecret(result.exportKey, username);
  result = null;
  return {wrappingSecret, username};
}

export const beginTotpSetup = () => post('setup/start', {}, 'otp');
export const finishTotpSetup = (challenge, code) => post('setup/finish', {challenge, code}, 'otp');

export async function registerAccount(username, password) {
  username = canonicalUsername(username);
  checkPassword(password);
  await opaque.ready;
  let first = opaque.client.startRegistration({password});
  const response = await post('register/start', {username, registrationRequest: first.registrationRequest});
  let result = opaque.client.finishRegistration({
    password, clientRegistrationState: first.clientRegistrationState, registrationResponse: response.registrationResponse,
    identifiers: {client: username, server: serverIdentifier}, keyStretching: 'memory-constrained',
  });
  first = null;
  const registered = await post('register/finish', {challenge: response.challenge, registrationRecord: result.registrationRecord});
  const wrappingSecret = await deriveWrappingSecret(result.exportKey, username);
  result = null;
  return {...registered, username, wrappingSecret};
}

export async function changePassword(username, currentPassword, newPassword, vault) {
  checkPassword(newPassword);
  const current = await loginAccount(username, currentPassword);
  return replacePassword(current.username, newPassword, vault, current.wrappingSecret);
}

// The server accepts this operation only after a recent verified passkey or
// password proof.
export async function replacePassword(username, newPassword, vault, oldWrappingSecret) {
  username = canonicalUsername(username);
  checkPassword(newPassword);
  await opaque.ready;
  let first = opaque.client.startRegistration({password: newPassword});
  const response = await post('change/start', {registrationRequest: first.registrationRequest});
  if (response.username !== username) throw new CypherError('Аккаунт изменился в другой вкладке. Войдите заново.');
  let result = opaque.client.finishRegistration({
    password: newPassword, clientRegistrationState: first.clientRegistrationState,
    registrationResponse: response.registrationResponse,
    identifiers: {client: username, server: serverIdentifier}, keyStretching: 'memory-constrained',
  });
  first = null;
  const wrappingSecret = await deriveWrappingSecret(result.exportKey, username);
  const payload = {challenge: response.challenge, registrationRecord: result.registrationRecord};
  let updatedVault = vault;
  if (vault) {
    const wrapped_key = await rewrapVault(vault, oldWrappingSecret, wrappingSecret);
    payload.vault_id = vault.id;
    payload.wrapped_key = wrapped_key;
    updatedVault = {...vault, wrapped_key};
  }
  await post('change/finish', payload);
  result = null;
  return {wrappingSecret, username, vault: updatedVault};
}

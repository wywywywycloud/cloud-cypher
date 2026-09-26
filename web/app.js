// SPDX-License-Identifier: Apache-2.0
import {
  CypherError, MAX_PLAINTEXT_BYTES, TAG_BYTES, assertUuid, createVault,
  decryptFile, decryptMetadata, encryptFile, unlockVault, validateFileRecord, validateVault,
} from './crypto.js';
import { loginAccount, registerAccount, changePassword, replacePassword, setCodePrompt, beginTotpSetup, finishTotpSetup } from './account.js';
import { enrollPasskey, loginPasskey, beginPasskeyReset, finishPasskeyReset } from './passkeys.js';

const API = '/api/cypher/';
const $ = id => document.getElementById(id);
const state = {
  session: null, key: null, files: [], information: new Map(), generation: 0,
  busy: false, view: 'list', objectURLs: new Set(), controllers: new Set(),
  previewURL: null, deleteTarget: null, resetChallenge: null, totpChallenge: null,
};
const safeImages = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);
const numberFormat = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
const dateFormat = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'short', year: 'numeric' });
const collator = new Intl.Collator('ru-RU', { numeric: true, sensitivity: 'base' });

class SessionChanged extends Error {}

function formatBytes(value) {
  if (value < 1024) return `${value} Б`;
  if (value < 1024 * 1024) return `${numberFormat.format(value / 1024)} КиБ`;
  return `${numberFormat.format(value / (1024 * 1024))} МиБ`;
}

function setStatus(message, kind = 'info') {
  $('status-message').textContent = message;
  $('status-message').dataset.kind = kind;
  $('status-message').hidden = !message;
  if (kind === 'error') {
    const errorSlot = document.querySelector('dialog[open] .dialog-error');
    if (errorSlot) { errorSlot.textContent = message; errorSlot.hidden = false; }
  }
}

function clearErrors() {
  setStatus('');
  document.querySelectorAll('.dialog-error').forEach(item => { item.textContent = ''; item.hidden = true; });
}

function showError(error) {
  if (error instanceof SessionChanged || error?.name === 'AbortError') return;
  const message = error instanceof CypherError || error?.userVisible
    ? error.message : 'Не удалось выполнить действие. Проверьте подключение и повторите попытку.';
  setStatus(message, 'error');
}

function clearPasswords() {
  document.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
}

function releaseURL(url) {
  if (url) { URL.revokeObjectURL(url); state.objectURLs.delete(url); }
}

function closePreview() {
  $('preview-image').removeAttribute('src');
  $('preview-image').alt = '';
  $('preview-title').textContent = 'Просмотр изображения';
  releaseURL(state.previewURL);
  state.previewURL = null;
}

export function lockVault(showMessage = true) {
  state.generation += 1;
  state.key = null;
  state.files = [];
  state.information.clear();
  state.deleteTarget = null;
  for (const controller of state.controllers) controller.abort();
  state.controllers.clear();
  for (const url of state.objectURLs) URL.revokeObjectURL(url);
  state.objectURLs.clear();
  closePreview();
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  clearPasswords();
  $('file-input').value = '';
  $('file-list').replaceChildren();
  $('upload-progress').hidden = true;
  render();
  if (showMessage) setStatus('Хранилище закрыто. Войдите с паролем или passkey.');
}

function vaultIdentity(vault) {
  return vault ? `${vault.id}:${vault.version}:${vault.wrapped_key.iv}:${vault.wrapped_key.ct}` : null;
}

async function limitedBytes(response, limit) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
    await response.body?.cancel();
    throw new CypherError('Сервер вернул данные недопустимого размера.');
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new CypherError('Сервер вернул данные недопустимого размера.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

async function jsonResponse(response) {
  if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    await response.body?.cancel();
    throw new CypherError('Сервер вернул неожиданный ответ. Обновите страницу.');
  }
  const raw = await limitedBytes(response, 16 * 1024 * 1024);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    throw new CypherError('Сервер вернул неверный формат данных.');
  }
}

async function request(path, { method = 'GET', body, json, binaryLimit } = {}) {
  const controller = new AbortController();
  state.controllers.add(controller);
  const headers = { Accept: binaryLimit === undefined ? 'application/json' : 'application/octet-stream' };
  if (method !== 'GET') {
    if (!state.session?.csrf_token) throw new CypherError('Сессия устарела. Обновите страницу.');
    headers['X-CSRFToken'] = state.session.csrf_token;
  }
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  try {
    const response = await fetch(API + path, {
      method, body, headers, credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', signal: controller.signal,
    });
    if (response.status === 401) {
      lockVault(false);
      state.session = null;
      render();
      throw new CypherError('Сессия завершилась. Войдите в аккаунт ещё раз.');
    }
    if (!response.ok) {
      let detail = null;
      try { detail = await jsonResponse(response); } catch { /* The status is enough to explain a failed request. */ }
      if (detail?.error === 'vault_changed' || detail?.code === 'vault_changed') {
        lockVault(false);
        throw new CypherError('Хранилище изменилось в другой сессии. Войдите повторно.');
      }
      const message = typeof detail?.error === 'string' && /[а-яё]/i.test(detail.error)
        ? detail.error.slice(0, 300)
        : response.status === 413 ? 'Для этих файлов недостаточно свободного места.'
          : response.status === 403 ? 'Нет доступа к действию. Обновите страницу и войдите повторно.'
            : response.status === 409 ? 'Состояние хранилища изменилось. Обновите список и повторите действие.'
              : response.status === 404 ? 'Файл или хранилище уже удалены.'
                : 'Не удалось выполнить действие на сервере. Повторите попытку.';
      throw new CypherError(message);
    }
    if (binaryLimit !== undefined) return await limitedBytes(response, binaryLimit);
    return await jsonResponse(response);
  } finally {
    state.controllers.delete(controller);
  }
}

function validateSession(session) {
  if (!session || typeof session.authenticated !== 'boolean'
      || typeof session.csrf_token !== 'string' || session.csrf_token.length > 256) {
    throw new CypherError('Не удалось проверить сессию.');
  }
  if (session.authenticated) {
    if (typeof session.user?.username !== 'string' || session.user.username.length > 150
        || !Number.isSafeInteger(session.quota_bytes) || session.quota_bytes < 0
        || !Number.isSafeInteger(session.used_bytes) || session.used_bytes < 0
        || session.vault === undefined) throw new CypherError('Не удалось проверить параметры хранилища.');
    if (session.vault !== null) validateVault(session.vault);
  }
  return session;
}

export async function refreshSession() {
  const previous = state.session;
  const session = validateSession(await request('session/'));
  if (previous?.authenticated && (
    !session.authenticated || previous.user.username !== session.user.username
    || vaultIdentity(previous.vault) !== vaultIdentity(session.vault)
  )) {
    lockVault(false);
  }
  state.session = session;
  render();
  return session;
}

function context() {
  if (!state.key || !state.session?.vault) throw new SessionChanged();
  return { generation: state.generation, key: state.key, vaultId: state.session.vault.id };
}

function checkContext(expected) {
  if (state.generation !== expected.generation || state.key !== expected.key
      || state.session?.vault?.id !== expected.vaultId) throw new SessionChanged();
}

async function freshContext() {
  const before = context();
  await refreshSession();
  checkContext(before);
  return before;
}

function render() {
  const authenticated = Boolean(state.session?.authenticated);
  const opened = authenticated && Boolean(state.key);
  $('loading-panel').hidden = true;
  $('public-panel').hidden = authenticated;
  $('account-toolbar').hidden = !authenticated;
  $('locked-panel').hidden = !authenticated || opened;
  $('files-panel').hidden = !opened;
  $('vault-footer').hidden = !authenticated || !state.session?.vault;
  $('password-settings-button').hidden = !authenticated;
  $('passkey-enrollment').hidden = !opened || Boolean(state.session?.passkey_ready);
  if (authenticated) {
    $('account-name').textContent = state.session.user.email || state.session.user.username;
    $('unlock-username').value = state.session.user.username;
    $('logout-csrf').value = state.session.csrf_token;
    $('quota-label').textContent = `${formatBytes(state.session.used_bytes)} / ${formatBytes(state.session.quota_bytes)}`;
    $('quota-meter').value = state.session.quota_bytes ? Math.min(100, state.session.used_bytes * 100 / state.session.quota_bytes) : 0;
  } else {
    $('account-name').textContent = '';
    $('logout-csrf').value = '';
  }
  applyBusy();
}

function applyBusy() {
  const ids = ['upload-button', 'refresh-button', 'unlock-button', 'login-button', 'register-button', 'change-password-button', 'reset-vault-button', 'confirm-delete-button', 'password-settings-button', 'enroll-confirm-button', 'recovery-button', 'reset-send-button', 'after-reset-button', 'passkey-login-button', 'passkey-unlock-button'];
  ids.forEach(id => { if ($(id)) $(id).disabled = state.busy; });
  $('confirm-reset-button').disabled = state.busy || $('reset-confirm').value !== 'DELETE ALL FILES';
  $('upload-button').disabled = state.busy || !state.session?.passkey_ready;
  $('file-input').disabled = state.busy || !state.session?.passkey_ready;
  $('file-list').querySelectorAll('button').forEach(button => { button.disabled = state.busy; });
  $('files-panel').setAttribute('aria-busy', String(state.busy));
}

async function runAction(action) {
  if (state.busy) return;
  state.busy = true;
  clearErrors();
  applyBusy();
  try {
    await action();
  } catch (error) {
    showError(error);
  } finally {
    state.busy = false;
    $('upload-progress').hidden = true;
    applyBusy();
  }
}

export async function openVaultWithSecret(wrappingSecret, expectedUsername, passkeyVault = null) {
  const session = await refreshSession();
  if (!session.authenticated) throw new CypherError('Сначала войдите в аккаунт.');
  if (!expectedUsername || session.user.username !== expectedUsername) throw new CypherError('Аккаунт изменился в другой вкладке. Войдите заново.');
  if (passkeyVault && !session.vault) throw new CypherError('Хранилище passkey больше не существует.');
  const generation = state.generation;
  const username = session.user.username;
  let vault = session.vault;
  let key;
  if (vault) {
    if (passkeyVault && passkeyVault.id !== vault.id) throw new CypherError('Хранилище изменилось. Войдите заново.');
    key = await unlockVault(passkeyVault || vault, wrappingSecret);
  } else {
    const created = await createVault(wrappingSecret);
    if (generation !== state.generation || state.session?.user?.username !== username) throw new SessionChanged();
    const response = await request('vault/', { method: 'POST', json: created.vault });
    vault = validateVault(response.vault);
    if (vaultIdentity(vault) !== vaultIdentity(created.vault)) throw new CypherError('Сервер вернул другое хранилище.');
    key = created.key;
    state.session.vault = vault;
  }
  if (generation !== state.generation || state.session?.user?.username !== username) throw new SessionChanged();
  state.key = key;
  clearPasswords();
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  render();
  await loadFiles();
}

function makeElement(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#icon-${name}`);
  svg.append(use);
  return svg;
}

function actionButton(label, iconName, callback, extraClass = '') {
  const button = makeElement('button', `icon-button ${extraClass}`.trim());
  button.type = 'button';
  button.setAttribute('aria-label', label);
  button.title = label;
  button.append(icon(iconName));
  button.addEventListener('click', callback);
  return button;
}

function fileType(type) {
  if (safeImages.has(type)) return 'Изображение';
  if (type === 'application/pdf') return 'PDF';
  if (type.startsWith('text/')) return 'Текстовый файл';
  if (type.startsWith('video/')) return 'Видео';
  if (type.startsWith('audio/')) return 'Аудио';
  return 'Файл';
}

function renderFiles() {
  $('file-list').replaceChildren();
  $('file-list').dataset.view = state.view;
  document.querySelector('.list-heading').hidden = state.view !== 'list' || state.files.length === 0;
  $('empty-state').hidden = state.files.length !== 0;
  $('view-list').setAttribute('aria-pressed', String(state.view === 'list'));
  $('view-grid').setAttribute('aria-pressed', String(state.view === 'grid'));
  $('file-count').textContent = state.files.length ? `Файлов: ${state.files.length}` : 'Файлов пока нет';
  const sorted = [...state.files].sort((a, b) => collator.compare(state.information.get(a.id)?.name || a.id, state.information.get(b.id)?.name || b.id));
  for (const record of sorted) {
    const metadata = state.information.get(record.id);
    const invalid = !metadata;
    const name = metadata?.name || `Повреждённый файл ${record.id.slice(0, 8)}`;
    const row = makeElement('article', `file-row${invalid ? ' invalid-file' : ''}`);
    row.dataset.fileId = record.id;
    const main = makeElement('div', 'file-main');
    const symbol = makeElement('span', `file-icon${safeImages.has(metadata?.type) ? ' image-icon' : ''}`);
    symbol.append(icon(safeImages.has(metadata?.type) ? 'image' : 'file'));
    const text = makeElement('div', 'file-name-wrap');
    const nameElement = makeElement('span', 'file-name', name);
    nameElement.title = name;
    text.append(nameElement, makeElement('span', 'file-type', invalid ? 'Не удалось проверить метаданные' : fileType(metadata.type)));
    main.append(symbol, text);
    const size = makeElement('span', 'file-size', metadata ? formatBytes(metadata.size) : '—');
    const timestamp = typeof record.created_at === 'string' ? new Date(record.created_at) : null;
    const date = makeElement('span', 'file-date', timestamp && Number.isFinite(timestamp.getTime()) ? dateFormat.format(timestamp) : '—');
    const actions = makeElement('div', 'file-actions');
    if (metadata) {
      if (safeImages.has(metadata.type)) actions.append(actionButton(`Просмотреть ${name}`, 'image', () => runAction(() => obtainFile(record, true)), 'preview-file'));
      actions.append(actionButton(`Скачать ${name}`, 'download', () => runAction(() => obtainFile(record, false)), 'download-file'));
    }
    actions.append(actionButton(`Удалить ${name}`, 'trash', () => {
      state.deleteTarget = record;
      $('delete-description').textContent = name;
      $('delete-dialog').showModal();
    }, 'delete-file'));
    row.append(main, size, date, actions);
    $('file-list').append(row);
  }
  applyBusy();
}

export async function loadFiles() {
  const expected = await freshContext();
  const response = await request('files/');
  checkContext(expected);
  if (!Array.isArray(response.files) || response.files.length > 10000) {
    throw new CypherError('Сервер вернул некорректный список файлов.');
  }
  const records = [];
  const information = new Map();
  const seen = new Set();
  for (const record of response.files) {
    assertUuid(record?.id);
    if (record.vault_id !== expected.vaultId || seen.has(record.id)) throw new CypherError('Сервер вернул некорректный список файлов.');
    seen.add(record.id);
    records.push(record);
    try {
      const metadata = await decryptMetadata(expected.key, expected.vaultId, record);
      information.set(record.id, { name: metadata.name, type: metadata.type, size: metadata.size });
    } catch (error) {
      if (!(error instanceof CypherError)) throw error;
      // Corrupt records remain removable, but are never offered for download or preview.
    }
    checkContext(expected);
  }
  state.files = records;
  state.information = information;
  renderFiles();
  if (information.size !== records.length) setStatus('Некоторые файлы не прошли проверку. Их содержимое не открывается.', 'error');
}

function createObjectURL(blob) {
  const url = URL.createObjectURL(blob);
  state.objectURLs.add(url);
  return url;
}

function downloadBytes(data, name) {
  const url = createObjectURL(new Blob([data], { type: 'application/octet-stream' }));
  const link = makeElement('a');
  link.href = url;
  link.download = name;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => releaseURL(url), 30000);
}

function matchesRaster(type, data) {
  const starts = values => values.every((value, index) => data[index] === value);
  if (type === 'image/png') return starts([137, 80, 78, 71, 13, 10, 26, 10]);
  if (type === 'image/jpeg') return starts([255, 216, 255]);
  if (type === 'image/gif') return starts([71, 73, 70, 56]) && [55, 57].includes(data[4]) && data[5] === 97;
  if (type === 'image/webp') return starts([82, 73, 70, 70]) && data.length >= 12 && [87, 69, 66, 80].every((value, index) => data[index + 8] === value);
  return false;
}

async function obtainFile(record, preview) {
  const expected = await freshContext();
  validateFileRecord(record, expected.vaultId);
  const ciphertext = await request(`files/${record.id}/download/`, { binaryLimit: record.ciphertext_bytes });
  checkContext(expected);
  const plaintext = await decryptFile(expected.key, expected.vaultId, record, ciphertext);
  try {
    checkContext(expected);
    if (preview) {
      if (!safeImages.has(plaintext.type) || !matchesRaster(plaintext.type, plaintext.bytes)) {
        throw new CypherError('Формат изображения не подходит для просмотра. Файл можно скачать.');
      }
      closePreview();
      state.previewURL = createObjectURL(new Blob([plaintext.bytes], { type: plaintext.type }));
      $('preview-title').textContent = plaintext.name;
      $('preview-image').alt = plaintext.name;
      $('preview-image').src = state.previewURL;
      $('preview-dialog').showModal();
    } else {
      downloadBytes(plaintext.bytes, plaintext.name);
      setStatus('Файл проверен, расшифрован и передан для скачивания.', 'success');
    }
  } finally {
    plaintext.bytes.fill(0);
  }
}

async function uploadFiles(fileList) {
  if (!state.session?.passkey_ready) throw new CypherError('Перед загрузкой настройте passkey для восстановления доступа.');
  const files = Array.from(fileList);
  if (!files.length) return;
  const expected = await freshContext();
  let total = 0;
  for (const file of files) {
    if (!(file instanceof File) || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_PLAINTEXT_BYTES) {
      throw new CypherError('Размер одного файла не должен превышать 50 МиБ.');
    }
    total += file.size + TAG_BYTES;
    if (!Number.isSafeInteger(total)) throw new CypherError('Выбрано слишком много данных.');
  }
  if (total > state.session.quota_bytes - state.session.used_bytes) {
    throw new CypherError('Для выбранных файлов недостаточно места. В размер загрузки входят 16 байт шифрования на файл.');
  }
  let completed = 0;
  try {
    for (const file of files) {
      checkContext(expected);
      $('upload-progress').hidden = false;
      $('upload-progress-text').textContent = `Шифруем ${completed + 1} из ${files.length}: ${file.name}`;
      const raw = new Uint8Array(await file.arrayBuffer());
      let encrypted;
      try {
        checkContext(expected);
        if (raw.byteLength !== file.size) throw new CypherError('Размер прочитанного файла изменился.');
        encrypted = await encryptFile(expected.key, expected.vaultId, { name: file.name, type: file.type, bytes: raw });
      } finally {
        raw.fill(0);
      }
      checkContext(expected);
      $('upload-progress-text').textContent = `Загружаем ${completed + 1} из ${files.length}: ${file.name}`;
      const form = new FormData();
      form.append('vault_id', encrypted.vault_id);
      form.append('id', encrypted.id);
      form.append('metadata', JSON.stringify(encrypted.metadata));
      form.append('file', new Blob([encrypted.ciphertext], { type: 'application/octet-stream' }), `${encrypted.id}.bin`);
      const response = await request('files/', { method: 'POST', body: form });
      checkContext(expected);
      validateFileRecord(response.file, expected.vaultId);
      if (response.file.id !== encrypted.id || response.file.ciphertext_bytes !== encrypted.ciphertext_bytes
          || ['v', 'iv', 'ct'].some(k => response.file.metadata[k] !== encrypted.metadata[k])) {
        throw new CypherError('Сервер вернул несоответствующие данные загрузки.');
      }
      completed += 1;
      state.session.used_bytes += encrypted.ciphertext_bytes;
      render();
    }
    await loadFiles();
    setStatus(`Загружено файлов: ${completed}. Они зашифрованы на этом устройстве.`, 'success');
  } catch (error) {
    if (completed && !(error instanceof SessionChanged) && error?.name !== 'AbortError') {
      try { await loadFiles(); } catch { /* Preserve the reason the upload stopped. */ }
      if (error instanceof CypherError) error.message = `Загружено ${completed} из ${files.length}. ${error.message}`;
    }
    throw error;
  } finally {
    $('file-input').value = '';
  }
}

async function deleteFile() {
  const record = state.deleteTarget;
  if (!record) return;
  const expected = await freshContext();
  if (record.vault_id !== expected.vaultId) throw new SessionChanged();
  assertUuid(record.id);
  await request(`files/${record.id}/`, { method: 'DELETE' });
  checkContext(expected);
  $('delete-dialog').close();
  state.deleteTarget = null;
  await loadFiles();
  setStatus('Файл удалён.', 'success');
}

function openResetDialog() {
  state.resetChallenge = null;
  $('reset-confirm').value = '';
  $('reset-code').value = '';
  $('reset-email').value = state.session?.user?.email || '';
  $('reset-form').hidden = true;
  $('reset-start-form').hidden = false;
  openDialog('reset-dialog');
  applyBusy();
}

async function passkeySignIn() {
  const generation = state.generation;
  const result = await loginPasskey();
  if (state.generation !== generation) throw new SessionChanged();
  await openVaultWithSecret(result.wrappingSecret, result.username, result.vault);
  setStatus('Хранилище открыто с passkey.', 'success');
}

async function signIn(username, password) {
  const generation = state.generation;
  const result = await loginAccount(username, password);
  if (state.generation !== generation) throw new SessionChanged();
  await openVaultWithSecret(result.wrappingSecret, result.username);
  setStatus('Хранилище открыто.', 'success');
}

function openDialog(id) {
  clearErrors();
  $(id).showModal();
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $('theme-button').setAttribute('aria-label', theme === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему');
  try { localStorage.setItem('cloud-cypher-theme', theme); } catch { /* Preferences are optional; keys never use browser storage. */ }
}

function wireEvents() {
  setCodePrompt(method => new Promise((resolve, reject) => {
    $('otp-code').value = '';
    $('otp-description').textContent = method === 'totp' ? 'Введите код из вашего TOTP-генератора.' : 'Введите код, отправленный на вашу почту.';
    const cancel = () => { cleanup(); reject(new CypherError('Вход отменён.')); };
    const submit = event => { event.preventDefault(); const code = $('otp-code').value; cleanup(); resolve(code); };
    const cleanup = () => {
      $('otp-form').removeEventListener('submit', submit);
      $('otp-cancel-button').removeEventListener('click', cancel);
      $('otp-dialog').removeEventListener('cancel', cancel);
      $('otp-dialog').removeEventListener('close', cancel);
      $('otp-code').value = '';
      $('otp-dialog').close();
    };
    $('otp-form').addEventListener('submit', submit);
    $('otp-cancel-button').addEventListener('click', cancel);
    $('otp-dialog').addEventListener('cancel', cancel);
    $('otp-dialog').addEventListener('close', cancel);
    $('otp-dialog').showModal();
  }));
  $('totp-settings-button').addEventListener('click', () => {
    $('totp-start-form').hidden = false;
    $('totp-finish-form').hidden = true;
    openDialog('totp-dialog');
  });
  $('totp-dialog').addEventListener('close', () => { $('totp-secret').value = ''; $('totp-code').value = ''; state.totpChallenge = null; });
  $('totp-start-form').addEventListener('submit', event => {
    event.preventDefault();
    const password = $('totp-password').value;
    clearPasswords();
    runAction(async () => {
      const generation = state.generation;
      const username = state.session.user.username;
      await loginAccount(username, password);
      if (generation !== state.generation || !$('totp-dialog').open) throw new SessionChanged();
      const session = await refreshSession();
      if (session.user?.username !== username) throw new SessionChanged();
      const setup = await beginTotpSetup();
      if (generation !== state.generation || !$('totp-dialog').open || state.session.user?.username !== username) throw new SessionChanged();
      state.totpChallenge = setup.challenge;
      $('totp-secret').value = setup.secret;
      $('totp-start-form').hidden = true;
      $('totp-finish-form').hidden = false;
    });
  });
  $('totp-finish-form').addEventListener('submit', event => {
    event.preventDefault();
    runAction(async () => {
      await finishTotpSetup(state.totpChallenge, $('totp-code').value);
      $('totp-dialog').close();
      setStatus('TOTP подключён. При входе с паролем используйте код из генератора вместо письма.', 'success');
    });
  });
  try {
    const view = localStorage.getItem('cloud-cypher-view');
    if (['list', 'grid'].includes(view)) state.view = view;
    const theme = localStorage.getItem('cloud-cypher-theme');
    setTheme(['light', 'dark'].includes(theme) ? theme : matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  } catch { setTheme(matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); }
  $('theme-button').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('login-link').addEventListener('click', event => { event.preventDefault(); openDialog('login-dialog'); });
  $('register-link').addEventListener('click', event => { event.preventDefault(); openDialog('register-dialog'); });
  document.querySelectorAll('[data-close-dialog]').forEach(button => button.addEventListener('click', () => $(button.dataset.closeDialog).close()));
  ['login-dialog', 'register-dialog', 'password-dialog'].forEach(id => $(id).addEventListener('close', () => { $(id).querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; }); }));
  $('login-form').addEventListener('submit', event => {
    event.preventDefault();
    const username = $('auth-username').value.trim();
    const password = $('auth-password').value;
    $('auth-password').value = '';
    runAction(() => signIn(username, password));
  });
  $('unlock-form').addEventListener('submit', event => {
    event.preventDefault();
    const username = state.session?.user?.username;
    const password = $('unlock-password').value;
    $('unlock-password').value = '';
    if (username) runAction(() => signIn(username, password));
  });
  $('register-form').addEventListener('submit', event => {
    event.preventDefault();
    if ($('register-password').value !== $('register-password-confirm').value) { setStatus('Пароли не совпадают.', 'error'); return; }
    const username = `u${crypto.randomUUID().replaceAll('-', '')}`;
    const email = $('register-email').value.trim();
    const password = $('register-password').value;
    clearPasswords();
    runAction(async () => {
      const result = await registerAccount(username, email, password);
      if (result.verification_required && typeof result.verify_url === 'string') {
        const destination = new URL(result.verify_url, location.origin);
        if (destination.origin !== location.origin) throw new CypherError('Сервер вернул неверный адрес подтверждения.');
        location.assign(destination.href);
      } else {
        $('register-dialog').close();
        $('auth-username').value = username;
        setStatus('Аккаунт создан. Войдите, чтобы открыть хранилище.', 'success');
        openDialog('login-dialog');
      }
    });
  });
  $('password-settings-button').addEventListener('click', () => openDialog('password-dialog'));
  $('password-form').addEventListener('submit', event => {
    event.preventDefault();
    if ($('new-password').value !== $('new-password-confirm').value) { setStatus('Новые пароли не совпадают.', 'error'); return; }
    const current = $('current-password').value;
    const next = $('new-password').value;
    clearPasswords();
    runAction(async () => {
      const session = await refreshSession();
      if (!session.authenticated) throw new CypherError('Сессия завершилась. Войдите повторно.');
      const generation = state.generation;
      const result = await changePassword(session.user.username, current, next, session.vault);
      if (state.generation !== generation) throw new SessionChanged();
      lockVault(false);
      await openVaultWithSecret(result.wrappingSecret, result.username);
      setStatus('Пароль изменён. Ваши файлы сохранены.', 'success');
    });
  });
  $('logout-form').addEventListener('submit', () => lockVault(false));
  $('lock-button').addEventListener('click', () => lockVault());
  $('upload-button').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', () => {
    const files = Array.from($('file-input').files);
    runAction(() => uploadFiles(files));
  });
  $('refresh-button').addEventListener('click', () => runAction(loadFiles));
  ['list', 'grid'].forEach(view => $(`view-${view}`).addEventListener('click', () => {
    state.view = view;
    try { localStorage.setItem('cloud-cypher-view', view); } catch { /* Optional non-secret preference. */ }
    renderFiles();
  }));
  let dragDepth = 0;
  $('drop-area').addEventListener('dragenter', event => {
    event.preventDefault();
    if (state.key && !state.busy) { dragDepth += 1; $('drop-area').classList.add('dragging'); }
  });
  $('drop-area').addEventListener('dragover', event => { event.preventDefault(); if (event.dataTransfer) event.dataTransfer.dropEffect = state.busy ? 'none' : 'copy'; });
  $('drop-area').addEventListener('dragleave', () => { dragDepth -= 1; if (dragDepth <= 0) { dragDepth = 0; $('drop-area').classList.remove('dragging'); } });
  $('drop-area').addEventListener('drop', event => {
    event.preventDefault();
    dragDepth = 0;
    $('drop-area').classList.remove('dragging');
    if (state.key && !state.busy) runAction(() => uploadFiles(event.dataTransfer.files));
  });
  $('close-preview-button').addEventListener('click', () => $('preview-dialog').close());
  $('preview-dialog').addEventListener('close', closePreview);
  $('preview-image').addEventListener('error', () => { if (state.previewURL) { $('preview-dialog').close(); setStatus('Браузер не смог открыть изображение. Его можно скачать.', 'error'); } });
  $('cancel-delete-button').addEventListener('click', () => $('delete-dialog').close());
  $('confirm-delete-button').addEventListener('click', () => runAction(deleteFile));
  $('reset-vault-button').addEventListener('click', openResetDialog);
  $('lost-passkey-button').addEventListener('click', () => { $('login-dialog').close(); openResetDialog(); });
  $('cancel-reset-button').addEventListener('click', () => $('reset-dialog').close());
  $('reset-confirm').addEventListener('input', applyBusy);
  $('reset-start-form').addEventListener('submit', event => {
    event.preventDefault();
    runAction(async () => {
      const result = await beginPasskeyReset($('reset-email').value.trim());
      state.resetChallenge = result.challenge;
      $('reset-start-form').hidden = true;
      $('reset-form').hidden = false;
      setStatus('Если аккаунт существует, код отправлен на его почту.');
    });
  });
  $('reset-form').addEventListener('submit', event => {
    event.preventDefault();
    runAction(async () => {
      await finishPasskeyReset(state.resetChallenge, $('reset-code').value, $('reset-confirm').value);
      lockVault(false);
      await refreshSession();
      openDialog('new-password-dialog');
    });
  });
  $('new-password-form').addEventListener('submit', event => {
    event.preventDefault();
    if ($('after-reset-password').value !== $('after-reset-confirm').value) { setStatus('Пароли не совпадают.', 'error'); return; }
    const password = $('after-reset-password').value;
    clearPasswords();
    runAction(async () => {
      const session = await refreshSession();
      if (session.vault) throw new CypherError('Сброс хранилища не подтверждён.');
      const result = await replacePassword(session.user.username, password, null, null);
      await openVaultWithSecret(result.wrappingSecret, result.username);
      setStatus('Создано пустое хранилище. Подключите новый passkey перед загрузкой.', 'success');
    });
  });
  $('passkey-login-button').addEventListener('click', () => runAction(passkeySignIn));
  $('passkey-unlock-button').addEventListener('click', () => runAction(passkeySignIn));
  for (const id of ['forgot-password-button', 'locked-forgot-button']) {
    $(id).addEventListener('click', () => { $('login-dialog').close(); openDialog('recovery-dialog'); });
  }
  $('enroll-passkey-button').addEventListener('click', () => openDialog('enroll-dialog'));
  $('enroll-form').addEventListener('submit', event => {
    event.preventDefault();
    const password = $('enroll-password').value;
    clearPasswords();
    runAction(async () => {
      const result = await loginAccount(state.session.user.username, password);
      const session = await refreshSession();
      await enrollPasskey(session.vault, result.wrappingSecret);
      $('enroll-dialog').close();
      await refreshSession();
      setStatus('Passkey подключён. Теперь можно загружать файлы.', 'success');
    });
  });
  $('recovery-form').addEventListener('submit', event => {
    event.preventDefault();
    if ($('recovery-password').value !== $('recovery-password-confirm').value) { setStatus('Пароли не совпадают.', 'error'); return; }
    const password = $('recovery-password').value;
    clearPasswords();
    runAction(async () => {
      const generation = state.generation;
      const recovered = await loginPasskey();
      if (state.generation !== generation) throw new SessionChanged();
      const result = await replacePassword(recovered.username, password, recovered.vault, recovered.wrappingSecret);
      if (state.generation !== generation) throw new SessionChanged();
      lockVault(false);
      await openVaultWithSecret(result.wrappingSecret, result.username);
      setStatus('Пароль восстановлен через passkey. Все файлы сохранены.', 'success');
    });
  });
  window.addEventListener('pagehide', () => lockVault(false));
  window.addEventListener('pageshow', event => { if (event.persisted) refreshSession().catch(showError); });
  window.addEventListener('focus', () => { if (!state.busy && state.session) refreshSession().catch(showError); });
}

async function boot() {
  wireEvents();
  try {
    await refreshSession();
    if (location.hash === '#login' && !state.session?.authenticated) openDialog('login-dialog');
    if (location.hash === '#register' && !state.session?.authenticated) openDialog('register-dialog');
  } catch (error) {
    render();
    showError(error);
  }
}

export const ready = boot();

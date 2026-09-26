# Результаты проверки 26 сентября 2026

Это воспроизводимые проверки прототипа на синтетических данных, а не независимый аудит безопасности. Локальный стенд использовал Django 5.2.17, Python 3.14, Node.js 24 и Chrome 153.0.8010.53. Секреты, БД, файлы пользователей, исходные HAR и cookies не публикуются.

| Проверка | Результат | Отчёт |
| --- | --- | --- |
| Django: аккаунты, OPAQUE, OTP, WebAuthn, storage, legacy regression | 143 теста прошли | [unit-checks.json](unit-checks.json) |
| Web Crypto и безопасная сериализация авторизации | 20 тестов прошли | [unit-checks.json](unit-checks.json) |
| Независимый verifier и границы vendor-инструмента | 38 тестов прошли | [unit-checks.json](unit-checks.json) |
| Сценарии в настоящем браузере | 19 проверок прошли | [browser-e2e.json](browser-e2e.json) |
| БД и blobs: нет открытого содержимого и имени тестового файла | Прошло | [storage-inspection.json](storage-inspection.json) |
| Полученные ответы сайта совпадают с независимым локальным эталоном | Совпадают | [delivery-url.json](delivery-url.json) |
| Тела, реально полученные браузером, совпадают с эталоном | Совпадают в наблюдаемой области | [delivery-browser.json](delivery-browser.json) |
| В контролируемой копии сервера изменён app.js | Подмена обнаружена, ожидаемый mismatch | [delivery-tampered.json](delivery-tampered.json) |
| Браузер действительно загрузил изменённый app.js | Подмена обнаружена по HAR, ожидаемый mismatch | [delivery-tampered-browser.json](delivery-tampered-browser.json) |
| После восстановления app.js | Совпадают | [delivery-restored.json](delivery-restored.json) |
| Vendored OPAQUE и закреплённый upstream npm-архив | SHA-512 архива и все пять файлов совпадают | [vendor-integrity.json](vendor-integrity.json) |

Браузерные сценарии включают регистрацию и подтверждение email; OPAQUE с кодом письма; блокировку upload до настройки passkey; WebAuthn/PRF; загрузку и скачивание точных исходных байтов; зашифрованные имена; локальное превью; новый изолированный browser context; смену пароля; вход через passkey после удаления cookies; восстановление забытого пароля без потери файла; отказ при порче ciphertext; TOTP вместо письма; destructive reset, отзыв старых сессий и создание нового пустого vault. Проверено отсутствие паролей, имени и открытых байтов файла в захваченных запросах клиента.

[Снимки интерфейса](screenshots/) содержат синтетический аккаунт и тестовые файлы: list/grid × light/dark × 1280/390/320 px. Автоматическая проверка не обнаружила горизонтального переполнения; репрезентативные снимки также просмотрены вручную.

## Воспроизведение

В [cloud-nimbus-e2ee](https://github.com/wywywywycloud/cloud-nimbus-e2ee), клонированном с `--recurse-submodules`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
# Node.js 24 и pnpm 11.19.0 должны быть в PATH.
(cd cloud-cypher && pnpm install --frozen-lockfile --ignore-scripts && pnpm exec playwright install chromium)
.venv/bin/python scripts/run_checks.py --report-dir new-reports
PLAYWRIGHT_MODULE="$PWD/cloud-cypher/node_modules/playwright" .venv/bin/python scripts/test_e2ee.py --report-dir new-reports
```

Стенд сам создаёт временные SQLite, файловое хранилище, OPAQUE setup, почтовый ящик и браузерный профиль; после проверки удаляет их. Для Linux зависимости браузера устанавливаются через `pnpm exec playwright install --with-deps chromium`. Для установленного Chrome можно указать `PLAYWRIGHT_CHANNEL=chrome`. Окружение `OPAQUE_NODE` позволяет задать путь Node. `--delivery-only` повторяет только проверки окончательных публичных ресурсов и контролируемой подмены.

Отчёты сайта после финальной правки текстовой инструкции пересозданы через `--delivery-only`; исполняемые JS/CSS/HTML приложения сохранили байты полного браузерного прогона. Проверка vendor-пакета воспроизводит опубликованные npm-байты, а не сборку Rust/WASM из исходников.

## Проверенные границы

WebAuthn использовал виртуальный CTAP2.1-аутентификатор Chrome с настоящими подписями и PRF. Физическая синхронизация Apple/Google/других менеджеров и восстановление их аккаунтов не проверялись. Подписанные BE/BS-флаги требуют поддержки резервирования и сообщённого состояния backup, но не доказывают успешное будущее восстановление у провайдера. Экспорт/импорт credential через Chrome DevTools не переносит внутренний PRF-секрет и не считается тестом синхронизации.

Проверка сайта относится к полученным байтам и указанным заголовкам. Она не предотвращает исполнение кода, не удостоверяет происхождение произвольного HAR и не доказывает одинаковую выдачу всем посетителям. Отсутствие открытого тестового маркера не является самостоятельным доказательством криптостойкости: отдельно проверяются формат, теги, ключи и сквозное расшифрование. Production-развёртывание, PostgreSQL-конкурентность, нагрузка и независимый аудит в этот отчёт не входят.

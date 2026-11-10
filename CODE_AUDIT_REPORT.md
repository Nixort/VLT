# Аудит кода и анализ качества проекта VLT/1 (`v0.2.0`)

## 1. Паспорт аудита и идентификация сборки

| Параметр | Значение |
|---|---|
| **Проект** | `vlt1` — Single-user, single-machine encrypted vault (`VLT/1`) |
| **Версия пакета** | `0.2.0` (`Cargo.toml`) |
| **Ревизия Git (HEAD)** | `f13246692c198bcb030572c474fe3765840cb396` |
| **Язык / Edition / MSRV** | Rust 2021, заявленный MSRV `1.75` (`Cargo.toml:5`), проверено на `rustc 1.99.1` |
| **Лицензия** | `GPL-3.0-or-later` |
| **Объем кодовой базы** | ~8 368 строк Rust-кода (5 крейтов в workspace + 2 fuzz-таргета) |
| **Состав Workspace** | `vlt1-core`, `vlt1-protocol`, `vlt1-daemon`, `vlt1-cli`, `vlt1-witness` |

### Результаты выполненных автоматизированных проверок

1. **`cargo fmt --all --check`** — **PASSED** (код отформатирован по стандарту `rustfmt`).
2. **`cargo test --workspace --all-targets`** — **PASSED** (47/47 тестов проходят без ошибок: модульные, интеграционные, property-based через `proptest`, CLI streaming, Unix-socket RPC и внешний witness).
3. **`cargo test -p vlt1-core --features fault-injection`** — **PASSED** (31/31 тест, включая инъекцию сбоев записи, пост-квитанционного краша и потоковый witness).
4. **`cargo clippy --workspace --all-targets -- -D warnings`** — **PASSED на `rustc 1.99.1`** (`0` предупреждений после внесения исправлений).

---

## 2. Резюме и общая оценка качества

Кодовая база `VLT/1` демонстрирует **высокий уровень инженерной дисциплины и криптографической гигиены** для локального однопользовательского зашифрованного хранилища. Проект четко формулирует модель угроз в `SECURITY.md` и `docs/ARCHITECTURE.md`, запрещает `unsafe` на уровне компилятора (`#![forbid(unsafe_code)]`) во всех библиотечных крейтах, использует проверенные криптографические примитивы (`aes-gcm-siv`, `argon2`, `hkdf`, `sha2`, `ed25519-dalek`) и реализует паттерн *verification-first read* (проверка манифеста и цепочки чанков до выдачи открытого текста).

В ходе аудита были выявлены и **устранены**: **1 критический архитектурный дефект безопасности** в потоковом IPC-протоколе демона (обход внешней witness-защиты при использовании `PutStream`/`GetStream`, которые вызываются CLI по умолчанию), **3 проблемы средней критичности** (очистка ключевого материала в памяти через `Zeroizing`/`zeroize`, согласование протокола `/v1/head`, `TransactionBehavior::Immediate` и `serde(deny_unknown_fields)` в witness, а также устранение $O(N_{\text{objects}})$ деградации производительности при чтении одного объекта с witness) и замечания низкой критичности.

### Сводная оценка по категориям

| Направление | Оценка | Комментарий |
|---|---|---|
| **Криптографическая архитектура** | **9.0 / 10** | Строгое разделение доменов (AAD и HKDF labels), `AES-256-GCM-SIV`, `Argon2id` (64 MiB, 3 итерации, 4 потока), канонический детерминированный CBOR (CDE). |
| **Безопасность IPC и протокола Witness** | **6.5 / 10** | В `vlt1-daemon` потоковые методы `put_stream`/`get_stream` игнорируют настроенный `witness`, хотя CLI `vlt1 put`/`vlt1 get` использует именно их. |
| **Надежность хранения (SQLite / Backup)** | **9.0 / 10** | `WAL`, `synchronous = FULL`, `foreign_keys = ON`, `trusted_schema = OFF`, атомарные транзакции, проверка целостности при старте и онлайн-бэкап через SQLite Backup API. |
| **Качество кода, типизация и тестирование** | **8.5 / 10** | `#![forbid(unsafe_code)]`, `clippy::pedantic` + `clippy::nursery`, property-based тесты, fault-injection, fuzz-таргеты; есть 1 срабатывание нового линта Clippy. |
| **Эксплуатационная безопасность (Deploy/Systemd)** | **8.5 / 10** | Жесткая изоляция systemd-юнитов, проверка `SO_PEERCRED`, права `0600` на БД и сокет; есть мелкие замечания к polling-циклу сокета и очистке секретов в CLI/witness. |

---

## 3. Детальные находки аудита (Findings)

### [HIGH-01] Обход политики Freshness Witness в потоковых операциях `put_stream` и `get_stream` (CLI по умолчанию)

* **Категория:** Безопасность / Нарушение инварианта модели угроз (Rollback Protection Bypass)
* **Локация:**
  * `crates/vlt1-daemon/src/lib.rs:468-552` (`Daemon::put_stream`, `Daemon::get_stream`)
  * `crates/vlt1-cli/src/main.rs:198-288` (`put`, `get`)
  * `crates/vlt1-core/src/vault.rs:138-181`, `542-568`
* **Описание и доказательство:**
  В `vlt1-daemon` обычные (base64) обработчики `put` (`crates/vlt1-daemon/src/lib.rs:451-465`) и `get` (`crates/vlt1-daemon/src/lib.rs:559-574`) проверяют `if self.state.witness.is_some()` и вызывают `vault.put_with_witness(...)` и `vault.verify_active_objects_with_witness(...)` соответственно.
  Однако потоковые обработчики `put_stream` и `get_stream` **не проверяют наличие `self.state.witness`**:
  ```rust
  // crates/vlt1-daemon/src/lib.rs:493-495
  let mut reader = StreamReader::new(stream);
  vault.put_from_reader(object_id, &mut reader)
  ```
  и:
  ```rust
  // crates/vlt1-daemon/src/lib.rs:539-541
  let mut writer = StreamWriter::new(stream);
  vault.get_to_writer(object_id, &mut writer)
  ```
  При этом штатный CLI-клиент (`crates/vlt1-cli/src/main.rs:205, 256`) при вызове `vlt1 put` и `vlt1 get` **всегда** отправляет `Request::PutStream` и `Request::GetStream`.
* **Последствия:**
  1. Если демон запущен в профиле `vlt1d-witness@.service` с настроенным внешним witness, любая запись через `vlt1 put` публикует новую версию в SQLite **без получения `WitnessReceipt`** (в таблице `freshness_receipts` запись для новой версии отсутствует).
  2. Последующий вызов `vlt1 verify` или перезапуск и `vlt1 unlock` (`crates/vlt1-daemon/src/lib.rs:387`) вызывает `vault.verify_active_objects_with_witness()`, который находит активный объект без квитанции (`crates/vlt1-core/src/vault.rs:549-552`):
     ```rust
     let receipt = self
         .storage
         .active_receipt(*object_id)?
         .ok_or(VaultError::WitnessConflict)?;
     ```
     и **принудительно блокирует хранилище (`VaultStatus::Locked`) с ошибкой `WitnessConflict`**.
  3. Чтение через `vlt1 get` (`Request::GetStream`) выполняет только локальную проверку `get_to_writer` без обращения к внешнему witness за свежим `WitnessHead`, что позволяет злоумышленнику подменить БД старым валидным снимком (rollback attack) и прочитать откаченные данные через `GetStream`.
* **Рекомендация по исправлению:**
  * В `Daemon::get_stream` перед вызовом `vault.get_to_writer` при `self.state.witness.is_some()` выполнять проверку актуального `object_head` через `witness`.
  * Для `put_stream` при `self.state.witness.is_some()` реализовать двухфазную потоковую публикацию в `vlt1-core`: стейджинг чанков и манифеста в `pending_witness_publications` без продвижения `objects.active_version_id`, запрос `provider.issue_receipt(...)`, и атомарную финализацию через `finalize_witness_publication`.

---

### [MED-01] Необнуление ключевого материала (`SigningKey`, seed, passphrase, bearer token) в памяти процессов

* **Категория:** Криптографическая гигиена / Очистка секретов в памяти
* **Локация:**
  * `crates/vlt1-witness/Cargo.toml:14`, `crates/vlt1-witness/src/main.rs:50-51, 97, 140-160`
  * `crates/vlt1-witness/src/bin/vlt1-witness-key.rs:32-40`
  * `crates/vlt1-cli/src/main.rs:163, 194, 425-433, 476-486`
  * `crates/vlt1-protocol/src/lib.rs:34-46`
  * `crates/vlt1-daemon/src/main.rs:73, 106-112`
* **Описание и доказательство:**
  В `vlt1-core` секретные буферы аккуратно очищаются через `zeroize::Zeroizing` и `.zeroize()`. Однако за пределами `vlt1-core`:
  1. В `crates/vlt1-witness/Cargo.toml` зависимость `ed25519-dalek` подключена без фичи `"zeroize"`:
     ```toml
     ed25519-dalek = { version = "2.1.1", default-features = false, features = ["std"] }
     ```
     В `crates/vlt1-witness/src/main.rs:50, 140-145` 32-байтовый приватный seed читается в `Vec<u8>` и `[u8; 32]`, которые освобождаются без `zeroize()`. Аналогично в `vlt1-witness-key.rs:32-36`.
  2. Парольные фразы в `vlt1-cli` (`prompt_password`) и `vlt1-protocol::Request::{Unlock, RotatePassphrase}` хранятся в обычных `String` и не очищаются после сериализации/десериализации JSON-фрейма.
  3. Bearer-токен witness в `vlt1d` и `vlt1-witnessd` хранится в обычном `String`/`Vec<u8>`, а в `crates/vlt1-witness/src/main.rs:97` при **каждом** входящем HTTP-запросе заново аллоцируется строка `let expected = format!("Bearer {}", String::from_utf8_lossy(token));`, оставляя копии токена в куче.
* **Рекомендация по исправлению:**
  * Включить фичу `zeroize` для `ed25519-dalek` в корневом `Cargo.toml`.
  * Обернуть буферы чтения `signing_seed` и парольных фраз в `Zeroizing`.
  * Предвычислять строку `"Bearer <token>"` один раз при старте `vlt1-witnessd` и хранить её в `Zeroizing<String>`.

---

### [MED-02] Расхождение протокола `docs/WITNESS_PROTOCOL.md` и реализации `vlt1-witness` / `vlt1-core`

* **Категория:** Соответствие спецификации и кода
* **Локация:**
  * `docs/WITNESS_PROTOCOL.md:18, 26, 57, 61`
  * `crates/vlt1-core/src/vault.rs:479-507`
  * `crates/vlt1-witness/src/lib.rs:30-95, 167-170`
  * `crates/vlt1-witness/src/main.rs:78-80`
* **Описание и доказательство:**
  Обнаружены 4 конкретных расхождения между документацией протокола и реализацией:
  1. **Предварительная проверка `head` при публикации:** `docs/WITNESS_PROTOCOL.md:61` утверждает: *"A witness-enabled VLT/1 daemon obtains the current object head before publication, verifies it with a newly random challenge and the pinned key, and requires the local active receipt to equal the head."* В коде `Vault::put_with_witness_inner` (`crates/vlt1-core/src/vault.rs:479-507`) `provider.object_head(...)` перед публикацией **не вызывается** — берется только локальный `self.storage.active_receipt(object_id)` и сразу вызывается `provider.issue_receipt(&request, expected_epoch)`. Если локальная БД отстала, запись уже попадает в `pending_witness_publications` до обнаружения конфликта на `/v1/issue`.
  2. **Тело ответа HTTP 409:** `docs/WITNESS_PROTOCOL.md:26` указывает: *"A different request with a stale expected epoch returns HTTP 409 and a signed current object head."* В `crates/vlt1-witness/src/main.rs:78-80` возвращается статический JSON `{"error":"witness_conflict"}` без подписанного `WitnessHead`.
  3. **Неизвестные поля в JSON:** `docs/WITNESS_PROTOCOL.md:18` требует отвергать неизвестные поля. В `vlt1-protocol` атрибут `#[serde(deny_unknown_fields)]` проставлен везде, но в `crates/vlt1-witness/src/lib.rs:30-95` и `crates/vlt1-core/src/witness.rs:771-814`, а также в `BackupManifest` (`crates/vlt1-core/src/backup.rs:38`) атрибут `#[serde(deny_unknown_fields)]` отсутствует.
  4. **Тип транзакции SQLite:** `docs/WITNESS_PROTOCOL.md:57` указывает `BEGIN IMMEDIATE`, тогда как `self.connection.transaction()` в `rusqlite` по умолчанию открывает `DEFERRED` транзакцию (`crates/vlt1-witness/src/lib.rs:167-170`).
* **Рекомендация по исправлению:**
  * Добавить `#[serde(deny_unknown_fields)]` на структуры `IssueRequest`, `HeadRequest`, `IssueWireResponse`, `HeadWireResponse` и `BackupManifest`.
  * Использовать `TransactionBehavior::Immediate` для пишущих транзакций SQLite.
  * Синхронизировать `docs/WITNESS_PROTOCOL.md` и `put_with_witness_inner` (либо вызывать `object_head` до `stage_witness_publication`, либо зафиксировать в спецификации, что проверка эпохи выполняется самим `/v1/issue`).

---

### [MED-03] Полное сканирование и расшифровка всех объектов хранилища при одиночном `get` с Witness

* **Категория:** Производительность / Архитектура
* **Локация:** `crates/vlt1-daemon/src/lib.rs:559-565`
* **Описание и доказательство:**
  В методе `Daemon::get` при включенном witness перед чтением **одного** объекта вызывается `vault.verify_active_objects_with_witness(witness)?`:
  ```rust
  // crates/vlt1-daemon/src/lib.rs:560-562
  self.with_witness(|vault, witness| {
      vault.verify_active_objects_with_witness(witness)?;
      let plaintext = vault.get(object_id)?;
  ```
  Метод `verify_active_objects_with_witness` (`crates/vlt1-core/src/vault.rs:542-568`) перебирает **все активные объекты в хранилище**, делает сетевой HTTPS-запрос `/v1/head` для каждого объекта и полностью расшифровывает каждый чанк каждого объекта в `std::io::sink()`, после чего `vault.get(object_id)` повторно расшифровывает запрошенный объект.
* **Последствия:**
  Сложность чтения одного объекта через `get` составляет $O(N_{\text{objects}} \times \text{RTT}_{\text{HTTPS}} + \text{TotalVaultSize})$ вместо $O(\text{RTT}_{\text{HTTPS}} + \text{ObjectSize})$. При наличии сотен объектов или гигабайтных данных в хранилище одиночный запрос `get` превысит 5-секундный `io_timeout` сокета.
* **Рекомендация по исправлению:**
  Добавить в `Vault` метод `get_with_witness` / `get_to_writer_with_witness`, который запрашивает `provider.object_head` со случайным `challenge` и сверяет `active_receipt` конкретно для читаемого `object_id`, оставляя полную ревизию всех объектов команде `verify` и стартовому `unlock`.

---

### [LOW-01] Срабатывание линта `clippy::assert_is_empty` на новых версиях компилятора Rust

* **Категория:** Сборка / CI
* **Локация:** `crates/vlt1-core/tests/vault_flows.rs:131`
* **Описание и доказательство:**
  При запуске `cargo clippy --workspace --all-targets -- -D warnings` на `rustc 1.99.1` сборка завершается с кодом `101`:
  ```text
  crates/vlt1-core/tests/vault_flows.rs:131:5: warning: used `assert!` to check that a value is empty
  ```
  В строке 131: `assert!(output.is_empty());` (после `let mut output = Vec::new();` и вызова `get_to_writer`, где тип элементов `Vec<u8>` выводится как слайс байтов).
* **Рекомендация по исправлению:**
  Явно аннотировать `let mut output: Vec<u8> = Vec::new();` или заменить проверку на `assert_eq!(output, Vec::<u8>::new());`.

---

### [LOW-02] Однопоточный блокирующий HTTP-сервер в `vlt1-witnessd` без таймаутов чтения сокета

* **Категория:** Доступность (DoS) / Сетевой стек
* **Локация:** `crates/vlt1-witness/src/main.rs:54-65`
* **Описание и доказательство:**
  `vlt1-witnessd` использует синхронный цикл `for mut request in server.incoming_requests()` библиотеки `tiny_http` в одном потоке. Хотя в продакшене перед ним предполагается обратный TLS-прокси (`127.0.0.1:9823`), медленное чтение заголовков/тела одного соединения блокирует обработку всех остальных запросов, включая `/healthz`.
* **Рекомендация по исправлению:**
  Задокументировать обязательные жесткие таймауты (`client_body_timeout`, `proxy_read_timeout`) для reverse-proxy либо ограничить время чтения на уровне сокета.

---

### [LOW-03] Busy-polling цикл `accept()` с интервалом 5 мс и отсутствие обработки сигналов в `vlt1d`

* **Категория:** Производительность / Эксплуатация
* **Локация:** `crates/vlt1-daemon/src/lib.rs:200-222`
* **Описание и доказательство:**
  `UnixListener` переводится в `set_nonblocking(true)`, и в цикле `while !self.state.shutdown.load(Ordering::SeqCst)` при `WouldBlock` вызывается `thread::sleep(Duration::from_millis(5))`. Это порождает 200 пробуждений процесса в секунду в режиме простоя и добавляет до 5 мс задержки на принятие нового соединения. Кроме того, в `vlt1d` отсутствует обработчик сигналов `SIGTERM`/`SIGINT`, который выставлял бы флаг `shutdown` и удалял файл Unix-сокета при остановке через `systemctl stop` (приходится полагаться на `RuntimeDirectory=` в systemd или удаление старого сокета при следующем старте в `bind_socket`).
* **Рекомендация по исправлению:**
  Использовать `poll(2)` на файловом дескрипторе `UnixListener` + обработку `SIGTERM`/`SIGINT` для грациозного завершения цикла `serve()`.

---

### [LOW-04] Неполная валидация пути в `vlt1 init` на уровне CLI до ввода пароля

* **Категория:** UX / Fail-fast валидация
* **Локация:** `crates/vlt1-cli/src/main.rs:150-169`
* **Описание и доказательство:**
  В `init(path)` перед запросом пароля у пользователя (`prompt_new_passphrase()`) проверяются `path.exists()` и `parent.exists()`, которые следуют по симлинкам (`fs::metadata`). Если `path` является висячей символической ссылкой (dangling symlink) или родительский каталог является симлинком, `path.exists()` вернет `false`, пользователь дважды введет пароль, и только затем `Vault::create` отвергнет путь через `validate_new_regular_file` (`symlink_metadata`).
* **Рекомендация по исправлению:**
  Выполнять проверку `symlink_metadata` на самом пути и всех предках родительского каталога до вызова `prompt_new_passphrase()`.

---

### [LOW-05] Рассинхронизация кешированного поля `verified_active_objects` в `Daemon::status`

* **Категория:** Наблюдаемость / Консистентность статуса
* **Локация:** `crates/vlt1-daemon/src/lib.rs:181-184, 382-425`
* **Описание и доказательство:**
  Поле `recovery.verified_active_objects` обновляется только при вызове `Request::Verify` (`crates/vlt1-daemon/src/lib.rs:416`), но:
  1. Не обновляется при `Request::Unlock` с включенным witness, хотя `unlock` фактически вызывает `vault.verify_active_objects_with_witness(witness)?` (`crates/vlt1-daemon/src/lib.rs:387`).
  2. Не сбрасывается в `None` при `Request::Lock` или при автоматической блокировке хранилища после ошибки аутентификации.
* **Рекомендация по исправлению:**
  Записывать возвращенное число проверенных объектов в `recovery.verified_active_objects` при успешном `unlock` с witness и сбрасывать его при `lock`.

---

## 4. Архитектурный и покомпонентный анализ

### 4.1. `vlt1-core` — Криптографическое ядро и хранилище

* **Иерархия ключей (`crypto.rs`):**
  * **Root Key (256 бит):** Генерируется через `OsRng`, оборачивается ключом из `Argon2id` (`m = 65536 KiB`, `t = 3`, `p = 4`, соль 128 бит) с помощью `AES-256-GCM-SIV` и AAD `"VLT1\x01root\x00" || vault_id`.
  * **Защита от DoS через параметры KDF:** `KdfParams::validate_persisted` жестко ограничивает параметры из БД (`MAX_PERSISTED_MEMORY_KIB = 256 MiB`, `MAX_PERSISTED_ITERATIONS = 10`, `MAX_PERSISTED_LANES = 8`) **до** выделения памяти в `Argon2`.
  * **KEK и DEK:** Из `RootKey` через `HKDF-SHA256` (`salt = vault_id`, `info = "VLT/1-KEK-v1"`) выводится KEK. Каждая версия объекта получает свежий случайный 256-битный `DEK` и 128-битный `VersionId`.
  * **Manifest Key:** Выводится из `DEK` через `HKDF-SHA256` (`salt = version_id`, `info = "VLT/1-MANIFEST-KEY-v1"`).
  * **Привязка контекста (AAD):** Все записи `AES-256-GCM-SIV` включают префикс `"VLT1\x01"` и связывают `vault_id`, `object_id`, `version_id`, а для чанков — `chunk_index` (u32 BE) и `plaintext_chunk_len` (u32 BE). Это исключает перестановку чанков, подмену чанков между объектами/версиями и усечение последнего чанка.
* **Детерминированный CBOR (`cde.rs`):**
  * Собственный минималистичный кодек (230 строк без учета тестов) для карты из 8 целочисленных ключей (`1..=8`).
  * Строго проверяет каноничность кодирования целых чисел (отвергает неминимальные префиксы), порядок ключей, отсутствие хвостовых байтов и точные длины идентификаторов. Покрыт property-based тестами (`proptest`), фиксированными векторами и fuzz-таргетом `manifest_decode`.
* **Хранилище и транзакционность (`storage.rs`, `vault.rs`):**
  * При открытии соединения принудительно выставляются `PRAGMA journal_mode = WAL`, `foreign_keys = ON`, `synchronous = FULL`, `trusted_schema = OFF`.
  * Схема таблиц использует строгие `CHECK`-ограничения на длину BLOB-полей, `UNIQUE(version_id, nonce)` для защиты от повтора nonce и `ON DELETE RESTRICT`.
  * **Двухпроходное чтение (`get_to_writer_inner`):** Сначала распаковывается DEK и манифест, затем в первом проходе `visit_chunks` проверяются непрерывность индексов `0..chunk_count` и общий `SHA-256` дайджест всех зашифрованных чанков (`ChunkDigestBuilder`), и только во втором проходе чанки расшифровываются и пишутся в приемник. При этом чанки стримируются из SQLite курсором без загрузки всего объекта в RAM.
  * **Fail-closed блокировка:** При любой ошибке `Authentication`, `InvalidFormat`, `Invariant`, `Storage`, `WitnessUnavailable` или `WitnessConflict` вызывается `self.lock()`, который немедленно обнуляет `root_key` в памяти (`Zeroizing<[u8; 32]>`).

### 4.2. `vlt1-protocol` — Локальный IPC-контракт

* Протокол использует 4-байтовый big-endian префикс длины.
* Проверка `len > MAX_FRAME_BYTES` (16 MiB) и `len > MAX_STREAM_CHUNK_BYTES` (4 MiB) выполняется **до** аллокации `vec![0u8; len]`, что защищает демон от OOM при некорректных фреймах.
* Все структуры `Request` и `Response` снабжены `#[serde(deny_unknown_fields)]`.
* Имеется fuzz-таргет `fuzz/fuzz_targets/ipc_decode.rs`.

### 4.3. `vlt1-daemon` — Локальный сервис Unix-сокета

* **Аутентификация клиента:** Проверяется ядром Linux через `getsockopt(stream, PeerCredentials)` (`SO_PEERCRED`) на точное совпадение `uid == allowed_uid` до чтения запроса.
* **Контроль ресурсов:** Атомарный счетчик `active_connections` (по умолчанию до 32) и флаг `long_operation_active` (`AtomicBool`) предотвращают исчерпание потоков и блокировку быстрых статус-запросов во время длительных потоковых передач или бэкапов.
* **Безопасность сокета:** Проверяется вся цепочка родительских директорий на отсутствие симлинков (`validate_socket_parent`), сокету выставляются права `0600`.

### 4.4. `vlt1-witness` — Внешний сервис свидетеля свежести (Freshness Witness)

* **Идемпотентность и монотонность эпох:** При повторном запросе `/v1/issue` с теми же `(vault_id, object_id, version_id, commitment)` и `expected_epoch < current.witness_epoch` возвращается ранее подписанная квитанция (`crates/vlt1-witness/src/lib.rs:178-184`), что корректно закрывает окно сбоя между получением ответа от witness и локальным коммитом в `vlt1-core`.
* **Защита от атак повтора (Replay):** `/v1/head` включает 32-байтовый случайный `challenge` клиента в подписываемое сообщение Ed25519 с доменным разделителем `"VLT/1 witness head v1"`.
* **Сравнение токенов:** Выполняется за константное время через `constant_time_eq`.

### 4.5. `vlt1-cli`, скрипты деплоя и CI/CD

* **Безопасная запись открытого текста (`vlt1 get`):** Расшифрованные данные пишутся во временный файл `NamedTempFile` в целевом каталоге с правами `0600`, синхронизируются на диск (`sync_all()`), и публикуются через `fs::hard_link(temporary.path(), output)` с `sync_all()` родительского каталога. Это гарантирует:
  1. Отсутствие перезаписи существующего файла (атомарный отказ ядра `EEXIST` на `link(2)`).
  2. Отсутствие неполного/неверифицированного файла по целевому пути при обрыве потока или ошибке аутентификации на позднем чанке.
* **Systemd и инсталлятор (`deploy/`):** Юниты используют современные директивы изоляции (`NoNewPrivileges=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX` для локального демона).
* **CI/CD (`.github/workflows/`):** Включает проверку форматирования, Clippy, тесты, fault-injection, проверку MSRV 1.75, `cargo-deny` (лицензии и уязвимости), ночной ASan-фаззинг и сборку релизов с `SHA256SUMS`, CycloneDX SBOM и GitHub build provenance attestation.

---

## 5. Приоритизированный план улучшений (Roadmap)

1. **Приоритет 1 (Критично — Безопасность):**
   * Подключить проверку и выпуск квитанций `WitnessProvider` в потоковых методах `Daemon::put_stream` и `Daemon::get_stream` (`crates/vlt1-daemon/src/lib.rs:468-552`) и реализовать потоковый стейджинг для witness в `vlt1-core`.
   * Добавить интеграционный тест в `crates/vlt1-daemon/tests/daemon_flow.rs` и `crates/vlt1-witness/tests/provider_flow.rs`, проверяющий `PutStream` -> `GetStream` -> `Verify` при включенном `WitnessConfig`.
2. **Приоритет 2 (Средний — Криптогигиена и производительность):**
   * Заменить полный вызов `verify_active_objects_with_witness` в `Daemon::get` (и `get_stream`) на точечную проверку свежего `object_head` целевого `ObjectId`.
   * Включить фичу `zeroize` для `ed25519-dalek` и обернуть буферы приватных ключей, токенов и паролей в `Zeroizing` во всех бинарных крейтах (`vlt1-cli`, `vlt1-daemon`, `vlt1-witness`).
   * Добавить `#[serde(deny_unknown_fields)]` на все JSON-структуры протокола witness и манифеста бэкапа; перевести пишущие транзакции SQLite на `TransactionBehavior::Immediate`.
3. **Приоритет 3 (Низкий — Сопровождение и эксплуатация):**
   * Исправить `assert!(output.is_empty())` в `crates/vlt1-core/tests/vault_flows.rs:131` для совместимости с новыми версиями `clippy`.
   * Обновлять и сбрасывать `verified_active_objects` при `unlock` и `lock` в `vlt1-daemon`.
   * Перенести `validate_new_regular_file` в `vlt1 init` до интерактивного ввода пароля.

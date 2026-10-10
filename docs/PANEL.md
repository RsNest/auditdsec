# Веб-панель

Панель — страница агента: состояние, лента событий, баны и доверенные адреса,
диагностика. Она дополняет Telegram-бота, а не заменяет его: бот будит вас ночью,
панель отвечает на вопрос «что вообще происходило».

Панель состоит из статики (`internal/web/assets`, встроена в бинарник) и
HTTP-сервера с API (`internal/api`). Она выключена по умолчанию. Сам агент говорит
только по HTTP и только на loopback; наружу панель публикует обратный прокси (Caddy) с
TLS, и только когда это выбрал владелец в `./install.sh`.

## Как включить

### Suspicious address review

The address section contains a deduplicated review list of failed SSH authentication
sources inside the configured detection window. Low-frequency sources (one to five
failures with the default threshold) are for manual review. The sixth failure triggers
an automatic ban decision. Confirmed active blocks and allowlisted addresses leave
the review queue; all underlying attempts remain in the event journal. Critical
evidence such as `login_after_bruteforce` stays visible even after blocking its source.

After a successful firewall ban, the deck immediately removes ordinary cards for that
address and shows the next remaining card. Buttons are disabled while confirmation or
the request is pending, and already blocked addresses cannot be banned again from a
journal card. Repeated API requests retain the original ban and repeat count.

Failed or disabled enforcement never displays a successful block. The decision remains
recorded, the source stays visible with `needs_attention`, and a manual retry can apply
the same decision. Real automatic blocking requires detection enabled and an enforcing
nftables deployment (`./install.sh --enforce`); the default minimal image records decisions
without changing the firewall. Existing explicit detection settings are not overwritten.

`GET /api/v1/suspects` requires a completed-setup session. It returns `items` with
`ip`, `attempts`, `first`, `last`, `state` (`review` or `needs_attention`), and the latest
representative `event`, plus `threshold`, `window_seconds`, `auto_enforcing` and `truncated`.
Aggregation streams journal records rather than using the latest 200-event page. At most
10,000 addresses are tracked (or the smaller configured `detect.max_tracked`), and 100
are returned; attention items take priority, followed by low-frequency review items.
When `truncated` is true, the UI explicitly points to the full journal. Counts use the
journal and timestamps; they describe observed failures rather than unique TCP packets.

`POST /api/v1/bans` returns the ban with `already_banned`. A successful recorded-only
decision has `applied: false`; firewall rejection returns `502` with `error: "firewall"`.

Обычный путь — `./install.sh` (README, «Веб-панель»): он спрашивает домен или IP,
проверяет DNS, выбирает публичный HTTPS-порт, проверяет его снаружи и печатает ссылку.

Вручную:

```yaml
schema_version: 1
web:
  enabled: true
  upstream_listen: 127.0.0.1:9477        # старое имя: listen — то же самое
  public_https_port: 27431               # публичный порт прокси; 0 = 443
  public_url: https://panel.example.com:27431
  session_ttl: 12h
  trusted_proxies: [127.0.0.1, ::1]
  cert_check: verify                     # verify | expiry | off
```

Переменные окружения: `AUDITDSEC_WEB=1`, `AUDITDSEC_WEB_UPSTREAM_LISTEN`
(старое `AUDITDSEC_WEB_LISTEN`), `AUDITDSEC_WEB_PUBLIC_HTTPS_PORT`,
`AUDITDSEC_WEB_PUBLIC_URL`, `AUDITDSEC_WEB_TRUSTED_PROXIES`, `AUDITDSEC_WEB_CERT_CHECK`.

Сертификат панели агент проверяет сам: раз в час (первый раз через минуту после старта)
TLS-подключение к `public_url` (если сервер не достаёт свой публичный адрес — к
`127.0.0.1` с тем же именем), оценка срока и цепочки. `cert_check: verify` — срок и
цепочка по системным CA; `expiry` — только срок (staging, самоподписанный, частный CA);
`off` — не проверять. Проблема — событие `panel_cert` (warn) не чаще раза в 6 часов;
текущее состояние — поле `panel_cert` в `GET /diagnostics`.

Три порта не путаются:

| Что | Где | Кто слушает |
| --- | --- | --- |
| upstream | `127.0.0.1:9477` (`PANEL_UPSTREAM_PORT`) | агент, обычный HTTP, наружу не виден |
| публичный HTTPS | `PANEL_HTTPS_PORT`: 443 или выбранный | Caddy |
| подтверждение ACME | 80 (HTTP-01), 443 (TLS-ALPN-01) | Caddy или certbot |
| admin API Caddy | `127.0.0.1:2019` | Caddy, только локально |

Публичный адрес, `0.0.0.0`, `[::]` и пустой хост в `upstream_listen` агент не примет.
`public_url` должен содержать тот же порт, что `public_https_port`, иначе конфигурация
отклоняется: ссылка бы не открылась. Агент при каждом старте пишет в журнал
`public_url` и состояние первой настройки (`bootstrap`, `ready`, `locked`).

## Первая настройка

Новая установка не имеет владельца. Пока его нет:

1. Вход принимает только `admin` / `admin`. Ответ — `{"token", "expires", "setup": true}`:
   это **сессия настройки** на 15 минут, а не сессия панели. Все обычные запросы с ней
   получают `401`; проверка на сервере, не в JavaScript.
2. `POST /api/v1/setup/complete` с этой сессией:
   `{login, password, password_confirm, keep_admin_confirmed}`. Сервер проверяет:
   логин 3–64 символа из латиницы, цифр и `. _ - @`, `admin` — только с
   `keep_admin_confirmed: true`; пароль 8–128 символов, строчная и заглавная буква, не
   `admin`, не совпадает с логином, не из списка распространённых; оба поля пароля
   совпадают. Отказ — `400 {"error":"weak_credentials","reasons":[...]}` с кодами
   `password_short`, `password_long`, `password_need_lower`, `password_need_upper`,
   `password_default`, `password_same_as_login`, `password_common`, `password_mismatch`,
   `login_length`, `login_chars`, `login_admin_unconfirmed`.
3. Успех — `204`. Логин и хеш пароля (PBKDF2-SHA256) атомарно пишутся в
   `<state_dir>/panel-credentials.json` (0600), затем метка `panel-setup-done`. Все сессии,
   включая сессию настройки, отзываются; `admin` / `admin` больше не работает. Владелец
   входит заново новыми данными.

Запросы на завершение выполняются по одному: две вкладки не установят две разные пары.
Если запись не удалась — `500 bootstrap_persistence_failed`, настройка не завершена,
полный доступ не выдаётся. Если каталог состояния не записывается уже при старте, панель
сразу сообщает `locked` и не принимает `admin` / `admin`.

После завершения настройки ни перезапуск, ни обновление контейнера, ни повторный
`./install.sh` не возвращают `admin` / `admin`. Если файл учётных данных пропал или
повреждён, вход останавливается (`locked`) с диагностикой в журнале, а не откатывается к
паре по умолчанию. Восстановление — только локально на сервере:
`auditdsec reset-credentials -yes`, затем перезапуск. Старые установки с паролем в
`web.password_hash` / `AUDITDSEC_WEB_PASSWORD_HASH` переносятся в управляемый файл при
первом старте и к `admin` / `admin` не сбрасываются; дальше источник истины — файл.

`GET /api/v1/setup/state` без авторизации → `{"state": "bootstrap" | "ready" | "locked"}`.

## Чем защищён вход

| Что | Как |
| --- | --- |
| Пароль | PBKDF2-SHA256, 310 000 итераций, случайная соль; сравнение за постоянное время. |
| Неверный логин | Проверяется против хеша-обманки той же стоимости, чтобы имя нельзя было подобрать по времени ответа. |
| Подбор | 5 неудач с адреса за 10 минут → `429` с `Retry-After`. Удачный вход сбрасывает счётчик. Параллельных проверок пароля не больше двух. |
| Сессия | 256 бит случайности, в памяти только SHA-256 от токена, не больше 16 сессий, перезапуск завершает все. |
| CSRF | `X-Requested-With: auditdsec` на изменяющих запросах, отказ на чужой `Origin`, токен не в cookie. |
| Адрес клиента | `X-Forwarded-For` принимается только от `trusted_proxies`, иначе берётся адрес сокета. |
| Самоблокировка | Бан собственного адреса отклоняется с `409`. |
| Журнал | Вход, неудача входа, бан, разбан, белый список и mute пишутся в лог агента с адресом. |

## Вид и поведение

Оформление — в духе тёмного лейбла SharX: графит `#0A0C0E`, костяные чернила
`#EDE7DC`, один янтарный акцент и один бирюзовый; акценты только в тексте,
точке или линии, без заливок, градиентов и свечения. Заголовки — Syne,
мелкий текст — Sora (для кириллицы подставлены Unbounded и Manrope: у Syne и
Sora её нет). Третий, красный сигнальный цвет добавлен намеренно: критичное
событие не должно выглядеть как янтарное предупреждение.

**До входа** на экране только логотип, поле логина, поле пароля и кнопка.
Навигации, плиток и данных нет. **После входа** открывается вся панель:

1. портал — две створки расходятся по скроллу, заголовок растёт и сжимается,
   половинки расходятся к краям, под ним суточный круговой график;
2. обзор — фраза о состоянии, показатели, циферблат;
3. события — колода карточек (перетаскивание, стрелки влево/вправо) и журнал
   с фильтрами по важности, типу, периоду, адресу, пользователю и поиском;
4. типы событий, адреса (баны и доверенные), оповещения, система и проверка
   настройки.

Всё, что привязано к скроллу, обратимо; появления срабатывают один раз. При
`prefers-reduced-motion` и без JS показывается готовая страница.

## Что это за файлы

| Файл | Назначение |
| --- | --- |
| `internal/web/assets/index.html` | Каркас. Ни одного встроенного скрипта или стиля: политика безопасности их запрещает. |
| `internal/web/assets/app.css` | Все цвета — переменные на `:root`, светлая тема переопределяет их. |
| `internal/web/assets/core.js` | Состояние, доступ к API, вход, форматы, общие виджеты. |
| `internal/web/assets/feed.js` | Колода карточек и журнал событий. |
| `internal/web/assets/views.js` | Вход, шапка, секции страницы, анимация скролла. |
| `internal/web/assets/i18n.js` | Словари RU и EN. Внутри — строгий JSON, его читает тест. |
| `internal/web/assets/fonts/*.woff2` | Шрифты (подмножества, около 77 КБ). |
| `internal/web/assets/dev/mock.js` | Демонстрационные данные. **Не встраивается в бинарник**, тест это проверяет. |
| `internal/web/web.go` | `go:embed` и раздача статики с заголовками безопасности. |

Ограничения: ни одной внешней зависимости, ни CDN, ни сборщика; код меньше
150 КБ и шрифты меньше 100 КБ (`TestAssetBudget`); значения из журнала
аудита попадают на страницу только через `textContent`.

## Как посмотреть

```sh
make preview          # соберёт preview.html с демо-данными
```

Демо-вход: логин `admin`, пароль `demo`. Параметры:
`?mock=1`, `?scenario=quiet|warn|alert|degraded`, `?theme=dark|light`,
`?lang=ru|en`. При схеме `file:` панель сама переходит в демо-режим.

## Контракт API

Всё под `/api/v1`, время в ISO 8601 UTC, локализация во фронтенде.
Ошибка — код состояния 4xx/5xx и тело `{"error": "код", "message": "текст"}`.
На `401` панель возвращается на экран входа, на `429` пишет, что попыток слишком много.

- `POST /login` `{login, password}` → `{token, expires}`; во время первой настройки
  `admin` / `admin` даёт `{token, expires, setup: true}` (см. «Первая настройка»).
  `401` — неверные данные, `429` — слишком много попыток, `503` — вход остановлен
  (`locked`).
- `GET /setup/state`, `POST /setup/complete` — см. «Первая настройка».
- `POST /logout` → `204`, сессия отзывается сразу.

### Чтение

- `GET /status` — шапка, плитки и баннер на обзоре.

```json
{
  "host": "nl-2-12489", "profile": "simple", "version": "0.3.0",
  "uptime_seconds": 132000, "lang": "ru", "debug": false, "log_level": "info",
  "ban": {"backend": "nftables", "dry_run": false, "enforcing": true},
  "muted_until": null,
  "auditd": {"healthy": true, "last_write": "2026-10-09T19:58:12Z"},
  "counters": {"events_24h": 58, "critical_24h": 1, "warn_24h": 9,
               "events_total": 1898, "alerts_sent": 37,
               "lines_skipped": 2140, "rate_limited": 0},
  "bans_active": 3, "allowlist_count": 2,
  "last_event_time": "2026-10-09T19:58:12Z",
  "rules_loaded": true,
  "by_kind": {"ssh_login_fail": 12, "sudo": 5},
  "hourly": [{"hour": "2026-10-09T19:00:00Z", "info": 4, "warn": 1, "critical": 0}]
}
```

  `by_kind` необязателен: счётчики по типам за сутки для раздела «Типы».
  `hourly` — ровно 24 часа подряд, включая пустые. `rules_loaded`
  необязателен: без него панель считает правила установленными, если за
  сутки были события.

- `GET /events?severity=&kind=&ip=&user=&since=&until=&q=&limit=&before=`
  → `{"items": [...], "next": "курсор или null"}`. Поля события: `id`, `time`,
  `host`, `kind`, `severity`, `user`, `src_ip`, `summary` (уже на нужном
  языке), `args`, `raw`. `before` — `id` последнего показанного события.
- `GET /explain/{kind}?lang=ru` → `{"kind", "what", "risk", "todo"}`.
  Панель принимает и `{"text": "..."}` из трёх строк — тогда она сама режет
  его по переводам строки.
- `GET /bans` → список `{ip, reason, created, until, permanent, repeat_count,
  applied, source}`. `applied` — правило действительно стоит в nftables;
  разница между «заблокирован» и «только записан» видна в таблице.
- `GET /allowlist` → `{ip, added, source}`, где `source` — `manual` или
  `first_login`.
- `GET /config` → действующая конфигурация с замаскированными секретами.
  Панель читает из неё `telegram.min_severity`, `telegram.quiet_hours`,
  `telegram.dedup_window`, `telegram.rate_per_minute`, `telegram.chat_ids`.
- `GET /diagnostics` → `{debug, log_level, counters, audit_log, offset,
  detector, banner, panel_cert}`. `panel_cert` — «ok, valid until …», «PROBLEM: …»,
  «unknown: …» (не удалось подключиться) или «not checked yet»; нет поля — панель не по https.

### Изменение

- `GET /settings/telegram` возвращает настройки, `has_token`, `available_kinds`,
  `status`, `bot_username`, `last_delivery`, `last_error`; поля с токеном нет.
- `PUT /settings/telegram` сохраняет полный набор: `enabled`, `token`, `chat_ids`,
  `kinds`, `min_severity`, `quiet_from`, `quiet_to`, `rate_per_minute`, `bans`,
  `startup_notice`. Пустой `token` сохраняет имеющийся секрет. Если уведомления
  включены, перед записью проверяется `getMe`; проверка не отправляет сообщений.
- `POST /settings/telegram/verify` принимает тот же черновик и проверяет бота,
  `POST /settings/telegram/test` дополнительно отправляет тест каждому получателю.
  Эти операции не сохраняют черновик. Повторные операции ограничены интервалом
  3 секунды; параллельные изменения отклоняются. Все маршруты требуют полной
  сессии владельца, первый вход `admin/admin` до смены пароля их не разрешает.
  `configured` означает наличие настроек, `connected` — успешную доставку текущим
  ботом текущему списку получателей. Проверка токена сама по себе не доказывает
  доставку. Статус доставки относится к текущему запуску и не сохраняется на диск.

Форма находится в **Оповещения → Настроить Telegram** и доступна на русском и
английском. Тихие часы используют часовой пояс агента. Критичные события обходят
тихие часы и ручное приглушение, но исключение категории и отключение Telegram
блокируют также критичные уведомления. Сохранённые настройки имеют приоритет над
исходной конфигурацией. При смене бота старый опрос и команды завершаются перед
запуском нового; курсор Telegram хранится отдельно для каждого токена.

- `POST /bans` `{ip, duration: "1h"|"24h"|"30d"|"permanent", reason}`.
  Адрес из доверенных должен возвращать ошибку с `"error": "allowlisted"` —
  панель показывает её отдельным текстом, потому что это не сбой, а правило.
- `DELETE /bans/{ip}`
- `POST /allowlist` `{ip}` · `DELETE /allowlist/{ip}`
- `POST /mute` `{hours}` → `{muted_until}` · `DELETE /mute`

Панель шлёт `Authorization: Bearer <токен>` и `X-Requested-With: auditdsec`
на изменяющих запросах; сервер должен требовать и то, и другое.


## Контракт RemoteProbe

Внешняя проверка порта выполняется сервисом `cmd/auditdsec-probe`, который владелец
запускает на **другой** машине. Клиент — `auditdsec remote-check` (его вызывает
установщик). Код — `internal/netcheck/probe.go`.

Запрос: `POST /v1/check`, `Authorization: Bearer <token>`, JSON не больше 2 КБ,
неизвестные поля отклоняются:

```json
{"ip": "203.0.113.10", "port": 27431, "family": 4,
 "kind": "nonce", "nonce": "3f9a...", "host": "", "server_name": ""}
```

- `kind: "nonce"` — HTTP `GET /.well-known/auditdsec-probe/<nonce>` на `ip:port`;
  успех, если ответ 200 и содержит nonce. Это временный слушатель установщика
  (`auditdsec probe-listen`), который отдаёт только эту строку и живёт минуты.
- `kind: "tls"` — TLS-рукопожатие с проверкой цепочки для `server_name` (по умолчанию —
  сам адрес), затем `GET /api/v1/setup/state`; успех, если ответ 200 и содержит `"state"`.
- `host` — необязательное имя: принимается, только если разрешается в тот же `ip`;
  соединение всё равно идёт к литералу адреса.

Ответ `200`:

```json
{"result": "reachable", "detail": "", "http_status": 200,
 "tls": {"verified": true, "error": "", "not_after": "2026-10-16T14:19:21Z",
         "sha256": "...", "names": ["203.0.113.10"]}}
```

`result`: `reachable`, `refused` (сброс соединения), `timeout` (нет ответа: файрвол,
security group, NAT или маршрут — без уточнения), `wrong_endpoint` (ответил кто-то
другой или другим протоколом), `unknown` (проверку выполнить не удалось, в том числе цель
запрещена). Коды сервиса: `401` без токена, `400` на неверный JSON, `429` с
`Retry-After` при превышении лимита, `503` — заняты все слоты. Клиент считает любой
не-200 и любую сетевую ошибку `external_check_unavailable`, а не вердиктом о порте.

Ограничения сервиса: токен не короче 32 символов, сравнение за постоянное время; по
умолчанию 30 проверок в минуту всего, 6 в минуту на адрес, 4 одновременно; отказ для
loopback, private, link-local, CGNAT, multicast, документационных и metadata-адресов —
до соединения и ещё раз на сокете; без редиректов; без `-cert` только loopback-адрес.
`-allow-private-targets` и `-roots` существуют для стенда и в публичной установке не
используются. Клиент отправляет токен только по HTTPS (или на loopback).


## Что ещё предстоит

1. Перечитывание `hourly` и `by_kind` постранично: сейчас сутки событий
   читаются целиком и кешируются на 5 секунд, чего хватает до нескольких
   десятков тысяч событий в день.
2. Экспорт событий (CSV) и ссылка на отфильтрованный журнал.
3. Вторая страница для нескольких хостов.
4. Явный режим за CDN/балансировщиком (сейчас поддерживается только DNS-only, прямой
   доступ к VPS) и DNS-01 для домена при закрытых 80 и 443.

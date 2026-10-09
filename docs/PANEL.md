# Веб-панель

Панель — локальная страница агента: состояние, лента событий, баны и
доверенные адреса, диагностика. Она дополняет Telegram-бота, а не заменяет
его: бот будит вас ночью, панель отвечает на вопрос «что вообще происходило».

Сейчас в репозитории лежит только интерфейс (`internal/web/assets`) и
обработчик статики (`internal/web`). HTTP-сервера и API в агенте ещё нет —
этот документ фиксирует контракт, под который интерфейс уже написан.

## Что это за файлы

| Файл | Назначение |
| --- | --- |
| `internal/web/assets/index.html` | Каркас страницы. Ни одного встроенного скрипта или стиля: политика безопасности их запрещает. |
| `internal/web/assets/app.css` | Все цвета — переменные на `:root`, светлая тема переопределяет их. |
| `internal/web/assets/core.js` | Состояние, доступ к API, формат дат, иконки, общие виджеты, шапка, маршрутизация. |
| `internal/web/assets/views.js` | Экраны: обзор, события, баны, оповещения, диагностика, проверка настройки. |
| `internal/web/assets/i18n.js` | Словари RU и EN. Внутри — строгий JSON, его читает тест на совпадение ключей. |
| `internal/web/assets/dev/mock.js` | Демонстрационные данные. **Не встраивается в бинарник**, тест это проверяет. |
| `internal/web/web.go` | `go:embed` и раздача статики с заголовками безопасности. |

Ограничения, которые стоит сохранить: ни одной внешней зависимости, ни CDN,
ни сборщика; иконки и график — рукописный inline SVG; весь встраиваемый
набор меньше 150 КБ (тест `TestAssetBudget`).

## Как посмотреть

```sh
make preview          # соберёт preview.html с демо-данными
```

Страницу можно открыть двойным щелчком. Параметры:
`?scenario=quiet|warn|alert|degraded`, `?theme=dark|light`, `?lang=ru|en`.
Сценарий `degraded` показывает остановленный аудит и баны, которые
записываются, но не применяются.

Отдельные файлы (`internal/web/assets/index.html`) тоже открываются с диска:
при схеме `file:` панель сама переходит в демо-режим.

## Контракт API

Всё под `/api/v1`, время в ISO 8601 UTC, локализация во фронтенде.
Ошибка — код состояния 4xx/5xx и тело `{"error": "код", "message": "текст"}`.
На `401` панель показывает окно ввода токена.

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
  "hourly": [{"hour": "2026-10-09T19:00:00Z", "info": 4, "warn": 1, "critical": 0}]
}
```

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
  detector, banner}`.

### Изменение

- `POST /bans` `{ip, duration: "1h"|"24h"|"30d"|"permanent", reason}`.
  Адрес из доверенных должен возвращать ошибку с `"error": "allowlisted"` —
  панель показывает её отдельным текстом, потому что это не сбой, а правило.
- `DELETE /bans/{ip}`
- `POST /allowlist` `{ip}` · `DELETE /allowlist/{ip}`
- `POST /mute` `{hours}` → `{muted_until}` · `DELETE /mute`

Панель шлёт `Authorization: Bearer <токен>` и `X-Requested-With: auditdsec`
на изменяющих запросах; сервер должен требовать и то, и другое.

## Что ещё предстоит сделать в агенте

1. HTTP-сервер, по умолчанию на `127.0.0.1`. Наружу — только через
   SSH-туннель или обратный прокси; открывать порт в интернет не нужно.
2. Токен доступа в конфигурации, сравнение в постоянном времени, отказ
   стартовать с пустым токеном, если адрес прослушивания не loopback.
3. Реализация `/api/v1/*` поверх `store` и `pipeline`.
4. Ограничение частоты на изменяющие запросы и запись в журнал агента, кто
   что забанил через панель.

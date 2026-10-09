# auditdsec

Лёгкий агент на Go: читает Linux **auditd**, переводит сырые события на человеческий язык
и присылает их в **Telegram**. Для владельцев VPS/VDS, которым важна безопасность,
но не хочется разбираться в `type=SYSCALL arch=c000003e syscall=257`.

Вместо этого вы получаете в чат:

```
🚨 web01 · критично
Изменён файл SSH-ключей /root/.ssh/authorized_keys, пользователь uid=0
2026-10-09 20:14:03
          [🚫 Забанить 198.51.100.7]  [✅ Это я]
```

> **Статус: v0.1 (MVP).** Работают разбор auditd, события, Telegram с кнопками, хранение,
> ротация логов, Docker. Детектор брутфорса и применение банов — v0.2, CrowdSec — v0.3
> (см. [Дорожную карту](#дорожная-карта)).

## Содержание

- [Что он замечает](#что-он-замечает)
- [Чего он не делает](#чего-он-не-делает)
- [Быстрый старт: Docker](#быстрый-старт-docker)
- [Быстрый старт: бинарник](#быстрый-старт-бинарник)
- [Правила аудита](#правила-аудита)
- [Телеграм-бот](#телеграм-бот)
- [Настройки](#настройки)
- [Профили simple и pro](#профили-simple-и-pro)
- [Как это устроено](#как-это-устроено)
- [Безопасность](#безопасность)
- [Дорожная карта](#дорожная-карта)
- [Разработка](#разработка)
- [English](#english)

## Что он замечает

| Событие | Тип | Важность |
|---|---|---|
| Вход по SSH | `ssh_login_ok` | под root — критично, иначе обычное |
| Неудачная попытка входа | `ssh_login_fail` | внимание |
| Команда через sudo или su | `sudo` | обычное |
| Новый пользователь, смена пароля, правка sudoers | `user_change` | критично |
| Изменение `authorized_keys` | `authorized_keys_change` | критично |
| Правка cron, systemd-юнитов, `.bashrc` | `persistence` | внимание |
| Правка `sshd_config` | `config_change` | внимание |
| Чистка журналов, отключение аудита, загрузка модулей ядра | `log_tamper` | критично |
| Запуск программы из `/tmp`, `/dev/shm`, `/var/tmp` | `suspicious_exec` | внимание |
| Аудит остановлен или молчит | `auditd_stopped` | критично |

Последний пункт — главный. Тишина на взломанном сервере выглядит точно так же, как тишина
на спокойном, поэтому агент отдельно следит за тем, что журнал аудита вообще пишется,
и сообщает, если он пропал или не обновлялся слишком долго.

Любой тип можно разобрать подробно: `auditdsec explain authorized_keys_change`
или `/explain authorized_keys_change` в чате — что это значит, насколько опасно, что делать.

## Чего он не делает

Честный список на версию 0.1:

- **не банит сам.** Кнопка «Забанить» записывает решение и показывает его в `/bans`,
  но правила файрвола пока не меняются. Применение — v0.2.
- **не детектирует брутфорс.** Каждая неудачная попытка видна, но «47 попыток за минуту
  с одного адреса» пока не считается отдельным событием. Повторы при этом группируются
  в одно сообщение, так что чат не заливает.
- **не интегрируется с CrowdSec.** Настройки читаются, обмена с LAPI пока нет.
- **не различает вход по ключу и по паролю.** auditd этого прямо не пишет; надёжный
  способ — разбирать и журнал sshd, это в планах.
- **не защищает журнал от root.** Получивший root вычистит локальные логи. Поэтому
  критичные события сразу уходят в Telegram: это и есть копия вне хоста.

## Быстрый старт: Docker

Нужны Docker с Compose и работающий auditd на хосте (`systemctl status auditd`).

```bash
git clone https://github.com/RsNest/auditdsec.git
cd auditdsec

cp .env.example .env
nano .env                 # вписать AUDITDSEC_TG_TOKEN и AUDITDSEC_TG_CHAT_ID

docker compose up -d
docker compose logs -f
```

В чат придёт «auditdsec запущен на …» — значит токен и chat id верные.
Дальше поставьте [правила аудита](#правила-аудита), иначе события по файлам
собираться не будут (входы по SSH и sudo работают и без них).

Контейнер монтирует `/var/log/audit` только на чтение, работает с `read_only: true`,
`cap_drop: ALL` и лимитом 64 МБ. Привилегии ему не нужны.

## Быстрый старт: бинарник

Если Docker не нужен:

```bash
make build
sudo make install                      # /usr/local/bin, /etc/auditdsec, systemd-юнит

sudo install -m 0600 /dev/stdin /etc/auditdsec/auditdsec.env <<'ENV'
AUDITDSEC_TG_TOKEN=123456789:AA...
AUDITDSEC_TG_CHAT_ID=111222333
ENV

sudo systemctl daemon-reload
sudo systemctl enable --now auditdsec
sudo systemctl status auditdsec
```

Бинарник статический, около 7 МБ, без зависимостей; в памяти занимает десятки мегабайт.

## Правила аудита

Входы по SSH, sudo и операции с учётными записями auditd пишет сам через PAM — правила
для них не нужны. А вот слежение за файлами нужно включить:

```bash
sudo make rules          # копирует правила, добавляет .ssh всех пользователей, перезагружает auditd
```

Или вручную:

```bash
sudo cp deploy/auditdsec.rules /etc/audit/rules.d/50-auditdsec.rules
sudo deploy/gen-sshkeys-rules.sh | sudo tee -a /etc/audit/rules.d/50-auditdsec.rules
sudo augenrules --load
sudo auditctl -l | head
```

`gen-sshkeys-rules.sh` нужен потому, что в правилах аудита нельзя написать `/home/*/.ssh`:
маски не поддерживаются, и строка требуется на каждый домашний каталог. После добавления
пользователя скрипт стоит запустить снова.

Имена ключей (`-k ads_identity` и остальные) должны совпадать с теми, что ждёт агент.
Если переименовать ключ в правилах, агент перестанет понимать событие.

Проверить, что всё сошлось:

```bash
sudo touch /etc/passwd            # должно прийти сообщение об изменении учётных записей
```

## Телеграм-бот

Создайте бота у [@BotFather](https://t.me/BotFather), получите токен. Затем напишите
боту любое сообщение и узнайте свой chat id:

```bash
curl -s "https://api.telegram.org/bot<ТОКЕН>/getUpdates" | grep -o '"chat":{"id":[-0-9]*'
```

Бот отвечает **только** чатам из `chat_ids` и без этого списка не запускается: иначе
утёкший токен отдал бы постороннему все команды.

| Команда | Что делает |
|---|---|
| `/status` | хост, профиль, время работы, события за 24 ч, состояние оповещений |
| `/last [N]` | последние события, свежие сверху |
| `/allow <IP>` | добавить адрес в белый список (его нельзя забанить) |
| `/unallow <IP>` | убрать из белого списка |
| `/allowlist` | показать белый список |
| `/bans` | решения о блокировках |
| `/unban <IP>` | снять блокировку |
| `/mute [часы]` | заглушить оповещения (критичные всё равно придут) |
| `/unmute` | включить оповещения |
| `/explain <тип>` | объяснить тип события |
| `/help` | список команд |

Под алертами есть кнопки: **🚫 Забанить**, **✅ Это я** (адрес уходит в белый список)
и **🔕 Тишина 24 ч**.

## Настройки

Всё настраивается файлом (`config.example.yaml` — шаблон с комментариями) или
переменными окружения; переменные важнее файла, поэтому секреты держите в них.

| Переменная | Значение |
|---|---|
| `AUDITDSEC_TG_TOKEN` | токен бота |
| `AUDITDSEC_TG_CHAT_ID` | разрешённые chat id через запятую |
| `AUDITDSEC_PROFILE` | `simple` или `pro` |
| `AUDITDSEC_LANG` | `ru` или `en` |
| `AUDITDSEC_HOST` | имя хоста в сообщениях |
| `AUDITDSEC_AUDIT_LOG` | путь к `audit.log` |
| `AUDITDSEC_STATE_DIR` | каталог состояния |
| `AUDITDSEC_CONFIG` | путь к файлу настроек |
| `AUDITDSEC_LOG_FILE`, `AUDITDSEC_LOG_LEVEL` | свой журнал агента |
| `AUDITDSEC_MIN_SEVERITY` | порог алертов: `info`, `warn`, `critical` |
| `AUDITDSEC_RETENTION_DAYS` | срок хранения событий |

Проверить настройки перед запуском (токен в выводе маскируется):

```bash
auditdsec check-config -config /etc/auditdsec/auditdsec.yaml
```

Полезные параметры файла:

- `min_severity` — порог отправки. События ниже порога всё равно пишутся на диск и видны в `/last`.
- `dedup_window` — окно склейки повторов: одинаковые события внутри окна становятся
  одним сообщением и счётчиком «ещё N».
- `quiet_from` / `quiet_to` — тихие часы для некритичного.
- `rate_per_minute` — предохранитель от шторма сообщений.
- `heartbeat.stale_after` — через сколько молчания журнала считать аудит мёртвым.
- `read_from_start` — читать ли существующий журнал при первом запуске (по умолчанию нет,
  чтобы установка не вылилась в чат историей за месяцы).

## Профили simple и pro

| | simple | pro |
|---|---|---|
| Для кого | один VPS, не админ | 5–10 серверов |
| Порог алертов | `warn` (sudo пишется, но не шлётся) | `info` (всё) |
| Хранение | 14 дней | 90 дней |
| Лимит сообщений | 10/мин | 30/мин |
| Окно склейки | 10 минут | 5 минут |
| Heartbeat | 6 часов | 2 часа |

Профиль — это набор значений по умолчанию, любое из них можно переопределить.

## Как это устроено

```
audit.log → source → parse → semantic → ┬→ store (JSONL по дням)
          (поллинг)  (склейка  (смысл и  └→ notify (Telegram)
                     событий)  важность)
```

- **source** следит за файлом поллингом раз в секунду, понимает ротацию и усечение,
  запоминает смещение, так что перезапуск не теряет и не дублирует события.
- **parse** собирает записи одного события по серийному номеру и раскрывает
  вложенный `msg='...'` и hex-значения, которыми auditd кодирует команды.
- **semantic** переводит это в событие с типом, важностью, пользователем и адресом.
- **store** пишет по файлу JSONL на сутки — ретеншн сводится к удалению старых файлов,
  а сами события остаются читаемыми обычным `grep` и `jq`.
- **notify** применяет политику: порог, mute, тихие часы, склейку повторов, лимит.

Внешних зависимостей нет: только стандартная библиотека Go. Подробнее —
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Безопасность

- **Секреты маскируются.** Пароли и токены в командах заменяются на `***` — и в сообщении,
  и в том, что ложится на диск. auditd кодирует команду в hex, поэтому агент декодирует
  её, маскирует и подменяет hex в сохранённой копии: иначе пароль утекал бы в файл в
  обратимом виде.
- **Токен не попадает в логи.** Он есть только в URL запроса, и из текстов ошибок
  вырезается.
- **Белый список сильнее бана.** Адрес из белого списка забанить нельзя — это защита
  от самоблокировки на динамическом адресе. Добавление в белый список снимает
  существующий бан.
- **Контейнеру не нужны привилегии.** Только чтение `/var/log/audit`, `cap_drop: ALL`,
  `read_only`. Применять баны будет bouncer CrowdSec или отдельный профиль с `NET_ADMIN` —
  агент не должен уметь трогать файрвол по умолчанию.
- **Входящее из чата не доверяется.** Команды принимаются только от разрешённых chat id,
  а значения из журналов экранируются перед отправкой, чтобы путь к файлу не мог
  подделать разметку сообщения.

## Дорожная карта

- **v0.1 — готово.** Разбор auditd, 10 типов событий, Telegram с кнопками и командами,
  белый список, хранение с ретеншном, heartbeat, i18n RU/EN, Docker, systemd.
- **v0.2.** Детектор брутфорса на скользящем окне, применение банов через nftables/ipset,
  эскалация 1 ч → 1 сутки → 30 суток → навсегда для рецидивистов, автоматическое
  добавление адреса владельца в белый список при первом входе по ключу.
- **v0.3.** CrowdSec в обе стороны, проверка настроек хоста (`/score`) с готовыми
  командами исправления, режим обучения на 3–7 дней и алерты на новое поведение.
- **v0.4.** Профиль pro: несколько хостов в одном чате, метрики Prometheus,
  маршрутизация оповещений (ntfy, webhook, Discord), `auditdsec query`.

## Разработка

```bash
make check      # gofmt, go vet, go test
make build      # bin/auditdsec
make docker     # образ
go test ./internal/parse/ -run TestParseLine -v
```

Требуется только Go 1.24, зависимостей нет. Тесты разбора написаны на настоящих строках
`audit.log`, Telegram проверяется через `httptest` без сети.

## English

**auditdsec** is a lightweight Go agent that reads the Linux audit log, explains what
happens on a host in plain language and reports it to Telegram. It is aimed at VPS owners
who care about security without wanting to read raw auditd records.

It reports SSH logins, failed login attempts, sudo commands, account and sudoers changes,
`authorized_keys` edits, persistence (cron, systemd, shell profiles), `sshd_config`
changes, log and audit tampering, execution from temporary directories — and, importantly,
auditd going silent, because silence on a compromised host looks just like silence on a
quiet one.

v0.1 ships parsing, alerting with inline buttons, bot commands, an allowlist that always
wins over a ban, storage with retention, the heartbeat, Russian and English, Docker and
systemd. It does **not** yet enforce bans on the host, detect brute force as such, or talk
to CrowdSec — those are v0.2 and v0.3.

Quick start, configuration, the bot command list and the security notes are in the Russian
sections above; the settings themselves are documented in English in
[`config.example.yaml`](config.example.yaml), and the design is described in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Zero external dependencies: Go standard
library only.

## Лицензия

MIT. См. [LICENSE](LICENSE).

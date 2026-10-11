<h1 align="center">auditdsec</h1>

<p align="center">
  <strong>Безопасность Linux-сервера — понятными событиями.</strong><br>
  Лёгкий агент на Go, веб-панель и уведомления в Telegram для вашего VPS/VDS.
</p>

<p align="center">
  <a href="https://github.com/RsNest/auditdsec/actions/workflows/ci.yml"><img src="https://github.com/RsNest/auditdsec/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/RsNest/auditdsec?logo=go&amp;label=Go" alt="Go version"></a>
  <a href="https://github.com/users/RsNest/packages/container/package/auditdsec"><img src="https://img.shields.io/badge/platform-linux%2Famd64%20%C2%B7%20linux%2Farm64-38bdf8" alt="Linux amd64 and arm64"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/RsNest/auditdsec" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#быстрый-старт">Установка</a> ·
  <a href="#веб-панель">Веб-панель</a> ·
  <a href="#обновление-и-доступ">Обновление</a> ·
  <a href="#документация">Документация</a> ·
  <a href="https://github.com/RsNest/auditdsec/issues">Обратная связь</a> ·
  <a href="#english">English</a>
</p>

---

auditdsec читает Linux **auditd**, объясняет происходящее на сервере и помогает
реагировать: от подозрительного SSH-входа до изменения ключей и остановки аудита.
События остаются в локальном журнале, панель помогает их разобрать, Telegram сообщает
о важном. Бота можно подключить после установки.

```text
🚨 web01 · критично
Изменён файл SSH-ключей /root/.ssh/authorized_keys, пользователь uid=0
                 [🚫 Забанить IP]  [✅ Это я]
```

## Возможности

- **Понятные события.** SSH, sudo/su, учётные записи, SSH-ключи, cron и systemd,
  конфигурация SSH, вмешательство в журналы и запуск программ из временных каталогов.
- **Брутфорс и последствия.** Неудачные SSH-входы, успешный вход после серии попыток,
  контекст SSH-сессии и связанные события в одном инциденте.
- **Блокировки через nftables.** Ручные и автоматические решения, эскалация срока,
  доверенные адреса и защита от самоблокировки. Применение включается отдельно.
- **Управляемые оповещения.** Настройка Telegram из панели, категории, важность,
  тихие часы, группировка повторов и очередь доставки, сохраняемая при перезапуске.
- **Контроль самого агента.** Состояние auditd, диагностика, проверка правил и
  сертификата панели. Отсутствие событий и недоступность аудита показываются отдельно.
- **Свои данные на своём сервере.** Журнал JSONL с ретеншном, маскирование секретов,
  экспорт событий и инцидентов через API. Go-агент использует стандартную библиотеку.

## Веб-панель

**От общего состояния — к конкретному событию и действию.** Тёмная и светлая темы,
русский и английский интерфейс, адаптивная вёрстка. В тёмной теме — графитовый фон,
янтарные и бирюзовые акценты; критические события выделяются красным.

| Раздел | Что можно сделать |
| --- | --- |
| **Обзор** | Оценить состояние аудита, активность за сутки и события, требующие внимания. |
| **События** | Листать карточки или открыть журнал с поиском и фильтрами по времени, важности, типу, пользователю и IP; посмотреть детали и объяснение события. |
| **Инциденты** | Разобрать связанные события, подтвердить инцидент, закрыть его или вернуть в работу. |
| **Исключения** | Приглушить конкретную ожидаемую активность на ограниченный срок. События остаются в журнале; критические уведомления не подавляются. |
| **Адреса** | Проверить подозрительные IP, решения о блокировках и доверенные адреса. Видно, применён ли бан в файрволе. |
| **Оповещения** | Подключить Telegram, проверить бота, отправить тест и изменить настройки без перезапуска. |
| **Система** | Посмотреть диагностику, состояние очереди уведомлений, конфигурацию с замаскированными секретами и проверки настройки. |

[Описание панели и API →](docs/PANEL.md) ·
[Инциденты →](docs/ARCHITECTURE.md#incidents) ·
[Исключения →](docs/ARCHITECTURE.md#exceptions)

<details>
<summary><strong>Посмотреть интерфейс локально с демонстрационными данными</strong></summary>

```bash
make preview
```

Откройте созданный `preview.html`. Демо-вход: `admin` / `demo`.
Это локальный макет с тестовыми данными, не подключение к вашему серверу.
[Параметры предпросмотра](docs/PANEL.md#как-посмотреть).

</details>

## Быстрый старт

**Нужно:** Linux amd64/arm64, Docker с Compose, Git, curl и работающий auditd на хосте.
Для HTTPS — домен с DNS на сервер или публичный IPv4/IPv6, доступный порт панели и
порты подтверждения сертификата: для IP — 80, для домена — 80 или 443.

```bash
git clone https://github.com/RsNest/auditdsec.git
cd auditdsec
sudo ./install.sh
```

Запускайте **от root** (`sudo ./install.sh`): без root установщик останавливается до
любых изменений, сам `sudo` не вызывает и пароль не спрашивает. `--help`, `--status`
и `--status --json` работают и без root.

Установщик по этапам (`[1/6] … [6/6]`) проверяет сервер, спрашивает, как открывать панель
(домен, IP-адрес или SSH-туннель), скачивает **готовый образ из GHCR**, проверяет адрес и
порты, показывает план и просит подтвердить, запускает Caddy и сертификат и проверяет
панель. Исходники на VDS компилировать не нужно. Порт панели начинается с **443**; если
он занят, установщик скажет, чем, и спросит другой порт. Занятый порт он не освобождает и
правила файрвола не меняет. Баннер и цвета — только в терминале (`NO_COLOR=1`,
`NO_BANNER=1` отключают их); результат всегда содержит слова `[ OK ]`, `[WARN]`, `[FAIL]`.

В итоге раздельно сказано: приложение отвечает, HTTPS проверен (сертификат), и что с
проверкой снаружи: подтверждена, не проводилась или не прошла. **RemoteProbe не нужен**:
это необязательная дополнительная проверка с другого узла
(`--probe-url`, `--probe-token-file`; отдельная команда `sudo ./install.sh --remote-check`).
Без неё установщик проверяет всё, что может, с самого сервера, и честно пишет, чего не
проверял; это не ошибка. [Контракт RemoteProbe](docs/PANEL.md#контракт-remoteprobe).

<details>
<summary><strong>Запустить RemoteProbe на другом сервере</strong></summary>

На отдельной машине с Go и копией репозитория:

```bash
go build -o auditdsec-probe ./cmd/auditdsec-probe
umask 077
./auditdsec-probe -generate-token > probe.token
./auditdsec-probe -listen :8443 -cert fullchain.pem -key privkey.pem -token-file probe.token
```

Сертификат должен соответствовать адресу RemoteProbe. Передайте установщику URL
этого сервиса и путь к файлу с тем же токеном на устанавливаемом VDS:
`--probe-url https://probe.example.net:8443 --probe-token-file /root/probe.token`.

</details>

После успешных проверок установщик покажет ссылку. На новой установке вход
**`admin` / `admin`** открывает только обязательную настройку нового логина и пароля.
После её завершения стандартный пароль отключается.

Установите правила наблюдения за файлами на хосте:

```bash
sudo make rules
```

Без этих правил файловые события не собираются. После добавления пользователей
обновите правила для их `.ssh`. Для диагностики используйте
[`auditdsec check-rules` и `auditdsec doctor`](docs/DOCTOR.md).

<details>
<summary><strong>Другие варианты установки и доступа</strong></summary>

**Только через SSH-туннель:** `sudo ./install.sh --mode tunnel`.
Установщик покажет команду туннеля и локальную ссылку.

**С применением блокировок:** `sudo ./install.sh --enforce`.
Потребуются nftables и capability `NET_ADMIN`; обычная установка только записывает
решения о блокировке.

**Тестовый сертификат:** `sudo ./install.sh --staging`.
Браузер не доверяет staging-сертификату. Для перехода на production:
`sudo ./install.sh --production`.

**Бинарник и systemd** — альтернативная установка из исходников:

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now auditdsec
```

Настройки — `/etc/auditdsec/auditdsec.yaml`;
[шаблон конфигурации](config.example.yaml). Веб-панель требует отдельного включения
и настройки доступа по [инструкции](docs/PANEL.md#как-включить).

Все параметры: `./install.sh --help`.

</details>

## Обновление и доступ

Повторный запуск установщика открывает меню: проверить состояние, подключить или
сменить домен, перейти на IP или SSH-туннель, сменить учётные данные, обновить приложение.
Сохранённые настройки, события и сертификаты используются повторно.

То же можно сделать в панели: **Настройки → Доступ и HTTPS** (мастер «Подключить домен»).
Панель сама ничего не меняет: изменение применяет установщик через небольшую локальную службу,
которую включает `sudo ./install.sh --enable-panel-control`. Без неё панель покажет точную команду для сервера.
Подробности и границы проверки: [Доступ и HTTPS](docs/ACCESS.md).

```bash
sudo ./install.sh
```

Выберите **«Обновить приложение»**. В Git-копии установщик предложит получить новые
исходники через `git pull --ff-only`, затем скачает образ соответствующего коммита.
При проблемах с новой конфигурацией предусмотрено восстановление предыдущей.

Набор Compose-файлов сохраняется в `.env` (`COMPOSE_FILE`), поэтому из каталога установки
обычные `docker compose up -d`, `pull` и `restart` сохраняют выбранный режим доступа; указывать `-f`
вручную не нужно. Свой дополнительный файл добавляется строкой `PANEL_COMPOSE_EXTRA='путь'` в `.env`
и применяется при следующем запуске установщика. Если панель отвечает 502, а агент работает:
`sudo ./install.sh --action check` покажет сети контейнеров и причину, а
`sudo ./install.sh --action repair` запустит сохранённую конфигурацию (данные и сертификаты не трогаются).

```bash
sudo ./install.sh --status     # текущий адрес и состояние
sudo ./install.sh --restore    # последняя проверенная конфигурация
sudo ./install.sh --logs       # последние операции и их trace ID
sudo ./install.sh --logs ID    # все записи одной операции
```

Логи всех компонентов — JSON-строки в `/var/log/auditseclogs` с `trace_id`, скрытыми
секретами и ротацией: [Логи и диагностика](docs/LOGS.md).

Образы для amd64/arm64:
[агент](https://github.com/users/RsNest/packages/container/package/auditdsec) ·
[агент с nftables](https://github.com/users/RsNest/packages/container/package/auditdsec-enforce) ·
[RemoteProbe](https://github.com/users/RsNest/packages/container/package/auditdsec-probe).
Установщик использует тег `sha-<commit>`; сборки публикуются после проверок
[GitHub Actions](https://github.com/RsNest/auditdsec/actions/workflows/ci.yml).

**Сохраняйте весь том состояния при обновлении и резервном копировании**, включая
очередь уведомлений и её маркер инициализации. Не удаляйте их для обхода ошибки запуска.
[Доставка и восстановление](docs/DELIVERY.md).

## Telegram

Создайте бота через [@BotFather](https://t.me/BotFather), напишите ему и подключите
токен и chat ID в **Оповещения → Настроить Telegram**. Доступны тест бота, тестовое
сообщение и сохранение без перезапуска. До подключения Telegram агент и панель работают.

Основные команды: `/status`, `/last`, `/incidents`, `/bans`, `/allowlist`,
`/ban`, `/unban`, `/mute`, `/unmute`, `/explain`, `/debug`. Полный список — `/help`.
Под алертами — **«Забанить»**, **«Это я»** и **«Тишина 24 ч»**.
Критические уведомления обходят mute и тихие часы.

## Документация

| Материал | Содержание |
| --- | --- |
| [Панель и API](docs/PANEL.md) | Вход, интерфейс, RemoteProbe и HTTP API. |
| [Архитектура](docs/ARCHITECTURE.md) | Сбор событий, сессии, детектор, инциденты, исключения и блокировки. |
| [Логи и диагностика](docs/LOGS.md) | Каталог логов, формат, `trace_id`, ротация, ошибки браузера. |
| [Доступ и HTTPS](docs/ACCESS.md) | Смена домена, IP и туннеля из установщика и из панели, откат, что проверено. |
| [Диагностика](docs/DOCTOR.md) | Проверки `doctor`, причины ошибок и способы исправления. |
| [Доставка уведомлений](docs/DELIVERY.md) | Очередь, повторы, ограничения и восстановление. |
| [Конфигурация](config.example.yaml) · [.env](.env.example) | Параметры агента и установщика. |
| [Проверка развёртывания](docs/VERIFY.md) | Воспроизводимые проверки и границы тестирования. |

Экспорт доступен авторизованному пользователю через API:
`/api/v1/export/events` — JSONL/CSV,
`/api/v1/export/incidents` — JSON/CSV.
Поддерживаемые параметры — в [реализации экспорта](internal/api/export.go).

## Границы продукта

auditdsec наблюдает за одним Linux-хостом и опирается на доступные записи аудита.
Обычная установка **не меняет файрвол**; блокировки применяются только при включённом
nftables backend. Доверенный IP имеет приоритет над баном.

Публичная панель работает через HTTPS-прокси; агент слушает только loopback.
Токены и пароли маскируются, но контроль root над хостом позволяет вмешаться в локальные
журналы. Внешние уведомления зависят от доступности Telegram и сети.

CrowdSec, управление несколькими хостами и режим обучения остаются в
[дорожной карте](docs/ARCHITECTURE.md#roadmap).

## Разработка

Нужен Go версии из [go.mod](go.mod). `make check` запускает форматирование, vet и
тесты; для тестов сертификатов нужен Python с `cryptography`.

```bash
make check
make build
make preview
```

Локальная Docker-сборка для разработки: `sudo ./install.sh --build-local`.
[Ошибки и предложения](https://github.com/RsNest/auditdsec/issues) ·
[Pull requests](https://github.com/RsNest/auditdsec/pulls).

## English

**auditdsec** is a self-hosted Linux security agent with a web panel and optional
Telegram alerts. It turns auditd records into readable events, detects SSH brute force,
correlates incidents and can enforce nftables bans when explicitly enabled.

The panel includes an event journal, incidents, targeted exceptions, suspicious and
trusted addresses, Telegram settings and diagnostics. It supports Russian/English and
dark/light themes. Events and incidents can be exported through the authenticated API.

Run `./install.sh` to download a prebuilt amd64/arm64 image, configure domain or IP HTTPS
and complete first-time setup. External reachability verification requires a RemoteProbe
provider on another machine; `--no-external-check` skips that verification. Run the
installer again to change access or update. Keep the complete state volume across upgrades.

[Panel & API](docs/PANEL.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Diagnostics](docs/DOCTOR.md) · [Delivery](docs/DELIVERY.md).

---

Лицензия: [MIT](LICENSE).

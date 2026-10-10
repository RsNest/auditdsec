# Проверка установщика

Здесь отдельно: что проверено **на настоящем Docker**, что **со стендом без демона**, и
что **не проверено вообще**. Подменённое на стенде не выдаётся за проверенное в жизни.

## 0. Публичная панель, этап 0 (scripts/e2e/stage0)

Стенд — одноразовая Linux-машина или привилегированный контейнер `docker:dind`, который
играет роль VPS: в нём свой `dockerd`, и стенд меняет там правила iptables и занимает
порты. **Не запускайте его на рабочей машине.**

```sh
scripts/e2e/stage0/lab.sh up            # CoreDNS, Pebble, RemoteProbe
scripts/e2e/stage0/scenarios.sh         # 13 сценариев, PASS/FAIL на каждое утверждение
python3 scripts/e2e/stage0/interactive.py   # вопросы через настоящий pty
scripts/e2e/stage0/lab.sh down
```

| Настоящее в жизни | На стенде |
|---|---|
| публичный DNS | CoreDNS с зоной `.test`; установщик направлен на него `PANEL_DNS_RESOLVERS` |
| Let's Encrypt | Pebble 2.9.0 (`httpPort 80`, `tlsPort 443`, профиль `shortlived`) |
| внешний узел RemoteProbe | `auditdsec-probe` в контейнере в **отдельной** Docker-сети: его соединения входят в VPS через сетевой интерфейс и проходят цепочку INPUT, где стенд ставит DROP |
| публичный IP | адрес `docker0` внутри VPS (частный, поэтому `--public-ip` и `-allow-private-targets` у зонда) |
| файрвол провайдера | правило `iptables -j DROP` на VPS для трафика из «внешней» сети |

Настоящие: Docker 29 и Compose, образы `caddy:2.10-alpine` и `certbot/certbot:v5.8.0` с
Docker Hub, сборка `deploy/Dockerfile` на `golang:1.24-alpine`, host networking, тома,
выпуск сертификатов по HTTP-01 и TLS-ALPN-01 (Pebble ходит на 80 и 443 VPS), агент.

Сценарии (последний прогон: 70 из 70 утверждений, интерактивный — 11 из 11):

| Сценарий | Что доказывает |
|---|---|
| `ip_auto` | IP, автоматический порт: 443 свободен и достижим снаружи, порт 80 достижим, сертификат выпущен и проверен снаружи; итог «published», `admin / admin`, ссылка последней строкой без `:443`; токен зонда не в выводе; временный слушатель удалён; агент пишет `public_url` |
| `setup_persists` | сессия настройки не читает события; после настройки повторный `./install.sh` не печатает `admin / admin`, `admin / admin` отвергается, новый логин входит |
| `manual_port` | порт 27431 вручную: ссылка `https://IP:27431`, проверенный сертификат на 27431, на 443 ничего |
| `port_in_use` | занятый порт → `port_in_use`, выход 10, занявший процесс не тронут, нет ссылки |
| `firewall_timeout` | DROP на порту → `external_port_unreachable`, выход 11, «timeout», стек не запущен |
| `auto_skips_blocked` | DROP на 443 → выбран случайный порт из 20000–29999, ссылка с ним |
| `no_probe` | без RemoteProbe → `external_check_unavailable`, выход 12 |
| `dns_mismatch` | A на чужой адрес, и смешанные A (свой + чужой) → `dns_mismatch`, выход 13; имя нормализуется (`MIXED.test.` → `mixed.test`) |
| `domain` | домен на 443: Caddy получает сертификат, «published» |
| `challenge_blocked` | IP, DROP на 80 → `acme_challenge_unreachable`, выход 14 |
| `domain_alpn` | домен на 443, DROP на 80 → предупреждение, выпуск через TLS-ALPN-01, «published» |
| `no_external` | `--no-external-check` → выход 0, но «NOT published» и `Link (NOT published)` |
| `persistence_fails` | том состояния только для чтения → агент не стартует, `service_start_failed`, выход 17, `admin / admin` не предлагается. Узкий случай `bootstrap_persistence_failed` (агент работает, но не может записать учётные данные) проверяется Go-тестом `TestUnwritableStateDirStopsFirstTimeSetup` и путём `locked` в установщике, но не на стенде |

Наблюдение за сертификатом панели: после `ip_auto` и `setup_persists` (с `KEEP=1`) через
минуту `GET /api/v1/diagnostics` вернул `"panel_cert":"ok, valid until …"`, в `.env` —
`PANEL_CERT_CHECK=expiry` (на стенде задан `--cacert`). Сигнал о проблеме (`panel_cert` в
Telegram) проверен Go-тестами `TestPanelCertificateIsWatched` и `TestCertProblem`, на стенде
не вызывался: истекающий сертификат там не моделировался.

`interactive.py`: первый вопрос — домен или IP, туннеля в меню нет, адрес раньше порта,
порт раньше e-mail, итог «published», ссылка последней строкой; повторный запуск
переносит панель на порт, введённый руками, и не спрашивает зонд повторно.

Коды `certificate_issuance_failed` и `tls_validation_failed` на этом стенде не вызывались
(для них нужен отказ CA после успешной проверки порта 80 или чужой сертификат); их
ветки проверены только чтением кода.

## 1. На настоящем Docker-демоне (scripts/e2e/real), до этапа 0

**После переписывания установщика эти сценарии не перезапускались.** Они вызывают его
с `--no-external-check` (проверки снаружи у них нет) и опираются на прежние формулировки
итога; часть утверждений может не совпасть. Прежний `interactive.py` удалён: меню из
четырёх пунктов и вопроса про staging больше нет, его заменяет
`scripts/e2e/stage0/interactive.py`.

Запускается настоящий `dockerd`, настоящий `docker compose`, настоящие контейнеры:
сеть хоста, именованные тома, bind mount, `cap_drop`, healthcheck, перезапуск.
Внутри работают настоящие **certbot 5.8.0** (релиз с PyPI) и **Caddy 2.10**, и агент,
собранный из этого дерева. ACME-сервер — **Pebble** (тестовый сервер Let's Encrypt),
два экземпляра: один изображает staging, другой — production.

**Что в этом стенде заменено** (регистры и серверы Let's Encrypt недоступны из среды, где
это писалось):

| Настоящее | Здесь |
|---|---|
| образ `certbot/certbot:v5.8.0` с Docker Hub | образ с тем же тегом, собранный `FROM scratch`: тот же certbot 5.8.0, но не официальный образ |
| образ `caddy:2.10-alpine` | то же: официальный бинарник Caddy 2.10.0 в образе `FROM scratch` |
| сборка `deploy/Dockerfile` (стадия `build` на `golang:1.24-alpine`) | заменена `go build` с теми же флагами; стадия `minimal` повторена `FROM scratch` |
| Let's Encrypt staging и production | два Pebble, выпускающие профиль `shortlived` (6 дней) на IP и обычные сертификаты на имя |

Повторить:

```sh
CADDY_BIN=/путь/к/caddy scripts/e2e/real/lab.sh up     # dockerd, образы, два Pebble
scripts/e2e/real/scenarios.sh                           # все сценарии (несколько десятков минут)
scripts/e2e/real/scenarios.sh ip_promote untrusted      # выборочно
scripts/e2e/real/lab.sh down
```

Нужны: `docker` с `compose`, `dockerd` (если демон не запущен, `lab.sh` поднимет свой), `go`,
`python3` с `venv`, `openssl`, `curl`, `git` (клонирует и собирает Pebble; зависимости у
него в `vendor/`, доступ к прокси модулей не нужен).

Сценарии и что каждый доказывает:

| Сценарий | Проверяется |
|---|---|
| `tunnel` | запуск в настоящем контейнере; панель только на loopback, не на других адресах; `.env` 0600; `$` в хеше не потерян |
| `selfsigned` | сертификат проверяется по корню собственного CA прокси; пароль идёт по проверенному TLS; без CA клиент соединение не проверит |
| `ip_promote` | staging → повторный запуск (сертификат переиспользован, не заменён) → `--production`: другой сертификат на 443, другой CA, HSTS `max-age=0` → `max-age=31536000`; тома staging на месте и не тронуты; агентский том (события) сохранён; `meta.json` фиксирует окружение |
| `domain_promote` | то же для домена через Caddy (ACME HTTP-01 к Pebble) |
| `ip_change` | смена IP: старый сертификат отвергнут с причиной «it is for … not for …», выпущен новый, SAN новый, старая версия осталась в архиве certbot |
| `domain_to_ip` | прокси домена держит порт 80, установщик останавливает **свой** прокси на время выпуска, выпуск проходит, порт 80 свободен после, данные домена не удалены |
| `domain_to_ip_fails` | выпуск не удался (недоступный ACME): установщик возвращает работающий домен, тот же сертификат, прежний пароль входит, `.env.failed` (0600) сохранён, certbot-контейнера не осталось |
| `restore` | непроверенный прогон не затирает `.env.last-good`; `--restore` возвращает проверенную конфигурацию, лишние контейнеры убраны |
| `untrusted` | production-сертификат без доверия: итог «NOT trusted», код возврата ≠ 0, вход проверен **только** на loopback, **в логе прокси нет ни одного `/api/v1/login`**; контрольный прогон с `--cacert` показывает, что такой запрос в логе был бы виден |
| `reuse` | подложенный в production-том сертификат staging отвергнут по окружению; подменённый приватный ключ обнаружен, выпуск не повторялся: использована исправная копия certbot |
| `renew_and_reload` | естественное продление (`certbot renew`, без `--force`), новый сертификат на 443 совпадает с файлом; reload отвергнут Caddy → `RELOAD FAILED` в логе, healthcheck падает, Docker помечает контейнер `unhealthy`, на 443 прежний сертификат; после исправления цикл сам повторяет reload без нового продления, 443 отдаёт новый сертификат, контейнер снова `healthy` |
| (всегда в конце) | в выводе установщика и логах контейнеров нет пароля, хеша и токена |


Отдельно, внутри настоящего контейнера certbot: `python3 -m unittest deploy/test_certtool.py`
(16 проверок решения «можно ли использовать этот сертификат»: SAN для IP и имени, IPv6,
срок, ещё-не-действителен, чужой ключ, staging-издатель в production, окружение и ACME-сервер
в `meta.json`).

## 2. Стенд с подменённым Docker-демоном (scripts/e2e/run.sh)

Для машины без демона: настоящий `docker compose config`, но `docker` заменён скриптом,
который запускает настоящий агент и настоящий Caddy как обычные процессы. Он проверяет
только **`tunnel` и `selfsigned`**; для `selfsigned` он не умеет `compose cp`, поэтому честно
отвечает «не удалось проверить сертификат» и вход идёт через loopback. Режимы `domain`
и `ip` этим стендом больше не проверяются: их проверяет настоящий Docker выше.

```sh
CADDY_BIN=/путь/к/caddy scripts/e2e/run.sh tunnel
CADDY_BIN=/путь/к/caddy scripts/e2e/run.sh selfsigned --site 127.0.0.1
scripts/e2e/stop.sh
```

## 3. Остальное

```sh
make check            # gofmt, go vet, go test, тесты certtool
shellcheck -x install.sh scripts/e2e/*.sh scripts/e2e/real/*.sh scripts/e2e/stage0/*.sh deploy/*.sh
```

SSH-туннель проверялся на локальном sshd (`ssh -N -L … -p 2222 …`), а не между двумя
машинами; в настоящем Docker проверена только сторона сервера (панель на loopback).

## 4. Не проверено

1. **Настоящий Let's Encrypt, staging и production.** Всё идёт против Pebble. Не
   проверены: ответ реального CA на `--ip-address` и профиль `shortlived`, лимиты
   (5 сертификатов за 168 часов), проверка HTTP-01 и TLS-ALPN-01 из интернета, отличия
   production CA от Pebble. **Успех на Pebble или в staging не означает, что production
   заработает**: production считается рабочим только когда установщик подтвердил его сам.
2. **Доступность из настоящего интернета.** Внешняя проверка на стенде идёт из соседней
   Docker-сети через файрвол VPS. Файрвол провайдера, security group, настоящий NAT и
   маршрутизация не моделировались. Работающего публичного RemoteProbe нет: его нужно
   поднять владельцу на другой машине.
3. **Настоящий публичный DNS** и распространение записей: стенд — один CoreDNS, поэтому
   «серверы расходятся во мнениях» не воспроизводилось; это покрыто Go-тестами
   `internal/netcheck`.
4. **IPv6** — ни AAAA-проверка с реальным DNS, ни выпуск на IPv6-адрес, ни внешняя
   проверка по IPv6 не прогонялись (в стенде только IPv4).
5. **Прокси/CDN перед доменом** не поддерживается и не проверялся: установщик требует
   DNS-only записи.
6. **`certificate_issuance_failed` и `tls_validation_failed`** на стенде не вызывались;
   их ветки проверены чтением кода.
7. **Старые сценарии `scripts/e2e/real`** и стенд `scripts/e2e/run.sh` после переписывания
   установщика не перезапускались.
8. **Разные версии Docker Compose:** проверено на Docker 29.x.
9. **Режим `enforce` (nftables)** вместе с панелью не прогонялся.
10. **Внешний аудит безопасности** установщика и зонда не проводился.

## Stage 1.3 focused verification

Unit tests cover journal-to-outbox recovery after an interrupted import, legacy migration
without retrospective notifications, durable intake receipts, compaction, torn-tail repair,
fail-closed corrupt/missing state, queue reserves, critical backpressure, independent workers,
provider acknowledgment counters, policy suppression, durable grouping and Telegram route
validation/error classification. Tests use local fake senders or `httptest`; no real owner
receives messages. CI runs the full Go suite with the race detector on Linux and publishes
commit-tagged amd64/arm64 images only after the checks pass.

No live VDS, real Telegram outage, or forced machine power loss was exercised for this
stage. Crash behavior is verified at the persisted journal/WAL boundaries; the unavoidable
provider-acceptance/receipt gap is documented as at-least-once delivery.

## Stage 1.5 focused verification

`internal/redact` and `internal/sanitize` tests cover: PROCTITLE hex with NUL-separated
arguments, EXECVE arguments where the option and its value are separate fields or sit in
separate records, fragmented `a1[0]` arguments, a hex sudo command, terminal input,
undecodable (odd-length) hex, headers, `NAME=value` environment arguments, sub-command
keywords, commands embedded in `sh -c` arguments, tool-specific options (sshpass, mysql,
redis-cli, curl, docker login, openssl), and everyday commands that must stay unchanged
(`mkdir -p`, `ssh -p`, `docker run -p`, `--user 1000:1000`). Idempotency is asserted on
every representation, and decoding/output bounds on oversized input.

`TestSecretsNeverReachPersistentFiles` drives realistic audit lines through the mapper and
the pipeline with a notifier that puts the whole event into its plan, then scans every file
the agent wrote (event journal, outbox WAL) for each planted secret in plain and hex form.
It was checked to fail when the pipeline guard is disabled.

Not verified: a live auditd on a real host; arguments of programs the tables do not know;
secrets typed after a prompt; text in free-form fields other than the ones listed. The
masking is pattern based, not a guarantee. Retained journals written by earlier versions are
not rewritten; the events API masks them on the way out, so a stored secret can still sit
in an old file on disk.

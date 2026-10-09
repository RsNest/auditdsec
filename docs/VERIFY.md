# Проверка установщика

Что проверено живым запуском, как это повторить и что проверить нельзя без настоящего
сервера. Сборка образа остаётся неинтерактивной; вопросы и итог — только в `install.sh`.

## Повторяемые проверки

Нужны: `docker` CLI (используется настоящий `docker compose config`, демон не нужен),
`go`, `python3`, `openssl`, `curl`, для режимов с прокси — `caddy` (`CADDY_BIN=/путь`).

```sh
make check                                   # gofmt, vet, тесты Go
bash -n install.sh && shellcheck install.sh  # если shellcheck установлен

# Установщик целиком, с подменой docker-демона (scripts/e2e/fakedocker):
# настоящий compose-интерполятор, настоящий агент, настоящий Caddy.
scripts/e2e/run.sh tunnel
scripts/e2e/run.sh selfsigned --site 127.0.0.1
scripts/e2e/run.sh ip --site 127.0.0.1       # exit=1 ожидаем: тестовый сертификат недоверенный
scripts/e2e/run.sh domain --site example.test --email a@b.c   # нужен резолв имени
scripts/e2e/stop.sh
```

Что доказывают прогоны: хеш с `$` и кавычками переживает `.env` → Compose → агент
(установщик входит в панель выбранным паролем), повторный запуск сохраняет хеш и
настройки, пароль и токен не попадают в вывод, а сертификат без доверия не получает
зелёную сводку.

### Настоящий SSH-туннель

```sh
# локальный sshd на 127.0.0.1:2222 (ключ, пользователь tunneluser), агент на 19477
ssh -N -L 29477:127.0.0.1:19477 -p 2222 tunneluser@127.0.0.1 &
curl --noproxy '*' -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:29477/   # 200
```

### Совместимость Compose

```sh
PANEL_DOMAIN=old.example.com docker compose -f docker-compose.yml -f deploy/compose.proxy.yml config | grep -i public_url
docker compose -f docker-compose.yml -f deploy/compose.proxy.yml config            # без PANEL_SITE/PANEL_DOMAIN — ошибка с подсказкой
docker compose --env-file .env -f docker-compose.yml -f deploy/compose.proxy.yml \
  -f deploy/compose.acme-ip.yml config | grep -A1 'type: bind'                    # пути абсолютные
```

Конфигурации Caddy проверены настоящим Caddy 2.10:
`caddy validate --config deploy/Caddyfile` (с `PANEL_SITE`, `PANEL_UPSTREAM`),
`deploy/Caddyfile.selfsigned`, `deploy/Caddyfile.acme-ip` (нужны `/certs/*.pem`).

## Не проверено (нужен настоящий сервер с Docker и интернетом)

1. Настоящая сборка образа и `docker compose up` в контейнерах: проверялся бинарник и
   `compose config`, а не работа демона.
2. Выпуск сертификата Let's Encrypt для домена через Caddy (HTTP-01/TLS-ALPN-01).
3. Выпуск `shortlived`-сертификата на публичный IPv4 и IPv6, его продление и перезагрузка
   Caddy хуком из контейнера certbot. Сам certbot подменён заглушкой; опции
   (`--ip-address --preferred-profile shortlived`) и версия ≥ 5.3 не сверены с реальным
   `certbot/certbot:latest`.
4. Доступность порта 80/443 из интернета, фаервол провайдера, NAT.
5. Публичный IPv6, A/AAAA с несколькими адресами в реальном DNS.
6. Допущение, что `docker compose config` показывает `$` как `$$` и это не влияет на
   запуск: проверено на установленной версии Compose, поведение других версий — нет.
7. SSH-туннель проверен на локальном sshd, а не через сеть между двумя машинами.

Первый боевой запуск имеет смысл делать с `./install.sh --staging`, чтобы не упереться в
лимит Let's Encrypt (5 сертификатов за 168 часов).

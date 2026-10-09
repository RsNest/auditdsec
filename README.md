# auditdsec

Лёгкий агент на Go: читает Linux **auditd**, переводит сырые события на человеческий язык,
присылает их в **Telegram** и банит брутфорс (собственный детектор + **CrowdSec**).
Для владельцев VPS/VDS (профиль `simple`) и админов 5–10 серверов (профиль `pro`).

> Статус: ранняя разработка (v0.1 в работе). Архитектура — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Возможности (план)
- Разбор `/var/log/audit/audit.log`: входы по SSH, sudo, новые пользователи, правки `authorized_keys`, персистенция, заметание следов
- Алерты в Telegram с кнопками «Забанить IP», «Это я», «Заглушить на 24ч»
- Детектор брутфорса и эскалация банов (1ч → 1д → 30д → навсегда после рецидивов), allowlist от самобана
- Интеграция с CrowdSec (отправка событий и получение решений)
- Docker как основной способ установки, статический бинарник как запасной; ротация логов, лимиты ресурсов
- Русский язык по умолчанию, English поддерживается

## Roadmap
- v0.1 парсер, события, Telegram, Docker
- v0.2 детектор брутфорса, баны, профили audit-правил
- v0.3 CrowdSec, hardening-чек, режим обучения
- v0.4 профиль pro: мультихост, метрики, маршрутизация

## English
auditdsec is a lightweight Go agent that reads Linux auditd logs, explains events in plain language,
alerts via Telegram and bans brute-force attackers (built-in detector + CrowdSec). Early development.

## Лицензия
MIT

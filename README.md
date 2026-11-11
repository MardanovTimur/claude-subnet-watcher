# tg-claude-check-bot

Сервис мониторинга IP-подсетей Claude (Anthropic) для маршрутизатора с **Podkop (OpenWrt)** + **Telegram-бот** для уведомлений и управления.

Не требует внешних Python-библиотек — работает на стандартной библиотеке Python 3.11+.

## Что делает сервис

1. **Скачивает официальную Markdown-документацию** `https://platform.claude.com/docs/en/api/ip-addresses.md`.
2. **Парсит и валидирует CIDR-подсети** через модуль `ipaddress`, строго отделяя активные подсети (`Inbound`, `Outbound`, `IPv6`) от устаревших (`Phased out IP addresses`).
3. **Раздаёт готовые текстовые списки по HTTP** (по одной подсети на строку — формат `Remote Subnet List` в Podkop) и сохраняет их в папку `data/`:
   - `/inbound.txt` — только Inbound IPv4 (`160.79.104.0/23`, `153.61.224.0/22`)
   - `/outbound.txt` — только Outbound IPv4 (`160.79.104.0/21`, `153.61.208.0/20`)
   - `/all.txt` — все активные IPv4 (Inbound + Outbound без дублей)
   - `/supernets.txt` — минимальные агрегированные суперсети IPv4 (`ipaddress.collapse_addresses`, **рекомендуется для Podkop**, чтобы не дублировать пересекающиеся `/23` внутри `/21`)
   - `/ipv6.txt` — IPv6 подсети (`2607:6bc0::/48`)
   - `/all-with-ipv6.txt` — все активные IPv4 + IPv6
   - `/status.json` — полный статус и метаданные в JSON
4. **Отправляет уведомления в Telegram**, если Anthropic изменил список IP или если при проверке возникла ошибка (при ошибке Podkop продолжает получать последний валидный кэш).
5. **Отвечает на команды в Telegram**:
   - `/start` — справка и показ вашего `TG_CHAT_ID`
   - `/status` — текущие подсети в кэше и время последней проверки
   - `/check` — принудительно проверить документацию прямо сейчас
   - `/urls` — список ссылок для Podkop

## Быстрый старт

1. Скопируйте конфиг и укажите `TG_BOT_TOKEN` и `TG_CHAT_ID`:
   ```bash
   cp .env.example .env
   nano .env
   ```
2. Разовая проверка парсера и генерация файлов в `data/`:
   ```bash
   python3 app.py --once
   ```
3. Запуск сервера и бота:
   ```bash
   python3 app.py
   ```

### Запуск через systemd

```bash
sudo cp tg-claude-check-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tg-claude-check-bot
sudo systemctl status tg-claude-check-bot
```

### Запуск через Docker Compose

```bash
docker compose up -d --build
```

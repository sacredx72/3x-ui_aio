# 3x-ui_aio — LucX-UI All-in-One installer

Автоматическая установка proxy/VPN-сервера на VPS (Ubuntu 24.04/26.04, Debian 12/13):

- **LucX-UI** (форк 3x-ui) — VLESS/VMess/Trojan/Hysteria2/MTProto/AWG и sidecar-протоколы;
- **nginx** — SNI-роутинг на :443 (`stream` + `ssl_preread`), TLS панели и подписок, decoy-сайт;
- **AdGuard Home** — DoH `https://<DOMAIN>/dns-query` и DoT `<DOMAIN>:853` для внешних клиентов,
  админка только на секретном пути `https://<DOMAIN>/adg-<random>/`;
- **UFW + fail2ban** — открыты только нужные порты, баны сканеров и перебора SSH.

## Быстрый старт

```bash
cp aio.env.example aio.env      # заполните домены (A-записи → IP сервера)
chmod 600 aio.env
sudo bash lucx-ui-aio.sh        # или: sudo bash lucx-ui-aio.sh --env /path/aio.env
```

Пустые логины/пароли генерируются автоматически. Итоговые данные выводятся в терминал и
сохраняются в `/root/lucx-ui-credentials.txt` и `/etc/x-ui/install-result.env` (права 600);
в лог установки `/root/lucx-ui-install.log` они не пишутся.

## Безопасность (v11)

| Что | Как |
|---|---|
| Панель, подписка, vhost 7443/9443, Xray REALITY 8443, AdGuard (web/DNS) | слушают только `127.0.0.1` |
| Наружу | SSH (автоопределение порта, `ufw limit`), 80, 443/tcp, Hysteria2/udp, 853 (DoT), порты sidecar без SNI-маршрута, AWG/udp |
| Форвардинг | `ufw default deny routed`, разрешён только из AWG-подсетей |
| AdGuard API | корневой `/control/` закрыт, доступ только через секретный путь |
| Сканеры | ловушки (`/.env`, `/wp-login.php`, `/phpmyadmin`, …) → `444` + бан fail2ban на сутки |
| Загрузки | LucX-UI и AdGuard Home закреплённых версий, SHA256 (`.sha256` / `checksums.txt`), sidecar сверяются с `lucx-pins.txt` |
| Сертификаты | `certbot.timer`, ACME через nginx :80 → loopback, без остановки nginx |
| Сбой установки | бэкап `/root/lucx-backup-*/` (nginx, x-ui.db, AGH yaml, UFW), откат невалидного nginx, восстановление UFW |

## Переменные aio.env

См. комментарии в [`aio.env.example`](aio.env.example). Новые в v11:
`LUCX_VERSION`, `AGH_VERSION` (пусто — проверенные пины, `latest` — последний релиз),
`TIMEZONE`, `SSH_PORTS`, `ACME_PORT`. Неизвестные переменные игнорируются с предупреждением.

## Уже установленный сервер (v10)

`lucx-ui-aio-autofix.sh` переносит клиентов Hysteria2/MTProto из `settings.users[]` в
`settings.clients[]` (с `auth` / FakeTLS-секретом) и выполняет `x-ui migrate`:

```bash
sudo bash lucx-ui-aio-autofix.sh --dry-run   # показать изменения
sudo bash lucx-ui-aio-autofix.sh             # применить (с бэкапом БД)
```

## Проверка после установки

Скрипт сам выполняет диагностику (сервисы, `nginx -t`, loopback-биндинги, UFW, fail2ban,
DoH/DoT self-test) и завершается с кодом `2` при критических ошибках. Работу клиентов
проверьте реальным подключением.

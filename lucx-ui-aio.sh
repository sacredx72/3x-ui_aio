#!/bin/bash
###############################################################################
#  LucX-UI All-in-One Installer  v11 (2026)
#  ─────────────────────────────────────────────────────────────────────────────
#  v11: Hysteria2/MTProto в settings.clients[] (auth / FakeTLS secret); пины
#  версий LucX-UI/AGH + SHA256; панель/подписка/vhost/REALITY только 127.0.0.1;
#  AGH API без корневого /control/; DoT — TLS в nginx → plain DNS AGH;
#  UFW: автоопределение SSH, deny routed (кроме AWG), только нужные порты;
#  fail2ban (sshd + honeypot); certbot без остановки nginx; бэкап + откат nginx;
#  строгая валидация env; секреты не попадают в лог установки.
#  ─────────────────────────────────────────────────────────────────────────────
#  v10: keygen awg/wg/cryptography + validate; AWG seed keys+allowedIPs; AWG 3.1 defaults;
#  AGH upstreams/filters; DoT after AGH; nginx panel SSL + no 502→404 mask.
#  Устанавливает:
#    • LucX-UI панель (AlexeyLCP/lucx-ui — форк 3x-ui с AmneziaWG + sidecars)
#    • Nginx как SNI-stream + reverse-proxy (всё на 443)
#    • Let's Encrypt TLS (certbot, standalone)
#
#  XRAY inbounds (за 443):
#    VLESS-REALITY (+Vision — flow задаётся на клиенте) | VLESS-WS+TLS
#    VLESS-XHTTP+TLS (UDS) | VLESS-XHTTP+TLS (2-й UDS) | VLESS-gRPC+TLS
#    Trojan-gRPC | VMess-WS+TLS | VLESS-HTTPUpgrade | Hysteria2 (свой UDP-порт)
#  XRAY inbounds (опционально за 443 через SNI-домены):
#    VLESS-XHTTP+REALITY (-x x.example.com) | VLESS-gRPC+REALITY (-g g.example.com)
#    Без домена — на прямых портах (REALITY-инбаунд = один на SNI).
#
#  LucX-UI sidecar inbounds (панель управляет sidecar-бинарниками сама):
#    NaiveProxy | olcRTC | qWDTT | mieru | TrustTunnel (-u tt.example.com)
#    Telegram MTProto Proxy (mtg) | Telegram WEB proxy (tproxy, -t tg.example.com)
#
#  Подписки: sub / json / clash-mihomo — автоопределение клиента по User-Agent.
#
#  ОС: Ubuntu 24.04 / 26.04, Debian 12 / 13  (amd64 / arm64)
#  Запуск: sudo bash lucx-ui-all-in-one-v7.sh \
#            [--env /path/to/lucx-ui-all-in-one-v7.env] \
#            [-d panel.example.com] [-r reality.example.com] \
#            [-x xhttp-reality.example.com] [-g grpc-reality.example.com] \
#            [-t tgweb.example.com] [-u trusttunnel.example.com]
#  Конфигурационный файл: переменные можно задать в env-файле
#  lucx-ui-all-in-one-v7.env (рядом со скриптом или через --env <путь>).
#  Пустые значения в env/аргументах — скрипт запросит ввод по ходу установки.
#    -x/-g — SNI-домены для REALITY-транспортов за 443 (нужны A-записи,
#            реальные сертификаты НЕ нужны — nginx форвардит raw TCP в xray)
#    -t    — домен Telegram WEB proxy (нужна A-запись + сертификат)
#    -u    — домен TrustTunnel (нужна A-запись + сертификат; клиенты TT
#            подключаются только к порту 443!)
###############################################################################
# set -e отключён в пользу обработки ошибок через функции
# Ошибки обрабатываются только через die()/ok()/warn()
set -uo pipefail


# ─── Цвета ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
inf()  { echo -e "${BLUE}[--]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}  $*"; }
die()  { err "$*"; exit 1; }

# ─── Самопроверка целостности скрипта (heredoc/синтаксис) ───────────────────
# Ловит порчу heredoc/шаблонов (например, «line 729: =: command not found»)
# до того, как скрипт начнёт писать конфиги.
if [[ -s "$0" && -r "$0" ]] && ! bash -n "$0" 2>/tmp/lucx-syntax-err; then
    err "Скрипт повреждён (синтаксис/heredoc):"
    cat /tmp/lucx-syntax-err >&2
    die "Восстановите скрипт из чистой копии и повторите запуск"
fi
rm -f /tmp/lucx-syntax-err

# ─── Лог-файл установки ─────────────────────────────────────────────────────
# Весь вывод скрипта дублируется в /root/lucx-ui-install.log
LOG_FILE="/root/lucx-ui-install.log"
mkdir -p /root
touch "$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" 2>/dev/null || true
# fd 3 — исходный stdout (терминал): учётные данные выводятся только туда, не в лог
exec 3>&1
exec > >(tee -a "$LOG_FILE") 2>&1

# ─── Root check ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Запустите от root: sudo bash $0"

# ─── OS detection ───────────────────────────────────────────────────────────
[[ -f /etc/os-release ]] && source /etc/os-release || die "Не удалось определить ОС"
case "${ID:-}" in
    ubuntu|debian) ;;
    *) die "Поддерживаются только Ubuntu 24.04/26.04 и Debian 12/13. Обнаружено: ${ID:-unknown}" ;;
esac
case "${ID}:${VERSION_ID:-}" in
    ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
    *) warn "ОС ${ID} ${VERSION_ID:-?} не тестировалась (поддержка: Ubuntu 24.04/26.04, Debian 12/13)" ;;
esac

# ─── Архитектура ────────────────────────────────────────────────────────────
get_arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64)           echo 'amd64'  ;;
        armv8*|arm64|aarch64)       echo 'arm64'  ;;
        armv7*|arm)                 echo 'armv7'  ;;
        i*86|x86)                   echo '386'    ;;
        *) die "Неподдерживаемая архитектура: $(uname -m)" ;;
    esac
}
ARCH=$(get_arch)

###############################################################################
# Вспомогательные функции
###############################################################################

# Случайный порт в диапазоне 10000-59151
rand_port() { echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 )); }

# Трекер портов, уже выданных этим скриптом (free_port раньше не помнил свои же значения)
declare -a USED_PORTS=()

# Проверка: порт уже выдан скриптом или занят в системе (TCP/UDP)
is_port_used() {
    local p="$1" line
    for u in "${USED_PORTS[@]:-}"; do
        [[ "$u" == "$p" ]] && return 0
    done
    while IFS= read -r line; do
        [[ "$line" == *":$p " || "$line" == *":$p"$ ]] && return 0
    done < <(ss -ltnuh 2>/dev/null)
    return 1
}

# Свободный порт (TCP+UDP учёт + память скрипта)
free_port() {
    local p tries=0
    while true; do
        p=$(rand_port)
        if ! is_port_used "$p"; then
            USED_PORTS+=("$p")
            echo "$p"
            return
        fi
        tries=$((tries+1))
        [[ $tries -gt 200 ]] && die "Не удалось найти свободный порт после 200 попыток"
    done
}

# Случайная строка из букв/цифр
rand_str() { openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c "$1"; }

# Случайная шестнадцатеричная строка
rand_hex() { openssl rand -hex "$1"; }

###############################################################################
# Загрузка конфигурации из ENV-файла
###############################################################################
# Путь к скрипту и каталогу
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
SCRIPT_NAME="$(basename "$0")"
# Дефолтный env-файл: aio.env (рядом со скриптом); fallback — <имя-скрипта>.env
DEFAULT_ENV_FILE="${SCRIPT_DIR}/aio.env"
[[ -f "$DEFAULT_ENV_FILE" ]] || DEFAULT_ENV_FILE="${SCRIPT_DIR}/${SCRIPT_NAME%.sh}.env"

# load_env_file читает файл в формате:
#   ПЕРЕМЕННАЯ = "значение"
#   (пробелы вокруг "=" допускаются; inline-комментарии — через " #")
# Пустая строка = переменная задаётся пустой (скрипт запросит/сгенерирует).
# Разрешённые переменные env-файла (остальные игнорируются с предупреждением)
ENV_ALLOWED_RE='^((REALITY_|TG_WEB_|XHTTP_R_|GRPC_R_|TT_)?DOMAIN|PANEL_USER|PANEL_PASS|AGH_USER|AGH_PASS|INSTALL_ADGUARD|SKIP_PKG|SKIP_CLEANUP|LUCX_VERSION|AGH_VERSION|TIMEZONE|SSH_PORTS|[A-Z0-9_]+_PORT|AWG[0-9]+_SUBNET|AMNEZIAWG_SUBNET)$'
load_env_file() {
    local f="$1" line name value
    [[ -f "$f" ]] || return 0
    inf "Конфигурация из файла: $f"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line//$'\r'/}"                         # убрать CR (Windows)
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        name="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
        if [[ "$value" =~ ^\"([^\"]*)\" || "$value" =~ ^\'([^\']*)\' ]]; then
            value="${BASH_REMATCH[1]}"                 # в кавычках '#' — часть значения
        else
            [[ "$value" == \#* ]] && value=""
            value="${value%%[[:space:]]#*}"            # inline-комментарий
            value="${value%"${value##*[![:space:]]}"}" # правый trim
        fi
        if [[ ! "$name" =~ $ENV_ALLOWED_RE ]]; then
            warn "env: неизвестная переменная ${name} — пропущена"
            continue
        fi
        printf -v "$name" '%s' "$value"
        export "${name?}"
    done < "$f"
}

###############################################################################
# Инициализация доменов + загрузка ENV-файла (до генерации портов/кредов,
# чтобы PANEL_USER / PANEL_PASS / PANEL_PORT могли быть переопределены)
###############################################################################
DOMAIN=""
REALITY_DOMAIN=""
TG_WEB_DOMAIN=""
XHTTP_R_DOMAIN=""
GRPC_R_DOMAIN=""
TT_DOMAIN=""
DO_UNINSTALL="n"
SKIP_PKG="n"
SKIP_CLEANUP="n"
ENV_FILE=""

# 1-й проход CLI: ищем --env <путь> / --env=<путь>
CLI_ARGS_SAVED=("$@")
for ((_i=0; _i<${#CLI_ARGS_SAVED[@]}; _i++)); do
    if [[ "${CLI_ARGS_SAVED[$_i]}" == "--env" ]]; then
        ENV_FILE="${CLI_ARGS_SAVED[$((_i+1))]}"
        break
    fi
    if [[ "${CLI_ARGS_SAVED[$_i]}" == "--env="* ]]; then
        ENV_FILE="${CLI_ARGS_SAVED[$_i]#--env=}"
        break
    fi
done

# Загружаем env-файл: приоритет — переданный --env, иначе дефолтный рядом
if [[ -n "$ENV_FILE" ]]; then
    load_env_file "$ENV_FILE"
else
    load_env_file "$DEFAULT_ENV_FILE"
fi

###############################################################################
# Переменные (генерируются один раз)
###############################################################################

# ─── Порты: фикс из env или случайный свободный (NEW v7.2) ──────────────────
# Если переменная порта задана в env (непустая) — используется на ВСЕХ этапах
# (панель, xray, nginx stream/vhost, UFW, отчёт/креды). Пусто — генерируется сам.
pick_port() {
    local name="$1" cur p
    cur="${!1:-}"
    if [[ -n "$cur" ]]; then
        if ! [[ "$cur" =~ ^[0-9]+$ ]] || (( cur < 1 || cur > 65535 )); then
            die "env ${name}='${cur}': должен быть числом 1-65535"
        fi
        if is_port_used "$cur"; then
            die "env ${name}=${cur}: порт уже занят/используется скриптом"
        fi
        USED_PORTS+=("$cur")
        echo "$cur"
        return
    fi
    free_port
}

# Проверка подсети AWG из env (формат a.b.c.1/24, сервер — последний октет .1)
validate_awg_subnet() {
    local name="$1" val="$2"
    [[ "$val" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/24$ ]] || die "env ${name}='${val}': ожидается CIDR /24 (например 10.221.0.1/24)"
    local last="${val%%/*}"; last="${last##*.}"
    [[ "$last" == "1" ]] || die "env ${name}='${val}': адрес сервера должен оканчиваться на .1 (gateway туннеля)"
}

# ─── AdGuard Home (NEW v7.3) ────────────────────────────────────────────────
# 1 — установить (по умолчанию), 0 — пропустить. Задаётся в aio.env.
INSTALL_ADGUARD="${INSTALL_ADGUARD:-1}"
[[ "$INSTALL_ADGUARD" =~ ^[01]$ ]] || die "env INSTALL_ADGUARD='${INSTALL_ADGUARD}': ожидается 1 (установить) или 0 (пропустить)"
# NEW v7.3: логин/пароль админки AdGuard Home — можно задать в aio.env
# (AGH_USER / AGH_PASS); пусто — admin + случайный пароль.
AGH_USER="${AGH_USER:-admin}"
AGH_PASS="${AGH_PASS:-$(rand_str 20)}"

# Панель (порт можно переопределить в env-файле; пусто — случайный свободный)
PANEL_PORT=$(pick_port PANEL_PORT)         # internal web UI
SUB_PORT=$(pick_port SUB_PORT)             # subscription server (панель, loopback)
# Порт certbot standalone (loopback) для продления через nginx :80 без остановки nginx
ACME_PORT=$(pick_port ACME_PORT)

# XRAY внутренние порты (слушают 127.0.0.1, nginx проксирует)
VLESS_WS_PORT=$(pick_port VLESS_WS_PORT)
VLESS_GRPC_PORT=$(pick_port VLESS_GRPC_PORT)
TROJAN_GRPC_PORT=$(pick_port TROJAN_GRPC_PORT)
VMESS_WS_PORT=$(pick_port VMESS_WS_PORT)

# NEW v5: SNI-домены для REALITY-транспортов за 443 (опционально)
VLESS_XHTTP_R_PORT=$(pick_port VLESS_XHTTP_R_PORT)  # VLESS + XHTTP + REALITY
VLESS_GRPC_R_PORT=$(pick_port VLESS_GRPC_R_PORT)    # VLESS + gRPC + REALITY
# NEW v4: HTTPUpgrade за nginx (443)
VLESS_HU_PORT=$(pick_port VLESS_HU_PORT)

# Hysteria2 — свой UDP-порт (по умолчанию 443/udp; можно переопределить в env)
HY2_PORT="${HY2_PORT:-443}"
[[ "$HY2_PORT" =~ ^[0-9]+$ ]] || die "env HY2_PORT='${HY2_PORT}': должен быть числом"
if is_port_used "$HY2_PORT"; then die "HY2_PORT=${HY2_PORT}: порт уже занят/используется"; fi
USED_PORTS+=("$HY2_PORT")

# Sidecar-протоколы (LucX-UI запускает сам через panel)
NAIVE_PORT=$(pick_port NAIVE_PORT)         # NaiveProxy (caddy-naive, свой TLS)
OLCRTC_PORT=$(pick_port OLCRTC_PORT)       # olcRTC
QWDTT_PORT=$(pick_port QWDTT_PORT)         # qWDTT (DTLS/UDP)
MIERU_PORT=$(pick_port MIERU_PORT)         # mieru
TRUSTTUNNEL_PORT=$(pick_port TRUSTTUNNEL_PORT)  # TrustTunnel
ANYTLS_PORT=$(pick_port ANYTLS_PORT)       # AnyTLS
TG_PORT=$(pick_port TG_PORT)               # Telegram MTProto
TPROXY_PORT=$(pick_port TPROXY_PORT)       # Telegram WEB proxy (caddy, за nginx SNI)

# NEW v10.1: AWG kernel × 9 (AWG1..AWG9) + native AmneziaWG
# Версии: 1–3 → 1.5, 4–6 → 2.0, 7–9 → 3.1
AWG1_PORT="${AWG1_PORT:-53201}"; AWG1_SUBNET="${AWG1_SUBNET:-10.221.0.1/24}"
AWG2_PORT="${AWG2_PORT:-53202}"; AWG2_SUBNET="${AWG2_SUBNET:-10.222.0.1/24}"
AWG3_PORT="${AWG3_PORT:-53203}"; AWG3_SUBNET="${AWG3_SUBNET:-10.223.0.1/24}"
AWG4_PORT="${AWG4_PORT:-53204}"; AWG4_SUBNET="${AWG4_SUBNET:-10.224.0.1/24}"
AWG5_PORT="${AWG5_PORT:-53205}"; AWG5_SUBNET="${AWG5_SUBNET:-10.225.0.1/24}"
AWG6_PORT="${AWG6_PORT:-53206}"; AWG6_SUBNET="${AWG6_SUBNET:-10.226.0.1/24}"
AWG7_PORT="${AWG7_PORT:-53207}"; AWG7_SUBNET="${AWG7_SUBNET:-10.227.0.1/24}"
AWG8_PORT="${AWG8_PORT:-53208}"; AWG8_SUBNET="${AWG8_SUBNET:-10.228.0.1/24}"
AWG9_PORT="${AWG9_PORT:-53209}"; AWG9_SUBNET="${AWG9_SUBNET:-10.229.0.1/24}"
AMNEZIAWG_PORT="${AMNEZIAWG_PORT:-53210}"; AMNEZIAWG_SUBNET="${AMNEZIAWG_SUBNET:-10.230.0.1/24}"
[[ -n "${AWG15_PORT:-}" ]] && AWG1_PORT="$AWG15_PORT"
[[ -n "${AWG20_PORT:-}" ]] && AWG2_PORT="$AWG20_PORT"
[[ -n "${AWG31_PORT:-}" ]] && AWG3_PORT="$AWG31_PORT"
[[ -n "${AWG15_SUBNET:-}" ]] && AWG1_SUBNET="$AWG15_SUBNET"
[[ -n "${AWG20_SUBNET:-}" ]] && AWG2_SUBNET="$AWG20_SUBNET"
[[ -n "${AWG31_SUBNET:-}" ]] && AWG3_SUBNET="$AWG31_SUBNET"
for _awg_n in AWG1 AWG2 AWG3 AWG4 AWG5 AWG6 AWG7 AWG8 AWG9 AMNEZIAWG; do
    _awg_p="${_awg_n}_PORT"; _awg_s="${_awg_n}_SUBNET"
    [[ "${!_awg_p}" =~ ^[0-9]+$ ]] || die "env ${_awg_p}='${!_awg_p}': должен быть числом"
    is_port_used "${!_awg_p}" && die "AWG-порт ${!_awg_p} (${_awg_p}) уже занят/используется"
    validate_awg_subnet "${_awg_s}" "${!_awg_s}"
done
USED_PORTS+=( "$AWG1_PORT" "$AWG2_PORT" "$AWG3_PORT" "$AWG4_PORT" "$AWG5_PORT" \
              "$AWG6_PORT" "$AWG7_PORT" "$AWG8_PORT" "$AWG9_PORT" "$AMNEZIAWG_PORT" )

# Пути (секретные)
PANEL_PATH="/$(rand_str 10)"
SUB_PATH="/$(rand_str 10)"
JSON_PATH="/$(rand_str 10)"
CLASH_PATH="/$(rand_str 10)"
AWG_PATH="/$(rand_str 10)"
WS_PATH="/$(rand_str 12)"
XHTTP_PATH="/$(rand_str 12)"
XHTTP_TLS_PATH="/$(rand_str 12)"
HU_PATH="/$(rand_str 12)"
GRPC_SVC="$(rand_str 12)"
TROJAN_GRPC_SVC="$(rand_str 12)"
GRPC_R_SVC="$(rand_str 12)"
VMESS_WS_PATH="/$(rand_str 12)"
DIAG_TOKEN=$(rand_str 16)
DIAG_PATH="/net-$(rand_str 12)/"
TPROXY_SECRET=$(rand_hex 16)   # 32 hex-символа (16 байт) — секрет tproxy
# AdGuard Home — порты web-UI и plain-DNS (loopback 127.0.0.1; наружу — nginx)
AGH_WEB_PORT=$(pick_port AGH_WEB_PORT)
AGH_DNS_PORT=$(pick_port AGH_DNS_PORT)
# Web-UI AGH — только plain HTTP; TLS (DoH и DoT :853) терминирует nginx.
AGH_PATH="adg-$(rand_str 12)"

# Учётные данные панели (можно задать в env-файле; пусто — случайные)
[[ -n "${PANEL_USER:-}" ]] || PANEL_USER=$(rand_str 10)
[[ -n "${PANEL_PASS:-}" ]] || PANEL_PASS=$(rand_str 14)

# Константы
LUCX_REPO="AlexeyLCP/lucx-ui"
# Закреплённые версии (проверены с этим скриптом). "latest" — последний релиз
# (SHA256 проверяется всегда; совместимость latest не гарантируется).
LUCX_VERSION="${LUCX_VERSION:-v3.9.0-lucx.280}"
AGH_VERSION="${AGH_VERSION:-v0.107.79}"
TIMEZONE="${TIMEZONE:-}"
SSH_PORTS="${SSH_PORTS:-}"
BACKUP_DIR="/root/lucx-backup-$(date +%Y%m%d-%H%M%S)"
XUIDB="/etc/x-ui/x-ui.db"
# Первый тестовый клиент подписки (ссылки Sub/JSON/Clash/AWG в отчёте)
# v10.1: автосоздание первого клиента убрано (ломало БД).
TEST_CLIENT_EMAIL=""
TEST_SUB_ID=""

###############################################################################
# Аргументы командной строки (2-й проход — CLI приоритетнее env-файла)
###############################################################################
set -- "${CLI_ARGS_SAVED[@]}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)          DOMAIN="$2";          shift 2 ;;
        -r|--reality-domain)  REALITY_DOMAIN="$2";  shift 2 ;;
        -t|--tproxy-domain)   TG_WEB_DOMAIN="$2";   shift 2 ;;
        -x|--xhttp-r-domain)  XHTTP_R_DOMAIN="$2";  shift 2 ;;
        -g|--grpc-r-domain)   GRPC_R_DOMAIN="$2";   shift 2 ;;
        -u|--tt-domain)       TT_DOMAIN="$2";       shift 2 ;;
        --env)                shift 2 ;;
        --env=*)              shift   ;;
        --uninstall)          DO_UNINSTALL="y";     shift   ;;
        --skip-packages)      SKIP_PKG="y";         shift   ;;
        --no-cleanup)         SKIP_CLEANUP="y";     shift   ;;
        *)                    shift ;;
    esac
done

###############################################################################
# УДАЛЕНИЕ
###############################################################################
do_uninstall() {
    inf "Удаление LucX-UI и сопутствующих компонентов..."
    systemctl stop x-ui hysteria2 telegram-proxy AdGuardHome lucx-sub-sidecar 2>/dev/null || true
    systemctl disable x-ui hysteria2 telegram-proxy AdGuardHome lucx-sub-sidecar 2>/dev/null || true
    if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
        /opt/AdGuardHome/AdGuardHome -s uninstall 2>/dev/null || true
    fi
    rm -f /etc/systemd/system/x-ui.service \
          /etc/systemd/system/hysteria2.service \
          /etc/systemd/system/telegram-proxy.service \
          /etc/systemd/system/AdGuardHome.service \
          /etc/systemd/system/lucx-sub-sidecar.service
    rm -rf /usr/local/x-ui /etc/x-ui /etc/hysteria2 /etc/telegram-proxy /opt/AdGuardHome /opt/lucx-sub-sidecar
    rm -f /etc/fail2ban/jail.d/lucx.conf /etc/fail2ban/filter.d/lucx-nginx-honeypot.conf \
          /etc/letsencrypt/renewal-hooks/deploy/lucx-reload.sh \
          /etc/systemd/system/nginx.service.d/after-adguard.conf
    systemctl restart fail2ban 2>/dev/null || true
    rm -rf /etc/nginx/stream-enabled/* /etc/nginx/sites-enabled/* /etc/nginx/sites-available/*
    apt-get -y purge nginx nginx-full certbot 2>/dev/null || true
    apt-get -y autoremove 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    ok "Полностью удалено."
    exit 0
}
[[ "$DO_UNINSTALL" == "y" ]] && do_uninstall

###############################################################################
# ОЧИСТКА ПРЕДЫДУЩИХ УСТАНОВОК (для чистой установки без конфликтов)
###############################################################################
cleanup_old() {
    inf "Очистка предыдущих установок/конфигов (можно отключить флагом --no-cleanup)..."
    local ts
    ts=$(date +%s)

    # ── 1. Панели (3x-ui / lucx-ui / x-ui) ────────────────────────────────
    for svc in x-ui lucx-ui 3x-ui; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service" "/lib/systemd/system/${svc}.service" 2>/dev/null || true
    done
    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f '/usr/local/x-ui/x-ui' 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # Бэкап старых данных панели (не удаляем молча — вдруг нужны креды)
for dir in /usr/local/x-ui /etc/x-ui; do
    if [[ -e "$dir" ]]; then
        if ! mv "$dir" "${dir}.old.${ts}" 2>/dev/null; then
            rm -rf "$dir" 2>/dev/null || true
        else
            warn "  Бэкап старых ${dir} > ${dir}.old.${ts}"
        fi
    fi
done


    # ── 2. Nginx: сброс конфигов УСТАНОВЩИКА (не трогаем сам nginx.conf) ─
    for d in /etc/nginx/stream-enabled /etc/nginx/snippets; do
        [[ -d "$d" ]] && find "$d" -mindepth 1 -delete 2>/dev/null || true
    done
    [[ -d /etc/nginx/sites-enabled ]] && find /etc/nginx/sites-enabled -maxdepth 1 -type l -delete 2>/dev/null || true
    [[ -d /etc/nginx/sites-enabled ]] && find /etc/nginx/sites-enabled -maxdepth 1 -type f ! -name default -delete 2>/dev/null || true
    [[ -d /etc/nginx/sites-available ]] && find /etc/nginx/sites-available -maxdepth 1 -type f ! -name default ! -name '*.template' ! -name '*.example' -delete 2>/dev/null || true

    # ── 3. Останавливаем/чистим sidecar-процессы и сервисы форка ─────────
    for p in caddy-naive tproxy mtproxy mieru qwdtt olcrtc trusttunnel mtg anytls; do
        pkill -f "$p" 2>/dev/null || true
    done
    for svc in caddy-naive tproxy mieru trusttunnel telegram-proxy hysteria2 caddy lucx-sub-sidecar; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done
    rm -f /etc/systemd/system/lucx-sub-sidecar.service 2>/dev/null || true

    # ── 4. AdGuard Home (unit + процесс; бинарник/данные оставляем) ────────
    # Иначе повторный запуск падает: «Init already exists: AdGuardHome.service»
    systemctl stop AdGuardHome 2>/dev/null || true
    systemctl disable AdGuardHome 2>/dev/null || true
    if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
        /opt/AdGuardHome/AdGuardHome -s uninstall 2>/dev/null || true
    fi
    rm -f /etc/systemd/system/AdGuardHome.service \
          /lib/systemd/system/AdGuardHome.service 2>/dev/null || true
    # Старый yaml с чужими портами ломает nginx→AGH: бэкапим, на setup пересоздадим
    if [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]]; then
        mv -f /opt/AdGuardHome/AdGuardHome.yaml \
              "/opt/AdGuardHome/AdGuardHome.yaml.old.${ts}" 2>/dev/null || \
            rm -f /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true
        warn "  Бэкап AdGuardHome.yaml > /opt/AdGuardHome/AdGuardHome.yaml.old.${ts}"
    fi
    pkill -f '/opt/AdGuardHome/AdGuardHome' 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # certbot/letsencrypt и симлинки /root/cert НЕ удаляем: get_certs обновит их,
    # а откат конфига nginx при сбое продолжит находить сертификаты

    systemctl stop nginx 2>/dev/null || true
    ok "Старые компоненты очищены (бэкапы панели: /usr/local/x-ui.old.*, /etc/x-ui.old.*)"
}

###############################################################################
# ВВОД ДОМЕНОВ
###############################################################################
collect_domains() {
    # Если запуск без интерактивного TTY (ssh без -t, cron, nohup) —
    # read вернёт EOF мгновенно и цикл зациклится. Защищаемся.
    local tries=0
    [[ -z "$DOMAIN" ]] && inf "Домен панели не задан — будет запрошен ввод"
    while [[ -z "$DOMAIN" ]]; do
        [[ ! -t 0 ]] && die "DOMAIN пуст, а запуск идёт без TTY. Укажите его в env-файле (DOMAIN=\"...\") или аргументом -d"
        read -rp "Домен для панели (panel.example.com): " DOMAIN
        tries=$((tries+1)); [[ $tries -ge 5 ]] && die "Домен панели не введён (5 попыток)"
    done
    tries=0
    [[ -z "$REALITY_DOMAIN" ]] && inf "Домен REALITY не задан — будет запрошен ввод"
    while [[ -z "$REALITY_DOMAIN" ]]; do
        [[ ! -t 0 ]] && die "REALITY_DOMAIN пуст, а запуск идёт без TTY. Укажите его в env-файле (REALITY_DOMAIN=\"...\") или аргументом -r"
        read -rp "Домен для REALITY (r.example.com): " REALITY_DOMAIN
        tries=$((tries+1)); [[ $tries -ge 5 ]] && die "Домен REALITY не введён (5 попыток)"
    done
    [[ "$DOMAIN" == "$REALITY_DOMAIN" ]] && die "Домены панели и REALITY должны быть разными!"
    DOMAIN="${DOMAIN// /}"
    REALITY_DOMAIN="${REALITY_DOMAIN// /}"
    # NEW v4: Telegram WEB proxy — опциональный третий домен.
    # Панель сама запускает tproxy-server + MTProxy + Caddy (TLS на своём
    # порту), а nginx по SNI заводит tg-домен:443 на этот порт. Если домен
    # не задан — tproxy inbound просто не создаётся.
    if [[ -n "$TG_WEB_DOMAIN" ]]; then
        TG_WEB_DOMAIN="${TG_WEB_DOMAIN// /}"
        if [[ "$TG_WEB_DOMAIN" == "$DOMAIN" || "$TG_WEB_DOMAIN" == "$REALITY_DOMAIN" ]]; then
            die "Домен tproxy должен отличаться от остальных!"
        fi
        inf "Telegram WEB proxy будет поднят на домене: ${TG_WEB_DOMAIN}"
    else
        inf "Домен tproxy не задан — Telegram WEB proxy пропускается (добавьте -t tg.example.com)"
    fi

    # NEW v5: SNI-домены для REALITY-транспортов за 443 (XHTTP+REALITY, gRPC+REALITY)
    local extra_domains=()
    [[ -n "$XHTTP_R_DOMAIN" ]] && extra_domains+=("XHTTP_R_DOMAIN=$XHTTP_R_DOMAIN")
    [[ -n "$GRPC_R_DOMAIN" ]] && extra_domains+=("GRPC_R_DOMAIN=$GRPC_R_DOMAIN")
    [[ -n "$TT_DOMAIN" ]]     && extra_domains+=("TT_DOMAIN=$TT_DOMAIN")
    for pair in "${extra_domains[@]:-}"; do
        if [[ -z "$pair" ]]; then continue; fi
        local vname="${pair%%=*}" dval="${pair##*=}"
        dval="${dval// /}"
        if [[ "$dval" == "$DOMAIN" || "$dval" == "$REALITY_DOMAIN" || "$dval" == "$TG_WEB_DOMAIN" ]]; then
            die "Домен $dval должен отличаться от остальных!"
        fi
        printf -v "$vname" '%s' "$dval"
        inf "  $vname → SNI за 443: ${dval}"
    done
    # После сбора доменов продолжаем к определению IP сервера
    echo "[OK] collect_domains completed" >&2
    [[ -z "$XHTTP_R_DOMAIN" ]] && inf "Домен -x не задан — VLESS+XHTTP+REALITY останется на прямом порту ${VLESS_XHTTP_R_PORT}"
    [[ -z "$GRPC_R_DOMAIN" ]] && inf "Домен -g не задан — VLESS+gRPC+REALITY останется на прямом порту ${VLESS_GRPC_R_PORT}"
    [[ -z "$TT_DOMAIN" ]]     && warn "Домен -u не задан — TrustTunnel будет на прямом порту (клиенты TT ходят только на 443!)"
}
collect_domains

###############################################################################
# ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ (значения попадают в SQL/YAML/nginx — только безопасные символы)
###############################################################################
is_valid_domain() {
    [[ ${#1} -le 253 && "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}
validate_inputs() {
    local v
    for v in DOMAIN REALITY_DOMAIN TG_WEB_DOMAIN XHTTP_R_DOMAIN GRPC_R_DOMAIN TT_DOMAIN; do
        [[ -z "${!v}" ]] && continue
        is_valid_domain "${!v}" || die "${v}='${!v}': некорректное доменное имя"
        printf -v "$v" '%s' "${!v,,}"
    done
    for v in PANEL_USER AGH_USER; do
        [[ "${!v}" =~ ^[A-Za-z0-9._-]{3,64}$ ]] || die "${v}: допустимо 3–64 символа [A-Za-z0-9._-]"
    done
    for v in PANEL_PASS AGH_PASS; do
        [[ "${!v}" =~ ^[A-Za-z0-9._~@%+=:,^!*-]{8,128}$ ]] || \
            die "${v}: 8–128 символов из [A-Za-z0-9._~@%+=:,^!*-] (без кавычек, пробелов, \\, \$, #, &, /)"
    done
    for v in LUCX_VERSION AGH_VERSION; do
        [[ "${!v}" == latest || "${!v}" =~ ^v[0-9][A-Za-z0-9._-]*$ ]] || die "${v}='${!v}': ожидается тег вида v1.2.3 или latest"
    done
    if [[ -n "$TIMEZONE" && ! -f "/usr/share/zoneinfo/${TIMEZONE}" ]]; then
        die "TIMEZONE='${TIMEZONE}': нет в /usr/share/zoneinfo"
    fi
    for v in $SSH_PORTS; do
        [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 65535 )) || die "SSH_PORTS: '${v}' — не порт"
    done
}
validate_inputs

###############################################################################
# ЗАГРУЗКИ С ПРОВЕРКОЙ (staging → SHA256 → установка)
###############################################################################
download() {
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 600 -o "$2" "$1"
}
verify_sha256() {
    local f="$1" want="${2,,}" got
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || return 1
    got=$(sha256sum "$f" | awk '{print $1}')
    [[ "$got" == "$want" ]]
}
# Тег последнего релиза без GitHub API (нет лимита 60 запросов/час)
gh_latest_tag() {
    local url
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --connect-timeout 15 --max-time 60 \
        "https://github.com/$1/releases/latest" 2>/dev/null) || return 1
    printf '%s\n' "${url##*/tag/}"
}

###############################################################################
# БЭКАП ПЕРЕД ИЗМЕНЕНИЯМИ + ОТКАТ NGINX ПРИ СБОЕ
###############################################################################
backup_state() {
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR" || die "Не удалось создать ${BACKUP_DIR}"
    [[ -d /etc/nginx ]] && cp -a /etc/nginx "${BACKUP_DIR}/nginx"
    if [[ -f "$XUIDB" ]]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$XUIDB" ".backup '${BACKUP_DIR}/x-ui.db'" 2>/dev/null || cp -a "$XUIDB" "${BACKUP_DIR}/x-ui.db"
        else
            cp -a "$XUIDB" "${BACKUP_DIR}/x-ui.db"
        fi
    fi
    [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]] && cp -a /opt/AdGuardHome/AdGuardHome.yaml "${BACKUP_DIR}/"
    [[ -f /etc/ufw/before.rules ]] && cp -a /etc/ufw/before.rules "${BACKUP_DIR}/"
    crontab -l > "${BACKUP_DIR}/crontab" 2>/dev/null || true
    UFW_WAS_ACTIVE=0
    ufw status 2>/dev/null | grep -q '^Status: active' && UFW_WAS_ACTIVE=1
    ok "Бэкап текущего состояния: ${BACKUP_DIR}"
}
on_exit() {
    local rc=$?
    (( rc == 0 )) && return
    err "Установка прервана (код ${rc}). Лог: ${LOG_FILE}"
    if [[ -d "${BACKUP_DIR}/nginx" ]] && command -v nginx >/dev/null 2>&1 && ! nginx -t >/dev/null 2>&1; then
        warn "Конфиг nginx невалиден — откат из ${BACKUP_DIR}/nginx"
        rm -rf /etc/nginx && cp -a "${BACKUP_DIR}/nginx" /etc/nginx && \
            { systemctl restart nginx 2>/dev/null || true; }
    fi
    if [[ "${UFW_WAS_ACTIVE:-0}" == 1 ]] && ! ufw status 2>/dev/null | grep -q '^Status: active'; then
        warn "UFW был активен до установки — включаю обратно"
        ufw --force enable >/dev/null 2>&1 || err "ufw enable не удался — включите firewall вручную"
    fi
    [[ -d "$BACKUP_DIR" ]] && err "Бэкап (БД панели, AGH yaml, UFW, crontab): ${BACKUP_DIR}"
}

# Получаем IP сервера
SERVER_IP4=""
if SERVER_IP4=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+'); then
    : # ок, IP получен
fi
if [[ ! "$SERVER_IP4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SERVER_IP4=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]' || true)
fi
if [[ ! "$SERVER_IP4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    die "Не удалось определить IP сервера (проверьте сеть/DNS)."
fi
inf "IP сервера: ${SERVER_IP4}"

# ─── Обновляем apt-кэш до очистки — чтобы cleanup_old не конфликтовал с заблокированными портами ───
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>/dev/null || true

# Очистка предыдущих установок (nginx/панель/sidecar) — чтобы не было
# конфликтов портов и конфигов при установке. Отключить: --no-cleanup
backup_state
trap on_exit EXIT
if [[ "$SKIP_CLEANUP" != "y" ]]; then
    cleanup_old
fi

###############################################################################
# УСТАНОВКА ПАКЕТОВ
###############################################################################
install_packages() {
    inf "Установка системных пакетов (apt-get; может занять несколько минут)..."
    ufw disable 2>/dev/null || true
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq --no-install-recommends \
        curl wget jq socat ca-certificates openssl gnupg2 lsb-release \
        nginx-full certbot python3-certbot-nginx \
        sqlite3 ufw fail2ban python3-systemd apache2-utils \
        net-tools netcat-openbsd \
        build-essential libmnl-dev pkg-config dkms git \
        python3 python3-cryptography xxd mtr || die "apt-get install завершился с ошибкой"
    systemctl daemon-reload && systemctl enable --now nginx || die "nginx не стал"
    ok "Пакеты установлены"
}
[[ "$SKIP_PKG" != "y" ]] && install_packages
ok "Системные пакеты готовы"

###############################################################################
# SSL-СЕРТИФИКАТЫ
###############################################################################
get_certs() {
    inf "Получение SSL-сертификатов (Let's Encrypt)..."
    inf "  шаг 1: останавливаем nginx для освобождения 80/443..."
    systemctl stop nginx 2>/dev/null || true
    fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null || true
    sleep 1
    
    inf "  шаг 2: запрос сертификатов..."
    local cert_domains=()
    CERT_DOMAINS=()
    cert_domains+=("$DOMAIN")
    cert_domains+=("$REALITY_DOMAIN")
    # TT и tproxy проверяют PEM-сертификат на покрытие hostname — им нужен cert
    [[ -n "$TT_DOMAIN" ]]     && cert_domains+=("$TT_DOMAIN")
    [[ -n "$TG_WEB_DOMAIN" ]] && cert_domains+=("$TG_WEB_DOMAIN")
    # XHTTP_R_DOMAIN / GRPC_R_DOMAIN — REALITY-домены: реальный сертификат НЕ нужен

    inf "  Запрашиваемые домены (${#cert_domains[@]}): ${cert_domains[*]}"

    local failed=0
    for d in "${cert_domains[@]}"; do
        inf "  certbot: $d"
        if certbot certonly --standalone --non-interactive --agree-tos \
            --register-unsafely-without-email -d "$d" 2>&1; then
            ok "  SSL для $d получен"
        else
            err "  SSL для $d не получен"
            failed=$((failed+1))
        fi
    done
    [[ $failed -gt 0 ]] && die "$failed домен(ов) без сертификата. Проверьте DNS A-запись → ${SERVER_IP4}"

    CERT_DOMAINS=("${cert_domains[@]}")
    # Симлинки в /root/cert/<domain>/
    mkdir -p /root/cert && chmod 700 /root/cert
    for d in "${cert_domains[@]}"; do
        mkdir -p "/root/cert/${d}"
        chmod 700 "/root/cert/${d}"
        ln -sf "/etc/letsencrypt/live/${d}/fullchain.pem" "/root/cert/${d}/fullchain.pem"
        ln -sf "/etc/letsencrypt/live/${d}/privkey.pem"   "/root/cert/${d}/privkey.pem"
    done
    ok "Сертификаты получены"
}
get_certs

###############################################################################
# УСТАНОВКА LUCX-UI ПАНЕЛИ
###############################################################################
install_panel() {
    inf "Установка LucX-UI (${LUCX_REPO})..."

    local tag="$LUCX_VERSION"
    if [[ "$tag" == "latest" ]]; then
        tag=$(gh_latest_tag "$LUCX_REPO") || tag=""
    fi
    [[ -n "$tag" ]] || die "Не удалось определить версию LucX-UI"
    inf "  Версия: ${tag}"

    local asset="x-ui-linux-${ARCH}.tar.gz"
    local rel="https://github.com/${LUCX_REPO}/releases/download/${tag}"
    local stage
    stage=$(mktemp -d /root/.lucx-stage.XXXXXX) || die "mktemp не сработал"
    inf "  Загрузка ${asset} (${tag})..."
    download "${rel}/${asset}" "${stage}/${asset}" || die "Ошибка загрузки LucX-UI ${tag}"
    download "${rel}/${asset}.sha256" "${stage}/${asset}.sha256" \
        || die "В релизе ${tag} нет ${asset}.sha256 — непроверенный архив не устанавливаю"
    verify_sha256 "${stage}/${asset}" "$(awk '{print $1; exit}' "${stage}/${asset}.sha256")" \
        || die "SHA256 архива LucX-UI не совпадает — архив повреждён или подменён"
    ok "  Архив загружен, SHA256 совпадает"

    tar -xzf "${stage}/${asset}" -C "$stage" || die "Ошибка распаковки LucX-UI"
    [[ -x "${stage}/x-ui/x-ui" ]] || die "В архиве нет исполняемого x-ui"
    local pins="${stage}/x-ui/bin/lucx-pins.txt" pin_name pin_sum bad=0
    if [[ -f "$pins" ]]; then
        while read -r pin_name pin_sum; do
            [[ -n "$pin_name" && -f "${stage}/x-ui/bin/${pin_name}" ]] || continue
            verify_sha256 "${stage}/x-ui/bin/${pin_name}" "$pin_sum" || { err "  ${pin_name}: SHA256 не совпадает с lucx-pins.txt"; bad=$((bad+1)); }
        done < "$pins"
        (( bad == 0 )) || die "Sidecar-бинарники не прошли проверку lucx-pins.txt"
        ok "  Sidecar-бинарники сверены с lucx-pins.txt"
    fi

    # Атомарная замена: старая версия → /usr/local/x-ui.prev
    systemctl stop x-ui 2>/dev/null || true
    if [[ -d /usr/local/x-ui ]]; then
        rm -rf /usr/local/x-ui.prev
        mv /usr/local/x-ui /usr/local/x-ui.prev || die "Не удалось сохранить предыдущую версию панели"
    fi
    mv "${stage}/x-ui" /usr/local/x-ui || die "Не удалось установить /usr/local/x-ui"
    rm -rf "$stage"
    cd /usr/local/x-ui || die "Нет /usr/local/x-ui"
    chmod +x x-ui x-ui.sh 2>/dev/null || true
    mkdir -p bin
    chmod +x bin/*-linux-* 2>/dev/null || true

    local missing=() sc
    for sc in caddy-naive olcrtc qwdtt mieru trusttunnel anytls mtg; do
        compgen -G "bin/${sc}-linux-*" >/dev/null || missing+=("$sc")
    done
    [[ -n "$TG_WEB_DOMAIN" ]] && for sc in tproxy mtproxy; do
        compgen -G "bin/${sc}-linux-*" >/dev/null || missing+=("$sc")
    done
    if (( ${#missing[@]} )); then
        warn "  В архиве ${ARCH} нет sidecar: ${missing[*]} (доустановка в панели: Cores)"
    else
        ok "  Sidecar-бинарники на месте"
    fi

    inf "  Geo-файлы (geoip.dat, geosite.dat)..."
    for gf in geoip.dat geosite.dat; do
        [[ -s "bin/${gf}" ]] && continue
        if curl -fLRo "bin/${gf}" --connect-timeout 15 --max-time 120 \
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/${gf}" 2>/dev/null; then
            ok "  ${gf}: загружен"
        else
            warn "  ${gf}: не загружен (панель может использовать встроенные)"
        fi
    done
    # RU + IR geofile'ы (без IR xray падает: invalid geodata asset file geoip_IR.dat)
    for pair in \
        "geoip_RU.dat|https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat" \
        "geosite_RU.dat|https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat" \
        "geoip_IR.dat|https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat" \
        "geosite_IR.dat|https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat" \
        "geoip_ROSCOM.dat|https://github.com/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat" \
        "geosite_ROSCOM.dat|https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat"; do
        local fname="${pair%%|*}" url="${pair##*|}"
        [[ -s "bin/${fname}" ]] && continue
        if curl -fLRo "bin/${fname}" --connect-timeout 15 --max-time 120 "$url" 2>/dev/null; then
            ok "  ${fname}: загружен"
        else
            warn "  ${fname}: не загружен"
        fi
    done

    inf "  CLI-скрипт x-ui (из проверенного архива)..."
    if install -m 755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui 2>/dev/null; then
        ok "  x-ui CLI установлен"
    else
        warn "  x-ui CLI не установлен (нет x-ui.sh в архиве)"
    fi
    mkdir -p /var/log/x-ui

    inf "  Первичная конфигурация панели..."
    /usr/local/x-ui/x-ui setting \
        -username "$PANEL_USER" -password "$PANEL_PASS" \
        -port "$PANEL_PORT" -webBasePath "${PANEL_PATH}" -listenIP 127.0.0.1 >/dev/null 2>&1 \
        || warn "  x-ui setting завершился с ошибкой"
    /usr/local/x-ui/x-ui migrate >/dev/null 2>&1 || warn "  x-ui migrate завершился с ошибкой"

    inf "  Systemd unit..."
    local svc_file="x-ui.service"
    [[ -f "x-ui.service.debian" ]] && svc_file="x-ui.service.debian"
    [[ -f "$svc_file" ]] && cp -f "$svc_file" /etc/systemd/system/x-ui.service

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui || die "x-ui не запустился — journalctl -u x-ui"
    for _ in $(seq 1 20); do [[ -f "$XUIDB" ]] && break; sleep 1; done

    ok "LucX-UI ${tag} установлен"
}
install_panel

###############################################################################
# NGINX: SNI STREAM + VHOST (TLS termination → xray inbound'ы)
###############################################################################
configure_nginx() {
    inf "Настройка nginx..."

    inf "  Проверка/добавление stream-блока в nginx.conf..."
    # nginx.conf: stream-блок
    # НЕ добавляем load_module вручную — на Ubuntu/Debian nginx-full уже подключает
    # ngx_stream_module через /etc/nginx/modules-enabled/50-mod-stream.conf.
    # Повторный load_module вызывает "[emerg] module is already loaded".
    # Добавляем только stream{} блок если его ещё нет.
    if ! grep -q "stream {" /etc/nginx/nginx.conf; then
        echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
        ok "  stream-блок добавлен"
    else
        ok "  stream-блок уже есть"
    fi
    # Также убираем случайно добавленный load_module если он уже есть
    # (на случай повторного запуска скрипта)
    if grep -q "load_module.*ngx_stream_module" /etc/nginx/nginx.conf; then
        sed -i '/load_module.*ngx_stream_module/d' /etc/nginx/nginx.conf
        ok "  лишний load_module убран"
    fi

    inf "  Тюнинг производительности (worker_connections, worker_rlimit_nofile)..."
    sed -i "/worker_connections/c\\worker_connections 4096;" /etc/nginx/nginx.conf
    grep -q "worker_rlimit_nofile" /etc/nginx/nginx.conf || \
        echo "worker_rlimit_nofile 65536;" >> /etc/nginx/nginx.conf
    ok "  производительность настроена"

    mkdir -p /etc/nginx/stream-enabled /etc/nginx/snippets

    # ── Stream: SNI-роутинг на порту 443 ──────────────────────────────────
    # REALITY-домен → xray 8443 (xray сам терминирует TLS)
    # panel-домен   → nginx vhost 7443 (nginx терминирует TLS, проксирует к xray)
    # NEW v5: SNI-роутинг опциональных доменов (raw TCP — TLS терминирует xray/TT)
    local extra_stream_map="" extra_stream_upstream=""
    [[ -n "$XHTTP_R_DOMAIN" ]] && extra_stream_map+="    ${XHTTP_R_DOMAIN}      xhttp_reality_upstream;"$'\n'
    [[ -n "$GRPC_R_DOMAIN" ]] && extra_stream_map+="    ${GRPC_R_DOMAIN}       grpc_reality_upstream;"$'\n'
    [[ -n "$TT_DOMAIN" ]]     && extra_stream_map+="    ${TT_DOMAIN}           tt_upstream;"$'\n'
    [[ -n "$XHTTP_R_DOMAIN" ]] && extra_stream_upstream+="upstream xhttp_reality_upstream { server 127.0.0.1:${VLESS_XHTTP_R_PORT}; }"$'\n'
    [[ -n "$GRPC_R_DOMAIN" ]] && extra_stream_upstream+="upstream grpc_reality_upstream { server 127.0.0.1:${VLESS_GRPC_R_PORT}; }"$'\n'
    [[ -n "$TT_DOMAIN" ]]     && extra_stream_upstream+="upstream tt_upstream { server 127.0.0.1:${TRUSTTUNNEL_PORT}; }"$'\n'

    # NEW v4: tg-домен → caddy tproxy (raw TCP, caddy терминирует TLS сам)
    local tg_stream_map="" tg_stream_upstream=""
    if [[ -n "$TG_WEB_DOMAIN" ]]; then
        tg_stream_map="    ${TG_WEB_DOMAIN}            tproxy_upstream;"
        tg_stream_upstream="upstream tproxy_upstream { server 127.0.0.1:${TPROXY_PORT}; }"
    fi
    # PROXY protocol: stream :443 → backends получают реальный client IP.
    # Panel (7443) и xray REALITY умеют PP; TT/tproxy — через strip-прокси
    # (принимает PP, дальше отдаёт «чистый» TCP без заголовка).
    local tt_strip_server="" tg_strip_server=""
    local TT_PP_STRIP=12722 TPROXY_PP_STRIP=12723
    if [[ -n "$TT_DOMAIN" ]]; then
        # upstream tt_* уже указывает на TRUSTTUNNEL_PORT — перенаправляем на strip
        extra_stream_upstream=$(printf '%s' "${extra_stream_upstream}" | sed "s/server 127.0.0.1:${TRUSTTUNNEL_PORT}/server 127.0.0.1:${TT_PP_STRIP}/")
        tt_strip_server=$(cat <<STRIP
# TrustTunnel: снять PROXY protocol перед sidecar
server {
    listen 127.0.0.1:${TT_PP_STRIP} proxy_protocol;
    proxy_protocol off;
    proxy_pass 127.0.0.1:${TRUSTTUNNEL_PORT};
}
STRIP
)
    fi
    if [[ -n "$TG_WEB_DOMAIN" ]]; then
        tg_stream_upstream="upstream tproxy_upstream { server 127.0.0.1:${TPROXY_PP_STRIP}; }"
        tg_strip_server=$(cat <<STRIP
# Telegram WEB proxy: снять PROXY protocol перед caddy/tproxy
server {
    listen 127.0.0.1:${TPROXY_PP_STRIP} proxy_protocol;
    proxy_protocol off;
    proxy_pass 127.0.0.1:${TPROXY_PORT};
}
STRIP
)
    fi

    cat > /etc/nginx/stream-enabled/sni-443.conf <<STREAM
map \$ssl_preread_server_name \$sni_route {
    hostnames;
    ${REALITY_DOMAIN}    reality_upstream;
${extra_stream_map}${tg_stream_map}
    ${DOMAIN}            panel_upstream;
    default              panel_upstream;
}
upstream reality_upstream { server 127.0.0.1:8443; }
upstream panel_upstream   { server 127.0.0.1:7443; }
${extra_stream_upstream}
${tg_stream_upstream}

# v7.3 FIX: proxy_protocol on — иначе HTTP на 7443 видит только 127.0.0.1
# (stream L4 без PP), и AGH/панель показывают localhost вместо реальных IP.
server {
    listen     443;
    listen     [::]:443;
    ssl_preread on;
    proxy_protocol on;
    proxy_pass \$sni_route;
}
${tt_strip_server}
${tg_strip_server}

# DoT :853 — отдельный stream-конфиг dot-853.conf (setup_adguard)
STREAM

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────
    rm -f /etc/nginx/sites-enabled/default
    cat > /etc/nginx/sites-available/000-redirect.conf <<REDIR
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    # certbot renew (standalone на 127.0.0.1:${ACME_PORT}) — без остановки nginx
    location ^~ /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:${ACME_PORT};
        proxy_set_header Host \$host;
    }
    location / { return 301 https://\$host\$request_uri; }
}
REDIR

    # ── Maps ──────────────────────────────────────────────────────────────
    # v4: Clash/JSON автоопределение выполняет сама панель LucX-UI
    # (subClashAutoDetect / subJsonAutoDetect по User-Agent) — nginx-хак
    # с генератором clash.yaml больше не нужен.
    cat > /etc/nginx/sites-available/001-maps.conf <<MAPS
# v4: все maps перенесены в vhost; автоопределение подписок — в панели LucX-UI.
MAPS

    # ── Определяем http2 директиву совместимо ────────────────────────────
    local ngx_ver http2_listen="" http2_on=""
    ngx_ver=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+')
    if printf '%s\n' 1.25.1 "$ngx_ver" | sort -V | head -1 | grep -q "^1\.25\.1$"; then
        http2_on="http2 on;"
    else
        http2_listen=" http2"
    fi

    # ── AdGuard Home locations (NEW v7.3, если INSTALL_ADGUARD != 0) ────────
    # Web-UI AGH — plain HTTP на loopback (port_https=0); TLS только у nginx.
    # Прокси на HTTPS-порт AGH давал 502→error_page→«404 Not Found nginx».
    local agh_nginx=""
    if [[ "$INSTALL_ADGUARD" != "0" ]]; then
        agh_nginx=$(cat <<AGHLOC

    # ── AdGuard Home ────────────────────────────────────────────────────────
    # DNS-over-HTTPS (стандартный путь; без auth — отвечает только wireformat)
    location ^~ /dns-query {
        if (\$hack = 1) { return 404; }
        proxy_pass http://127.0.0.1:${AGH_WEB_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        # \$remote_addr уже реальный IP (PROXY protocol + real_ip_header)
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_intercept_errors off;
        access_log off;
    }
    # Admin UI (random path). AGH без base-path: proxy_pass со trailing slash
    # срезает префикс; Location/cookie переписываются. SPA обращается к API
    # относительным путём control/ → /${AGH_PATH}/control/ (корневой /control/ закрыт).
    location ^~ /${AGH_PATH}/ {
        if (\$hack = 1) { return 404; }
        limit_req zone=panel_rl burst=50 nodelay;
        proxy_pass http://127.0.0.1:${AGH_WEB_PORT}/;
        proxy_redirect http://\$host/    /${AGH_PATH}/;
        proxy_redirect https://\$host/   /${AGH_PATH}/;
        proxy_redirect / /${AGH_PATH}/;
        proxy_cookie_path / /${AGH_PATH}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        # чтобы sub_filter видел тело (не gzip от AGH)
        proxy_set_header Accept-Encoding "";
        proxy_read_timeout 300s;
        proxy_intercept_errors off;
        # SPA/HTML: абсолютные пути → подпрефикс
        sub_filter_once off;
        sub_filter_types application/javascript application/json text/css;
        sub_filter 'href="/' 'href="/${AGH_PATH}/';
        sub_filter 'src="/'  'src="/${AGH_PATH}/';
        sub_filter 'url(/'   'url(/${AGH_PATH}/';
        sub_filter '"/control/' '"/${AGH_PATH}/control/';
        sub_filter "'/control/" "'/${AGH_PATH}/control/";
        add_header X-Robots-Tag "noindex, nofollow" always;
    }
    location = /${AGH_PATH} { return 302 /${AGH_PATH}/; }
AGHLOC
)
    fi

    # ── Главный vhost: TLS termination на 7443, все proxy locations ───────
    local DOMAIN_RE="${DOMAIN//./\\.}"
    cat > "/etc/nginx/sites-available/${DOMAIN}" <<VHOST
# ── Rate limiting ──────────────────────────────────────────────────────────
limit_req_zone  \$binary_remote_addr zone=panel_rl:10m  rate=30r/s;
limit_req_zone  \$binary_remote_addr zone=diag_api:10m  rate=6r/m;
limit_req_zone  \$binary_remote_addr zone=diag_page:10m rate=30r/m;
limit_conn_zone \$binary_remote_addr zone=per_ip:10m;

map \$cookie_diag_key \$diag_auth {
    "${DIAG_TOKEN}" 1;
    default          0;
}

server {
    server_tokens off;
    server_name ${DOMAIN};
    # proxy_protocol: stream :443 передаёт реальный client IP (иначе 127.0.0.1)
    listen 127.0.0.1:7443 ssl${http2_listen} proxy_protocol;
    ${http2_on}
    # Восстановить \$remote_addr из PROXY protocol (источник — stream loopback)
    set_real_ip_from  127.0.0.1;
    set_real_ip_from  ::1;
    real_ip_header    proxy_protocol;
    real_ip_recursive on;

    root /var/www/html/;
    index index.html;
    absolute_redirect off;

    # HTTP/2 upload performance
    http2_body_preread_size 128k;
    client_body_buffer_size 512k;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers   ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_session_cache    shared:SSL:10m;
    ssl_session_timeout  10m;
    ssl_stapling         off;
    ssl_stapling_verify  off;
    ssl_certificate      /root/cert/${DOMAIN}/fullchain.pem;
    ssl_certificate_key  /root/cert/${DOMAIN}/privkey.pem;

    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # Защита от неправильного хоста / зондирования
    if (\$host !~* ^(.*\.)?${DOMAIN_RE}\$)             { return 444; }
    if (\$ssl_server_name !~* ^(.*\.)?${DOMAIN_RE}\$)  { return 444; }
    if (\$request_uri ~* "(\"|'|\`|~|,|:|;|%|\\\$|&&|\?\?|0x00|0X00|\||\\\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)") { set \$hack 1; }
    # v10: не маскировать 502/503 панели в 404 (иначе «nginx 404» вместо real upstream error)
    error_page 400 401 402 403 =404 /404;
    proxy_intercept_errors on;

    # ── Ловушки для сканеров (fail2ban jail lucx-nginx-honeypot) ──────────
    location ~* ^/(\.env|\.git|\.aws|\.ssh|\.DS_Store|wp-login\.php|wp-admin|wp-content|xmlrpc\.php|phpmyadmin|pma|myadmin|boaform|cgi-bin|actuator|vendor/phpunit|HNAP1|owa|autodiscover|solr|manager/html|admin\.php|config\.php|setup\.php|shell|eval-stdin\.php|server-status)(/|\$) {
        access_log /var/log/nginx/lucx-honeypot.log;
        return 444;
    }

    # ── LucX-UI Panel ──────────────────────────────────────────────────────
    location ${PANEL_PATH}/ {
        limit_req zone=panel_rl burst=50 nodelay;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        # v10: TLS к панели на loopback — SNI + без verify (самоподписанный cert панели)
        proxy_ssl_name \$host;
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_intercept_errors off;
        proxy_pass https://127.0.0.1:${PANEL_PORT};
    }
    location = ${PANEL_PATH} {
        return 301 ${PANEL_PATH}/;
    }

    # ── Subscription ────────────────────────────────────────────────────────
    # v4: автоопределение Clash/Mihomo/Xray-JSON делает сама панель
    # (subClashAutoDetect / subJsonAutoDetect по User-Agent).
    location ${SUB_PATH}/ {
        if (\$hack = 1) { return 404; }
        # v7.3 FIX (PR mozaroc/3x-ui-pro#5): большие заголовки подписки
        # ("upstream sent too big header" → 502 → error_page → 404)
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }
    location = ${SUB_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }
    location ~ ^${SUB_PATH}/(?<sub_id>[^/]+)\$ {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }
    # NEW v4: отдельные пути для JSON- и Clash-подписок (панель отдаёт сама)
    location ${JSON_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }
    location ${CLASH_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }

    # ── AmneziaWG subscription (random path, панель отдаёт .conf / vpn://) ──
    location ${AWG_PATH}/ {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }
    location = ${AWG_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }
    location ~ ^${AWG_PATH}/(?<sub_id>[^/]+)\$ {
        if (\$hack = 1) { return 404; }
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${SUB_PORT};  # built-in panel subscription (no sidecar)
        proxy_ssl_verify off;
    }

    # ── VLESS WebSocket ─────────────────────────────────────────────────────
    # v5 FIX: префикс-локация (а не точное совпадение) — часть клиентов добавляет к пути
    # суффикс/query; точное совпадение давало 404 → EOF в Throne.
    location ${WS_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:${VLESS_WS_PORT};
    }

    # ── VMess WebSocket ─────────────────────────────────────────────────────
    location ${VMESS_WS_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:${VMESS_WS_PORT};
    }

    # ── XHTTP / VLESS-XHTTP (за nginx TLS → UDS) ───────────────────────────
    # v5 FIX (по логу Throne): в packet-up upload идёт POST'ом на
    # /<путь>/<session> — точная локация location= давала 404
    # ("failed to send upload > bad status code:404"). Нужен prefix-match.
    location ${XHTTP_PATH} {
        if (\$hack = 1) { return 404; }
        client_max_body_size 0;
        proxy_pass http://unix:/dev/shm/lucx-xhttp.sock;
        proxy_http_version 1.1;
        proxy_set_header Connection        "";
        proxy_set_header Host              \$host;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_socket_keepalive on;
        proxy_buffering         off;
        proxy_request_buffering off;
        proxy_read_timeout      1d;
        proxy_send_timeout      1d;
    }

    # ── VLESS-XHTTP + TLS (второй UDS-сокет) ────────────────────────────────
    location ${XHTTP_TLS_PATH} {
        if (\$hack = 1) { return 404; }
        client_max_body_size 0;
        proxy_pass http://unix:/dev/shm/lucx-xhttp-tls.sock;
        proxy_http_version 1.1;
        proxy_set_header Connection        "";
        proxy_set_header Host              \$host;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_socket_keepalive on;
        proxy_buffering         off;
        proxy_request_buffering off;
        proxy_read_timeout      1d;
        proxy_send_timeout      1d;
    }

    # ── VLESS HTTPUpgrade (за nginx TLS) ────────────────────────────────────
    location ${HU_PATH} {
        if (\$hack = 1) { return 404; }
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:${VLESS_HU_PORT};
    }

    # ── VLESS gRPC ──────────────────────────────────────────────────────────
    location /${GRPC_SVC} {
        if (\$hack = 1) { return 404; }
        if (\$request_method != "POST") { return 404; }
        client_body_buffer_size 1m;
        client_body_timeout 1d;
        client_max_body_size 0;
        grpc_pass grpc://127.0.0.1:${VLESS_GRPC_PORT};
        grpc_socket_keepalive on;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_set_header X-Real-IP \$remote_addr;
    }

    # ── Trojan gRPC ─────────────────────────────────────────────────────────
    location /${TROJAN_GRPC_SVC} {
        if (\$hack = 1) { return 404; }
        if (\$request_method != "POST") { return 404; }
        client_body_buffer_size 1m;
        client_body_timeout 1d;
        client_max_body_size 0;
        grpc_pass grpc://127.0.0.1:${TROJAN_GRPC_PORT};
        grpc_socket_keepalive on;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_set_header X-Real-IP \$remote_addr;
    }

    # ── NaiveProxy ──────────────────────────────────────────────────────────
    # v4 FIX: NaiveProxy-клиент делает HTTP/2 CONNECT на произвольные адреса —
    # маршрутизация по пути "/naive-proxy/" невозможна. caddy-naive теперь
    # слушает свой публичный порт ${NAIVE_PORT} с TLS (cert DOMAIN) напрямую,
    # share-ссылка: naive+https://user:pass@${DOMAIN}:${NAIVE_PORT}

    # ── Диагностика SSO bridge ──────────────────────────────────────────────
    location = ${PANEL_PATH}/diag {
        auth_request /__diag_auth;
        error_page 401 403 = @diag_login;
        try_files /__nonexistent @diag_sso_ok;
    }
    location @diag_login  { return 302 ${PANEL_PATH}/; }
    location @diag_sso_ok {
        add_header Set-Cookie "diag_key=${DIAG_TOKEN}; Path=${DIAG_PATH}; Secure; HttpOnly; SameSite=Lax; Max-Age=604800";
        return 302 ${DIAG_PATH};
    }
    location = /__diag_auth {
        internal;
        proxy_pass https://127.0.0.1:${PANEL_PORT}${PANEL_PATH}/panel/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Requested-With XMLHttpRequest;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_intercept_errors on;
        error_page 300 301 302 303 304 307 308 400 401 402 403 404 405 500 501 502 503 504 =401 @diag_denied;
    }
    location @diag_denied { return 401; }
    location ^~ ${DIAG_PATH} {
        if (\$diag_auth = 0) { return 302 ${PANEL_PATH}/diag; }
        limit_req  zone=diag_page burst=10 nodelay;
        limit_conn per_ip 5;
        alias /var/www/diagnostics/;
        index index.html;
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-store" always;
        add_header X-Robots-Tag "noindex, nofollow" always;
    }

    # ── Генераторы ──────────────────────────────────────────────────────────
    # v4: /__clash_api удалён — Clash/YAML подписки отдает панель LucX-UI
    # нативно (subClashPath + subClashAutoDetect).

    # ── Universal Xray proxy (WS / gRPC / HTTP по порту+пути) ───────────────
    # Используется для динамически добавленных inbound'ов.
    location ~ ^/(?<fwdport>[0-9]+)/(?<fwdpath>.*)\$ {
        if (\$hack = 1) { return 404; }
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_read_timeout 1d;
        grpc_socket_keepalive on;
        grpc_send_timeout 1d;
        proxy_read_timeout 1d;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        if (\$content_type ~* "grpc") {
            grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args;
            break;
        }
        if (\$http_upgrade ~* "(websocket|ws)") {
            proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
            break;
        }
        proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
    }

${agh_nginx}
    location / { try_files \$uri \$uri/ =404; }
}
VHOST

    # ── Reality vhost (декой, реальный TLS за xray 8443) ──────────────────
    # nginx здесь не нужен — xray напрямую слушает 8443 и nginx stream
    # форвардит сырой TCP без TLS-терминации. Но оставим vhost на 9443
    # для "реального" HTTPS ответа при зондировании через этот домен.
    cat > "/etc/nginx/sites-available/${REALITY_DOMAIN}" <<RVHOST
server {
    server_tokens off;
    server_name ${REALITY_DOMAIN};
    listen 127.0.0.1:9443 ssl${http2_listen};
    ${http2_on}
    root /var/www/html/;
    index index.html;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3;
    ssl_certificate     /root/cert/${REALITY_DOMAIN}/fullchain.pem;
    ssl_certificate_key /root/cert/${REALITY_DOMAIN}/privkey.pem;
    # v7.2 (аудит #4): REALITY-fallback шлёт на 9443 сырой/не-TLS трафик —
    # это ожидаемый шум камуфляжа, снижаем уровень логов.
    error_log /var/log/nginx/real.vhost.err notice;
    if (\$host !~* ^(.*\.)?${REALITY_DOMAIN}\$) { return 444; }
    location / { try_files \$uri \$uri/ =404; }
}
RVHOST

    # NEW v4: декой-сайт на loopback 8087 — upstream камуфлирующего сайта
    # Telegram WEB proxy (tproxy-server отдаёт его клиентам на tg-домене).
    if [[ -n "$TG_WEB_DOMAIN" ]]; then
        cat > /etc/nginx/sites-available/002-tproxy-decoy.conf <<DECOY
server {
    listen 127.0.0.1:8087;
    server_name _;
    root /var/www/html/;
    index index.html;
    location / { try_files \$uri \$uri/ =404; }
}
DECOY
        ln -sf /etc/nginx/sites-available/002-tproxy-decoy.conf /etc/nginx/sites-enabled/
    fi

    # Активируем конфиги
    ln -sf "/etc/nginx/sites-available/000-redirect.conf"   /etc/nginx/sites-enabled/
    ln -sf "/etc/nginx/sites-available/001-maps.conf"       /etc/nginx/sites-enabled/
    ln -sf "/etc/nginx/sites-available/${DOMAIN}"           /etc/nginx/sites-enabled/
    ln -sf "/etc/nginx/sites-available/${REALITY_DOMAIN}"   /etc/nginx/sites-enabled/

    nginx -t || die "nginx конфигурация невалидна"
    systemctl restart nginx
    ok "Nginx настроен"
}
configure_nginx

###############################################################################
# НАСТРОЙКА БАЗЫ ДАННЫХ ПАНЕЛИ (все inbounds)
###############################################################################
configure_db() {
    inf "Настройка inbound'ов в БД панели..."

    [[ ! -f "$XUIDB" ]] && die "x-ui.db не найден: ${XUIDB}"
    systemctl stop x-ui 2>/dev/null || true
    sleep 1
    sqlite3 "$XUIDB" ".backup '${XUIDB}.pre-configure.bak'" 2>/dev/null \
        && chmod 600 "${XUIDB}.pre-configure.bak" \
        || warn "Бэкап x-ui.db перед настройкой не создан"

    # X25519 ключи для REALITY
    local xray_bin="/usr/local/x-ui/bin/xray-linux-${ARCH}"
    [[ -x "$xray_bin" ]] || xray_bin="/usr/local/x-ui/bin/xray-linux-arm"
    [[ -x "$xray_bin" ]] || die "xray binary не найден"
    local x25519_out private_key public_key
    x25519_out=$("$xray_bin" x25519 2>/dev/null)
    private_key=$(echo "$x25519_out" | grep "^PrivateKey:" | awk '{print $2}')
    # v7.2 FIX (аудит #2): у разных версий Xray метка PublicKey/Password —
    # парсим последнее поле строки, а не фиксированное $3.
    # v7.2 FIX (аудит #2): у разных версий Xray метка публичного ключа
    # различается: "Password (PublicKey): ..." (26.x), "PublicKey: ...",
    # "Public key: ...". Берём последнее поле строки-матча — устойчиво ко всем.
    public_key=$( echo "$x25519_out" | grep -iE 'public.?key|password' | tail -n1 | awk '{print $NF}')
    [[ -z "$public_key" ]] && die "Не удалось распарсить публичный ключ REALITY (x25519): ${x25519_out}"
    [[ -z "$private_key" ]] && die "Не удалось сгенерировать ключи REALITY"

    # REALITY short IDs
    local sids=()
    for _ in 1 2 3 4 5 6 7 8; do sids+=( "$(rand_hex 8)" ); done
    local sids_json
    sids_json=$(printf '"%s",' "${sids[@]}"); sids_json="[${sids_json%,}]"

    # Emoji флага страны
    local emoji
    emoji=$(curl -s --max-time 8 https://ipwho.is/ 2>/dev/null | jq -r '.flag.emoji // "🌐"' 2>/dev/null || echo "🌐")

    # Пароль для Trojan / Hysteria2 / mieru / sidecar
    local hy2_pass
    hy2_pass=$(rand_str 20)
    # Sidecar random credentials (вынесли из SQL heredoc)
    local SC_NAIVE_PASS SC_OLCRTC_KEY SC_OLCRTC_ROOM SC_QWDTT_PASS SC_TG_SECRET SC_TT_PREFIX SC_ANYTLS_PASS
    SC_NAIVE_PASS=$(rand_str 16)
    SC_OLCRTC_KEY=$(rand_hex 16)      # 64 hex (32 байта) — CryptoKey olcRTC
    SC_OLCRTC_ROOM=$(rand_hex 6)      # комната jitsi (требует сигналинг с токеном)
    SC_QWDTT_PASS=$(rand_str 20)
    # MTProto FakeTLS: "ee" + 16 случайных байт (hex) + hex(fakeTlsDomain)
    SC_TG_SECRET="ee$(rand_hex 16)$(printf '%s' "$DOMAIN" | od -An -tx1 | tr -d ' \n')"
    SC_TT_PREFIX="$(rand_hex 4)/ffffffff"   # TLS Client Random prefix/mask для TT
    SC_ANYTLS_PASS=$(rand_str 16)

    # Проверяем наличие колонки group_id в hosts
    local gid_col="" gids=()
    if sqlite3 "$XUIDB" "PRAGMA table_info(hosts);" | grep -qw "group_id"; then
        gid_col='"group_id",'
        # v7.4: 20 слотов (16 xray/hosts + 3 kernel AWG + 1 native amneziawg)
        for _ in $(seq 1 20); do gids+=( "'$(rand_str 16)'," ); done
    else
        for _ in $(seq 1 20); do gids+=( "" ); done
    fi

    # v4 FIX: все подписочные URI — с завершающим слэшем
    # (фронтенд панели склеивает subURI + subId напрямую; без слэша — 404)
    local sub_uri="https://${DOMAIN}${SUB_PATH}/"
    local json_uri="https://${DOMAIN}${JSON_PATH}/"
    local clash_uri="https://${DOMAIN}${CLASH_PATH}/"
    local awg_uri="https://${DOMAIN}${AWG_PATH}/"

    # NEW v5: условные параметры XHTTP+REALITY / gRPC+REALITY / TrustTunnel.
    # Если SNI-домен задан (-x/-g/-u) — xray слушает 127.0.0.1:<внутр. порт>,
    # nginx ведёт <домен>:443 → 127.0.0.1:<внутр. порт>. Если нет — прямой порт.
    local xhttp_r_listen="" xhttp_r_addr="$REALITY_DOMAIN" xhttp_r_adv=$VLESS_XHTTP_R_PORT xhttp_r_sni="$REALITY_DOMAIN"
    local xhttp_r_pp=false
    [[ -n "$XHTTP_R_DOMAIN" ]] && { xhttp_r_listen="127.0.0.1"; xhttp_r_addr="$XHTTP_R_DOMAIN"; xhttp_r_adv=443; xhttp_r_sni="$XHTTP_R_DOMAIN"; xhttp_r_pp=true; }
    local grpc_r_listen="" grpc_r_addr="$REALITY_DOMAIN" grpc_r_adv=$VLESS_GRPC_R_PORT grpc_r_sni="$REALITY_DOMAIN"
    local grpc_r_pp=false
    [[ -n "$GRPC_R_DOMAIN" ]] && { grpc_r_listen="127.0.0.1"; grpc_r_addr="$GRPC_R_DOMAIN"; grpc_r_adv=443; grpc_r_sni="$GRPC_R_DOMAIN"; grpc_r_pp=true; }
    # TrustTunnel: hostname = домен на сертификате; bind всегда на TRUSTTUNNEL_PORT.
    # Без -u — публичный порт (0.0.0.0), с -u — loopback (nginx SNI → TT).
    local tt_hostname="$DOMAIN" tt_listen="0.0.0.0:${TRUSTTUNNEL_PORT}" tt_adv=$TRUSTTUNNEL_PORT tt_addr="$DOMAIN"
    if [[ -n "$TT_DOMAIN" ]]; then
        tt_hostname="$TT_DOMAIN"; tt_listen="127.0.0.1:${TRUSTTUNNEL_PORT}"; tt_adv=443; tt_addr="$TT_DOMAIN"
    fi
    # v5: экспортируем реальные адреса/порты для итогового отчёта (print_results)
    export XHTTP_R_ADDR="$xhttp_r_addr" XHTTP_R_ADV="$xhttp_r_adv" XHTTP_R_SNI="$xhttp_r_sni"
    export GRPC_R_ADDR="$grpc_r_addr" GRPC_R_ADV="$grpc_r_adv" GRPC_R_SNI="$grpc_r_sni"
    export TT_HOST="$tt_hostname" TT_ADDR="$tt_addr" TT_ADV="$tt_adv"

    sqlite3 "$XUIDB" <<SQL

-- ── Настройки панели ────────────────────────────────────────────────────────
-- В settings часто НЕТ UNIQUE(key) → INSERT OR REPLACE плодит дубли subPath
-- (старый path в БД → 404 на подписке). Сначала чистим ключи, потом INSERT.
DELETE FROM settings WHERE key IN (
  'subPort','subPath','subURI','subJsonPath','subJsonURI',
  'subClashPath','subClashURI','subEnable','subEncrypt','subShowInfo',
  'subListen','subJsonEnable','subJsonAutoDetect','subJsonUserAgentRegex',
  'subJsonAlwaysArray','subClashEnable','subClashAutoDetect','subClashUserAgentRegex',
  'subAwgPath','subAwgURI','subAwgEnable','subClashEnableRouting',
  'subCertFile','subKeyFile','webListen','webDomain','webCertFile','webKeyFile',
  'sessionMaxAge','pageSize','remarkModel','timeLocation','tgBotEnable','secretEnable'
);

INSERT INTO "settings" ("key","value") VALUES
    ("subPort",          '${SUB_PORT}'),
    ("subPath",          '${SUB_PATH}/'),
    ("subURI",           '${sub_uri}'),
    ("subJsonPath",      '${JSON_PATH}/'),
    ("subJsonURI",       '${json_uri}'),
    ("subClashPath",     '${CLASH_PATH}/'),
    ("subClashURI",      '${clash_uri}'),
    ("subEnable",        'true'),
    ("subEncrypt",       'true'),
    ("subShowInfo",      'true'),
    -- NEW v4: подписки json / clash с автоопределением клиента по User-Agent
    ("subListen",        '127.0.0.1'),
    ("subJsonEnable",    'true'),
    ("subJsonAutoDetect",        'true'),
    ("subJsonUserAgentRegex",    '(?i)(v2rayn|v2rayng|sing-box|hiddify|nekoray|neko|throne|streisand|karing|exclave)'),
    ("subJsonAlwaysArray",       'false'),
    ("subClashEnable",   'true'),
    ("subClashAutoDetect",       'true'),
    ("subClashUserAgentRegex",   '(?i)(clash|clash.meta|clashverge|clashx|mihomo|stash|flclash)'),
    -- AmneziaWG subscription (random path, like Clash/JSON)
    ("subAwgPath",       '${AWG_PATH}/'),
    ("subAwgURI",        '${awg_uri}'),
    ("subAwgEnable",     'true'),
    -- Clash/Mihomo global routing (ключи панели 3x-ui/LucX-UI)
    ("subClashEnableRouting", 'true'),
    ("subCertFile",      '/root/cert/${DOMAIN}/fullchain.pem'),
    ("subKeyFile",       '/root/cert/${DOMAIN}/privkey.pem'),
    ("webListen",        '127.0.0.1'),
    ("webDomain",        ''),
    ("webCertFile",      ''),
    ("webKeyFile",       ''),
    ("sessionMaxAge",    '60'),
    ("pageSize",         '50'),
    ("remarkModel",      '-ieo'),
    ("timeLocation",     'Europe/Moscow'),
    ("tgBotEnable",      'false'),
    ("secretEnable",     'false');

-- ── 1. VLESS + REALITY + TCP (порт 8443, xray сам терминирует TLS) ─────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🔐 VLESS-REALITY',
  1, 0, '127.0.0.1', 8443, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"tcp",
    "security":"reality",
    "realitySettings":{
      "show":false,"xver":0,
      "dest":"127.0.0.1:9443",
      "target":"127.0.0.1:9443",
      "serverNames":["${REALITY_DOMAIN}"],
      "privateKey":"${private_key}",
      "shortIds":${sids_json},
      "settings":{
        "publicKey":"${public_key}",
        "fingerprint":"firefox",
        "serverName":"",
        "spiderX":"/"
      }
    },
    "tcpSettings":{"acceptProxyProtocol":true,"header":{"type":"none"}}
  }',
  'inbound-reality-8443',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 2. VLESS WebSocket (за nginx TLS, порт ${VLESS_WS_PORT}) ───────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🌐 VLESS-WS',
  1, 0, '127.0.0.1', ${VLESS_WS_PORT}, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"ws",
    "security":"none",
    "wsSettings":{
      "acceptProxyProtocol":false,
      "path":"${WS_PATH}",
      "headers":{"Host":"${DOMAIN}"}
    }
  }',
  'inbound-vless-ws-${VLESS_WS_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 3. VLESS XHTTP / gRPC over UDS ─────────────────────────────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} ⚡ VLESS-XHTTP',
  1, 0, '/dev/shm/lucx-xhttp.sock,0666', 0, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"xhttp",
    "security":"none",
    "xhttpSettings":{
      "path":"${XHTTP_PATH}",
      "host":"${DOMAIN}",
      "headers":{},
      "scMaxBufferedPosts":30,
      "scMaxEachPostBytes":"1000000",
      "noSSEHeader":false,
      "xPaddingBytes":"100-1000",
      "mode":"auto"
    },
    "sockopt":{
      "acceptProxyProtocol":false,
      "tcpFastOpen":true,
      "tcpMptcp":true,
      "tcpNoDelay":true,
      "domainStrategy":"UseIP",
      "tcpcongestion":"bbr",
      "tcpKeepAliveIdle":300,
      "tcpUserTimeout":10000,
      "tcpWindowClamp":600,
      "tcpMaxSeg":1440
    }
  }',
  'inbound-xhttp-uds',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 4. VLESS gRPC (за nginx, порт ${VLESS_GRPC_PORT}) ──────────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 📡 VLESS-gRPC',
  1, 0, '127.0.0.1', ${VLESS_GRPC_PORT}, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"grpc",
    "security":"none",
    "grpcSettings":{
      "serviceName":"${GRPC_SVC}",
      "authority":"${DOMAIN}",
      "multiMode":false
    }
  }',
  'inbound-vless-grpc-${VLESS_GRPC_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 5. Trojan gRPC (за nginx, порт ${TROJAN_GRPC_PORT}) ────────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🐴 Trojan-gRPC',
  1, 0, '127.0.0.1', ${TROJAN_GRPC_PORT}, 'trojan',
  '{"clients":[],"fallbacks":[]}',
  '{
    "network":"grpc",
    "security":"none",
    "grpcSettings":{
      "serviceName":"${TROJAN_GRPC_SVC}",
      "authority":"${DOMAIN}",
      "multiMode":false
    }
  }',
  'inbound-trojan-grpc-${TROJAN_GRPC_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 6. VMess WebSocket (за nginx, порт ${VMESS_WS_PORT}) ───────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🔵 VMess-WS',
  1, 0, '127.0.0.1', ${VMESS_WS_PORT}, 'vmess',
  '{"clients":[]}',
  '{
    "network":"ws",
    "security":"none",
    "wsSettings":{
      "acceptProxyProtocol":false,
      "path":"${VMESS_WS_PATH}",
      "headers":{"Host":"${DOMAIN}"}
    }
  }',
  'inbound-vmess-ws-${VMESS_WS_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 7. Hysteria2 (QUIC/UDP, порт ${HY2_PORT}, прямое подключение клиента) ──
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🌊 Hysteria2',
  1, 0, '', ${HY2_PORT}, 'hysteria',
  '{
    "version":2,
    "clients":[{"auth":"${hy2_pass}","email":"default@hy2","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":0,"subId":"","comment":"","reset":0}]
  }',
  '{
    "network":"hysteria",
    "security":"tls",
    "tlsSettings":{
      "serverName":"${DOMAIN}",
      "alpn":["h3"],
      "certificates":[{
        "usage":"encipherment",
        "certificateFile":"/root/cert/${DOMAIN}/fullchain.pem",
        "keyFile":"/root/cert/${DOMAIN}/privkey.pem"
      }]
    },
    "hysteriaSettings":{"version":2},
    "finalmask":{
      "quicParams":{
        "congestion":"brutal",
        "brutalUp":"100 mbps",
        "brutalDown":"100 mbps"
      }
    }
  }',
  'inbound-hysteria2-${HY2_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 8. NaiveProxy (sidecar — панель запускает caddy-naive) ─────────────────
-- v4 FIX: NaiveProxy = HTTP/2 CONNECT-прокси, путь-роутинг через nginx
-- невозможен. caddy-naive слушает публичный порт ${NAIVE_PORT} с TLS сам
-- (cert DOMAIN). Клиент: naive+https://user:pass@${DOMAIN}:${NAIVE_PORT}
-- routeThroughXray=false: egress прямой (маскировочный baseline; SOCKS-бридж
-- с routeXrayPort=0 рендерил невалидный конфиг и ронял caddy).
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🦊 NaiveProxy',
  1, 0, '', ${NAIVE_PORT}, 'naive',
  '{
    "remark":"NaiveProxy",
    "listen":"",
    "domain":"${DOMAIN}",
    "useAcme":false,
    "certFile":"/root/cert/${DOMAIN}/fullchain.pem",
    "keyFile":"/root/cert/${DOMAIN}/privkey.pem",
    "authUser":"naive",
    "authPass":"${SC_NAIVE_PASS}",
    "enableH3":false,
    "probeResistance":true,
    "logLevel":"INFO",
    "routeThroughXray":false,
    "routeXrayPort":0,
    "outboundTag":"",
    "behindCover":false,
    "clients":[]
  }',
  '{}',
  'inbound-naive-${NAIVE_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── 9. olcRTC (sidecar — WebRTC-based, рандомный порт ${OLCRTC_PORT}) ──────
-- v4 FIX: roomId обязателен (Validate падал без него) + routeThroughXray=false
-- (SOCKS-бридж не передаёт ICMP → клиентский ping ВСЕГДА падал при вкл.)
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🎙 olcRTC',
  1, 0, '', ${OLCRTC_PORT}, 'olcrtc',
  '{
    "remark":"olcRTC",
    "transport":"vp8channel",
    "provider":"jitsi",
    "roomId":"https://meet.jit.si/${SC_OLCRTC_ROOM}",
    "cryptoKey":"${SC_OLCRTC_KEY}",
    "dns":"8.8.8.8:53",
    "logLevel":"INFO",
    "routeThroughXray":false,
    "clients":[]
  }',
  '{}',
  'inbound-olcrtc-${OLCRTC_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── 10. qWDTT (QUIC/DTLS, рандомный порт ${QWDTT_PORT}) ────────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🎯 qWDTT',
  1, 0, '', ${QWDTT_PORT}, 'qwdtt',
  '{
    "remark":"qWDTT",
    "listenAddr":"0.0.0.0:${QWDTT_PORT}",
    "password":"${SC_QWDTT_PASS}",
    "routeThroughXray":true,
    "logLevel":"INFO",
    "clients":[]
  }',
  '{}',
  'inbound-qwdtt-${QWDTT_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── 11. mieru (TCP/порт ${MIERU_PORT}, рандом) ──────────────────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🦌 mieru',
  1, 0, '', ${MIERU_PORT}, 'mieru',
  '{
    "remark":"mieru",
    "portBindings":[{"port":${MIERU_PORT},"protocol":"TCP"}],
    "mtu":1400,
    "loggingLevel":"INFO",
    "routeThroughXray":false,
    "multiplexing":"MULTIPLEXING_LOW",
    "handshakeMode":"HANDSHAKE_NO_WAIT",
    "clients":[]
  }',
  '{}',
  'inbound-mieru-${MIERU_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── 12. TrustTunnel (TLS-based; клиенты TT ходят только на 443) ─────────────
-- v5 FIX: с -u <домен> — TT слушает loopback:${TRUSTTUNNEL_PORT}, а nginx
-- stream ведёт tt-домен:443 → сюда. Без -u — 0.0.0.0:${TRUSTTUNNEL_PORT}.
-- (пустой listen панель мерджила в "0.0.0.0:443" → конфликт с nginx!)
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🛡 TrustTunnel',
  1, 0, '', ${TRUSTTUNNEL_PORT}, 'trusttunnel',
  '{
    "remark":"TrustTunnel",
    "hostname":"${tt_hostname}",
    "listen":"${tt_listen}",
    "certFile":"/root/cert/${tt_hostname}/fullchain.pem",
    "keyFile":"/root/cert/${tt_hostname}/privkey.pem",
    "clientDns":"",
    "upstreamProtocol":"http2",
    "routeThroughXray":false,
    "routeXrayPort":0,
    "listenPreset":"fast",
    "clientRandomPrefix":"${SC_TT_PREFIX}",
    "clients":[]
  }',
  '{}',
  'inbound-trusttunnel-${TRUSTTUNNEL_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── 13. Telegram MTProto Proxy (встроенный mtg-multi) ───────────────────────
-- LucX-UI: протокол "mtproto", settings.clients[] (FakeTLS secret) + fakeTlsDomain
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} ✈️ Telegram MTProto',
  1, 0, '', ${TG_PORT}, 'mtproto',
  '{
    "fakeTlsDomain":"${DOMAIN}",
    "clients":[{"secret":"${SC_TG_SECRET}","email":"tg@lucx","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":0,"subId":"","comment":"","reset":0}]
  }',
  '{
    "network":"tcp",
    "security":"none",
    "tcpSettings":{"header":{"type":"none"}}
  }',
  'inbound-mtproto-${TG_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── 14. NEW v5: VLESS + XHTTP + REALITY ─────────────────────────────────────
-- Если задан -x <домен>: xray слушает 127.0.0.1:${VLESS_XHTTP_R_PORT},
-- nginx stream по SNI х-домен:443 → этот порт. Без -x — прямой порт.
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} ⚡ VLESS-XHTTP-REALITY',
  1, 0, '${xhttp_r_listen}', ${VLESS_XHTTP_R_PORT}, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"xhttp",
    "security":"reality",
    "xhttpSettings":{
      "path":"${XHTTP_PATH}",
      "host":"${xhttp_r_sni}",
      "headers":{},
      "scMaxBufferedPosts":30,
      "scMaxEachPostBytes":"1000000",
      "noSSEHeader":false,
      "xPaddingBytes":"100-1000",
      "mode":"auto"
    },
    "realitySettings":{
      "show":false,"xver":0,
      "dest":"127.0.0.1:9443",
      "target":"127.0.0.1:9443",
      "serverNames":["${xhttp_r_sni}"],
      "privateKey":"${private_key}",
      "shortIds":${sids_json},
      "settings":{
        "publicKey":"${public_key}",
        "fingerprint":"firefox",
        "serverName":"",
        "spiderX":"/"
      }
    },
    "sockopt":{"acceptProxyProtocol":${xhttp_r_pp}}
  }',
  'inbound-xhttp-reality-${VLESS_XHTTP_R_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 15. NEW v5: VLESS + gRPC + REALITY ──────────────────────────────────────
-- Если задан -g <домен>: за 443 через nginx SNI. Без -g — прямой порт.
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 📡 VLESS-gRPC-REALITY',
  1, 0, '${grpc_r_listen}', ${VLESS_GRPC_R_PORT}, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"grpc",
    "security":"reality",
    "grpcSettings":{
      "serviceName":"${GRPC_R_SVC}",
      "authority":"${grpc_r_sni}",
      "multiMode":false
    },
    "realitySettings":{
      "show":false,"xver":0,
      "dest":"127.0.0.1:9443",
      "target":"127.0.0.1:9443",
      "serverNames":["${grpc_r_sni}"],
      "privateKey":"${private_key}",
      "shortIds":${sids_json},
      "settings":{
        "publicKey":"${public_key}",
        "fingerprint":"firefox",
        "serverName":"",
        "spiderX":"/"
      }
    },
    "sockopt":{"acceptProxyProtocol":${grpc_r_pp}}
  }',
  'inbound-vless-grpc-reality-${VLESS_GRPC_R_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 16. NEW v5: VLESS + XHTTP + TLS (за nginx 443, второй UDS) ──────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} ⚡ VLESS-XHTTP-TLS',
  1, 0, '/dev/shm/lucx-xhttp-tls.sock,0666', 0, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"xhttp",
    "security":"none",
    "xhttpSettings":{
      "path":"${XHTTP_TLS_PATH}",
      "host":"${DOMAIN}",
      "headers":{},
      "scMaxBufferedPosts":30,
      "scMaxEachPostBytes":"1000000",
      "noSSEHeader":false,
      "xPaddingBytes":"100-1000",
      "mode":"auto"
    }
  }',
  'inbound-xhttp-tls-uds',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 18. NEW v4: VLESS + HTTPUpgrade (за nginx 443) ──────────────────────────
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🚀 VLESS-HTTPUpgrade',
  1, 0, '127.0.0.1', ${VLESS_HU_PORT}, 'vless',
  '{"clients":[],"decryption":"none","fallbacks":[]}',
  '{
    "network":"httpupgrade",
    "security":"none",
    "httpupgradeSettings":{
      "acceptProxyProtocol":false,
      "path":"${HU_PATH}",
      "host":"${DOMAIN}"
    }
  }',
  'inbound-vless-hu-${VLESS_HU_PORT}',
  '{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false}'
);

-- ── 17. NEW v6/v7: AnyTLS — sidecar (протокол anytls, не VLESS) ────────────
-- anytls-server сам подписывает cert если cert/key пусты; при наличии LE — используем.
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} 🔐 AnyTLS',
  1, 0, '', ${ANYTLS_PORT}, 'anytls',
  '{
    "port": ${ANYTLS_PORT},
    "password": "${SC_ANYTLS_PASS}",
    "sni": "${DOMAIN}",
    "certFile": "/root/cert/${DOMAIN}/fullchain.pem",
    "keyFile": "/root/cert/${DOMAIN}/privkey.pem",
    "clients": []
  }',
  '{}',
  'inbound-anytls-${ANYTLS_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);

-- ── Hosts: share-link адреса (всё через nginx 443, кроме UDP) ───────────────
INSERT INTO "hosts" ("inbound_id", ${gid_col} "sort_order","remark","address","port","security","fingerprint","alpn")
VALUES
  ((SELECT id FROM inbounds WHERE tag='inbound-reality-8443'),
   ${gids[0]} 0, 'REALITY', '${REALITY_DOMAIN}', 443, 'same', 'firefox', '[]'),

  -- v4 FIX: для WebSocket ALPN только http/1.1 — nginx (http2 on) выбирал h2,
  -- клиенты не умеют WS поверх HTTP/2 → VLESS-WS/VMess-WS не проходили ping.
  ((SELECT id FROM inbounds WHERE tag='inbound-vless-ws-${VLESS_WS_PORT}'),
   ${gids[1]} 1, 'VLESS-WS', '${DOMAIN}', 443, 'tls', 'firefox', '["http/1.1"]'),

  ((SELECT id FROM inbounds WHERE tag='inbound-xhttp-uds'),
   ${gids[2]} 2, 'XHTTP', '${DOMAIN}', 443, 'tls', 'firefox', '["h2","http/1.1"]'),

  ((SELECT id FROM inbounds WHERE tag='inbound-vless-grpc-${VLESS_GRPC_PORT}'),
   ${gids[3]} 3, 'VLESS-gRPC', '${DOMAIN}', 443, 'tls', 'firefox', '["h2","http/1.1"]'),

  ((SELECT id FROM inbounds WHERE tag='inbound-trojan-grpc-${TROJAN_GRPC_PORT}'),
   ${gids[4]} 4, 'Trojan-gRPC', '${DOMAIN}', 443, 'tls', 'firefox', '["h2","http/1.1"]'),

  ((SELECT id FROM inbounds WHERE tag='inbound-vmess-ws-${VMESS_WS_PORT}'),
   ${gids[5]} 5, 'VMess-WS', '${DOMAIN}', 443, 'tls', 'firefox', '["http/1.1"]'),

  -- Hysteria2: прямое UDP, клиент коннектится к ${DOMAIN}:${HY2_PORT}
  ((SELECT id FROM inbounds WHERE tag='inbound-hysteria2-${HY2_PORT}'),
   ${gids[6]} 6, 'Hysteria2', '${DOMAIN}', ${HY2_PORT}, 'tls', '', '[]'),

  -- qWDTT: DTLS/UDP, прямое подключение
  ((SELECT id FROM inbounds WHERE tag='inbound-qwdtt-${QWDTT_PORT}'),
   ${gids[7]} 7, 'qWDTT', '${DOMAIN}', ${QWDTT_PORT}, 'none', '', '[]'),

  -- mieru: прямое TCP подключение
  ((SELECT id FROM inbounds WHERE tag='inbound-mieru-${MIERU_PORT}'),
   ${gids[8]} 8, 'mieru', '${DOMAIN}', ${MIERU_PORT}, 'none', '', '[]'),

  -- olcRTC: прямое подключение
  ((SELECT id FROM inbounds WHERE tag='inbound-olcrtc-${OLCRTC_PORT}'),
   ${gids[9]} 9, 'olcRTC', '${DOMAIN}', ${OLCRTC_PORT}, 'none', '', '[]'),

  -- TrustTunnel: TCP, своя TLS (с -u — за nginx 443, иначе прямой порт)
  ((SELECT id FROM inbounds WHERE tag='inbound-trusttunnel-${TRUSTTUNNEL_PORT}'),
   ${gids[10]} 10, 'TrustTunnel', '${tt_addr}', ${tt_adv}, 'tls', '', '[]'),

  -- NEW v5: VLESS+XHTTP+REALITY (с -x — за 443 по SNI, иначе прямой порт)
  ((SELECT id FROM inbounds WHERE tag='inbound-xhttp-reality-${VLESS_XHTTP_R_PORT}'),
   ${gids[11]} 11, 'XHTTP-REALITY', '${xhttp_r_addr}', ${xhttp_r_adv}, 'same', 'firefox', '[]'),

  -- NEW v5: VLESS+gRPC+REALITY (с -g — за 443 по SNI, иначе прямой порт)
  ((SELECT id FROM inbounds WHERE tag='inbound-vless-grpc-reality-${VLESS_GRPC_R_PORT}'),
   ${gids[12]} 12, 'gRPC-REALITY', '${grpc_r_addr}', ${grpc_r_adv}, 'same', 'firefox', '[]'),

  -- NEW v5: VLESS+XHTTP+TLS — за nginx 443
  ((SELECT id FROM inbounds WHERE tag='inbound-xhttp-tls-uds'),
   ${gids[13]} 13, 'XHTTP-TLS', '${DOMAIN}', 443, 'tls', 'firefox', '["h2","http/1.1"]'),

  -- NEW v6/v7: AnyTLS — sidecar, прямой порт с TLS
  ((SELECT id FROM inbounds WHERE tag='inbound-anytls-${ANYTLS_PORT}'),
   ${gids[14]} 14, 'AnyTLS', '${DOMAIN}', ${ANYTLS_PORT}, 'tls', 'firefox', '[]'),

  -- v7 FIX: HTTPUpgrade — за nginx 443
  ((SELECT id FROM inbounds WHERE tag='inbound-vless-hu-${VLESS_HU_PORT}'),
   ${gids[15]} 15, 'HTTPUpgrade', '${DOMAIN}', 443, 'tls', 'firefox', '["http/1.1"]');

-- v7.3 FIX (PR mozaroc/3x-ui-pro#5): явный SNI для XHTTP-инбаундов.
-- Без него подписка отдавала SNI REALITY-домена → TLS XHTTP уходил на
-- обработчик REALITY вместо nginx→UDS обработчика. sni задаём явно,
-- override_sni_from_address=0 / keep_sni_blank=0 (дефолт, фиксируем).
UPDATE hosts SET sni='${DOMAIN}', override_sni_from_address=0, keep_sni_blank=0
  WHERE remark IN ('XHTTP','XHTTP-TLS');
-- один host на TrustTunnel (дубли в подписке)
DELETE FROM hosts WHERE remark='TrustTunnel' AND id NOT IN (
  SELECT MIN(id) FROM hosts WHERE remark='TrustTunnel'
);
SQL

# ── 18. NEW v4: Telegram WEB proxy (tproxy) — только если задан -t <домен> ──
# Панель сама запускает связку: MTProxy (mtg) → tproxy-server (relay) →
# Caddy (TLS на ${TG_WEB_DOMAIN}:${TPROXY_PORT}). nginx stream по SNI
# форвардит tg-домен:443 на этот порт. Сайт-маскировка — upstream nginx.
if [[ -n "$TG_WEB_DOMAIN" ]]; then
    sqlite3 "$XUIDB" <<SQL
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES (
  1, 0, 0, 0,
  '${emoji} ✈️ Telegram WEB proxy',
  1, 0, '127.0.0.1', ${TPROXY_PORT}, 'tproxy',
  '{
    "remark":"Telegram WEB proxy",
    "hostname":"${TG_WEB_DOMAIN}",
    "secret":"${TPROXY_SECRET}",
    "port":${TPROXY_PORT},
    "carrierMode":"https",
    "siteSource":"upstream",
    "siteUpstream":"http://127.0.0.1:8087",
    "certFile":"/root/cert/${TG_WEB_DOMAIN}/fullchain.pem",
    "keyFile":"/root/cert/${TG_WEB_DOMAIN}/privkey.pem",
    "externalTLS":false,
    "behindCover":false,
    "routeThroughXray":false,
    "routeXrayPort":0,
    "outboundTag":""
  }',
  '{}',
  'inbound-tproxy-${TPROXY_PORT}',
  '{"enabled":false,"destOverride":[],"metadataOnly":false}'
);
SQL
fi

    # ═══ NEW v7.2: AmneziaWG × 3 (v1.5 / v2.0 / v3.1) ═════════════════════════
    # Порты/подсети — из env (AWG15/20/31_PORT, AWG15/20/31_SUBNET) или дефолты.
    # v10: только awg genkey / wg genkey / Python cryptography.
    # DER+printf (openssl pkey) даёт невалидные ключи → die, не писать inbound.
    # Проверка: 44 символа base64url/std, декод = ровно 32 байта.
    awg_validate_key() {
        local k="$1" raw
        [[ ${#k} -eq 44 ]] || return 1
        raw=$(printf '%s' "$k" | base64 -d 2>/dev/null | wc -c) || return 1
        [[ "$raw" -eq 32 ]] || return 1
        return 0
    }
    awg_keypair() {
        local bin="" priv pub
        for bin in /usr/local/x-ui/bin/awg /usr/bin/awg \
                   /usr/local/x-ui/bin/wg  /usr/bin/wg; do
            [[ -x "$bin" ]] && break
            bin=""
        done
        if [[ -n "$bin" ]]; then
            priv=$("$bin" genkey 2>/dev/null) || priv=""
            pub=$(printf '%s' "$priv" | "$bin" pubkey 2>/dev/null) || pub=""
            if awg_validate_key "$priv" && awg_validate_key "$pub"; then
                echo "$priv"; echo "$pub"; return 0
            fi
        fi
        # Fallback: Python cryptography (X25519 → WireGuard base64 keys)
        local out
        out=$(python3 - <<'PYKP' 2>/dev/null
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
priv = X25519PrivateKey.generate()
priv_raw = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_raw = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print(base64.b64encode(priv_raw).decode())
print(base64.b64encode(pub_raw).decode())
PYKP
) || out=""
        if [[ -n "$out" ]]; then
            priv=$(printf '%s\n' "$out" | sed -n '1p')
            pub=$(printf '%s\n' "$out" | sed -n '2p')
            if awg_validate_key "$priv" && awg_validate_key "$pub"; then
                echo "$priv"; echo "$pub"; return 0
            fi
        fi
        return 1
    }

    # v7.2 FIX: настройки AWG по фактической схеме LucX-UI (protocol=awg,
    # плоский settings-JSON — см. internal/awg/instance.go):
    # privateKey/publicKey сервера, address, dns, jc/jmin/jmax/s1-s4/h1-h4/
    # i1-i5, awgVersion, mimicryProfile/browserProfile/region; клиенты —
    # publicKey/privateKey/allowedIPs[]/keepAlive/password.
    # obfLevel: 1=lite, 2=standard, 3=pro, 4=premium (UI «Профиль обфускации»)
    # v10: clients[] с реальным keypair + allowedIPs [10.x.x.2/32]; пустые ключи запрещены.
    # AWG 3.1: S1–S4 >= 16, contentPaddingAddition "8-24", при HPK → H1=1,H2=2,H3=3,H4=4.
    awg_setting() { # $1=port $2=version $3=subnet $4=svrPriv $5=svrPub $6=cliPriv $7=cliPub $8=email $9=subId $10=hpk
        local base="${3%%/*}"
        local cli_ip="${base%.*}.2/32"
        local sk="$4" spk="$5" csk="$6" cpk="$7" hpk="${10:-}"
        # Ключи обязательны (die до INSERT)
        if ! awg_validate_key "$sk" || ! awg_validate_key "$spk" \
           || ! awg_validate_key "$csk" || ! awg_validate_key "$cpk"; then
            die "AWG keypair невалиден (ожидается base64 44 символа → 32 байта). Установите awg/wg или python3-cryptography."
        fi
        jq -cn --argjson port "$1" --arg ver "$2" --arg addr "$3" \
               --arg sk "$sk" --arg spk "$spk" --arg csk "$csk" --arg cpk "$cpk" \
               --arg em "$8" --arg sid "$9" --arg hpk "$hpk" \
               --arg pw "$(rand_str 16)" --arg cli "$cli_ip" '{
            privateKey:$sk, publicKey:$spk,
            address:$addr, subnetIp:($addr|split("/")[0]), subnetCidr:24,
            dns:"1.1.1.1, 1.0.0.1",
            mtu:1420,
            awgVersion:$ver,
            obfLevel:4,
            region:"ru",
            mimicryProfile:"tls",
            browserProfile:"chrome",
            jc:5, jmin:50, jmax:100,
            # S1–S4: для 3.1 все >= 16 (s4 был 12 — ломал handshake)
            s1:(if $ver == "3.1" then 85 else 85 end),
            s2:(if $ver == "3.1" then 70 else 70 end),
            s3:(if $ver == "3.1" then 40 else 40 end),
            s4:(if $ver == "3.1" then 16 else 12 end),
            # Header Protection (3.1 + HPK): H1=1,H2=2,H3=3,H4=4; иначе диапазоны/константы
            h1:(if ($ver == "3.1" and ($hpk|length) > 0) then "1"
                elif $ver == "1.5" then "15000" else "15000-75000" end),
            h2:(if ($ver == "3.1" and ($hpk|length) > 0) then "2"
                elif $ver == "1.5" then "120000" else "120000-180000" end),
            h3:(if ($ver == "3.1" and ($hpk|length) > 0) then "3"
                elif $ver == "1.5" then "220000" else "220000-280000" end),
            h4:(if ($ver == "3.1" and ($hpk|length) > 0) then "4"
                elif $ver == "1.5" then "320000" else "320000-380000" end),
            i1:"", i2:"", i3:"", i4:"", i5:"",
            headerProtectionKey:$hpk,
            contentPaddingAddition:(if $ver == "3.1" then "8-24" else "0" end),
            rekeyAfterTime:(if $ver == "3.1" then "100-140" else "0" end),
            rekeyTimeout:(if $ver == "3.1" then "3-7" else "0" end),
            rejectAfterTime:(if $ver == "3.1" then "180-260" else "0" end),
            keepaliveTimeout:(if $ver == "3.1" then "8-14" else "0" end),
            maxHandshakeAttempts:(if $ver == "3.1" then "15-30" else "0" end),
            randomTrailers:($ver == "3.1"), disableCookies:($ver == "3.1"),
            routeThroughXray:false, outboundTag:"", p2p:false,
            clients:[]
        }'
    }

    # AWG1..AWG9 без сида клиентов (clients[] пустой)
    local -a AWG_VERS=( "1.5" "1.5" "1.5" "2" "2" "2" "3.1" "3.1" "3.1" )
    local -a AWG_PORTS=( "$AWG1_PORT" "$AWG2_PORT" "$AWG3_PORT" "$AWG4_PORT" "$AWG5_PORT"
                         "$AWG6_PORT" "$AWG7_PORT" "$AWG8_PORT" "$AWG9_PORT" )
    local -a AWG_SUBNETS=( "$AWG1_SUBNET" "$AWG2_SUBNET" "$AWG3_SUBNET" "$AWG4_SUBNET" "$AWG5_SUBNET"
                           "$AWG6_SUBNET" "$AWG7_SUBNET" "$AWG8_SUBNET" "$AWG9_SUBNET" )
    local HPK31
    HPK31=$(openssl rand -base64 32 2>/dev/null | tr -d '\n')

    sqlite3 "$XUIDB" "DELETE FROM inbounds WHERE tag LIKE 'inbound-awg-%' OR protocol='awg';" 2>/dev/null || true
    sqlite3 "$XUIDB" "DELETE FROM hosts WHERE remark LIKE 'AWG %' OR remark LIKE 'AWG%';" 2>/dev/null || true

    local _i _ver _port _subnet _hpk _Ps _Pc _S _tag _remark _sort
    for _i in 0 1 2 3 4 5 6 7 8; do
        _ver="${AWG_VERS[$_i]}"
        _port="${AWG_PORTS[$_i]}"
        _subnet="${AWG_SUBNETS[$_i]}"
        _hpk=""
        [[ "$_ver" == "3.1" ]] && _hpk="$HPK31"
        mapfile -t _Ps < <(awg_keypair)
        mapfile -t _Pc < <(awg_keypair)
        [[ ${#_Ps[@]} -eq 2 && ${#_Pc[@]} -eq 2 ]] || die "AWG$((_i+1)): invalid keypair"
        _S=$(awg_setting "$_port" "$_ver" "$_subnet" "${_Ps[0]}" "${_Ps[1]}" "${_Pc[0]}" "${_Pc[1]}" "" "" "$_hpk")
        _tag="inbound-awg-v$((_i+1))-${_port}"
        _remark="${emoji} 🔐 AWG $((_i+1)) (${_ver})"
        _sort=$((16 + _i))
        sqlite3 "$XUIDB" <<SQL
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES
  (1,0,0,0,'${_remark}',1,0,'',${_port},'awg',
   '${_S}','{}','${_tag}',
   '{"enabled":false,"destOverride":[],"metadataOnly":false}');
INSERT INTO "hosts" ("inbound_id", ${gid_col} "sort_order","remark","address","port","security","fingerprint","alpn")
VALUES
  ((SELECT id FROM inbounds WHERE tag='${_tag}'),
   0 ${_sort},'AWG $((_i+1))','${SERVER_IP4}',${_port},'none','','[]');
SQL
        ok "  AWG $((_i+1)) (${_ver}) :${_port} ${_subnet}"
    done

    # ── Native AmneziaWG (userspace amneziawg-go в панели) ──────────────────
    # v10: inbound создаём; ключи сервера/клиентов — пустые.
    # Пользователь генерирует ключи в панели (API/нормализатор), не сырой sqlite.
    # settings: { server: {...}, clients: [] } — не путать с kernel protocol "awg"
    local AMZ_HPK AMZ_SETTINGS
    AMZ_HPK=$(openssl rand -base64 32 2>/dev/null | tr -d '\n')
    local amz_base="${AMNEZIAWG_SUBNET%%/*}"
    local amz_net="${amz_base%.*}.0"
    AMZ_SETTINGS=$(jq -cn \
        --arg hpk "$AMZ_HPK" \
        --arg sip "$amz_net" --argjson cidr 24 \
        '{
          server: {
            privateKey: "", publicKey: "",
            subnetIp: $sip, subnetCidr: $cidr,
            mtu: 1420,
            primaryDns: "1.1.1.1", secondaryDns: "1.0.0.1",
            externalInterface: "", ipv6Enabled: false, ipv6Subnet: "",
            ipv6ExternalInterface: "",
            routeThroughXray: false,
            jc: 5, jmin: 50, jmax: 100,
            s1: 85, s2: 70, s3: 40, s4: 16,
            h1: "1", h2: "2", h3: "3", h4: "4",
            i1: "", i2: "", i3: "", i4: "", i5: "",
            headerProtectionKey: $hpk,
            contentPaddingAddition: "8-24",
            rekeyAfterTime: "100-140", rekeyTimeout: "3-7",
            rejectAfterTime: "180-260", keepaliveTimeout: "8-14",
            maxHandshakeAttempts: "15-30",
            randomTrailers: true, disableCookies: true
          },
          clients: []
        }')
    sqlite3 "$XUIDB" <<SQL
DELETE FROM inbounds WHERE tag LIKE 'inbound-amneziawg-%' OR protocol='amneziawg';
DELETE FROM hosts WHERE remark IN ('AmneziaWG','amneziawg');
INSERT INTO "inbounds"
  ("user_id","up","down","total","remark","enable","expiry_time","listen","port",
   "protocol","settings","stream_settings","tag","sniffing")
VALUES
  (1,0,0,0,'${emoji} 🔐 AmneziaWG',1,0,'',${AMNEZIAWG_PORT},'amneziawg',
   '${AMZ_SETTINGS}','{}','inbound-amneziawg-${AMNEZIAWG_PORT}',
   '{"enabled":false,"destOverride":[],"metadataOnly":false}');
INSERT INTO "hosts" ("inbound_id", ${gid_col} "sort_order","remark","address","port","security","fingerprint","alpn")
VALUES
  ((SELECT id FROM inbounds WHERE tag='inbound-amneziawg-${AMNEZIAWG_PORT}'),
   ${gids[19]} 19,'AmneziaWG','${SERVER_IP4}',${AMNEZIAWG_PORT},'none','','[]');
SQL

    # Клиенты: только шаблоны (seed_client_templates), без авто-сида в inbounds

    # Сохраняем учётные данные и сертификаты
    /usr/local/x-ui/x-ui setting \
        -username  "$PANEL_USER" \
        -password  "$PANEL_PASS" \
        -port      "$PANEL_PORT" \
        -webBasePath "${PANEL_PATH}" \
        -listenIP  127.0.0.1 >/dev/null 2>&1 || warn "x-ui setting завершился с ошибкой"

    /usr/local/x-ui/x-ui cert \
        -webCert    "/root/cert/${DOMAIN}/fullchain.pem" \
        -webCertKey "/root/cert/${DOMAIN}/privkey.pem" >/dev/null 2>&1 || warn "x-ui cert завершился с ошибкой"
    # Перенос clients[] из settings в таблицы clients/client_inbounds
    /usr/local/x-ui/x-ui migrate >/dev/null 2>&1 || warn "x-ui migrate завершился с ошибкой"

    systemctl start x-ui
    sleep 5


    # ═══ v10.1: только шаблоны клиентов (clients + client_traffics), без inbounds ═══
    seed_client_templates() {
        local py_src=""
        for cand in \
            "${SCRIPT_DIR}/add_lucx_clients_name.py" \
            "/root/add_lucx_clients_name.py" \
            "/opt/lucx-ui/add_lucx_clients_name.py"; do
            [[ -f "$cand" ]] && py_src="$cand" && break
        done
        if [[ -z "$py_src" ]]; then
            warn "add_lucx_clients_name.py не найден — шаблоны клиентов пропущены"
            return 0
        fi
        inf "Шаблоны клиентов из $(basename "$py_src") (clients table only)..."
        python3 "$py_src" "$XUIDB" --no-restart 2>&1 | tail -n 50 || warn "seed clients failed"
        ok "Шаблоны клиентов готовы (привязка к inbound — вручную в панели)"
    }
    seed_client_templates

    # DEBUG: Check inbounds count
    local total_inbounds
    total_inbounds=$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null || echo "?")
    
    # DEBUG: Check hosts count
    local total_hosts
    total_hosts=$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM hosts;" 2>/dev/null || echo "?")
    
    # DEBUG: Show any errors from hosts table
    local hosts_errors
    hosts_errors=$(sqlite3 "$XUIDB" "SELECT * FROM hosts;" 2>&1 | grep -i error || true)
    if [[ -n "$hosts_errors" ]]; then
        err "Ошибки в hosts: $hosts_errors"
    fi
    
    # DEBUG: Show hosts content
    local hosts_content
    hosts_content=$(sqlite3 "$XUIDB" "SELECT inbound_id, remark, address, port FROM hosts;" 2>&1 || echo "ERROR")
    if [[ "$hosts_content" != "ERROR" && -n "$hosts_content" ]]; then
        inf "Hosts content: $hosts_content"
    fi
    

    # ── Clash/Mihomo global routing rules → settings.subClashRules ──────────
    # Пишем через файл, чтобы не ломать SQL-heredoc многострочным YAML.
    # v7.3: шаблон вынесен в write_clash_template() — содержимое берётся из
    # Clash+Mihomo_routing.md (строки-комментарии убираются sed-ом при записи).
    # Функция вызывается и здесь, и из install_clash_routing_template.

    # ── Server Xray routing (ROSCOM) ──────────────────────────────────────────
    apply_roscom_routing() {
        local rules_file=""
        for cand in \
            "${SCRIPT_DIR}/routing-rules_Roscom.json" \
            "/root/routing-rules_Roscom.json" \
            "/opt/lucx-ui/routing-rules_Roscom.json"; do
            [[ -f "$cand" ]] && rules_file="$cand" && break
        done
        [[ -f "$rules_file" ]] || { warn "routing-rules_Roscom.json не найден"; return 0; }
        inf "Серверная маршрутизация из $(basename "$rules_file")..."
        python3 - "$XUIDB" "$rules_file" <<'ROUTPY'
import json, sqlite3, sys
db, rules_path = sys.argv[1], sys.argv[2]
rules = json.loads(open(rules_path, encoding="utf-8").read())
con = sqlite3.connect(db)
cur = con.cursor()
row = cur.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig' LIMIT 1").fetchone()
if not row or not row[0]:
    tmpl = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "inbounds": [],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
            {"tag": "api", "protocol": "freedom", "settings": {}},
            {"tag": "AWG_RUtoFI", "protocol": "freedom", "settings": {}},
            {"tag": "warp", "protocol": "freedom", "settings": {}}
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                              "statsOutboundUplink": True, "statsOutboundDownlink": True}},
        "stats": {}
    }
else:
    try:
        tmpl = json.loads(row[0])
    except Exception:
        tmpl = {}
    if not isinstance(tmpl, dict):
        tmpl = {}
    outs = tmpl.get("outbounds") or []
    have = {o.get("tag") for o in outs if isinstance(o, dict)}
    for tag, proto in (("direct", "freedom"), ("blocked", "blackhole"), ("api", "freedom"),
                       ("AWG_RUtoFI", "freedom"), ("warp", "freedom")):
        if tag not in have:
            outs.append({"tag": tag, "protocol": proto, "settings": {}})
    tmpl["outbounds"] = outs
    routing = tmpl.get("routing") if isinstance(tmpl.get("routing"), dict) else {}
    routing["domainStrategy"] = routing.get("domainStrategy") or "IPIfNonMatch"
    routing["rules"] = rules
    tmpl["routing"] = routing
cur.execute("DELETE FROM settings WHERE key='xrayTemplateConfig'")
cur.execute("INSERT INTO settings (key, value) VALUES ('xrayTemplateConfig', ?)",
            (json.dumps(tmpl, ensure_ascii=False, separators=(",", ":")),))
con.commit()
con.close()
print("roscom_routing_applied", len(rules))
ROUTPY
        ok "Xray routing (ROSCOM) → xrayTemplateConfig"
    }
    apply_roscom_routing

    write_clash_template() {
        local clash_rules_file="/etc/x-ui/clash-templates/global-ru.yaml"
        mkdir -p /etc/x-ui/clash-templates
        local _cm=""
        for cand in "${SCRIPT_DIR}/clash_mihomo_routing.md" "/root/clash_mihomo_routing.md"; do
            [[ -f "$cand" ]] && _cm="$cand" && break
        done
        if [[ -n "$_cm" ]]; then
            sed '/^[[:space:]]*#/d' "$_cm" > "$clash_rules_file"
            ok "Clash template from $(basename "$_cm")"
            return 0
        fi
        cat > "$clash_rules_file" <<'CLASHRULES'
# ============================================================
# Mihomo Config — Россия, 3x-ui
# Максимальная адаптивность + балансировка + полный DIRECT для РФ
# ============================================================

mode: rule
log-level: warning
mixed-port: 10000
unified-delay: true
allow-lan: true
tcp-concurrent: true
enable-process: true
find-process-mode: always
global-client-fingerprint: chrome
keep-alive-interval: 30
geo-auto-update: true
geo-update-interval: 168

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports:
        - 80
        - 8080-8880
      override-destination: true
    TLS:
      ports:
        - 443
        - 8443
      override-destination: true
    QUIC:
      ports:
        - 443
        - 8443
      override-destination: true
  skip-domain:
    - "+.push.apple.com"
    - "+.crl.apple.com"
    - "Mijia.*"
    - "+.srv.nintendo.net"
    - "+.stun.playstation.net"
    - "+.xboxlive.com"
    - "tun.msftconnecttest.com"

dns:
  enable: true
  prefer-h3: true
  use-hosts: true
  use-system-hosts: true
  listen: 127.0.0.1:6868
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  cache-algorithm: arc
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.localhost"
    - "*.home.arpa"
    - "localhost.ptlogin2.qq.com"
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"
    - "msftconnecttest.com"
    - "localhost.sec.qq.com"
    - "+.srv.nintendo.net"
    - "+.stun.playstation.net"
    - "+.xboxlive.com"
    - "*.mshome.net"
    - "*.miHoYo.com"
    - "*.mihoyo.com"
    - "+.star.cq.qq.com"
    - "+.logon.battlenet.com.cn"
    - "+.push.apple.com"
    - "+.crl.apple.com"
    - "+.steamcontent.com"
    - "+.steamstatic.com"
    - "+.steamcdn-a.akamaihd.net"
    - "+.steam-chat.com"
    - "+.max.ru"
    - "+.max.com"
    - "+.maxcdn.ru"
    - "+.vk.com"
    - "+.vk-portal.net"
    - "+.vk-cdn.net"
    - "+.vkuser.net"
    - "+.vkvideo.ru"
    - "+.vk-apps.com"
    - "+.vkuservideo.net"
    - "+.userapi.com"
    - "+.vkforms.ru"
    - "+.vkcdnglb.net"
    - "+.ok.ru"
    - "+.odnoklassniki.ru"
    - "+.mycdn.me"
    - "+.mail.ru"
    - "+.e.mail.ru"
    - "+.m.mail.ru"
    - "+.r.mail.ru"
    - "+.auth.mail.ru"
    - "+.account.mail.ru"
    - "+.imgsmail.ru"
    - "+.tamtam.chat"
    - "+.webinar.ru"
    - "+.loginza.ru"
    - "+.yandex.ru"
    - "+.yandex.net"
    - "+.yandex.com"
    - "+.ya.ru"
    - "+.kinopoisk.ru"
    - "+.music.yandex.ru"
    - "+.market.yandex.ru"
    - "+.eda.yandex.ru"
    - "+.lavka.yandex.ru"
    - "+.disk.yandex.ru"
    - "+.pdd.yandex.ru"
    - "+.moikrug.ru"
    - "+.narod.ru"
    - "+.turbopages.org"
    - "+.strm.yandex.net"
    - "+.yastatic.net"
    - "+.yastat.net"
    - "+.sberbank.ru"
    - "+.sber.ru"
    - "+.tinkoff.ru"
    - "+.tinkov.ru"
    - "+.vtb.ru"
    - "+.alfabank.ru"
    - "+.gazprombank.ru"
    - "+.openbank.ru"
    - "+.open.ru"
    - "+.raiffeisen.ru"
    - "+.psbank.ru"
    - "+.sovcombank.ru"
    - "+.rsb.ru"
    - "+.homecredit.ru"
    - "+.uralsib.ru"
    - "+.mkb.ru"
    - "+.rosbank.ru"
    - "+.sravni.ru"
    - "+.banki.ru"
    - "+.qiwi.com"
    - "+.yu-money.ru"
    - "+.yoomoney.ru"
    - "+.webmoney.ru"
    - "+.mts.ru"
    - "+.bank.mts.ru"
    - "+.megafon.ru"
    - "+.beeline.ru"
    - "+.tele2.ru"
    - "+.gosuslugi.ru"
    - "+.gosuslugi.kz"
    - "+.esia.gosuslugi.ru"
    - "+.nalog.gov.ru"
    - "+.nalog.ru"
    - "+.mos.ru"
    - "+.mfc.ru"
    - "+.mvd.ru"
    - "+.minjust.gov.ru"
    - "+.russianpost.ru"
    - "+.pochta.ru"
    - "+.mfms.dks.ru"
    - "+.sfr.gov.ru"
    - "+.pfr.gov.ru"
    - "+.sudact.ru"
    - "+.kad.arbitr.ru"
    - "+.my.e-government.ru"
    - "+.cbr.ru"
    - "+.banki.ru"
    - "+.e-disclosure.ru"
    - "+.wildberries.ru"
    - "+.wb.ru"
    - "+.wbcontent.net"
    - "+.wbx5.ru"
    - "+.ozon.ru"
    - "+.ozonusercontent.com"
    - "+.megamarket.ru"
    - "+.beru.ru"
    - "+.aliexpress.ru"
    - "+.lamoda.ru"
    - "+.dns-shop.ru"
    - "+.mvideo.ru"
    - "+.eldorado.ru"
    - "+.citilink.ru"
    - "+.2gis.com"
    - "+.2gis.ru"
    - "+.sbermarket.ru"
    - "+.perekrestok.ru"
    - "+.magnit.ru"
    - "+.delivery-club.ru"
    - "+.samokat.ru"
    - "+.ikea.ru"
    - "+.hh.ru"
    - "+.rabota.ru"
    - "+.superjob.ru"
    - "+.rutube.ru"
    - "+.ivi.ru"
    - "+.okko.tv"
    - "+.start.ru"
    - "+.more.tv"
    - "+.wink.rt.ru"
    - "+.premier.one"
    - "+.gpm_tv.ru"
    - "+.taxi.yandex.ru"
    - "+.citymobil.ru"
    - "+.gett.com"
    - "+.reg.ru"
    - "+.nic.ru"
    - "+.timepad.ru"
    - "+.tass.ru"
    - "+.ria.ru"
    - "+.interfax.ru"
    - "+.rbc.ru"
    - "+.kommersant.ru"
    - "+.lenta.ru"
    - "+.gazeta.ru"
    - "+.iz.ru"
    - "+.rt.com"
    - "+.cloudflare-dns.com"
    - "+.dns.google"

  default-nameserver:
    - 77.88.8.8
    - 195.208.4.1
    - system
  proxy-server-nameserver:
    - 77.88.8.8
    - 195.208.4.1
    - system
  direct-nameserver:
    - tls://77.88.8.8#DIRECT
    - tls://8.8.8.8#DIRECT
    - 195.208.4.1#DIRECT
    - system
  nameserver:
    - https://dns.cloudflare/dns-query#PROXY
    - https://dns.google/dns-query#PROXY
    - tls://8.8.4.4#PROXY
  fallback:
    - tls://8.8.8.8#PROXY
    - tls://1.1.1.1#PROXY
    - https://dns.cloudflare/dns-query#PROXY
  fallback-filter:
    geoip: true
    geoip-code: RU
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
    domain:
      - "+.google.com"
      - "+.facebook.com"
      - "+.youtube.com"
      - "+.twitter.com"
      - "+.x.com"

# v10.1: proxy-providers с чужим доменом убран; include-all-proxies.

proxy-groups:

  - name: 🌐 Internet
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)
      - DIRECT

  - name: 🌍 VPN (Manual)
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hijacking.png
    type: select
    include-all-proxies: true
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)

  - name: 🚀 Auto (Fastest)
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png
    type: url-test
    tolerance: 100
    url: https://cp.cloudflare.com/generate_204
    interval: 120
    include-all-proxies: true

  - name: 🎯 Balance (Load)
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/LoadBalance.png
    type: load-balance
    strategy: consistent-hashing
    url: https://cp.cloudflare.com/generate_204
    interval: 180
    tolerance: 150
    include-all-proxies: true

  - name: 🔄 Failover
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Availability.png
    type: fallback
    url: https://cp.cloudflare.com/generate_204
    interval: 120
    tolerance: 100
    include-all-proxies: true

  - name: 🔀 Round Robin
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png
    type: load-balance
    strategy: round-robin
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    include-all-proxies: true

  - name: ▶️ YouTube
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)
  - name: ➤ Telegram
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: 💬 Discord
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Discord.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: ➤ WhatsApp
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Facebook.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: 🤖 AI Services
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🔄 Failover
      - 🌍 VPN (Manual)

  - name: 🎬 Streaming
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Streaming.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🌍 VPN (Manual)

  - name: 🇷🇺 Blocked RU
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Russia.png
    type: select
    proxies:
      - 🚀 Auto (Fastest)
      - 🌍 VPN (Manual)
      - DIRECT

  - name: PROXY
    type: select
    hidden: true
    proxies:
      - 🚀 Auto (Fastest)
      - 🎯 Balance (Load)
      - 🔄 Failover
      - 🌍 VPN (Manual)

rule-providers:

  oisd_big:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/oisd/big.mrs
    path: ./oisd/big.mrs
    interval: 86400

  oisd_small:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/oisd/small.mrs
    path: ./oisd/small.mrs
    interval: 86400

  telegram-ips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/telegram.mrs
    path: ./rule-sets/telegram-ips.mrs

  telegram-domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/telegram.mrs
    path: ./rule-sets/telegram-domains.mrs

  whatsapp-domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/whatsapp.mrs
    path: ./rule-sets/whatsapp-domains.mrs

  facebook-ips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/facebook.mrs
    path: ./rule-sets/facebook-ips.mrs
  discord_domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/discord.mrs
    path: ./rule-sets/discord_domains.mrs

  discord_voiceips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/discord-voice-ip-list.mrs
    path: ./rule-sets/discord_voiceips.mrs

  youtube:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/youtube.mrs
    path: ./rule-sets/youtube.mrs

  torrent-trackers:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/torrent-trackers.mrs
    path: ./rule-sets/torrent-trackers.mrs
    interval: 86400

  torrent-clients:
    type: http
    behavior: classical
    format: yaml
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/torrent-clients.yaml
    path: ./rule-sets/torrent-clients.yaml
    interval: 86400

  refilter_domains:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/domain-rule.mrs
    path: ./re-filter/domain-rule.mrs
    interval: 86400

  refilter_ipsum:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/ip-rule.mrs
    path: ./re-filter/ip-rule.mrs
    interval: 86400

  ru-bundle:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/ru-bundle/rule.mrs
    path: ./ru-bundle/rule.mrs
    interval: 86400

  ai-services:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/openai.mrs
    path: ./rule-sets/ai-services.mrs
    interval: 86400

  google:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/google.mrs
    path: ./rule-sets/google.mrs
    interval: 86400

  streaming:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/netflix.mrs
    path: ./rule-sets/streaming.mrs
    interval: 86400

  blocked-ru:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/ru-bundle/blocked.mrs
    path: ./ru-bundle/blocked.mrs
    interval: 86400

  microsoft:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/microsoft.mrs
    path: ./rule-sets/microsoft.mrs
    interval: 86400

rules:
  - GEOIP,private,DIRECT,no-resolve
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT

  - RULE-SET,oisd_big,REJECT
  - RULE-SET,oisd_small,REJECT

  - OR,((DOMAIN-SUFFIX,ipwhois.app),(DOMAIN-SUFFIX,ipwho.is),(DOMAIN-SUFFIX,api.ip.sb),(DOMAIN-SUFFIX,ipapi.co),(DOMAIN-SUFFIX,ipinfo.io),(DOMAIN-SUFFIX,ip-api.com),(DOMAIN-SUFFIX,ifconfig.me),(DOMAIN-SUFFIX,icanhazip.com),(DOMAIN-SUFFIX,api.my-ip.io)),🌐 Internet

  - OR,((RULE-SET,telegram-ips),(RULE-SET,telegram-domains)),➤ Telegram
  - PROCESS-NAME,org.telegram.messenger,➤ Telegram
  - PROCESS-NAME,Telegram,➤ Telegram
  - PROCESS-NAME,telegram.exe,➤ Telegram

  - OR,((RULE-SET,facebook-ips),(RULE-SET,whatsapp-domains)),➤ WhatsApp
  - PROCESS-NAME,WhatsApp.exe,➤ WhatsApp
  - PROCESS-NAME,WhatsApp,➤ WhatsApp

  - OR,((RULE-SET,discord_domains),(RULE-SET,discord_voiceips)),💬 Discord
  - PROCESS-NAME,Discord.exe,💬 Discord
  - PROCESS-NAME,Discord,💬 Discord
  - PROCESS-NAME,discord,💬 Discord
  - PROCESS-NAME,Discord Helper,💬 Discord
  - PROCESS-NAME,Discord Helper (Renderer),💬 Discord

  - RULE-SET,youtube,▶️ YouTube
  - RULE-SET,google,▶️ YouTube

  - RULE-SET,ai-services,🤖 AI Services

  - RULE-SET,streaming,🎬 Streaming

  - OR,((RULE-SET,torrent-clients),(RULE-SET,torrent-trackers)),DIRECT
  - PROCESS-NAME,qBittorrent.exe,DIRECT
  - PROCESS-NAME,qbittorrent.exe,DIRECT
  - PROCESS-NAME,Transmission.exe,DIRECT
  - PROCESS-NAME,transmission-daemon,DIRECT
  - PROCESS-NAME,Deluge.exe,DIRECT
  - PROCESS-NAME,utorrent.exe,DIRECT
  - PROCESS-NAME,bitcomet.exe,DIRECT

  - RULE-SET,refilter_domains,🌐 Internet
  - RULE-SET,refilter_ipsum,🌐 Internet,no-resolve
  - RULE-SET,blocked-ru,🌐 Internet

  - DOMAIN-SUFFIX,max.ru,DIRECT
  - DOMAIN-SUFFIX,max.com,DIRECT
  - DOMAIN-SUFFIX,cdn.max.ru,DIRECT

  - DOMAIN-SUFFIX,vk.com,DIRECT
  - DOMAIN-SUFFIX,vk-portal.net,DIRECT
  - DOMAIN-SUFFIX,vk-cdn.net,DIRECT
  - DOMAIN-SUFFIX,vkuser.net,DIRECT
  - DOMAIN-SUFFIX,vkvideo.ru,DIRECT
  - DOMAIN-SUFFIX,vk-apps.com,DIRECT
  - DOMAIN-SUFFIX,vkuservideo.net,DIRECT
  - DOMAIN-SUFFIX,userapi.com,DIRECT
  - DOMAIN-SUFFIX,vkforms.ru,DIRECT
  - DOMAIN-SUFFIX,vkcdnglb.net,DIRECT
  - DOMAIN-SUFFIX,ok.ru,DIRECT
  - DOMAIN-SUFFIX,odnoklassniki.ru,DIRECT
  - DOMAIN-SUFFIX,mycdn.me,DIRECT
  - DOMAIN-SUFFIX,mail.ru,DIRECT
  - DOMAIN-SUFFIX,e.mail.ru,DIRECT
  - DOMAIN-SUFFIX,m.mail.ru,DIRECT
  - DOMAIN-SUFFIX,r.mail.ru,DIRECT
  - DOMAIN-SUFFIX,auth.mail.ru,DIRECT
  - DOMAIN-SUFFIX,account.mail.ru,DIRECT
  - DOMAIN-SUFFIX,imgsmail.ru,DIRECT
  - DOMAIN-SUFFIX,tamtam.chat,DIRECT
  - DOMAIN-SUFFIX,webinar.ru,DIRECT
  - DOMAIN-SUFFIX,loginza.ru,DIRECT

  - DOMAIN-SUFFIX,yandex.ru,DIRECT
  - DOMAIN-SUFFIX,yandex.net,DIRECT
  - DOMAIN-SUFFIX,yandex.com,DIRECT
  - DOMAIN-SUFFIX,ya.ru,DIRECT
  - DOMAIN-SUFFIX,kinopoisk.ru,DIRECT
  - DOMAIN-SUFFIX,music.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,market.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,eda.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,lavka.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,disk.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,pdd.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,moikrug.ru,DIRECT
  - DOMAIN-SUFFIX,narod.ru,DIRECT
  - DOMAIN-SUFFIX,turbopages.org,DIRECT
  - DOMAIN-SUFFIX,yastatic.net,DIRECT
  - DOMAIN-SUFFIX,yastat.net,DIRECT
  - DOMAIN-SUFFIX,cloud.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,clck.yandex.ru,DIRECT

  - DOMAIN-SUFFIX,sberbank.ru,DIRECT
  - DOMAIN-SUFFIX,sber.ru,DIRECT
  - DOMAIN-SUFFIX,tinkoff.ru,DIRECT
  - DOMAIN-SUFFIX,tinkov.ru,DIRECT
  - DOMAIN-SUFFIX,vtb.ru,DIRECT
  - DOMAIN-SUFFIX,alfabank.ru,DIRECT
  - DOMAIN-SUFFIX,gazprombank.ru,DIRECT
  - DOMAIN-SUFFIX,openbank.ru,DIRECT
  - DOMAIN-SUFFIX,open.ru,DIRECT
  - DOMAIN-SUFFIX,raiffeisen.ru,DIRECT
  - DOMAIN-SUFFIX,psbank.ru,DIRECT
  - DOMAIN-SUFFIX,sovcombank.ru,DIRECT
  - DOMAIN-SUFFIX,rsb.ru,DIRECT
  - DOMAIN-SUFFIX,homecredit.ru,DIRECT
  - DOMAIN-SUFFIX,uralsib.ru,DIRECT
  - DOMAIN-SUFFIX,mkb.ru,DIRECT
  - DOMAIN-SUFFIX,rosbank.ru,DIRECT
  - DOMAIN-SUFFIX,sravni.ru,DIRECT
  - DOMAIN-SUFFIX,banki.ru,DIRECT
  - DOMAIN-SUFFIX,qiwi.com,DIRECT
  - DOMAIN-SUFFIX,yu-money.ru,DIRECT
  - DOMAIN-SUFFIX,yoomoney.ru,DIRECT
  - DOMAIN-SUFFIX,webmoney.ru,DIRECT
  - DOMAIN-SUFFIX,cbr.ru,DIRECT
  - DOMAIN-SUFFIX,e-disclosure.ru,DIRECT

  - DOMAIN-SUFFIX,mts.ru,DIRECT
  - DOMAIN-SUFFIX,bank.mts.ru,DIRECT
  - DOMAIN-SUFFIX,megafon.ru,DIRECT
  - DOMAIN-SUFFIX,beeline.ru,DIRECT
  - DOMAIN-SUFFIX,tele2.ru,DIRECT
  - DOMAIN-SUFFIX,rostelecom.ru,DIRECT

  - DOMAIN-SUFFIX,gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,gosuslugi.kz,DIRECT
  - DOMAIN-SUFFIX,esia.gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,nalog.gov.ru,DIRECT
  - DOMAIN-SUFFIX,nalog.ru,DIRECT
  - DOMAIN-SUFFIX,mos.ru,DIRECT
  - DOMAIN-SUFFIX,mfc.ru,DIRECT
  - DOMAIN-SUFFIX,mvd.ru,DIRECT
  - DOMAIN-SUFFIX,minjust.gov.ru,DIRECT
  - DOMAIN-SUFFIX,russianpost.ru,DIRECT
  - DOMAIN-SUFFIX,pochta.ru,DIRECT
  - DOMAIN-SUFFIX,mfms.dks.ru,DIRECT
  - DOMAIN-SUFFIX,sfr.gov.ru,DIRECT
  - DOMAIN-SUFFIX,pfr.gov.ru,DIRECT
  - DOMAIN-SUFFIX,sudact.ru,DIRECT
  - DOMAIN-SUFFIX,kad.arbitr.ru,DIRECT
  - DOMAIN-SUFFIX,my.e-government.ru,DIRECT
  - DOMAIN-SUFFIX,gosmonitor.ru,DIRECT
  - DOMAIN-SUFFIX,e-government.ru,DIRECT
  - DOMAIN-SUFFIX,uslugi.mos.ru,DIRECT

  - DOMAIN-SUFFIX,wildberries.ru,DIRECT
  - DOMAIN-SUFFIX,wb.ru,DIRECT
  - DOMAIN-SUFFIX,wbcontent.net,DIRECT
  - DOMAIN-SUFFIX,wbx5.ru,DIRECT
  - DOMAIN-SUFFIX,ozon.ru,DIRECT
  - DOMAIN-SUFFIX,ozonusercontent.com,DIRECT
  - DOMAIN-SUFFIX,megamarket.ru,DIRECT
  - DOMAIN-SUFFIX,beru.ru,DIRECT
  - DOMAIN-SUFFIX,aliexpress.ru,DIRECT
  - DOMAIN-SUFFIX,lamoda.ru,DIRECT
  - DOMAIN-SUFFIX,dns-shop.ru,DIRECT
  - DOMAIN-SUFFIX,mvideo.ru,DIRECT
  - DOMAIN-SUFFIX,eldorado.ru,DIRECT
  - DOMAIN-SUFFIX,citilink.ru,DIRECT
  - DOMAIN-SUFFIX,2gis.com,DIRECT
  - DOMAIN-SUFFIX,2gis.ru,DIRECT
  - DOMAIN-SUFFIX,sbermarket.ru,DIRECT
  - DOMAIN-SUFFIX,perekrestok.ru,DIRECT
  - DOMAIN-SUFFIX,magnit.ru,DIRECT
  - DOMAIN-SUFFIX,delivery-club.ru,DIRECT
  - DOMAIN-SUFFIX,samokat.ru,DIRECT
  - DOMAIN-SUFFIX,ikea.ru,DIRECT
  - DOMAIN-SUFFIX,leroymerlin.ru,DIRECT
  - DOMAIN-SUFFIX,petrovich.ru,DIRECT
  - DOMAIN-SUFFIX,vprok.ru,DIRECT

  - DOMAIN-SUFFIX,hh.ru,DIRECT
  - DOMAIN-SUFFIX,rabota.ru,DIRECT
  - DOMAIN-SUFFIX,superjob.ru,DIRECT
  - DOMAIN-SUFFIX,work.ua,DIRECT
  - DOMAIN-SUFFIX,avito.ru,DIRECT
  - DOMAIN-SUFFIX,youla.ru,DIRECT

  - DOMAIN-SUFFIX,taxi.yandex.ru,DIRECT
  - DOMAIN-SUFFIX,citymobil.ru,DIRECT
  - DOMAIN-SUFFIX,gettaxi.com,DIRECT
  - DOMAIN-SUFFIX,rzd.ru,DIRECT
  - DOMAIN-SUFFIX,tutu.ru,DIRECT

  - DOMAIN-SUFFIX,rutube.ru,DIRECT
  - DOMAIN-SUFFIX,ivi.ru,DIRECT
  - DOMAIN-SUFFIX,okko.tv,DIRECT
  - DOMAIN-SUFFIX,start.ru,DIRECT
  - DOMAIN-SUFFIX,more.tv,DIRECT
  - DOMAIN-SUFFIX,wink.rt.ru,DIRECT
  - DOMAIN-SUFFIX,premier.one,DIRECT
  - DOMAIN-SUFFIX,gpm_tv.ru,DIRECT

  - DOMAIN-SUFFIX,tass.ru,DIRECT
  - DOMAIN-SUFFIX,ria.ru,DIRECT
  - DOMAIN-SUFFIX,interfax.ru,DIRECT
  - DOMAIN-SUFFIX,rbc.ru,DIRECT
  - DOMAIN-SUFFIX,kommersant.ru,DIRECT
  - DOMAIN-SUFFIX,lenta.ru,DIRECT
  - DOMAIN-SUFFIX,gazeta.ru,DIRECT
  - DOMAIN-SUFFIX,iz.ru,DIRECT
  - DOMAIN-SUFFIX,rt.com,DIRECT
  - DOMAIN-SUFFIX,rg.ru,DIRECT
  - DOMAIN-SUFFIX,aif.ru,DIRECT

  - DOMAIN-SUFFIX,reg.ru,DIRECT
  - DOMAIN-SUFFIX,nic.ru,DIRECT
  - DOMAIN-SUFFIX,timepad.ru,DIRECT

  - RULE-SET,microsoft,DIRECT

  - RULE-SET,ru-bundle,DIRECT

  - GEOIP,RU,DIRECT

  - MATCH,🌐 Internet
CLASHRULES
        # По ТЗ — без комментариев: вырезаем строки-комментарии при генерации
        sed -i '/^[[:space:]]*#/d' "$clash_rules_file"
    }
    write_clash_template
    # local в функции не виден снаружи — повторно объявляем для readfile()
    local clash_rules_file="/etc/x-ui/clash-templates/global-ru.yaml"
    sqlite3 "$XUIDB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('subClashEnableRouting','true');" 2>/dev/null || true
    sqlite3 "$XUIDB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('subClashRules', readfile('${clash_rules_file}'));" 2>/dev/null || \
        sqlite3 "$XUIDB" "INSERT OR REPLACE INTO settings (key,value) VALUES ('subClashRules', readfile('$clash_rules_file'));" 2>/dev/null || true
    ok "Clash/Mihomo routing rules записаны в панель (subClashRules)"

    ok "База данных панели настроена (${total_inbounds} inbound'ов, ${total_hosts} hosts)"
}
configure_db

###############################################################################
# ОПТИМИЗАЦИЯ СИСТЕМЫ (BBR + QUIC)
###############################################################################
tune_system() {
    if [[ -n "$TIMEZONE" ]]; then
        inf "Часовой пояс ${TIMEZONE}..."
        if command -v timedatectl >/dev/null 2>&1; then
            timedatectl set-timezone "$TIMEZONE" 2>/dev/null || true
        fi
        ln -sfn "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime 2>/dev/null || true
        echo "$TIMEZONE" > /etc/timezone 2>/dev/null || true
        ok "Timezone: ${TIMEZONE}"
    else
        inf "TIMEZONE не задан — часовой пояс системы не меняю"
    fi
    inf "Оптимизация сетевого стека (BBR, QUIC)..."
    local params=(
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
        "fs.file-max=2097152"
        "net.core.somaxconn=32768"
        "net.ipv4.tcp_max_syn_backlog=8192"
        "net.ipv4.tcp_timestamps=1"
        "net.ipv4.tcp_sack=1"
        "net.ipv4.tcp_window_scaling=1"
        "net.core.rmem_max=26214400"
        "net.core.wmem_max=26214400"
        "net.ipv4.tcp_rmem=4096 87380 16777216"
        "net.ipv4.tcp_wmem=4096 65536 16777216"
        "net.ipv4.udp_rmem_min=16384"
        "net.ipv4.udp_wmem_min=16384"
        "net.ipv4.ip_local_port_range=1024 65535"
        "net.ipv4.conf.all.rp_filter=1"
    )
    for p in "${params[@]}"; do
        grep -qxF "$p" /etc/sysctl.conf 2>/dev/null || echo "$p" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1 || warn "sysctl -p: часть параметров не применена"
    ok "Система оптимизирована"
}
tune_system

###############################################################################
# ДЕКОЙ-САЙТ, CRON, FIREWALL
###############################################################################
setup_misc() {
    # Декой-сайт
    mkdir -p /var/www/html
    if [[ ! -f /var/www/html/index.html ]]; then
        cat > /var/www/html/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5;}
.box{background:#fff;padding:2rem 3rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;}
h1{color:#333;font-size:1.8rem;}p{color:#666;}</style>
</head>
<body><div class="box"><h1>Welcome</h1><p>Service is running.</p></div></body>
</html>
HTML
    fi
    chown -R www-data:www-data /var/www/html 2>/dev/null || true

    # Cron: v10 перезапускал панель ежедневно и останавливал nginx на время
    # certbot renew — убираем; продление делает certbot.timer (см. setup_cert_renewal)
    if crontab -l >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vE 'x-ui restart|certbot renew' | crontab - 2>/dev/null || true
    fi
    setup_cert_renewal

    setup_firewall
}

# Порты sshd: env SSH_PORTS → слушающий sshd → sshd -T → 22
detect_ssh_ports() {
    local ports
    ports=$(ss -Hltnp 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' ')
    [[ -z "${ports// /}" ]] && ports=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | tr '\n' ' ')
    [[ -z "${ports// /}" ]] && ports="22"
    echo "$ports"
}

# Удалить правила UFW, созданные этим установщиком (v10 и v11), не трогая чужие
ufw_purge_managed() {
    local line rule
    while IFS= read -r line; do
        [[ "$line" =~ ^ufw\ (.+)\ comment\ \'(lucx:.*|SSH|HTTP|HTTPS|QUIC/Hysteria2|Hysteria2|qWDTT|olcRTC|mieru|TrustTunnel|Telegram\ MTProto|AnyTLS|VLESS\ XHTTP\ REALITY|VLESS\ gRPC\ REALITY|NaiveProxy|AWG\ kernel|AmneziaWG\ native|AdGuard\ Home\ DoT|AWG\ fwd)\'$ ]] || continue
        rule="${BASH_REMATCH[1]}"
        # shellcheck disable=SC2086
        if [[ "$rule" == route\ * ]]; then
            ufw route delete ${rule#route } >/dev/null 2>&1 || true
        else
            ufw delete ${rule} >/dev/null 2>&1 || true
        fi
    done < <(ufw show added 2>/dev/null)
}

setup_firewall() {
    inf "Firewall (UFW)..."
    local p wan_if
    SSH_PORTS_EFFECTIVE="${SSH_PORTS:-$(detect_ssh_ports)}"
    inf "  SSH-порт(ы): ${SSH_PORTS_EFFECTIVE}"
    wan_if=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    ufw disable >/dev/null 2>&1 || true
    ufw_purge_managed
    ufw default deny incoming  >/dev/null
    ufw default allow outgoing >/dev/null
    # Форвардинг закрыт по умолчанию; разрешаем только из AWG-подсетей (ниже)
    ufw default deny routed    >/dev/null

    for p in $SSH_PORTS_EFFECTIVE; do
        ufw limit "${p}/tcp" comment "lucx: SSH" >/dev/null
    done
    ufw allow 80/tcp  comment "lucx: HTTP (ACME, redirect)" >/dev/null
    ufw allow 443/tcp comment "lucx: HTTPS SNI" >/dev/null
    ufw allow "${HY2_PORT}/udp" comment "lucx: Hysteria2" >/dev/null
    # Прямые порты sidecar-протоколов (у них нет маршрута через 443)
    ufw allow "${NAIVE_PORT}/tcp"  comment "lucx: NaiveProxy" >/dev/null
    ufw allow "${OLCRTC_PORT}/tcp" comment "lucx: olcRTC" >/dev/null
    ufw allow "${QWDTT_PORT}/udp"  comment "lucx: qWDTT" >/dev/null
    ufw allow "${MIERU_PORT}/tcp"  comment "lucx: mieru" >/dev/null
    ufw allow "${ANYTLS_PORT}/tcp" comment "lucx: AnyTLS" >/dev/null
    ufw allow "${TG_PORT}/tcp"     comment "lucx: Telegram MTProto" >/dev/null
    # С SNI-доменом эти протоколы идут через 443 (nginx stream → 127.0.0.1)
    [[ -z "$TT_DOMAIN" ]]      && ufw allow "${TRUSTTUNNEL_PORT}/tcp"   comment "lucx: TrustTunnel" >/dev/null
    [[ -z "$XHTTP_R_DOMAIN" ]] && ufw allow "${VLESS_XHTTP_R_PORT}/tcp" comment "lucx: VLESS XHTTP REALITY" >/dev/null
    [[ -z "$GRPC_R_DOMAIN" ]]  && ufw allow "${VLESS_GRPC_R_PORT}/tcp"  comment "lucx: VLESS gRPC REALITY" >/dev/null
    for p in "$AWG1_PORT" "$AWG2_PORT" "$AWG3_PORT" "$AWG4_PORT" "$AWG5_PORT" \
             "$AWG6_PORT" "$AWG7_PORT" "$AWG8_PORT" "$AWG9_PORT" "$AMNEZIAWG_PORT"; do
        ufw allow "${p}/udp" comment "lucx: AWG" >/dev/null
    done
    [[ "$INSTALL_ADGUARD" != "0" ]] && ufw allow 853/tcp comment "lucx: DoT" >/dev/null

    local s_
    for s_ in "$AWG1_SUBNET" "$AWG2_SUBNET" "$AWG3_SUBNET" "$AWG4_SUBNET" "$AWG5_SUBNET" \
              "$AWG6_SUBNET" "$AWG7_SUBNET" "$AWG8_SUBNET" "$AWG9_SUBNET" "$AMNEZIAWG_SUBNET"; do
        if [[ -n "$wan_if" ]]; then
            ufw route allow out on "$wan_if" from "${s_%.*}.0/24" comment "lucx: AWG fwd" >/dev/null
        else
            ufw route allow from "${s_%.*}.0/24" comment "lucx: AWG fwd" >/dev/null
        fi
    done

    # NAT пишется в before.rules ДО включения UFW, иначе применится только после reload
    setup_awg_network
    ufw --force enable >/dev/null || die "ufw enable завершился с ошибкой"
    ok "Firewall настроен (SSH: ${SSH_PORTS_EFFECTIVE}; routed: deny, кроме AWG)"
}

# Продление сертификатов: certbot.timer + standalone на loopback-порту,
# nginx :80 проксирует /.well-known/acme-challenge/ — nginx не останавливается
setup_cert_renewal() {
    local d conf
    for d in "${CERT_DOMAINS[@]}"; do
        conf="/etc/letsencrypt/renewal/${d}.conf"
        [[ -f "$conf" ]] || continue
        sed -i -E '/^(http01_port|pre_hook|post_hook|renew_hook) *=/d' "$conf"
        sed -i "/^\[renewalparams\]/a http01_port = ${ACME_PORT}" "$conf"
    done
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/lucx-reload.sh <<'HOOK'
#!/bin/sh
# Новый сертификат: nginx перечитывает конфиг, панель — TLS sidecar/подписок
nginx -t && systemctl reload nginx
systemctl restart x-ui
HOOK
    chmod 755 /etc/letsencrypt/renewal-hooks/deploy/lucx-reload.sh
    systemctl enable --now certbot.timer >/dev/null 2>&1 || \
        warn "certbot.timer не включён — продление: certbot renew (проверка: certbot renew --dry-run)"
    ok "Продление сертификатов: certbot.timer, ACME через nginx → 127.0.0.1:${ACME_PORT}"
}

# fail2ban: sshd + ловушки nginx (сканеры .env/wp-login/phpmyadmin/...)
setup_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        warn "fail2ban не установлен — пропуск"
        return 0
    fi
    inf "fail2ban (sshd + nginx honeypot)..."
    local ignore="127.0.0.1/8 ::1" admin_ip="${SSH_CLIENT:-}"; admin_ip="${admin_ip%% *}"
    [[ "$admin_ip" =~ ^[0-9a-fA-F:.]+$ ]] && ignore+=" ${admin_ip}"
    mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
    touch /var/log/nginx/lucx-honeypot.log
    cat > /etc/fail2ban/filter.d/lucx-nginx-honeypot.conf <<'FLT'
[Definition]
# fail2ban вырезает дату ([...]) до сопоставления — в regex её нет
failregex = ^<HOST> - \S+ .*"[^"]*" \d{3} 
ignoreregex =
FLT
    cat > /etc/fail2ban/jail.d/lucx.conf <<JAIL
[DEFAULT]
banaction = ufw
banaction_allports = ufw
ignoreip = ${ignore}

[sshd]
enabled  = true
port     = $(printf '%s' "$SSH_PORTS_EFFECTIVE" | xargs | tr ' ' ',')
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h

[lucx-nginx-honeypot]
enabled  = true
port     = http,https
filter   = lucx-nginx-honeypot
logpath  = /var/log/nginx/lucx-honeypot.log
backend  = auto
maxretry = 2
findtime = 1h
bantime  = 1d
JAIL
    if ! fail2ban-client -t >/dev/null 2>&1; then
        warn "fail2ban: конфиг не прошёл проверку (fail2ban-client -t) — jail lucx отключён"
        rm -f /etc/fail2ban/jail.d/lucx.conf
    fi
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban 2>/dev/null || warn "fail2ban не перезапустился — journalctl -u fail2ban"
    ok "fail2ban: sshd + lucx-nginx-honeypot"
}

# NEW v7.2: ip_forward + MASQUERADE для AWG-подсетей (NAT для VPN-протоколов)
setup_awg_network() {
    grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    grep -q 'src_valid_mark=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.conf.all.src_valid_mark=1' >> /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null

    local wan_if
    wan_if=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$wan_if" ]] && { warn "WAN-интерфейс не определён — MASQUERADE не добавлен"; return 0; }

    # Блок NAT пересоздаётся при каждом запуске (подсети/WAN могли измениться)
    if grep -q 'AWG MASQUERADE' /etc/ufw/before.rules 2>/dev/null; then
        python3 - /etc/ufw/before.rules <<'PYNAT'
import re, sys
p = sys.argv[1]
t = open(p).read()
t = re.sub(r"\n?\*nat\n:POSTROUTING ACCEPT \[0:0\]\n# AWG MASQUERADE \(managed by lucx installer\)\n(?:-A POSTROUTING[^\n]*\n)*COMMIT\n", "\n", t)
open(p, "w").write(t)
PYNAT
    fi
    if ! grep -q 'AWG MASQUERADE' /etc/ufw/before.rules 2>/dev/null; then
        # v7.3 FIX: в -s нужен адрес сети .0/24, а не .1/24 (host bits set).
        cat >> /etc/ufw/before.rules <<NAT

*nat
:POSTROUTING ACCEPT [0:0]
# AWG MASQUERADE (managed by lucx installer)
-A POSTROUTING -s ${AWG1_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG2_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG3_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG4_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG5_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG6_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG7_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG8_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AWG9_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
-A POSTROUTING -s ${AMNEZIAWG_SUBNET%.*}.0/24 -o ${wan_if} -j MASQUERADE
COMMIT
NAT
    fi
    local s net
    for s in "$AWG1_SUBNET" "$AWG2_SUBNET" "$AWG3_SUBNET" "$AWG4_SUBNET" "$AWG5_SUBNET" "$AWG6_SUBNET" "$AWG7_SUBNET" "$AWG8_SUBNET" "$AWG9_SUBNET" "$AMNEZIAWG_SUBNET"; do
        net="${s%.*}.0/24"
        iptables -t nat -C POSTROUTING -s "$net" -o "$wan_if" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$net" -o "$wan_if" -j MASQUERADE
    done
    ok "AWG: ip_forward + MASQUERADE (AWG-подсети → ${wan_if}) готовы"
}
setup_misc
setup_fail2ban

###############################################################################
# CLASH / MIHOMO: глобальный шаблон маршрутизации (RU + adblock + url-test)
###############################################################################
install_clash_routing_template() {
    # v7.3: полный шаблон (Clash+Mihomo_routing.md, без комментариев) уже
    # записан write_clash_template() внутри configure_db. Здесь только
    # перезаписываем файл, если configure_db не выполнялся.
    if declare -F write_clash_template >/dev/null 2>&1; then
        inf "Обновление шаблона глобальных правил маршрутизации Clash/Mihomo..."
        write_clash_template
        ok "Шаблон Clash/Mihomo: /etc/x-ui/clash-templates/global-ru.yaml"
    else
        inf "Шаблон Clash/Mihomo уже записан configure_db — пропускаю"
    fi
}
install_clash_routing_template

###############################################################################
# LUCX SUB-SIDECAR (x-tuna lucx_sub_sidecar.py)
# Throne: amneziawg:// → wg://?enable_amnezia=true (+ корректный quote /+=)
# без этого delay/ping AWG в Throne/части клиентов не проходит.
# Также: mieru traffic-pattern, AnyTLS public endpoint, TrustTunnel HTTPS-only.
###############################################################################
setup_sub_sidecar() {
    # v10.1: sidecar ломал встроенную выдачу подписок — не используется;
    # убираем остатки старых установок.
    if [[ -f /etc/systemd/system/lucx-sub-sidecar.service ]]; then
        systemctl disable --now lucx-sub-sidecar 2>/dev/null || true
        rm -f /etc/systemd/system/lucx-sub-sidecar.service
        systemctl daemon-reload
    fi
    inf "Sub-sidecar не используется (встроенная подписка панели на SUB_PORT)"
}
setup_sub_sidecar

###############################################################################
# ADGUARD HOME (NEW v7.3, по мотивам x-ui-adguard.sh)
# Web-UI и plain-DNS только на 127.0.0.1; наружу — через nginx vhost панели:
#   /dns-query  → DoH-эндпоинт для клиентов
#   /adg-<rnd>/ → админ-интерфейс
###############################################################################
setup_adguard() {
    if [[ "$INSTALL_ADGUARD" == "0" ]]; then
        inf "AdGuard Home пропущен (INSTALL_ADGUARD=0)"
        rm -f /etc/nginx/stream-enabled/dot-853.conf \
              /etc/systemd/system/nginx.service.d/after-adguard.conf 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        return 0
    fi
    inf "Установка AdGuard Home (DoH + админка за nginx)..."

    local AGH_DIR="/opt/AdGuardHome"
    local AGH_YAML="${AGH_DIR}/AdGuardHome.yaml"

    # Пакеты (htpasswd для bcrypt-хэша пароля)
    command -v htpasswd >/dev/null 2>&1 || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apache2-utils >/dev/null 2>&1 || \
        die "Не удалось установить apache2-utils (htpasswd)"

    # ── Бинарник ────────────────────────────────────────────────────────────
    local agh_arch
    case "$ARCH" in
        amd64|arm64|armv7|386) agh_arch="$ARCH" ;;
        *) die "AdGuard Home: неподдерживаемая архитектура: ${ARCH}" ;;
    esac
    local agh_ver="$AGH_VERSION" agh_cur=""
    if [[ "$agh_ver" == "latest" ]]; then
        agh_ver=$(gh_latest_tag AdguardTeam/AdGuardHome) || agh_ver=""
    fi
    [[ -n "$agh_ver" ]] || die "Не удалось определить версию AdGuard Home"
    [[ -x "${AGH_DIR}/AdGuardHome" ]] && \
        agh_cur=$("${AGH_DIR}/AdGuardHome" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    if [[ "$agh_cur" == "$agh_ver" ]]; then
        ok "  AdGuard Home ${agh_ver} уже установлен"
    else
        local agh_asset="AdGuardHome_linux_${agh_arch}.tar.gz"
        local agh_rel="https://github.com/AdguardTeam/AdGuardHome/releases/download/${agh_ver}"
        local agh_stage agh_sum
        agh_stage=$(mktemp -d /root/.agh-stage.XXXXXX) || die "mktemp не сработал"
        inf "  Загрузка AdGuard Home ${agh_ver} (${agh_asset})..."
        download "${agh_rel}/${agh_asset}" "${agh_stage}/${agh_asset}" || die "Не удалось скачать AdGuard Home ${agh_ver}"
        download "${agh_rel}/checksums.txt" "${agh_stage}/checksums.txt" || die "Не удалось скачать checksums.txt AdGuard Home"
        agh_sum=$(awk -v a="$agh_asset" '$2==a || $2=="./"a {print $1; exit}' "${agh_stage}/checksums.txt")
        verify_sha256 "${agh_stage}/${agh_asset}" "$agh_sum" || die "SHA256 AdGuard Home не совпадает с checksums.txt"
        tar -xzf "${agh_stage}/${agh_asset}" -C "$agh_stage" || die "Ошибка распаковки AdGuard Home"
        [[ -x "${agh_stage}/AdGuardHome/AdGuardHome" ]] || die "AdGuardHome binary отсутствует в архиве"
        systemctl stop AdGuardHome 2>/dev/null || true
        mkdir -p "$AGH_DIR"
        install -m 755 "${agh_stage}/AdGuardHome/AdGuardHome" "${AGH_DIR}/AdGuardHome.new" \
            && mv -f "${AGH_DIR}/AdGuardHome.new" "${AGH_DIR}/AdGuardHome" \
            || die "Не удалось установить бинарник AdGuard Home"
        rm -rf "$agh_stage"
        ok "  AdGuard Home ${agh_ver}: SHA256 совпадает, установлен${agh_cur:+ (было ${agh_cur})}"
    fi

    # ── Конфиг: всегда пишем актуальные порты/сертификаты этого запуска ─────
    # (cleanup_old бэкапит старый yaml; повторный запуск без cleanup тоже
    #  перезаписывает порты, иначе nginx смотрит на новые, AGH — на старые)
    local agh_hash
    agh_hash=$(printf '%s\n' "$AGH_PASS" | htpasswd -niB x | cut -d: -f2)
    [[ "$agh_hash" == \$2* ]] || die "bcrypt-хэш не сгенерирован (htpasswd)"
    systemctl stop AdGuardHome 2>/dev/null || true
    # Хэш содержит '$2y$12$...' — quoted-heredoc + плейсхолдеры + sed.
    cat > "$AGH_YAML" <<'AGHYAML'
http:
  address: 127.0.0.1:__AGH_WEB__
  # trusted_proxies: nginx (loopback) — AGH берёт IP из X-Real-IP / X-Forwarded-For.
  # Реальный IP доходит только если stream :443 шлёт PROXY protocol на 7443.
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
users:
  - name: __AGH_USER__
    password: __AGH_HASH__
auth_attempts: 5
block_auth_min: 15
theme: auto
dns:
  bind_hosts:
    - 127.0.0.1
  port: __AGH_DNS__
  # Upstream: RU (основные) + зарубежные (резерв). Без NextDNS (нужен личный ID).
  # load_balance — параллельный выбор быстрого ответа; bootstrap — plain IP.
  upstream_mode: load_balance
  upstream_dns:
    # --- Российские / региональные ---
    - https://common.dot.dns.yandex.net/dns-query
    - tls://common.dot.dns.yandex.net
    - https://dns.comss.one/dns-query
    - tls://dns.comss.one
    - https://xbox-dns.ru/dns-query
    - tls://xbox-dns.ru
    - https://dns.astracat.network/dns-query
    - tls://dns.astracat.network
    - https://dns.geohide.ru:8443/dns-query
    # Yandex Safe (malware) — можно отключить в UI при ложных срабатываниях
    - https://safe.dot.dns.yandex.net/dns-query
    - tls://safe.dot.dns.yandex.net
    # --- Зарубежные резервные ---
    - https://cloudflare-dns.com/dns-query
    - tls://1dot1dot1dot1.cloudflare-dns.com
    - https://dns.google/dns-query
    - tls://dns.google
    - https://dns10.quad9.net/dns-query
    - tls://dns10.quad9.net
    - https://dns11.quad9.net/dns-query
    - tls://dns11.quad9.net
    - https://dns.quad9.net/dns-query
    - tls://dns.quad9.net
    - https://dns.adguard-dns.com/dns-query
    - tls://dns.adguard-dns.com
    - https://doh.dns.sb/dns-query
    - tls://dot.sb
    - https://dnsforge.de/dns-query
    - tls://dnsforge.de
    - https://freedns.controld.com/p0
    - tls://p0.freedns.controld.com
    - https://doh.cleanbrowsing.org/doh/security-filter/
    - tls://security-filter-dns.cleanbrowsing.org
    - https://doh.opendns.com/dns-query
    # Plain DNS53 (MSK-IX / НСДИ) — fallback без DoH/DoT
    - 62.76.62.76
    - 62.76.76.62
    - 195.208.4.1
    - 195.208.5.1
  bootstrap_dns:
    - 1.1.1.1
    - 1.0.0.1
    - 8.8.8.8
    - 8.8.4.4
    - 9.9.9.10
    - 149.112.112.10
    - 77.88.8.8
    - 77.88.8.1
  fallback_dns:
    - 1.1.1.1
    - 8.8.8.8
    - 9.9.9.10
  upstream_timeout: 10s
  cache_size: 4194304
  cache_optimistic: true
  ratelimit: 0
  refuse_any: true
# v11: TLS у AGH выключен полностью. Снаружи TLS терминирует nginx:
#   DoH  — vhost панели /dns-query → plain HTTP 127.0.0.1:__AGH_WEB__;
#   DoT  — nginx stream :853 (ssl) → plain DNS/TCP 127.0.0.1:__AGH_DNS__.
# allow_unencrypted_doh=true: DoH на plain HTTP для nginx. Схема 28 —
# AGH сам мигрирует её (в новых версиях → http.doh.insecure_enabled).
tls:
  enabled: false
  server_name: __AGH_DOMAIN__
  allow_unencrypted_doh: true
  # certificate_chain / private_key — только PEM-текст в YAML.
  # Пути к файлам — только certificate_path / private_key_path
  # (иначе AGH не парсит PEM и при сохранении обнуляет chain/key в "").
  certificate_chain: ""
  private_key: ""
  certificate_path: /root/cert/__AGH_DOMAIN__/fullchain.pem
  private_key_path: /root/cert/__AGH_DOMAIN__/privkey.pem
  port_https: 0
  port_dns_over_tls: 0
  port_dns_over_quic: 0
  port_quic: 0
# Фильтры HostlistsRegistry (+ AdAway с прямого URL).
# 1Hosts Lite выключен по умолчанию — агрессивно банит свежие домены.
filters:
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt
    name: OISD Blocklist Big
    id: 27
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt
    name: HaGeZi's Pro Blocklist
    id: 48
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt
    name: 1Hosts (Lite)
    id: 24
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt
    name: Phishing URL Blocklist (PhishTank and OpenPhish)
    id: 30
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt
    name: The Big List of Hacked Malware Web Sites
    id: 9
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt
    name: Dandelion Sprout's Anti-Malware List
    id: 12
  - enabled: false
    url: https://adaway.org/hosts.txt
    name: AdAway Default Blocklist
    id: 10001
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt
    name: Malicious URL Blocklist (URLHaus)
    id: 11
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt
    name: uBlock₀ filters – Badware risks
    id: 50
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt
    name: AdGuard DNS Popup Hosts filter
    id: 59
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt
    name: Scam Blocklist by DurableNapkin
    id: 10
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt
    name: Stalkerware Indicators List
    id: 31
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt
    name: ShadowWhisperer's Malware List
    id: 42
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt
    name: HaGeZi's Threat Intelligence Feeds
    id: 44
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt
    name: Phishing Army
    id: 18
whitelist_filters: []
user_rules: []
schema_version: 28
AGHYAML
    sed -i -e "s|__AGH_WEB__|${AGH_WEB_PORT}|" \
           -e "s|__AGH_DNS__|${AGH_DNS_PORT}|" \
           -e "s|__AGH_USER__|${AGH_USER}|" \
           -e "s|__AGH_HASH__|${agh_hash}|" \
           -e "s|__AGH_DOMAIN__|${DOMAIN}|g" "$AGH_YAML"
    chmod 600 "$AGH_YAML"
    ok "  AdGuardHome.yaml: web(http) 127.0.0.1:${AGH_WEB_PORT}, DNS 127.0.0.1:${AGH_DNS_PORT}"

    # ── Systemd (после cleanup unit снят; -s install безопасен) ─────────────
    # Если unit всё же остался (SKIP_CLEANUP / ручной остаток) — снимаем и ставим заново.
    if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^AdGuardHome\.service'; then
        systemctl stop AdGuardHome 2>/dev/null || true
        "${AGH_DIR}/AdGuardHome" -s uninstall 2>/dev/null || true
        rm -f /etc/systemd/system/AdGuardHome.service \
              /lib/systemd/system/AdGuardHome.service 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi
    "${AGH_DIR}/AdGuardHome" -s install || die "Не удалось установить сервис AdGuardHome"
    systemctl enable AdGuardHome 2>/dev/null || true
    systemctl restart AdGuardHome 2>/dev/null || systemctl start AdGuardHome 2>/dev/null || true

    # ── Ожидание запуска (web-UI только HTTP, port_https=0) ────────────────
    local up=0 code
    for _ in $(seq 1 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-redirs 0 \
            "http://127.0.0.1:${AGH_WEB_PORT}/" 2>/dev/null || echo "000")
        if [[ "$code" =~ ^(200|301|302|303|307|308)$ ]]; then
            up=1
            break
        fi
        sleep 0.5
    done
    if [[ $up -ne 1 ]]; then
        err "AdGuard Home не поднялся на 127.0.0.1:${AGH_WEB_PORT}"
        journalctl -u AdGuardHome -n 40 --no-pager >&2 || true
        die "AdGuard Home не поднялся — journalctl -u AdGuardHome"
    fi
    ok "  AdGuard Home слушает 127.0.0.1:${AGH_WEB_PORT} (HTTP ${code})"

    # Self-test админки через nginx (как увидит браузер)
    local agh_ui
    agh_ui=$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-redirs 0 \
        "https://${DOMAIN}/${AGH_PATH}/" --resolve "${DOMAIN}:443:127.0.0.1" 2>/dev/null || echo "000")
    if [[ "$agh_ui" =~ ^(200|301|302|303|307|308)$ ]]; then
        ok "  Админка через nginx: HTTP ${agh_ui} → https://${DOMAIN}/${AGH_PATH}/"
    else
        warn "  Админка через nginx: HTTP ${agh_ui} (ожидался 200/3xx) — проверьте nginx -t && curl -skI https://${DOMAIN}/${AGH_PATH}/"
    fi

    # ── Self-test DoH через nginx ───────────────────────────────────────────
    local doh_status
    doh_status=$(curl -so /dev/null -w '%{http_code}' -H 'Accept: application/dns-message' \
        "https://${DOMAIN}/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
        --resolve "${DOMAIN}:443:127.0.0.1" 2>/dev/null || echo "000")
    if [[ "$doh_status" == "200" ]]; then
        AGH_DOH_OK=1
        ok "  DoH-эндпоинт отвечает (HTTP 200)"
    else
        AGH_DOH_OK=0
        warn "  DoH self-test: HTTP ${doh_status} — проверьте позже (nginx/AdGuard)"
    fi

    # После миграции схемы AGH должен сохранить разрешение plain-HTTP DoH
    if ! grep -qE '^[[:space:]]*(insecure_enabled|allow_unencrypted_doh):[[:space:]]*true' "$AGH_YAML"; then
        warn "  AdGuardHome.yaml: не найден insecure_enabled/allow_unencrypted_doh=true — DoH через nginx может не работать"
    fi

    # ── DoT :853: TLS терминирует nginx (сертификат панели) → plain DNS AGH ──
    cat > /etc/nginx/stream-enabled/dot-853.conf <<DOT853
# DNS-over-TLS: TLS в nginx, дальше DNS/TCP на loopback AdGuard Home
limit_conn_zone \$binary_remote_addr zone=lucx_dot_conn:10m;
server {
    listen     853 ssl;
    listen     [::]:853 ssl;
    ssl_certificate      /root/cert/${DOMAIN}/fullchain.pem;
    ssl_certificate_key  /root/cert/${DOMAIN}/privkey.pem;
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_session_cache    shared:LUCXDOT:5m;
    ssl_handshake_timeout 10s;
    limit_conn           lucx_dot_conn 32;
    proxy_connect_timeout 5s;
    proxy_timeout        120s;
    proxy_pass           127.0.0.1:${AGH_DNS_PORT};
}
DOT853
    # systemd: nginx After=AdGuardHome (drop-in)
    mkdir -p /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/after-adguard.conf <<'DROPIN'
[Unit]
After=AdGuardHome.service
Wants=AdGuardHome.service
DROPIN
    systemctl daemon-reload 2>/dev/null || true
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
        ok "  DoT :853 (TLS nginx) → 127.0.0.1:${AGH_DNS_PORT}"
    else
        warn "  nginx -t не прошёл с DoT — конфиг /etc/nginx/stream-enabled/dot-853.conf отключён"
        rm -f /etc/nginx/stream-enabled/dot-853.conf
    fi

    # ── Self-test DoT (проверка сертификата + DNS-ответ) ────────────────────
    sleep 1
    if python3 - "$DOMAIN" <<'PYDOT' 2>/dev/null; then
import socket, ssl, struct, sys
q = b"\x4c\x58\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
ctx = ssl.create_default_context()
with socket.create_connection(("127.0.0.1", 853), timeout=8) as raw:
    with ctx.wrap_socket(raw, server_hostname=sys.argv[1]) as t:
        t.sendall(struct.pack("!H", len(q)) + q)
        hdr = t.recv(2)
        resp = t.recv(struct.unpack("!H", hdr)[0])
sys.exit(0 if resp[:2] == b"\x4c\x58" else 1)
PYDOT
        AGH_DOT_OK=1
        ok "  DoT self-test: OK (tls://${DOMAIN})"
    else
        AGH_DOT_OK=0
        warn "  DoT self-test не прошёл — проверьте: nginx -t; journalctl -u AdGuardHome -n 30"
    fi

    ok "AdGuard Home установлен: https://${DOMAIN}/${AGH_PATH}/ (логин ${AGH_USER})"
}
setup_adguard

###############################################################################
# ИТОГОВЫЙ ОТЧЁТ
###############################################################################
print_results() {
    clear
    local st="❌ ОСТАНОВЛЕНА"
    systemctl is-active --quiet x-ui 2>/dev/null && st="✅ РАБОТАЕТ"
    local ng_st="❌ ОСТАНОВЛЕН"
    systemctl is-active --quiet nginx 2>/dev/null && ng_st="✅ РАБОТАЕТ"

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗"
    echo -e "║      LUCX-UI ALL-IN-ONE — УСТАНОВКА ЗАВЕРШЕНА (v10.1)         ║"
    echo -e "╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Панель LucX-UI:   ${st}"
    echo -e "  Nginx:            ${ng_st}"
    echo ""
    echo -e "${BLUE}═══════════════════════  ДОСТУП К ПАНЕЛИ  ═══════════════════════════${NC}"
    echo -e "  URL:       https://${DOMAIN}${PANEL_PATH}/"
    echo -e "  Логин:     ${PANEL_USER}"
    echo -e "  Пароль:    ${PANEL_PASS}"
    echo ""
    echo -e "${BLUE}══════════════════════  INBOUND'Ы XRAY  ════════════════════════════${NC}"
    echo -e "  ┌─ Протокол ──────────────┬─ Порт/SNI ────────────────────────────┐"
    echo -e "  │ VLESS REALITY + Vision │ 443 TCP → SNI: ${REALITY_DOMAIN} (flow — на клиенте) │"
    echo -e "  │ VLESS WebSocket + TLS   │ 443 HTTPS → path: ${WS_PATH}          │"
    echo -e "  │ VLESS XHTTP + TLS (UDS) │ 443 HTTPS → path: ${XHTTP_PATH}      │"
    echo -e "  │ VLESS XHTTP + TLS (UDS2)│ 443 HTTPS → path: ${XHTTP_TLS_PATH}  │"
    if [[ -n "$XHTTP_R_DOMAIN" ]]; then
    echo -e "  │ VLESS XHTTP + REALITY   │ 443 → SNI: ${XHTTP_R_DOMAIN}  │"
    else
    echo -e "  │ VLESS XHTTP + REALITY   │ ${VLESS_XHTTP_R_PORT} TCP (прямое, SNI r-домен)  │"
    fi
    echo -e "  │ VLESS gRPC + TLS        │ 443 HTTPS → svc: ${GRPC_SVC}          │"
    if [[ -n "$GRPC_R_DOMAIN" ]]; then
    echo -e "  │ VLESS gRPC + REALITY    │ 443 → SNI: ${GRPC_R_DOMAIN}   │"
    else
    echo -e "  │ VLESS gRPC + REALITY    │ ${VLESS_GRPC_R_PORT} TCP (прямое, SNI r-домен)   │"
    fi
    echo -e "  │ Trojan gRPC             │ 443 HTTPS → svc: ${TROJAN_GRPC_SVC}   │"
    echo -e "  │ VMess WebSocket + TLS   │ 443 HTTPS → path: ${VMESS_WS_PATH}    │"
    echo -e "  │ VLESS HTTPUpgrade + TLS │ 443 HTTPS → path: ${HU_PATH}          │"
    echo -e "  │ Hysteria2 (QUIC/UDP)    │ 443/udp (только HY2, скрыт на 443)    │"
    echo -e "  │ AWG 1..9 (kernel)      │ ${AWG1_PORT}-${AWG9_PORT}/udp        │"
    echo -e "  │ AmneziaWG (native)     │ ${AMNEZIAWG_PORT}/udp → ${AMNEZIAWG_SUBNET} │"
    echo -e "  └─────────────────────────┴───────────────────────────────────────┘"
    echo ""
    echo -e "${BLUE}═══════════════════  SIDECAR-ПРОТОКОЛЫ LUCX-UI  ════════════════════${NC}"
    echo -e "  ┌─ Протокол ──────────────┬─ Порт ────────────────────────────────┐"
    echo -e "  │ NaiveProxy              │ ${NAIVE_PORT}/tcp (прямое, TLS caddy)             │"
    echo -e "  │ olcRTC                  │ ${OLCRTC_PORT}/tcp (прямое)                    │"
    echo -e "  │ qWDTT (DTLS/UDP)        │ ${QWDTT_PORT}/udp (прямое)                    │"
    echo -e "  │ mieru                   │ ${MIERU_PORT}/tcp (прямое)                    │"
    echo -e "  │ TrustTunnel             │ $(if [[ -n "$TT_DOMAIN" ]]; then echo "443 → SNI: ${TT_ADDR}"; else echo "${TT_ADV}/tcp (прямое, TLS)"; fi)              │"
    echo -e "  │ AnyTLS                  │ ${ANYTLS_PORT}/tcp (sidecar, TLS)              │"
    echo -e "  │ Telegram MTProto        │ ${TG_PORT}/tcp (прямое)                    │"
    if [[ -n "$TG_WEB_DOMAIN" ]]; then
    echo -e "  │ Telegram WEB proxy      │ 443 → SNI: ${TG_WEB_DOMAIN}  │"
    fi
    echo -e "  └─────────────────────────┴───────────────────────────────────────┘"
    echo ""
    echo -e "${YELLOW}  ⚠  Sidecar-протоколы (NaiveProxy/olcRTC/qWDTT/mieru/TrustTunnel/"
    echo -e "      AnyTLS/Telegram MTProto/WEB proxy) настраиваются в панели LucX-UI:"
    echo -e "      Inbounds → добавьте клиентов и нажмите Enable.${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════  ПОДПИСКА  ═════════════════════════════════${NC}"
    echo -e "  Sub base:      https://${DOMAIN}${SUB_PATH}/<subId>"
    echo -e "  JSON base:     https://${DOMAIN}${JSON_PATH}/<subId>"
    echo -e "  Clash base:    https://${DOMAIN}${CLASH_PATH}/<subId>"
    echo -e "  AmneziaWG base:https://${DOMAIN}${AWG_PATH}/<subId>"
    echo ""
    echo -e "  Автоопределение: UA Clash/Mihomo → YAML; v2rayN/sing-box/Throne → JSON."
    echo ""
    echo -e "${GREEN}  ⚠  Сохраните эти данные!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════════════${NC}"

    echo ""
    echo -e "${BLUE}═══════════════════  ADGUARD HOME (DoH + фильтрация)  ══════════════${NC}"
    if [[ "$INSTALL_ADGUARD" != "0" ]]; then
    echo -e "  Админка:   https://${DOMAIN}/${AGH_PATH}/"
    echo -e "  Логин:     ${AGH_USER}"
    echo -e "  Пароль:    ${AGH_PASS}"
    echo -e "  DoH:       https://${DOMAIN}/dns-query"
    echo -e "  DoT:       ${DOMAIN}:853"
    echo -e "  Клиенты:   DoH — реальные IP (PROXY protocol + X-Real-IP); DoT — 127.0.0.1 (L4 без PP)"
    else
    echo -e "  AdGuard Home не установлен (INSTALL_ADGUARD=0 в aio.env)"
    fi

    # Запись credentials в файл
    local cred_file="/etc/x-ui/install-result.env"
    mkdir -p /etc/x-ui
    chmod 700 /etc/x-ui
    cat > "$cred_file" <<CREDS
PANEL_URL=https://${DOMAIN}${PANEL_PATH}/
PANEL_USER=${PANEL_USER}
PANEL_PASS=${PANEL_PASS}
SUB_URL=https://${DOMAIN}${SUB_PATH}/
DOMAIN=${DOMAIN}
REALITY_DOMAIN=${REALITY_DOMAIN}
INBOUND_REALITY_PORT=443
INBOUND_WS_PORT=443
INBOUND_WS_PATH=${WS_PATH}
INBOUND_XHTTP_PORT=443
INBOUND_XHTTP_PATH=${XHTTP_PATH}
INBOUND_VLESS_GRPC_PORT=443
INBOUND_VLESS_GRPC_SVC=${GRPC_SVC}
INBOUND_TROJAN_GRPC_PORT=443
INBOUND_TROJAN_GRPC_SVC=${TROJAN_GRPC_SVC}
INBOUND_VMESS_WS_PORT=443
INBOUND_VMESS_WS_PATH=${VMESS_WS_PATH}
INBOUND_HY2_PORT=${HY2_PORT}
INBOUND_XHTTP_TLS_PATH=${XHTTP_TLS_PATH}
INBOUND_XHTTP_REALITY_ADDR=${XHTTP_R_ADDR}
INBOUND_XHTTP_REALITY_PORT=${XHTTP_R_ADV}
INBOUND_GRPC_REALITY_ADDR=${GRPC_R_ADDR}
INBOUND_GRPC_REALITY_PORT=${GRPC_R_ADV}
INBOUND_GRPC_REALITY_SVC=${GRPC_R_SVC}
INBOUND_HU_PATH=${HU_PATH}
INBOUND_NAIVE_PORT=${NAIVE_PORT}
INBOUND_OLCRTC_PORT=${OLCRTC_PORT}
INBOUND_QWDTT_PORT=${QWDTT_PORT}
INBOUND_MIERU_PORT=${MIERU_PORT}
INBOUND_TRUSTTUNNEL_HOST=${TT_HOST}
INBOUND_TRUSTTUNNEL_ADDR=${TT_ADDR}
INBOUND_TRUSTTUNNEL_PORT=${TT_ADV}
INBOUND_TG_PORT=${TG_PORT}
INBOUND_ANYTLS_PORT=${ANYTLS_PORT}
INBOUND_AWG1_PORT=${AWG1_PORT}
INBOUND_AWG2_PORT=${AWG2_PORT}
INBOUND_AWG3_PORT=${AWG3_PORT}
INBOUND_AWG4_PORT=${AWG4_PORT}
INBOUND_AWG5_PORT=${AWG5_PORT}
INBOUND_AWG6_PORT=${AWG6_PORT}
INBOUND_AWG7_PORT=${AWG7_PORT}
INBOUND_AWG8_PORT=${AWG8_PORT}
INBOUND_AWG9_PORT=${AWG9_PORT}
INBOUND_AMNEZIAWG_PORT=${AMNEZIAWG_PORT}
INBOUND_AWG1_SUBNET=${AWG1_SUBNET}
INBOUND_AWG2_SUBNET=${AWG2_SUBNET}
INBOUND_AWG3_SUBNET=${AWG3_SUBNET}
INBOUND_AWG4_SUBNET=${AWG4_SUBNET}
INBOUND_AWG5_SUBNET=${AWG5_SUBNET}
INBOUND_AWG6_SUBNET=${AWG6_SUBNET}
INBOUND_AWG7_SUBNET=${AWG7_SUBNET}
INBOUND_AWG8_SUBNET=${AWG8_SUBNET}
INBOUND_AWG9_SUBNET=${AWG9_SUBNET}
INBOUND_AMNEZIAWG_SUBNET=${AMNEZIAWG_SUBNET}
SUB_BASE=https://${DOMAIN}${SUB_PATH}/
SUB_JSON_BASE=https://${DOMAIN}${JSON_PATH}/
SUB_CLASH_BASE=https://${DOMAIN}${CLASH_PATH}/
SUB_AWG_BASE=https://${DOMAIN}${AWG_PATH}/
ADGUARD_ENABLED=${INSTALL_ADGUARD}
ADGUARD_ADMIN_URL=https://${DOMAIN}/${AGH_PATH}/
ADGUARD_USER=${AGH_USER}
ADGUARD_PASS=${AGH_PASS}
ADGUARD_DOH_URL=https://${DOMAIN}/dns-query
ADGUARD_DOT_URL=${DOMAIN}:853
CREDS
    chmod 600 "$cred_file"
    echo ""
    echo -e "  Credentials saved: ${cred_file} (mode 600)"

    # Файл с данными в /root/
    local root_cred="/root/lucx-ui-credentials.txt"
    cat > "$root_cred" <<RCREDS
=================================================================
  LUCX-UI ALL-IN-ONE v10 — ДАННЫЕ ДЛЯ ВХОДА
=================================================================
  Панель:        https://${DOMAIN}${PANEL_PATH}/
  Логин:         ${PANEL_USER}
  Пароль:        ${PANEL_PASS}
  ---------------------------------------------------------------
  Sub base:      https://${DOMAIN}${SUB_PATH}/<subId>
  JSON base:     https://${DOMAIN}${JSON_PATH}/<subId>
  Clash base:    https://${DOMAIN}${CLASH_PATH}/<subId>
  AmneziaWG base:https://${DOMAIN}${AWG_PATH}/<subId>
  ---------------------------------------------------------------
  REALITY:       ${REALITY_DOMAIN}:443
  XHTTP-REALITY: ${XHTTP_R_ADDR}:${XHTTP_R_ADV}
  gRPC-REALITY:  ${GRPC_R_ADDR}:${GRPC_R_ADV}
  Hysteria2:     ${DOMAIN}:${HY2_PORT}/udp
  AnyTLS:        ${DOMAIN}:${ANYTLS_PORT}
  qWDTT:         ${DOMAIN}:${QWDTT_PORT}/udp
  mieru:         ${DOMAIN}:${MIERU_PORT}/tcp
  AWG1..9:       ${SERVER_IP4}:${AWG1_PORT}..${AWG9_PORT}/udp
  AmneziaWG:     ${SERVER_IP4}:${AMNEZIAWG_PORT}/udp (${AMNEZIAWG_SUBNET})
  ---------------------------------------------------------------
  ADGUARD HOME (DoH + фильтрация рекламы):
    Админка:       https://${DOMAIN}/${AGH_PATH}/
    Логин:         ${AGH_USER}
    Пароль:        ${AGH_PASS}
    DoH для клиентов: https://${DOMAIN}/dns-query
    DoT для клиентов: ${DOMAIN}:853
    (DoH: реальные IP через PROXY protocol + X-Real-IP; DoT: 127.0.0.1)
  ---------------------------------------------------------------
  САЙТЫ-ЗАГЛУШКИ (декой) — правка маскировочного сайта:
    ${DOMAIN}          → файл: /var/www/html/index.html
    ${REALITY_DOMAIN}  → файл: /var/www/html/index.html (vhost: /etc/nginx/sites-available/${REALITY_DOMAIN})
$( [[ -n "$TG_WEB_DOMAIN" ]] && printf '    %s   → upstream декоя: nginx 127.0.0.1:8087 (тот же /var/www/html/index.html; vhost: /etc/nginx/sites-available/002-tproxy-decoy.conf)' "$TG_WEB_DOMAIN" )
    После правки index.html: systemctl reload nginx
  ---------------------------------------------------------------
  Лог установки:        ${LOG_FILE}
  Креды (env-формат):   /etc/x-ui/install-result.env
  ---------------------------------------------------------------
  Дата установки: $(date -R 2>/dev/null || date)
  Версия скрипта: v10.1 (AWG1-9, clients templates, ROSCOM, no sub-sidecar)
=================================================================
RCREDS
    chmod 600 "$root_cred"
    echo -e "  Файл с данными: ${root_cred} (mode 600)"
}
# Учётные данные — только в терминал (fd 3) и в файлы 600, не в лог установки
sleep 1
print_results >&3 2>&1
echo "[OK] Итоговый отчёт с учётными данными: /root/lucx-ui-credentials.txt (chmod 600)"

###############################################################################
# ФИНАЛЬНЫЙ РЕСТАРТ
###############################################################################
systemctl daemon-reload
systemctl restart x-ui 2>/dev/null || warn "x-ui restart failed — проверьте: systemctl status x-ui"
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx 2>/dev/null || warn "nginx reload failed — systemctl status nginx"
else
    warn "nginx -t не прошёл — reload пропущен (см. nginx -t)"
fi

###############################################################################
# СТАТУС И ДИАГНОСТИКА (по мотивам x-tuna / lucx-post-configure)
###############################################################################
status_and_diagnostics() {
    echo ""
    echo -e "${BLUE}═══════════════════  СТАТУС И ДИАГНОСТИКА  ══════════════════════════${NC}"
    local svc okc=0 failc=0 degc=0
    for svc in x-ui nginx; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GREEN}●${NC} ${svc}: active"
            ((okc++)) || true
        else
            echo -e "  ${RED}●${NC} ${svc}: $(systemctl is-active "$svc" 2>/dev/null || echo inactive)"
            ((failc++)) || true
        fi
    done
    if [[ "${INSTALL_ADGUARD:-1}" != "0" ]]; then
        if systemctl is-active --quiet AdGuardHome 2>/dev/null; then
            echo -e "  ${GREEN}●${NC} AdGuardHome: active"
            ((okc++)) || true
        else
            echo -e "  ${RED}●${NC} AdGuardHome: $(systemctl is-active AdGuardHome 2>/dev/null || echo inactive)"
            ((failc++)) || true
        fi
    fi
    if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^lucx-sub-sidecar\.service'; then
        if systemctl is-active --quiet lucx-sub-sidecar 2>/dev/null; then
            echo -e "  ${GREEN}●${NC} lucx-sub-sidecar: active"
            ((okc++)) || true
        else
            echo -e "  ${YELLOW}●${NC} lucx-sub-sidecar: $(systemctl is-active lucx-sub-sidecar 2>/dev/null || echo inactive)"
            ((failc++)) || true
        fi
    fi

    # nginx config
    if nginx -t >/dev/null 2>&1; then
        echo -e "  ${GREEN}●${NC} nginx -t: OK"
        ((okc++)) || true
    else
        echo -e "  ${RED}●${NC} nginx -t: FAIL"
        ((failc++)) || true
    fi

    # Listening sockets (panel/sub on loopback, 443 public); панели после restart нужно время
    for _ in $(seq 1 30); do
        ss -Hltn "sport = :${PANEL_PORT}" 2>/dev/null | grep -q . && break
        sleep 1
    done
    if ss -lnt 2>/dev/null | grep -qE ":${PANEL_PORT}\b"; then
        echo -e "  ${GREEN}●${NC} panel listen :${PANEL_PORT}"
        ((okc++)) || true
    else
        echo -e "  ${RED}●${NC} panel :${PANEL_PORT} не слушает"
        ((failc++)) || true
    fi
    if ss -lnt 2>/dev/null | grep -qE ":443\b"; then
        echo -e "  ${GREEN}●${NC} nginx/stream :443"
        ((okc++)) || true
    else
        echo -e "  ${RED}●${NC} :443 not listening"
        ((failc++)) || true
    fi

    # Sub endpoint smoke (HTTPS, no body dump)
    local sub_code
    if [[ -n "${TEST_SUB_ID}" ]]; then
        sub_code=$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 12 \
            "https://${DOMAIN}${SUB_PATH}/${TEST_SUB_ID}" 2>/dev/null || echo "000")
        if [[ "$sub_code" =~ ^(200|301|302|401|403)$ ]]; then
            echo -e "  ${GREEN}●${NC} Sub URL HTTP ${sub_code}"
            ((okc++)) || true
        else
            echo -e "  ${YELLOW}●${NC} Sub URL HTTP ${sub_code} — проверьте через 10–20 с"
        fi
    else
        echo -e "  ${GREEN}●${NC} Sub base: https://${DOMAIN}${SUB_PATH}/<subId> (клиенты из шаблонов)"
        ((okc++)) || true
    fi

    # Внутренние сервисы не должны слушать публичные адреса
    local lp laddr
    for lp in "$PANEL_PORT" "$SUB_PORT" 7443 9443 8443 "$AGH_WEB_PORT" "$AGH_DNS_PORT"; do
        laddr=$(ss -Hltn "sport = :${lp}" 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.0\.0\.1|\[::1\]):' | head -n1)
        if [[ -n "$laddr" ]]; then
            echo -e "  ${YELLOW}●${NC} :${lp} слушает ${laddr} (ожидался только 127.0.0.1; закрыт UFW)"
            ((degc++)) || true
        fi
    done

    # Firewall / fail2ban
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        echo -e "  ${GREEN}●${NC} ufw: active"
        ((okc++)) || true
    else
        echo -e "  ${RED}●${NC} ufw: inactive"
        ((failc++)) || true
    fi
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} fail2ban: active ($(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p'))"
        ((okc++)) || true
    else
        echo -e "  ${YELLOW}●${NC} fail2ban: inactive"
        ((degc++)) || true
    fi

    # DoH / DoT (результаты self-test из setup_adguard)
    if [[ "${INSTALL_ADGUARD:-1}" != "0" ]]; then
        if [[ "${AGH_DOH_OK:-0}" == 1 ]]; then echo -e "  ${GREEN}●${NC} DoH https://${DOMAIN}/dns-query"; ((okc++)) || true
        else echo -e "  ${YELLOW}●${NC} DoH self-test не прошёл"; ((degc++)) || true; fi
        if [[ "${AGH_DOT_OK:-0}" == 1 ]]; then echo -e "  ${GREEN}●${NC} DoT tls://${DOMAIN}:853"; ((okc++)) || true
        else echo -e "  ${YELLOW}●${NC} DoT self-test не прошёл"; ((degc++)) || true; fi
    fi

    # AWG UDP ports
    local awgp
    for awgp in "${AWG1_PORT}" "${AWG2_PORT}" "${AWG3_PORT}" "${AWG4_PORT}" "${AWG5_PORT}" "${AWG6_PORT}" "${AWG7_PORT}" "${AWG8_PORT}" "${AWG9_PORT}" "${AMNEZIAWG_PORT}"; do
        if ss -lun 2>/dev/null | grep -qE ":${awgp}\b"; then
            echo -e "  ${GREEN}●${NC} AWG UDP :${awgp}"
            ((okc++)) || true
        else
            # AWG interfaces may come up after x-ui fully loads inbounds
            echo -e "  ${YELLOW}●${NC} AWG UDP :${awgp} — ожидается после поднятия awg sidecar"
        fi
    done

    # test client auto-seed removed
    if [[ -n "${TEST_CLIENT_EMAIL}" && -f "$XUIDB" ]]; then
        local hit
        hit=$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM inbounds WHERE settings LIKE '%${TEST_CLIENT_EMAIL}%';" 2>/dev/null || echo 0)
        [[ "${hit:-0}" -ge 1 ]] && echo -e "  ${GREEN}●${NC} DB: клиент ${TEST_CLIENT_EMAIL}" && ((okc++)) || true
    fi

    echo ""
    if (( failc > 0 )); then
        echo -e "  ${RED}Итог диагностики: КРИТИЧНО — ${failc} ошибок, ${degc} предупреждений, ${okc} OK${NC}"
        echo -e "  Подсказки: journalctl -u x-ui -n 50; journalctl -u AdGuardHome -n 30; nginx -t"
    elif (( degc > 0 )); then
        echo -e "  ${YELLOW}Итог диагностики: работает с замечаниями — ${degc} предупреждений, ${okc} OK${NC}"
    else
        echo -e "  ${GREEN}Итог диагностики: OK (${okc} проверок)${NC}"
    fi
    echo -e "  Диагностика проверяет сервер локально; работу клиентов проверьте подключением."
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${NC}"
    DIAG_FAILED="$failc"
}
DIAG_FAILED=0
status_and_diagnostics
trap - EXIT
(( DIAG_FAILED == 0 )) || exit 2

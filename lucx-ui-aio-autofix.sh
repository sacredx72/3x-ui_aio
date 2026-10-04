#!/bin/bash
###############################################################################
#  LucX-UI AIO — AUTO-FIX протоколов  (v1, 2026)
#  ─────────────────────────────────────────────────────────────────────────────
#  Починка уже установленного сервера (установщик: lucx-ui-aio-v10.sh).
#
#  Что исправляется (идемпотентно, с бэкапом БД, безопасно к повторным прогонам):
#    1) Hysteria2 : settings.users[]  ->  settings.clients[] (+ поле auth)
#    2) MTProto   : settings.users[]  ->  settings.clients[] (+ FakeTLS secret
#                   формата "ee"+32hex+hex(domain)) и заполняется fakeTlsDomain
#    3) VLESS     : flow="xtls-rprx-vision" для TCP+REALITY/TLS инбаундов
#                   (для WS/XHTTP/gRPC/HTTPUpgrade flow снимается -> "")
#    4) VMess     : каждому клиенту security="auto" (если не задан)
#    5) Прогон штатного «хилера» панели: `x-ui migrate`
#       -> MigrateDB() -> MigrationRequirements() -> SyncInbound()
#       пересобирает таблицы clients / client_inbounds / client_traffics
#       из settings.clients (без этого подписки, лимиты и учёт не работают).
#
#  Диагноз (подтверждён по исходникам LucX-UI):
#    - Панель извлекает клиентов ТОЛЬКО из settings.clients
#      (internal/web/service/inbound_settings_clients.go: ParseInboundSettingsClients
#       читает исключительно ключ "clients"; ключ "users" не поддерживается).
#    - Схема Hysteria требует clients[].auth
#      (frontend/src/schemas/protocols/inbound/hysteria.ts;
#       тест internal/web/service/inbound_hysteria_auth_test.go: клиент без auth
#       отвергается с ошибкой "empty client ID").
#    - Схема MTProto требует clients[].secret в формате FakeTLS
#      (frontend/src/schemas/protocols/inbound/mtproto.ts;
#       model.GenerateFakeTLSSecret: "ee" + 16 случ. байт + hex(домен)).
#  Поэтому в v10 инбаунды Hysteria2 и MTProto создавались без клиентов, а сидер
#  дописывал их в неверный ключ "users" (Hysteria — ещё и без auth).
#
#  Запуск:
#    sudo bash lucx-ui-aio-autofix.sh                 # авто-режим
#    sudo bash lucx-ui-aio-autofix.sh --dry-run       # только показать, что будет
#    sudo bash lucx-ui-aio-autofix.sh --domain panel.example.com --tg-domain tg.example.com
#    sudo bash lucx-ui-aio-autofix.sh --help
#
#  Опции:
#    --db PATH          путь к базе панели (по умолчанию /etc/x-ui/x-ui.db)
#    --domain DOMAIN    домен панели (для fakeTlsDomain, если не определится сам)
#    --tg-domain DOMAIN домен для MTProto FakeTLS (по умолчанию = --domain,
#                       иначе www.cloudflare.com)
#    --dry-run          ничего не менять в БД, только отчёт
#    --no-backup        не делать бэкап БД (не рекомендуется)
#    --no-heal          не запускать `x-ui migrate` (только правка settings)
#    --no-restart       не перезапускать панель
#    --no-flow          не трогать поле flow у VLESS
#    --no-vmess         не трогать VMess-клиентов
#    -y, --yes          без подтверждения
#    -h, --help         эта справка
#
#  ОС: Ubuntu / Debian. Бинарь панели: /usr/local/x-ui/x-ui, сервис: x-ui.service
###############################################################################
# Ошибки обрабатываются через die()/warn(); set -e не используется (как в v10)
set -uo pipefail

# ─── Цвета ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }
inf()  { echo -e "${BLUE}[--]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}  $*"; }
die()  { err "$*"; exit 1; }

# ─── Самопроверка целостности (heredoc/синтаксис) ───────────────────────────
if [[ -s "$0" && -r "$0" ]] && ! bash -n "$0" 2>/tmp/lucx-autofix-syntax-err; then
    err "Скрипт повреждён (синтаксис/heredoc):"
    cat /tmp/lucx-autofix-syntax-err >&2
    die "Восстановите файл из чистой копии и повторите запуск"
fi
rm -f /tmp/lucx-autofix-syntax-err

# (Инициализация лога и проверка root вынесены НИЖЕ — после разбора аргументов,
#  чтобы `--help` отрабатывал без прав root.)

# ─── Глобальные значения ────────────────────────────────────────────────────
XUI_BIN="/usr/local/x-ui/x-ui"
XUI_SVC="x-ui"
DB_PATH=""
DOMAIN_OPT=""
TG_DOMAIN_OPT=""
DRY_RUN="n"
DO_BACKUP="y"
DO_HEAL="y"
DO_RESTART="y"
DO_FLOW="y"
DO_VMESS="y"
ASSUME_YES="n"
# ─── Справка ────────────────────────────────────────────────────────────────
usage() {
    awk 'NR>1 { if ($0 ~ /^#{10,}/) exit; print }' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# ─── Разбор аргументов ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)          DB_PATH="$2";            shift 2 ;;
        --db=*)        DB_PATH="${1#*=}";       shift ;;
        --domain)      DOMAIN_OPT="$2";         shift 2 ;;
        --domain=*)    DOMAIN_OPT="${1#*=}";    shift ;;
        --tg-domain)   TG_DOMAIN_OPT="$2";      shift 2 ;;
        --tg-domain=*) TG_DOMAIN_OPT="${1#*=}"; shift ;;
        --dry-run)     DRY_RUN="y";             shift ;;
        --no-backup)   DO_BACKUP="n";           shift ;;
        --no-heal)     DO_HEAL="n";             shift ;;
        --no-restart)  DO_RESTART="n";          shift ;;
        --no-flow)     DO_FLOW="n";             shift ;;
        --no-vmess)    DO_VMESS="n";            shift ;;
        -y|--yes)      ASSUME_YES="y";          shift ;;
        -h|--help)     usage ;;
        *) die "Неизвестный аргумент: $1 (см. --help)" ;;
    esac
done

# ─── Лог ────────────────────────────────────────────────────────────────────
LOG_FILE="${LOG_FILE:-/root/lucx-ui-autofix.log}"
mkdir -p /root 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" 2>/dev/null || true
exec > >(tee -a "$LOG_FILE") 2>&1

# ─── Root ───────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Запустите от root: sudo bash $0"

# ─── Определяем путь к БД ───────────────────────────────────────────────────
if [[ -z "$DB_PATH" ]]; then
    if [[ -n "${XUI_DB:-}" && -f "${XUI_DB:-}" ]]; then
        DB_PATH="$XUI_DB"
    elif [[ -f /etc/x-ui/x-ui.db ]]; then
        DB_PATH="/etc/x-ui/x-ui.db"
    elif [[ -f /usr/local/x-ui/x-ui.db ]]; then
        DB_PATH="/usr/local/x-ui/x-ui.db"
    else
        DB_PATH=$(ls -1 /etc/x-ui/*.db /usr/local/x-ui/*.db 2>/dev/null | head -n1 || true)
    fi
fi
[[ -n "$DB_PATH" && -f "$DB_PATH" ]] || die "Не найдена база панели (укажите --db PATH)"

# ─── Определяем домен (для MTProto fakeTlsDomain) ───────────────────────────
detect_domain() {
    local d=""
    if [[ -n "$DOMAIN_OPT" ]]; then printf '%s' "$DOMAIN_OPT"; return; fi
    if [[ -f /etc/x-ui/install-result.env ]]; then
        d=$(sed -n 's/^DOMAIN=//p' /etc/x-ui/install-result.env | head -n1 | tr -d '"'"'"'\r')
    fi
    if [[ -z "$d" && -f /root/lucx-ui-credentials.txt ]]; then
        d=$(sed -n 's|.*[Пп]анель:[[:space:]]*https\?://\([^/]*\).*|\1|p' /root/lucx-ui-credentials.txt 2>/dev/null | head -n1 | tr -d '\r')
    fi
    if [[ -z "$d" ]]; then
        d=$(sqlite3 "$DB_PATH" "SELECT address FROM hosts WHERE address GLOB '*[A-Za-z]*' LIMIT 1;" 2>/dev/null | head -n1 | tr -d '\r' || true)
    fi
    printf '%s' "$d"
}
DOMAIN="$(detect_domain)"
if [[ -n "$TG_DOMAIN_OPT" ]]; then
    TG_DOMAIN="$TG_DOMAIN_OPT"
elif [[ -n "$DOMAIN" ]]; then
    TG_DOMAIN="$DOMAIN"
else
    TG_DOMAIN="www.cloudflare.com"
fi

# ─── subId подписки (чтобы новые клиенты попали в подписку) ──────────────────
DEFAULT_SUBID=""
if [[ -f /etc/x-ui/install-result.env ]]; then
    DEFAULT_SUBID=$(sed -n 's/^TEST_SUB_ID=//p' /etc/x-ui/install-result.env | head -n1 | tr -d '"'"'"'\r')
fi
if [[ -z "$DEFAULT_SUBID" ]]; then
    DEFAULT_SUBID=$(sqlite3 "$DB_PATH" "SELECT sub_id FROM clients WHERE sub_id<>'' LIMIT 1;" 2>/dev/null | head -n1 | tr -d '\r' || true)
fi

# ─── Preflight ──────────────────────────────────────────────────────────────
command -v sqlite3 >/dev/null 2>&1 || die "Нужен sqlite3 (apt-get install -y sqlite3)"
command -v python3 >/dev/null 2>&1 || die "Нужен python3"
HAVE_XUI="n"
[[ -x "$XUI_BIN" ]] && HAVE_XUI="y"
[[ $HAVE_XUI == n ]] && warn "Не найден бинарь панели $XUI_BIN — хилер (x-ui migrate) будет пропущен"

echo
echo "=============================================================="
echo "  LucX-UI AIO — AUTO-FIX протоколов"
echo "=============================================================="
inf "База панели:        $DB_PATH"
inf "Домен (панель):     ${DOMAIN:-<не определён>}"
inf "MTProto FakeTLS:    $TG_DOMAIN"
inf "Режим:              $( [[ $DRY_RUN == y ]] && echo 'DRY-RUN (без изменений)' || echo 'боевой' )"
inf "Хилер панели:       $( [[ $DO_HEAL == y && $HAVE_XUI == y ]] && echo 'да (x-ui migrate)' || echo 'нет' )"
echo

# ─── Подтверждение ──────────────────────────────────────────────────────────
if [[ $DRY_RUN != y && $ASSUME_YES != y && -t 0 ]]; then
    read -rp "Продолжить? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "Отменено пользователем"
fi
# ─── Останов панели + бэкап БД ──────────────────────────────────────────────
BACKUP=""
if [[ $DRY_RUN == y ]]; then
    inf "DRY-RUN: панель не останавливаю, БД не меняю."
else
    if systemctl list-unit-files 2>/dev/null | grep -q "^${XUI_SVC}\.service"; then
        inf "Останавливаю ${XUI_SVC}.service..."
        systemctl stop "$XUI_SVC" 2>/dev/null || warn "Не удалось остановить ${XUI_SVC} — продолжаю"
        sleep 2
    else
        warn "Юнит ${XUI_SVC}.service не найден — пропускаю останов"
    fi

    if [[ $DO_BACKUP == y ]]; then
        BACKUP="${DB_PATH}.autofix.$(date +%Y%m%d-%H%M%S).bak"
        if sqlite3 "$DB_PATH" ".backup '$BACKUP'" 2>/dev/null && [[ -s "$BACKUP" ]]; then
            ok "Бэкап БД: $BACKUP"
        elif cp -a "$DB_PATH" "$BACKUP" 2>/dev/null; then
            ok "Бэкап БД (cp): $BACKUP"
        else
            BACKUP=""
            die "Не удалось сделать бэкап БД — прерываю (осознанно можно --no-backup)"
        fi
    else
        warn "Бэкап отключён (--no-backup)"
    fi
fi

# ─── Патч settings в БД ─────────────────────────────────────────────────────
inf "Правка settings.clients (Hysteria2 / MTProto / VLESS flow / VMess security)..."

python3 - "$DB_PATH" "$TG_DOMAIN" "$DRY_RUN" "$DO_FLOW" "$DO_VMESS" "$DEFAULT_SUBID" <<'PYFIX'
# -*- coding: utf-8 -*-
import binascii, json, os, sqlite3, sys, time

db_path   = sys.argv[1]
tg_domain = (sys.argv[2] or "").strip() or "www.cloudflare.com"
dry       = (sys.argv[3] == "y")
do_flow   = (sys.argv[4] == "y")
do_vmess  = (sys.argv[5] == "y")
default_subid = (sys.argv[6] if len(sys.argv) > 6 else "").strip()

con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row
cur = con.cursor()

cols = {r[1] for r in cur.execute("PRAGMA table_info(inbounds)").fetchall()}
has_disable_flow = "disable_flow" in cols
has_stream       = "stream_settings" in cols


def rand_hex(nbytes):
    return binascii.hexlify(os.urandom(nbytes)).decode()


ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def rand_str(n):
    return "".join(ALPHABET[b % len(ALPHABET)] for b in os.urandom(n))


def secret_middle(secret):
    """16-байтная середина секрета (32 hex) — сохраняем её при смене домена."""
    s = (secret or "")
    if s[:2] in ("ee", "dd"):
        s = s[2:]
    if len(s) >= 32:
        mid = s[:32]
        try:
            binascii.unhexlify(mid)
            return mid
        except Exception:
            pass
    return None


def fake_secret(domain, middle=None):
    return "ee" + (middle or rand_hex(16)) + binascii.hexlify(domain.encode()).decode()


def secret_is_valid(secret, domain):
    s = (secret or "")
    if not s.startswith("ee") or len(s) < 34:
        return False
    try:
        tail = binascii.unhexlify(s[34:]).decode("ascii")
    except Exception:
        return False
    return tail == domain


BASE = {"enable": True, "tgId": 0, "limitIp": 0, "totalGB": 0,
        "expiryTime": 0, "reset": 0, "comment": "autofix"}


def mk_client(email, sub_id="", **extra):
    c = dict(BASE)
    c["email"] = email
    c["subId"] = sub_id or default_subid
    c.update(extra)
    return c


def norm_list(v):
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


stats = {"hysteria": 0, "mtproto": 0, "vless": 0, "vmess": 0, "skipped": 0}
report = []

sel = "SELECT id, protocol, settings, "
sel += "stream_settings" if has_stream else "'' AS stream_settings"
sel += ", disable_flow" if has_disable_flow else ", 0 AS disable_flow"
sel += " FROM inbounds"
rows = cur.execute(sel).fetchall()
for row in rows:
    iid = int(row["id"])
    proto = (row["protocol"] or "").lower()
    try:
        settings = json.loads(row["settings"] or "{}")
        if not isinstance(settings, dict):
            raise ValueError("settings is not an object")
    except Exception as e:
        stats["skipped"] += 1
        report.append("SKIP id=%d proto=%s (битый settings: %s)" % (iid, proto, e))
        continue

    changed = False
    note = []

    # ── (1)(2) Hysteria2 / MTProto: users[] -> clients[] ────────────────────
    if proto in ("hysteria", "hysteria2", "mtproto"):
        users   = norm_list(settings.get("users"))
        clients = norm_list(settings.get("clients"))
        by_email = {u.get("email"): u for u in users if u.get("email")}

        if proto in ("hysteria", "hysteria2"):
            domain = None
        else:  # mtproto
            domain = (str(settings.get("fakeTlsDomain") or "")).strip() or tg_domain
            if settings.get("fakeTlsDomain") != domain:
                settings["fakeTlsDomain"] = domain
                changed = True
                note.append("fakeTlsDomain=%s" % domain)

        new_clients, seen = [], set()
        for c in clients:
            email = (str(c.get("email") or "")).strip() or "client-%d" % (len(new_clients) + 1)
            if email in seen:
                continue
            seen.add(email)
            nc = dict(c)
            nc["email"] = email
            if not nc.get("tgId"):
                nc["tgId"] = 0
            if proto in ("hysteria", "hysteria2"):
                src = by_email.get(email) or {}
                auth = str(nc.get("auth") or src.get("auth") or nc.get("password") or "").strip()
                if not auth:
                    auth = rand_str(20)
                    note.append("auth[%s] сгенерирован" % email)
                if nc.get("auth") != auth:
                    changed = True
                nc["auth"] = auth
            else:  # mtproto
                mid = secret_middle(nc.get("secret")) or secret_middle((by_email.get(email) or {}).get("secret"))
                if not secret_is_valid(nc.get("secret"), domain):
                    nc["secret"] = fake_secret(domain, mid)
                    changed = True
                    note.append("secret[%s] пересоздан" % email)
            new_clients.append(nc)

        for u in users:
            email = (str(u.get("email") or "")).strip()
            if not email or email in seen:
                continue
            seen.add(email)
            if proto in ("hysteria", "hysteria2"):
                auth = str(u.get("auth") or u.get("password") or "").strip() or rand_str(20)
                new_clients.append(mk_client(email, auth=auth))
            else:
                new_clients.append(mk_client(email, secret=fake_secret(domain, secret_middle(u.get("secret")))))
            changed = True
            note.append("+клиент %s из users[]" % email)

        if settings.get("clients") != new_clients:
            settings["clients"] = new_clients
            changed = True
        if "users" in settings:
            settings.pop("users", None)
            changed = True
        if proto in ("hysteria", "hysteria2") and settings.get("version") != 2:
            settings["version"] = 2
            changed = True
        if changed:
            key = "hysteria" if proto in ("hysteria", "hysteria2") else "mtproto"
            stats[key] += 1
            report.append("FIX id=%d proto=%s clients=%d %s" % (iid, proto, len(new_clients), ",".join(note)))
    # ── (3) VLESS: flow = Vision для TCP+REALITY/TLS ────────────────────────
    elif proto == "vless" and do_flow and not row["disable_flow"]:
        try:
            stream = json.loads(row["stream_settings"] or "{}")
            if not isinstance(stream, dict):
                stream = {}
        except Exception:
            stream = {}
        net = str(stream.get("network") or "tcp").lower()
        sec = str(stream.get("security") or "none").lower()
        want = "xtls-rprx-vision" if (net == "tcp" and sec in ("reality", "tls")) else ""
        clients = norm_list(settings.get("clients"))
        touched = False
        for c in clients:
            if str(c.get("flow") or "") != want:
                c["flow"] = want
                touched = True
        if touched:
            settings["clients"] = clients
            changed = True
            stats["vless"] += 1
            report.append("FIX id=%d proto=vless flow=%s (network=%s security=%s)"
                          % (iid, want or "<пусто>", net, sec))

    # ── (4) VMess: security="auto" ───────────────────────────────────────────
    elif proto == "vmess" and do_vmess:
        clients = norm_list(settings.get("clients"))
        touched = False
        for c in clients:
            if not str(c.get("security") or "").strip():
                c["security"] = "auto"
                touched = True
        if touched:
            settings["clients"] = clients
            changed = True
            stats["vmess"] += 1
            report.append("FIX id=%d proto=vmess security=auto" % iid)

    if changed and not dry:
        cur.execute(
            "UPDATE inbounds SET settings=? WHERE id=?",
            (json.dumps(settings, ensure_ascii=False, separators=(",", ":")), iid),
        )

if not dry:
    con.commit()
con.close()

print("--- ОТЧЁТ ПРАВКИ settings ---")
for line in report:
    print("  " + line)
if not report:
    print("  (нечего править — всё уже в порядке)")
print("Сводка: hysteria=%d mtproto=%d vless=%d vmess=%d skipped=%d%s"
      % (stats["hysteria"], stats["mtproto"], stats["vless"], stats["vmess"],
         stats["skipped"], "  [DRY-RUN: изменения не записаны]" if dry else ""))
PYFIX
FIX_RC=$?
if [[ $FIX_RC -ne 0 ]]; then
    err "Фиксer завершился с ошибкой (код $FIX_RC)."
    if [[ -n "$BACKUP" && -s "$BACKUP" ]]; then
        warn "Бэкап: $BACKUP"
        warn "Восстановление: systemctl stop x-ui && cp -a '$BACKUP' '$DB_PATH' && systemctl start x-ui"
    fi
    die "Правка прервана; при необходимости восстановите БД из бэкапа."
fi

# ─── Штатный «хилер» панели: x-ui migrate ───────────────────────────────────
if [[ $DRY_RUN != y && $DO_HEAL == y && $HAVE_XUI == y ]]; then
    inf "Прогон хилерa панели (x-ui migrate): пересборка clients/client_inbounds/client_traffics..."
    MIG_LOG="/tmp/lucx-autofix-migrate.log"
    if ( cd "$(dirname "$XUI_BIN")" && timeout 180 ./x-ui migrate ) >"$MIG_LOG" 2>&1; then
        sed 's/^/      /' "$MIG_LOG"
        ok "x-ui migrate выполнен успешно"
    else
        sed 's/^/      /' "$MIG_LOG" 2>/dev/null || true
        warn "x-ui migrate не удалось — таблицы будут пересобраны при старте панели"
    fi
    rm -f "$MIG_LOG"
fi

# ─── Запуск панели ──────────────────────────────────────────────────────────
if [[ $DRY_RUN != y && $DO_RESTART == y ]]; then
    inf "Запускаю ${XUI_SVC}.service..."
    systemctl restart "$XUI_SVC" 2>/dev/null || systemctl start "$XUI_SVC" 2>/dev/null \
        || warn "Не удалось запустить ${XUI_SVC} — запустите вручную: systemctl start ${XUI_SVC}"
    sleep 5
fi

# ─── Проверка результата ────────────────────────────────────────────────────
echo
inf "Проверка состояния БД:"
python3 - "$DB_PATH" <<'PYVER'
import json, sqlite3, sys
con = sqlite3.connect(sys.argv[1]); con.row_factory = sqlite3.Row; cur = con.cursor()
agg = {}
for r in cur.execute("SELECT protocol, settings FROM inbounds").fetchall():
    p = (r["protocol"] or "").lower()
    try:
        s = json.loads(r["settings"] or "{}")
        if not isinstance(s, dict):
            s = {}
    except Exception:
        s = {}
    n = len([x for x in (s.get("clients") or []) if isinstance(x, dict)])
    row = agg.setdefault(p, {"ib": 0, "cl": 0, "users": False})
    row["ib"] += 1
    row["cl"] += n
    row["users"] = row["users"] or ("users" in s)
for p in sorted(agg):
    a = agg[p]
    flag = "  <-- ВНИМАНИЕ: остался ключ users[]" if a["users"] else ""
    print("  %-12s inbounds=%-3d clients=%-4d%s" % (p, a["ib"], a["cl"], flag))
for tbl in ("clients", "client_inbounds", "client_traffics"):
    try:
        c = cur.execute("SELECT COUNT(*) FROM %s" % tbl).fetchone()[0]
        print("  таблица %-16s: %d строк" % (tbl, c))
    except Exception:
        pass
con.close()
PYVER

# ─── Итог ───────────────────────────────────────────────────────────────────
echo
echo "=============================================================="
if [[ $DRY_RUN == y ]]; then
    echo "  DRY-RUN завершён — изменения НЕ вносились."
    echo "  Запустите без --dry-run для применения."
else
    echo "  AUTO-FIX завершён."
fi
echo "=============================================================="
echo "  Что сделать далее:"
echo "   * В панели откройте Inbounds: у Hysteria2 и MTProto должны появиться клиенты."
echo "   * MTProto: ссылку tg:// нужно взять заново (секрет пересоздан в формате FakeTLS)."
echo "   * VLESS-REALITY: у клиента включён flow=xtls-rprx-vision (XTLS-Vision)."
echo "   * Перевыпустите подписки (или подождите автообновления) — состав протоколов изменился."
[[ -n "$BACKUP" ]] && echo "   * Бэкап БД: $BACKUP"
echo "   * Лог: $LOG_FILE"
echo
exit 0




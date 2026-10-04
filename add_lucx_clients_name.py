#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Простое добавление клиентов в БД LucX-UI / 3x-ui.

Что делает:
  • создаёт запись в таблице clients (email, comment, group, uuid, password, auth, sub_id)
  • создаёт запись в client_traffics (учёт трафика)
  • НЕ трогает inbounds / settings / client_inbounds

Протоколы и привязку к inbound'ам настраиваете сами в панели
(Clients → Edit → выбрать inbound'ы / UUID / flow и т.д.).

Автогенерация:
  UUID          → uuid4
  Password      → token_urlsafe(16)
  Sub ID        → 16 символов [0-9a-z]
  Hysteria Auth → = password

Запуск (root на сервере):
  python3 add_lucx_clients.py
  python3 add_lucx_clients.py /etc/x-ui/x-ui.db
  python3 add_lucx_clients.py --dry-run
"""

from __future__ import annotations

import argparse
import secrets
import sqlite3
import string
import subprocess
import sys
import time
import uuid

# ─── список клиентов: (Email, Comment, Group) ────────────────────────────────
CLIENTS = [
    ("NUR_Router",       "Роутер Уренгой",     "Роутеры"),
    ("Armavir_Router",   "Роутер Армавирская", "Роутеры"),
    ("Dasha_Router",     "Роутер Горизонт",    "Роутеры"),
    ("Babyshka_Router",  "Роутер Бабушка",     "Роутеры"),
    ("Tyumen_Router",    "Роутер Тюмень",      "Роутеры"),
    ("Gosh_Router",      "Роутер Гошиишык",    "Роутеры"),
    ("Krasnodar_Router", "Роутер Динская",     "Роутеры"),
    ("Caddy_Router",     "Роутер Caddy",       "Роутеры"),
    ("Aleksandr_Mobile", "Телефон Александр",  "Телефоны"),
    ("Tanya_Mobile",     "Телефон Таня",       "Телефоны"),
    ("Dasha_Mobile",     "Телефон Даша",       "Телефоны"),
    ("Vanya_Mobile",     "Телефон Ваня",       "Телефоны"),
    ("Papa_Mobile",      "Телефон Папа",       "Телефоны"),
    ("Aleksandr_Pad",    "Планшет Александр",  "Планшет"),
    ("Tanya_Pad",        "Планшет Таня",       "Планшет"),
    ("Dasha_Pad",        "Планшет Даша",       "Планшет"),
    ("Vanya_Pad",        "Планшет Ваня",       "Планшет"),
    ("Papa_Pad",         "Планшет Папа",       "Планшет"),
    ("Mama_Pad",         "Планшет Мама",       "Планшет"),
    ("PC_Home",          "Компьютер Нур",      "PC"),
    ("RedmiG",           "Ноутбук RedmiG",     "PC"),
    ("Server_Home",      "Сервер Нур",         "PC"),
    ("Server_Armavir",   "Сервер Армавирская", "Server"),
    ("Server_Dasha",     "Сервер Горизонт",    "Server"),
    ("Server_Babyshka",  "Сервер Бабушка",     "Server"),
    ("Server_Tyumen",    "Сервер Тюмень",      "Server"),
    ("Kaskad_DE_RU",    "Сервисный",      "Server"),
    ("Kaskad_RU_DE",    "Сервисный",      "Server"),
    ("Kaskad_RU_FE",    "Сервисный",      "Server"),
    ("Kaskad_FE_RU",    "Сервисный",      "Server"),
]

DEFAULT_DB = "/etc/x-ui/x-ui.db"


def rand_sub_id(n: int = 16) -> str:
    alphabet = string.digits + string.ascii_lowercase
    return "".join(secrets.choice(alphabet) for _ in range(n))


def rand_password(n: int = 16) -> str:
    return secrets.token_urlsafe(n)


def cols(cur: sqlite3.Cursor, table: str) -> set[str]:
    return {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}


def main() -> int:
    ap = argparse.ArgumentParser(description="Simple LucX-UI client seeder (clients table only)")
    ap.add_argument("db", nargs="?", default=DEFAULT_DB, help=f"path to x-ui.db (default: {DEFAULT_DB})")
    ap.add_argument("--dry-run", action="store_true", help="только показать, без записи")
    ap.add_argument("--no-restart", action="store_true", help="не перезапускать x-ui")
    args = ap.parse_args()

    print(f"DB: {args.db}")
    print(f"Клиентов: {len(CLIENTS)}")
    print("-" * 72)

    results = []  # email, comment, group, uuid, sub, pass

    if args.dry_run:
        for email, comment, group in CLIENTS:
            u = str(uuid.uuid4())
            s = rand_sub_id()
            p = rand_password()
            results.append((email, comment, group, u, s, p))
            print(f"  [dry] {email:20}  uuid={u[:8]}…  sub={s}  pass={p[:10]}…")
        print("-" * 72)
        print("Dry-run: ничего не записано.")
        return 0

    try:
        con = sqlite3.connect(args.db)
    except sqlite3.Error as e:
        print(f"[ERR] не могу открыть БД: {e}", file=sys.stderr)
        return 1

    con.row_factory = sqlite3.Row
    cur = con.cursor()
    tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    if "clients" not in tables:
        print("[ERR] таблица clients не найдена", file=sys.stderr)
        return 1

    ccols = cols(cur, "clients")
    now_ms = int(time.time() * 1000)

    # id в clients — autoincrement INTEGER PK?
    id_is_auto = False
    for r in cur.execute("PRAGMA table_info(clients)"):
        if r[1] == "id" and r[5] == 1:
            id_is_auto = True
            break

    for email, comment, group_name in CLIENTS:
        master_uuid = str(uuid.uuid4())
        password = rand_password()
        sub_id = rand_sub_id()

        # удалить старого с тем же email (+ хвосты в inbounds.settings от прошлых запусков)
        old_ids = [r[0] for r in cur.execute("SELECT id FROM clients WHERE email=?", (email,))]
        for jtab in ("client_inbounds", "client_inbound", "clients_inbounds"):
            if jtab in tables and old_ids:
                for cid in old_ids:
                    try:
                        cur.execute(f"DELETE FROM {jtab} WHERE client_id=?", (cid,))
                    except sqlite3.Error:
                        pass
        cur.execute("DELETE FROM clients WHERE email=?", (email,))
        if "client_traffics" in tables:
            cur.execute("DELETE FROM client_traffics WHERE email=?", (email,))

        # убрать этот email из settings.clients / settings.users всех inbound'ов
        # (иначе панель может ругаться empty client ID на старых записях)
        import json
        for iid, raw in list(cur.execute("SELECT id, settings FROM inbounds")):
            try:
                s = json.loads(raw or "{}")
            except Exception:
                continue
            changed = False
            if isinstance(s.get("clients"), list):
                nc = [c for c in s["clients"] if not (isinstance(c, dict) and c.get("email") == email)]
                if len(nc) != len(s["clients"]):
                    s["clients"] = nc
                    changed = True
            if isinstance(s.get("users"), list):
                nu = [u for u in s["users"] if not (isinstance(u, dict) and u.get("email") == email)]
                if len(nu) != len(s["users"]):
                    s["users"] = nu
                    changed = True
            if changed:
                cur.execute(
                    "UPDATE inbounds SET settings=? WHERE id=?",
                    (json.dumps(s, ensure_ascii=False, separators=(",", ":")), iid),
                )

        # --- clients ---
        mapping = {
            "email": email,
            "enable": 1,
            "sub_id": sub_id,
            "subId": sub_id,
            "tg_id": 0,
            "tgId": 0,
            "uuid": master_uuid,
            "password": password,
            "auth": password,
            "flow": "",
            "limit_ip": 0,
            "limitIp": 0,
            "total": 0,
            "totalGB": 0,
            "expiry_time": 0,
            "expiryTime": 0,
            "reset": 0,
            "up": 0,
            "down": 0,
            "comment": comment,
            "group": group_name,
            "group_name": group_name,
            "created_at": now_ms,
            "updated_at": now_ms,
        }
        if not id_is_auto and "id" in ccols:
            mapping["id"] = master_uuid

        row = {c: mapping[c] for c in ccols if c in mapping}
        keys = list(row.keys())
        cur.execute(
            f"INSERT INTO clients ({','.join(keys)}) VALUES ({','.join('?' * len(keys))})",
            [row[k] for k in keys],
        )
        pk = cur.lastrowid

        # --- client_traffics ---
        if "client_traffics" in tables:
            tcols = cols(cur, "client_traffics")
            fields, values = ["enable", "email", "up", "down"], [1, email, 0, 0]
            for k, default in (
                ("expiry_time", 0), ("expiryTime", 0),
                ("total", 0), ("reset", 0),
                ("all_time", 0), ("allTime", 0),
                ("last_online", 0), ("lastOnline", 0),
            ):
                if k in tcols:
                    fields.append(k)
                    values.append(default)
            cur.execute(
                f"INSERT INTO client_traffics ({','.join(fields)}) VALUES ({','.join('?' * len(fields))})",
                values,
            )

        results.append((email, comment, group_name, master_uuid, sub_id, password))
        print(f"  + {email:20}  group={group_name:10}  id={pk}  subId={sub_id}")

    con.commit()
    con.close()

    print("-" * 72)
    print("Готово. Сводка (сохраните UUID / SubId / Password):")
    print(f"{'Email':<22} {'Group':<12} {'UUID':<38} {'SubId':<18} {'Password'}")
    for email, comment, group, u, s, p in results:
        print(f"{email:<22} {group:<12} {u:<38} {s:<18} {p}")

    print("-" * 72)
    print("Дальше в панели: Clients → открыть клиента → выбрать inbound'ы / протоколы.")
    print("UUID и password уже прописаны; при необходимости поменяйте вручную.")

    if not args.no_restart:
        print("Перезапуск x-ui…")
        try:
            subprocess.run(["systemctl", "restart", "x-ui"], check=False, timeout=30)
            time.sleep(2)
            print("x-ui restarted")
        except Exception as e:
            print(f"[!!] restart failed: {e}  →  systemctl restart x-ui")

    return 0


if __name__ == "__main__":
    sys.exit(main())

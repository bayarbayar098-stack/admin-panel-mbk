"""Supabase холболтыг шалгана. Түлхүүрийг ХЭЗЭЭ Ч хэвлэхгүй.

Ажиллуулах:  python check_supabase.py
"""

from __future__ import annotations

import sys

from backend.config import ENV_FILE, ConfigError, load_config
from backend.supabase_client import SupabaseClient


def main() -> int:
    # Windows консолд монгол үсэг зөв харагдуулах
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("1) .env тохиргоо уншиж байна...")
    try:
        config = load_config()
    except ConfigError as err:
        print(f"   АЛДАА: {err}")
        print(f"   Файл: {ENV_FILE}")
        return 1
    print(f"   OK — Project URL: {config.url}")
    print(f"   OK — Түлхүүрийн төрөл: {config.key_type} (утгыг харуулахгүй)")

    client = SupabaseClient(config)

    print("2) Supabase Auth руу холбогдож байна...")
    try:
        res = client.auth("GET", "settings")
    except ConnectionError as err:
        print(f"   АЛДАА: {err}")
        return 1
    if res.status in (401, 403):
        print("   АЛДАА: Түлхүүр буруу эсвэл энэ төслийнх биш байна (401/403).")
        return 1
    if not res.ok:
        print(f"   АЛДАА: Хүлээгээгүй хариу, статус {res.status}.")
        return 1
    print("   OK — URL болон түлхүүр зөв, холболт амжилттай.")

    print("3) Нэвтрээгүй хэрэглэгч bookings хүснэгтийг уншиж чадахгүй эсэхийг шалгаж байна...")
    res = client.rest("GET", "bookings?select=id&limit=1")
    if res.status == 404:
        print("   АНХААР: bookings хүснэгт олдсонгүй — supabase.sql-ийг ажиллуулсан эсэхээ шалгана уу.")
    elif res.status in (401, 403) or (res.ok and res.data == []):
        print("   OK — Нэвтрээгүй хандалт хаалттай (RLS/эрх зөв ажиллаж байна).")
    elif res.ok and res.data:
        print("   АНХААР: Нэвтрээгүй хэрэглэгч өгөгдөл уншиж чадаж байна! RLS-ээ шалгана уу.")
        return 1
    else:
        print(f"   АНХААР: Хүлээгээгүй хариу, статус {res.status}.")

    print("Шалгалт дууслаа.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

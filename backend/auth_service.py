"""Supabase Auth болон админы өгөгдөлтэй ажиллах функцууд.

- Нууц үгийг энд хадгалахгүй, шалгахгүй — Supabase Auth шалгана.
- Токен, нууц үгийг алдааны мессеж, log-д хэзээ ч оруулахгүй.
- Өгөгдлийг админы access_token-оор уншдаг тул RLS бодлого хамгаална.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .supabase_client import SupabaseClient

log = logging.getLogger("mbk.admin")


class AuthError(Exception):
    """Хэрэглэгчид харуулах аюулгүй мессежтэй алдаа."""

    def __init__(self, user_message: str, status: int = 401):
        super().__init__(user_message)
        self.user_message = user_message
        self.status = status


class SessionExpired(Exception):
    pass


class DataError(Exception):
    pass


@dataclass
class TokenSet:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: float
    user_id: str
    email: str


def _tokens(data: Any) -> TokenSet:
    try:
        user = data["user"]
        return TokenSet(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_at=time.time() + int(data.get("expires_in", 3600)),
            user_id=user["id"],
            email=user.get("email") or "",
        )
    except (KeyError, TypeError, ValueError):
        raise AuthError("Supabase-ээс ирсэн хариу танигдсангүй.", 502) from None


def _error_code(data: Any) -> str:
    if isinstance(data, dict):
        return str(data.get("error_code") or data.get("error") or "")
    return ""


def sign_in(client: SupabaseClient, email: str, password: str) -> TokenSet:
    try:
        res = client.auth(
            "POST",
            "token?grant_type=password",
            body={"email": email, "password": password},
        )
    except ConnectionError:
        raise AuthError("Supabase-тэй холбогдож чадсангүй. Дараа дахин оролдоно уу.", 503) from None

    if res.ok:
        return _tokens(res.data)
    code = _error_code(res.data)
    # Зөвхөн статус ба алдааны код (жишээ: invalid_credentials) — имэйл, нууц үг биш
    log.warning("Нэвтрэлт амжилтгүй: статус %s, код %s", res.status, code or "-")
    if res.status == 429:
        raise AuthError("Хэт олон оролдлого хийлээ. Хэсэг хүлээгээд дахин оролдоно уу.", 429)
    if code == "email_not_confirmed":
        raise AuthError("Имэйл хаяг баталгаажаагүй байна.", 401)
    if res.status in (400, 401, 422):
        raise AuthError("Имэйл эсвэл нууц үг буруу байна.", 401)
    raise AuthError(f"Нэвтрэх үед алдаа гарлаа (статус {res.status}).", 502)


def refresh(client: SupabaseClient, refresh_token: str) -> TokenSet:
    try:
        res = client.auth(
            "POST", "token?grant_type=refresh_token", body={"refresh_token": refresh_token}
        )
    except ConnectionError:
        raise SessionExpired() from None
    if not res.ok:
        raise SessionExpired()
    try:
        return _tokens(res.data)
    except AuthError:
        raise SessionExpired() from None


def sign_out(client: SupabaseClient, access_token: str) -> None:
    try:
        client.auth("POST", "logout", access_token=access_token)
    except ConnectionError:
        pass  # Локал сесс устсан тул үргэлжлүүлнэ


def is_admin(client: SupabaseClient, access_token: str, user_id: str) -> bool:
    try:
        res = client.rest(
            "GET",
            f"admins?select=user_id&user_id=eq.{quote(user_id, safe='')}",
            access_token=access_token,
        )
    except ConnectionError:
        raise AuthError("Supabase-тэй холбогдож чадсангүй. Дараа дахин оролдоно уу.", 503) from None
    return res.ok and isinstance(res.data, list) and len(res.data) == 1


def select(client: SupabaseClient, access_token: str, query: str, what: str) -> list[dict]:
    """PostgREST-ээс мөрүүд уншина. `what` — алдааны мессежид гарах нэр."""
    try:
        res = client.rest("GET", query, access_token=access_token)
    except ConnectionError:
        raise DataError("Supabase-тэй холбогдож чадсангүй.") from None
    if res.status == 401:
        raise SessionExpired()
    if not res.ok or not isinstance(res.data, list):
        raise DataError(f"{what} уншиж чадсангүй (статус {res.status}).")
    return res.data


# ---------------------------------------------------------------------
# Захиалга (reservations) ба ажилтан (staff): унших / нэмэх / засах / устгах
# ---------------------------------------------------------------------
class NotFound(Exception):
    pass


# Хүснэгт бүрт хайлт хийх баганууд (нэр эсвэл утас)
CRUD_TABLES = {
    "reservations": {
        "columns": "id,guest_name,phone,reservation_date,start_time,guest_count,seating,"
                   "seat_label,status,deposit_amount,notes,created_at",
        "search": ("guest_name", "phone"),
        "order": "reservation_date.desc,start_time.desc",
    },
    "staff": {
        "columns": "id,full_name,position,phone,shift,status,hired_at,created_at",
        "search": ("full_name", "phone"),
        "order": "full_name.asc",
    },
}


def clean_search(text: str) -> str:
    """Хайлтын текстээс PostgREST-ийн тусгай тэмдэгтийг (, ( ) * " гэх мэт) хасна."""
    return re.sub(r"[^\w\s+\-@.]", "", text or "", flags=re.UNICODE).strip()[:60]


def _crud(client: SupabaseClient, token: str, method: str, query: str,
          body: Any = None, prefer: str | None = None) -> list[dict]:
    try:
        res = client.rest(method, query, access_token=token, body=body,
                          headers={"Prefer": prefer} if prefer else None)
    except ConnectionError:
        raise DataError("Supabase-тэй холбогдож чадсангүй.") from None
    if res.status == 401:
        raise SessionExpired()
    if not res.ok:
        code = res.data.get("code") if isinstance(res.data, dict) else None
        if code in ("23514", "22P02", "23502", "22007", "22008", "22003"):
            raise DataError("Оруулсан утга Supabase-ийн шаардлагад тохирохгүй байна.")
        if code in ("42P01", "PGRST205", "42703", "PGRST204") or res.status == 404:
            raise DataError("Хүснэгт эсвэл багана олдсонгүй. "
                            "supabase_migration_003.sql-ийг SQL Editor дээр ажиллуулсан эсэхээ шалгана уу.")
        raise DataError(f"Supabase алдаа (статус {res.status}).")
    return res.data if isinstance(res.data, list) else []


def list_records(client: SupabaseClient, token: str, table: str, search: str = "",
                 filters: dict[str, str] | None = None) -> list[dict]:
    spec = CRUD_TABLES[table]
    parts = [f"select={spec['columns']}", f"order={spec['order']}", "limit=500"]
    for col, value in (filters or {}).items():
        if value:
            parts.append(f"{col}=eq.{quote(value, safe='')}")
    term = clean_search(search)
    if term:
        ors = ",".join(f'{c}.ilike."*{term}*"' for c in spec["search"])
        parts.append("or=" + quote(f"({ors})", safe=""))
    return _crud(client, token, "GET", f"{table}?" + "&".join(parts))


def get_record(client: SupabaseClient, token: str, table: str, rid: str) -> dict:
    if not _UUID.match(rid or ""):
        raise NotFound()
    rows = _crud(client, token, "GET",
                 f"{table}?select={CRUD_TABLES[table]['columns']}&id=eq.{rid}")
    if len(rows) != 1:
        raise NotFound()
    return rows[0]


def create_record(client: SupabaseClient, token: str, table: str, data: dict) -> None:
    rows = _crud(client, token, "POST", f"{table}?select=id", body=data,
                 prefer="return=representation")
    if len(rows) != 1:
        raise DataError("Хадгалж чадсангүй.")


def update_record(client: SupabaseClient, token: str, table: str, rid: str, data: dict) -> None:
    if not _UUID.match(rid or ""):
        raise NotFound()
    rows = _crud(client, token, "PATCH", f"{table}?id=eq.{rid}&select=id", body=data,
                 prefer="return=representation")
    if len(rows) != 1:
        raise NotFound()


def delete_record(client: SupabaseClient, token: str, table: str, rid: str) -> None:
    if not _UUID.match(rid or ""):
        raise NotFound()
    rows = _crud(client, token, "DELETE", f"{table}?id=eq.{rid}&select=id",
                 prefer="return=representation")
    if len(rows) != 1:
        raise NotFound()


class StatusNotAllowed(Exception):
    """Supabase дээр шинэ төлөв (migration 002) хараахан нэмэгдээгүй."""


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def set_draft_status(client: SupabaseClient, access_token: str, draft_id: str,
                     from_status: str, to_status: str) -> bool:
    """Төлөвийг солино. Зөвхөн одоогийн төлөв `from_status` байвал өөрчилнө.
    True — солигдсон, False — аль хэдийн өөрчлөгдсөн эсвэл олдсонгүй."""
    if not _UUID.match(draft_id or ""):
        return False
    try:
        res = client.rest(
            "PATCH",
            f"content_drafts?id=eq.{draft_id}&status=eq.{quote(from_status)}&select=id",
            access_token=access_token,
            body={"status": to_status},
            headers={"Prefer": "return=representation"},
        )
    except ConnectionError:
        raise DataError("Supabase-тэй холбогдож чадсангүй.") from None
    if res.status == 401:
        raise SessionExpired()
    if isinstance(res.data, dict) and res.data.get("code") == "23514":
        raise StatusNotAllowed()
    if not res.ok:
        raise DataError(f"Төлөв сольж чадсангүй (статус {res.status}).")
    return isinstance(res.data, list) and len(res.data) == 1


def list_content_drafts(client: SupabaseClient, access_token: str) -> list[dict]:
    return select(
        client, access_token,
        "content_drafts?select=id,title,body,channel,status,publish_at,created_at"
        "&order=created_at.desc&limit=200",
        "Постуудыг",
    )


def list_bookings(client: SupabaseClient, access_token: str) -> list[dict]:
    return select(
        client, access_token,
        "bookings?select=id,customer_name,phone,email,booking_date,booking_time,guest_count,"
        "booking_type,vip_room,status,notes"
        "&order=booking_date.desc,booking_time.desc.nullslast&limit=200",
        "Захиалгуудыг",
    )


def list_events(client: SupabaseClient, access_token: str) -> list[dict]:
    return select(
        client, access_token,
        "events?select=id,name,event_date,start_time,guest_count,status,notes"
        "&order=event_date.desc,start_time.desc.nullslast&limit=200",
        "Арга хэмжээг",
    )


def list_staff(client: SupabaseClient, access_token: str) -> list[dict]:
    return select(
        client, access_token,
        "staff?select=id,full_name,position,phone,email,is_active"
        "&order=is_active.desc,full_name.asc&limit=500",
        "Ажилтнуудыг",
    )


def todays_bookings(client: SupabaseClient, access_token: str, today: str) -> list[dict]:
    """Өнөөдрийн захиалгууд (цуцлагдсан, ирээгүйг оруулахгүй)."""
    return select(
        client, access_token,
        "bookings?select=id,customer_name,booking_time,guest_count,booking_type,vip_room,status"
        f"&booking_date=eq.{quote(today)}&status=not.in.(cancelled,no_show)"
        "&order=booking_time.asc.nullslast&limit=500",
        "Өнөөдрийн захиалгыг",
    )


def todays_reservations(client: SupabaseClient, access_token: str, today: str) -> list[dict]:
    """Өнөөдрийн ширээ захиалга (цуцалсныг оруулахгүй)."""
    return select(
        client, access_token,
        "reservations?select=id,guest_name,start_time,guest_count,seating,seat_label,status"
        f"&reservation_date=eq.{quote(today)}&status=neq.cancelled"
        "&order=start_time.asc&limit=500",
        "Өнөөдрийн захиалгыг",
    )


def pending_reservations(client: SupabaseClient, access_token: str) -> list[dict]:
    return select(
        client, access_token,
        "reservations?select=id&status=eq.pending&limit=1000",
        "Хүлээгдэж буй захиалгыг",
    )


def pending_bookings(client: SupabaseClient, access_token: str) -> list[dict]:
    return select(
        client, access_token,
        "bookings?select=id&status=eq.pending&limit=1000",
        "Хүлээгдэж буй захиалгыг",
    )


def upcoming_events(client: SupabaseClient, access_token: str, today: str) -> list[dict]:
    return select(
        client, access_token,
        "events?select=id,name,event_date,start_time,guest_count,status"
        f"&event_date=gte.{quote(today)}&status=not.in.(cancelled,completed)"
        "&order=event_date.asc,start_time.asc.nullslast&limit=5",
        "Ойрын арга хэмжээг",
    )

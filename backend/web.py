"""MBK Lounge админ самбарын вэб сервер (Python стандарт сан).

Аюулгүй байдлын зарчим:
- Токеныг вэб хөтөч рүү илгээхгүй. Хөтөчид зөвхөн санамсаргүй сессийн ID
  (HttpOnly cookie) очно, токен сервер дээр санах ойд хадгалагдана.
- /admin доорх бүх хуудас нэвтрэлт шаардана.
- Log-д зөвхөн арга, зам (query-гүй), статус бичигдэнэ. Хүсэлтийн бие
  (нууц үг), cookie, токен хэзээ ч бичигдэхгүй.
"""

from __future__ import annotations

import html
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import auth_service as auth
from .supabase_client import SupabaseClient

log = logging.getLogger("mbk.admin")

COOKIE_NAME = "mbk_session"
STATIC_DIR = Path(__file__).resolve().parent / "static"
UB_TZ = timezone(timedelta(hours=8), "UB")
MAX_BODY = 10_000

# Зөвхөн жагсаасан статик файлуудыг үйлчилнэ (замаар хайхгүй)
STATIC_FILES = {
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
    "/static/brand/mbk-lounge-horizontal-white.png": (
        "brand/mbk-lounge-horizontal-white.png", "image/png"),
}


# ---------------------------------------------------------------- Сесс
@dataclass
class Session:
    tokens: auth.TokenSet = field(repr=False)
    last_seen: float = field(default_factory=time.time)


class SessionStore:
    IDLE_TIMEOUT = 8 * 3600

    def __init__(self) -> None:
        self._data: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, tokens: auth.TokenSet) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._data[sid] = Session(tokens)
        return sid

    def get(self, sid: str) -> Session | None:
        with self._lock:
            s = self._data.get(sid)
            if s is None:
                return None
            if time.time() - s.last_seen > self.IDLE_TIMEOUT:
                del self._data[sid]
                return None
            s.last_seen = time.time()
            return s

    def delete(self, sid: str) -> Session | None:
        with self._lock:
            return self._data.pop(sid, None)


class LoginLimiter:
    """IP тус бүрээр 5 минутад 5-аас олон буруу оролдлогыг хаана."""

    def __init__(self, max_failures: int = 5, window: float = 300) -> None:
        self.max, self.window = max_failures, window
        self._fails: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, ip: str) -> deque:
        q = self._fails[ip]
        while q and time.time() - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, ip: str) -> bool:
        with self._lock:
            return len(self._prune(ip)) >= self.max

    def fail(self, ip: str) -> None:
        with self._lock:
            self._prune(ip).append(time.time())

    def reset(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)


@dataclass
class App:
    client: SupabaseClient
    sessions: SessionStore = field(default_factory=SessionStore)
    limiter: LoginLimiter = field(default_factory=LoginLimiter)
    cookie_secure: bool = False


# ---------------------------------------------------------------- HTML
def e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


# Брэндбүүк: батлагдсан цагаан хэвтээ лого (эх файл, өөрчлөлтгүй).
# Эх файлын харьцаа 1600×644. Зурган дотор логоны эргэн тойронд хоосон зай
# (≈ X) аль хэдийн багтсан. Lockup нь зургийн өргөний ≈77.5%-ийг эзэлнэ.
# 323px өргөнтэй харуулахад lockup ≈ 250px → брэндбүүкийн дижитал доод хэмжээ.
LOGO_SRC = "/static/brand/mbk-lounge-horizontal-white.png"
LOGO_ALT = "MBK Lounge — MUSIC • BAR • KITCHEN"
FONT_CSS = "https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700&display=swap"


def logo(css_class: str, width: int = 323) -> str:
    height = round(width * 644 / 1600)
    return (
        f'<img class="{e(css_class)}" src="{LOGO_SRC}" width="{width}" height="{height}" '
        f'alt="{e(LOGO_ALT)}">'
    )


def page(title: str, body: str, *, body_class: str = "") -> str:
    return f"""<!doctype html>
<html lang="mn">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{e(title)} · MBK Lounge</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="{FONT_CSS}">
<link rel="stylesheet" href="/static/style.css">
</head>
<body class="{e(body_class)}">
{body}
</body>
</html>"""


def login_page(error: str = "", email: str = "") -> str:
    err = f'<p class="alert" role="alert">{e(error)}</p>' if error else ""
    return page(
        "Нэвтрэх",
        f"""
<main class="login">
  {logo("login-logo", 400)}
  <form class="login-form" method="post" action="/login" autocomplete="on">
    <h1>Админ самбарт нэвтрэх</h1>
    {err}
    <label for="email">Имэйл</label>
    <input id="email" type="email" name="email" value="{e(email)}" required maxlength="254"
           autocomplete="username" autofocus>
    <label for="password">Нууц үг</label>
    <input id="password" type="password" name="password" required maxlength="200"
           autocomplete="current-password">
    <button class="btn-primary" type="submit">Нэвтрэх</button>
  </form>
</main>""",
        body_class="login-body",
    )


CHANNEL_LABELS = {
    "facebook": "Facebook",
    "instagram": "Instagram",
    "tiktok": "TikTok",
    "website": "Вэбсайт",
    "email": "Имэйл",
}


def fmt_dt(value: str | None) -> str:
    if not value:
        return '<span class="muted">—</span>'
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UB_TZ)
        return e(dt.strftime("%Y.%m.%d %H:%M"))
    except ValueError:
        return e(value)


def preview(text: str | None, limit: int = 90) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# --- Захиалга, арга хэмжээ, ажилтны шошго ---
BOOKING_STATUS = {
    "pending": ("Хүлээгдэж буй", "magenta"),
    "confirmed": ("Баталгаажсан", "blue"),
    "seated": ("Ирсэн", "cyan"),
    "completed": ("Дууссан", "white"),
    "cancelled": ("Цуцлагдсан", "dashed"),
    "no_show": ("Ирээгүй", "dashed"),
}
BOOKING_TYPES = {
    "table": "Ширээ",
    "vip_room": "VIP өрөө",
    "birthday": "Төрсөн өдөр",
    "corporate": "Байгууллага",
    "other": "Бусад",
}
EVENT_STATUS = {
    "planned": ("Төлөвлөсөн", "magenta"),
    "confirmed": ("Баталгаажсан", "blue"),
    "in_progress": ("Явагдаж буй", "cyan"),
    "completed": ("Дууссан", "white"),
    "cancelled": ("Цуцлагдсан", "dashed"),
}
# Контентын төлөв (өмнөх CSS ангиудтай нийцүүлэв)
CONTENT_STATUS = {
    "draft": ("Ноорог", "white"),
    "review": ("Хүлээгдэж буй", "magenta"),
    "approved": ("Батлагдсан", "cyan"),
    "rejected": ("Татгалзсан", "dashed"),
    "scheduled": ("Төлөвлөсөн", "blue"),
    "published": ("Нийтэлсэн", "cyan-fill"),
    "archived": ("Архивласан", "dashed"),
}

# "Хүлээгдэж буй" (review) постын үйлдэл → шинэ төлөв
REVIEW_ACTIONS = {"approve": "approved", "reject": "rejected"}

# Үйлдлийн дараах мэдэгдэл. Зөвхөн тогтмол кодоор (хэрэглэгчийн текст буцааж харуулахгүй)
CONTENT_FLASH = {
    "approved": ("ok", "Пост батлагдлаа. Төлөв нь «Батлагдсан» боллоо."),
    "rejected": ("ok", "Пост татгалзагдлаа. Төлөв нь «Татгалзсан» боллоо."),
    "stale": ("warn", "Энэ постын төлөв аль хэдийн өөрчлөгдсөн байна. Жагсаалтыг шинэчиллээ."),
    "migrate": ("warn", "Supabase дээр «Батлагдсан», «Татгалзсан» төлөв хараахан нэмэгдээгүй байна. "
                        "supabase_migration_002.sql файлыг SQL Editor дээр ажиллуулна уу."),
    "error": ("warn", "Төлөв солиход алдаа гарлаа. Дахин оролдоно уу."),
}

DASH = '<span class="muted">—</span>'


def badge(value: str | None, mapping: dict[str, tuple[str, str]]) -> str:
    label, tone = mapping.get(value or "", (value or "—", "white"))
    return f'<span class="badge badge-{tone}">{e(label)}</span>'


def fmt_date(value: str | None) -> str:
    if not value:
        return DASH
    try:
        return e(datetime.fromisoformat(value).strftime("%Y.%m.%d"))
    except ValueError:
        return e(value)


def fmt_time(value: str | None) -> str:
    return e(value[:5]) if value else DASH


def today_ub() -> str:
    return datetime.now(UB_TZ).date().isoformat()


def alert(message: str) -> str:
    return f'<p class="alert" role="alert">{e(message)}</p>'


def table(columns: list[str], rows: list[list[str]], empty: str) -> str:
    """columns: гарчгууд; rows: аль хэдийн escape хийсэн HTML нүднүүд."""
    if not rows:
        return f'<p class="empty">{e(empty)}</p>'
    head = "".join(f"<th>{e(c)}</th>" for c in columns)
    body = "".join(
        "<tr>" + "".join(f'<td data-label="{e(c)}">{cell}</td>' for c, cell in zip(columns, r)) + "</tr>"
        for r in rows
    )
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


# --- Цэс ---
# (түлхүүр, зам, нэр, удахгүй эсэх)
NAV = [
    ("dashboard", "/admin", "Хянах самбар", False),
    ("content", "/admin/content", "Контент", False),
    ("facebook", "/admin/facebook", "Facebook", True),
    ("chat", "/admin/chat", "Чат", True),
    ("reservations", "/admin/reservations", "Захиалга", False),
    ("events", "/admin/events", "Арга хэмжээ", False),
    ("staff", "/admin/staff", "Ажилтан", False),
]


def shell(active: str, email: str, title: str, description: str, content: str) -> str:
    links = []
    for key, href, label, soon in NAV:
        current = ' aria-current="page"' if key == active else ""
        tag = '<span class="soon">Удахгүй</span>' if soon else ""
        links.append(f'<a href="{href}"{current}><span>{e(label)}</span>{tag}</a>')
    return page(
        title,
        f"""
<div class="shell">
  <aside class="sidebar">
    <a class="sidebar-logo" href="/admin">{logo("logo")}</a>
    <nav class="nav" aria-label="Үндсэн цэс">
      {"".join(links)}
    </nav>
    <div class="account">
      <span class="account-label">Нэвтэрсэн</span>
      <span class="account-email">{e(email)}</span>
      <form method="post" action="/logout"><button class="btn-ghost" type="submit">Гарах</button></form>
    </div>
  </aside>
  <main class="content">
    <header class="page-head">
      <h1>{e(title)}</h1>
      <p class="note">{e(description)}</p>
    </header>
    {content}
  </main>
</div>""",
    )


# --- Хуудсууд ---
def review_actions(d: dict) -> str:
    if d.get("status") != "review":
        return DASH
    did = e(d.get("id"))
    return f"""<div class="actions">
  <form method="post" action="/admin/content/status">
    <input type="hidden" name="id" value="{did}"><input type="hidden" name="action" value="approve">
    <button class="btn-sm btn-approve" type="submit">Батлах</button>
  </form>
  <form method="post" action="/admin/content/status">
    <input type="hidden" name="id" value="{did}"><input type="hidden" name="action" value="reject">
    <button class="btn-sm btn-reject" type="submit">Татгалзах</button>
  </form>
</div>"""


def content_body(drafts: list[dict] | None, error: str = "", flash: str = "") -> str:
    notice = ""
    if flash in CONTENT_FLASH:
        kind, msg = CONTENT_FLASH[flash]
        notice = f'<p class="notice notice-{kind}" role="status">{e(msg)}</p>'
    if error:
        return notice + alert(error)
    drafts = drafts or []
    counts = {k: 0 for k in CONTENT_STATUS}
    for d in drafts:
        if d.get("status") in counts:
            counts[d["status"]] += 1
    stats = "".join(
        f'<div class="stat"><span class="stat-label">{e(label)}</span><span class="num">{n}</span></div>'
        for label, n in (
            ("Нийт пост", len(drafts)),
            ("Хүлээгдэж буй", counts["review"]),
            ("Батлагдсан", counts["approved"]),
            ("Татгалзсан", counts["rejected"]),
            ("Ноорог", counts["draft"]),
            ("Нийтэлсэн", counts["published"]),
        )
    )
    rows = [
        [
            f'<strong>{e(d.get("title"))}</strong><span class="sub">{e(preview(d.get("body")))}</span>',
            e(CHANNEL_LABELS.get(d.get("channel"), d.get("channel"))),
            badge(d.get("status"), CONTENT_STATUS),
            fmt_dt(d.get("publish_at")),
            fmt_dt(d.get("created_at")),
            review_actions(d),
        ]
        for d in drafts
    ]
    return (
        notice
        + f'<section class="stats" aria-label="Төлөвөөр">{stats}</section>'
        + table(["Гарчиг", "Суваг", "Төлөв", "Нийтлэх огноо", "Үүсгэсэн", "Үйлдэл"], rows,
                "Одоогоор пост байхгүй байна.")
    )


def contact_cell(row: dict) -> str:
    parts = [e(v) for v in (row.get("phone"), row.get("email")) if v]
    return "<br>".join(parts) if parts else DASH


def bookings_body(bookings: list[dict] | None, error: str = "") -> str:
    if error:
        return alert(error)
    def type_cell(b: dict) -> str:
        label = e(BOOKING_TYPES.get(b.get("booking_type"), b.get("booking_type")))
        room = b.get("vip_room")
        return label + (f'<span class="sub">Өрөө: {e(room)}</span>' if room else "")

    rows = [
        [
            f'{fmt_date(b.get("booking_date"))}<span class="sub">{fmt_time(b.get("booking_time"))}</span>',
            f'<strong>{e(b.get("customer_name"))}</strong>',
            contact_cell(b),
            e(b.get("guest_count")),
            type_cell(b),
            badge(b.get("status"), BOOKING_STATUS),
            e(b.get("notes")) if b.get("notes") else DASH,
        ]
        for b in (bookings or [])
    ]
    return table(
        ["Огноо, цаг", "Захиалагч", "Холбоо барих", "Хүн", "Төрөл, VIP өрөө", "Төлөв", "Тэмдэглэл"],
        rows, "Одоогоор захиалга байхгүй байна.",
    )


def events_rows(events: list[dict], with_notes: bool) -> list[list[str]]:
    rows = []
    for ev in events:
        row = [
            f'<strong>{e(ev.get("name"))}</strong>',
            fmt_date(ev.get("event_date")),
            fmt_time(ev.get("start_time")),
            e(ev.get("guest_count")) if ev.get("guest_count") is not None else DASH,
            badge(ev.get("status"), EVENT_STATUS),
        ]
        if with_notes:
            row.append(e(ev.get("notes")) if ev.get("notes") else DASH)
        rows.append(row)
    return rows


def events_body(events: list[dict] | None, error: str = "") -> str:
    if error:
        return alert(error)
    return table(
        ["Нэр", "Огноо", "Эхлэх цаг", "Хүний тоо", "Төлөв", "Тэмдэглэл"],
        events_rows(events or [], True), "Одоогоор арга хэмжээ байхгүй байна.",
    )


def staff_body(staff: list[dict] | None, error: str = "") -> str:
    if error:
        return alert(error)
    rows = [
        [
            f'<strong>{e(s.get("full_name"))}</strong>',
            e(s.get("position")),
            e(s.get("phone")) if s.get("phone") else DASH,
            e(s.get("email")) if s.get("email") else DASH,
            (badge("active", {"active": ("Ажиллаж байгаа", "cyan")}) if s.get("is_active")
             else badge("inactive", {"inactive": ("Ажиллахгүй", "dashed")})),
        ]
        for s in (staff or [])
    ]
    return table(["Нэр", "Албан тушаал", "Утас", "Имэйл", "Төлөв"], rows,
                 "Одоогоор ажилтны мэдээлэл байхгүй байна.")


def coming_soon_body(name: str) -> str:
    return f"""<section class="soon-panel">
  <span class="soon">Удахгүй</span>
  <h2>{e(name)} хэсэг хөгжүүлэлтийн шатанд байна</h2>
  <p>Энэ хэсэг бэлэн болмогц цэснээс шууд ашиглах боломжтой болно.</p>
  <a class="btn-link" href="/admin">Хянах самбар руу буцах</a>
</section>"""


def dashboard_body(today: str, todays: list[dict] | str, pending: list[dict] | str,
                   upcoming: list[dict] | str) -> str:
    """Утга нь list бол өгөгдөл, str бол алдааны мессеж (тоо зохиохгүй)."""

    def stat(label: str, data, hint: str, href: str, button: str) -> str:
        if isinstance(data, str):
            value, extra = DASH, f'<span class="stat-error">Ачаалж чадсангүй</span>'
        else:
            n = len(data)
            value, extra = (f"{n}+" if n >= 1000 else str(n)), ""
        return f"""<div class="stat stat-lg">
  <span class="stat-label">{e(label)}</span>
  <span class="num">{value}</span>
  <span class="stat-hint">{e(hint)}</span>{extra}
  <a class="btn-link" href="{href}">{e(button)}</a>
</div>"""

    stats = (
        stat("Өнөөдрийн захиалга", todays,
             f"{fmt_date(today)} · цуцалсныг тооцохгүй",
             f"/admin/reservations?date={today}", "Өнөөдрийнхийг харах")
        + stat("Хүлээгдэж буй захиалга", pending,
               "Баталгаажуулаагүй бүх захиалга",
               "/admin/reservations?status=pending", "Хүлээгдэж буйг харах")
    )

    if isinstance(todays, str):
        today_html = alert(todays)
    else:
        today_html = table(
            ["Цаг", "Зочин", "Хүн", "Ширээ / VIP", "Төлөв"],
            [[fmt_time(r.get("start_time")), f'<strong>{e(r.get("guest_name"))}</strong>',
              e(r.get("guest_count")),
              e(SEATING.get(r.get("seating"), r.get("seating")))
              + (f'<span class="sub">{e(r.get("seat_label"))}</span>' if r.get("seat_label") else ""),
              badge(r.get("status"), RES_STATUS)] for r in todays],
            "Өнөөдөр захиалга алга.",
        )

    if isinstance(upcoming, str):
        events_html = alert(upcoming)
    else:
        events_html = table(
            ["Нэр", "Огноо", "Эхлэх цаг", "Хүний тоо", "Төлөв"],
            events_rows(upcoming, False), "Ойрын хугацаанд арга хэмжээ төлөвлөгдөөгүй байна.",
        )

    return f"""<section class="stats stats-lg" aria-label="Гол үзүүлэлт">{stats}</section>
<section class="block">
  <div class="block-head"><h2>Өнөөдрийн захиалга</h2></div>
  {today_html}
</section>
<section class="block">
  <div class="block-head">
    <h2>Ойрын арга хэмжээ</h2>
    <a class="btn-link" href="/admin/events">Бүгдийг харах</a>
  </div>
  {events_html}
</section>"""


# =====================================================================
# Захиалга (reservations) ба Ажилтан (staff): жагсаалт, хайлт, нэмэх, засах, устгах
# =====================================================================
RES_STATUS = {
    "pending": ("Хүлээгдэж буй", "magenta"),
    "confirmed": ("Баталгаажсан", "blue"),
    "cancelled": ("Цуцалсан", "dashed"),
    "completed": ("Дууссан", "white"),
}
SEATING = {"table": "Ширээ", "vip_room": "VIP өрөө"}
STAFF_POSITIONS = {
    "manager": "Менежер",
    "bartender": "Бармен",
    "waiter": "Зөөгч",
    "cashier": "Кассчин",
    "security": "Хамгаалагч",
}
SHIFTS = {"day": "Өдөр", "night": "Орой"}
STAFF_STATUS = {
    "active": ("Идэвхтэй", "cyan"),
    "on_leave": ("Чөлөөтэй", "magenta"),
    "left": ("Гарсан", "dashed"),
}

PHONE_RE = re.compile(r"^[0-9+ \-]{6,20}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_RE = re.compile(r"^\d{2}:\d{2}(:\d{2})?$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def fmt_money(value) -> str:
    try:
        n = float(value or 0)
    except (TypeError, ValueError):
        return DASH
    return e(f"{n:,.0f}₮" if n == int(n) else f"{n:,.2f}₮")


def _valid_date(v: str) -> bool:
    if not DATE_RE.match(v):
        return False
    try:
        datetime.strptime(v, "%Y-%m-%d")
        return True
    except ValueError:
        return False


# Талбарын тодорхойлолт: (нэр, шошго, төрөл, сонголт, заавал эсэх, тайлбар)
RES_FIELDS = [
    ("guest_name", "Зочны нэр", "text", None, True, ""),
    ("phone", "Утас", "tel", None, True, "Жишээ: 99001001"),
    ("reservation_date", "Огноо", "date", None, True, ""),
    ("start_time", "Эхлэх цаг", "time", None, True, ""),
    ("guest_count", "Хүний тоо", "number", None, True, "1–200"),
    ("seating", "Ширээ / VIP өрөө", "select", SEATING, True, ""),
    ("seat_label", "Ширээ, өрөөний дугаар", "text", None, False, "Жишээ: Ширээ 4, VIP 2"),
    ("status", "Төлөв", "select", {k: v[0] for k, v in RES_STATUS.items()}, True, ""),
    ("deposit_amount", "Урьдчилгаа (₮)", "number", None, False, "Урьдчилгаагүй бол 0"),
    ("notes", "Тэмдэглэл", "textarea", None, False, ""),
]
STAFF_FIELDS = [
    ("full_name", "Овог нэр", "text", None, True, ""),
    ("position", "Албан тушаал", "select", STAFF_POSITIONS, True, ""),
    ("phone", "Утас", "tel", None, True, "Жишээ: 99002001"),
    ("shift", "Ээлж", "select", SHIFTS, True, ""),
    ("status", "Төлөв", "select", {k: v[0] for k, v in STAFF_STATUS.items()}, True, ""),
    ("hired_at", "Ажилд орсон огноо", "date", None, False, ""),
]


def validate_reservation(form: dict[str, str]) -> tuple[dict, dict[str, str]]:
    v = {k: (form.get(k) or "").strip() for k, *_ in RES_FIELDS}
    err: dict[str, str] = {}
    if not v["guest_name"]:
        err["guest_name"] = "Зочны нэрийг оруулна уу."
    elif len(v["guest_name"]) > 120:
        err["guest_name"] = "Нэр хэт урт байна (120 тэмдэгтээс ихгүй)."
    if not PHONE_RE.match(v["phone"]):
        err["phone"] = "Утасны дугаараа зөв оруулна уу (6–20 цифр)."
    if not _valid_date(v["reservation_date"]):
        err["reservation_date"] = "Огноогоо сонгоно уу."
    if not TIME_RE.match(v["start_time"]):
        err["start_time"] = "Эхлэх цагаа оруулна уу."
    try:
        count = int(v["guest_count"])
        if not 1 <= count <= 200:
            raise ValueError
    except ValueError:
        count = None
        err["guest_count"] = "Хүний тоо 1-ээс 200-ийн хооронд байна."
    if v["seating"] not in SEATING:
        err["seating"] = "Ширээ эсвэл VIP өрөөг сонгоно уу."
    if len(v["seat_label"]) > 40:
        err["seat_label"] = "40 тэмдэгтээс ихгүй."
    if v["status"] not in RES_STATUS:
        err["status"] = "Төлөвөө сонгоно уу."
    raw_dep = v["deposit_amount"].replace(",", "").replace(" ", "") or "0"
    try:
        deposit = float(raw_dep)
        if deposit < 0 or deposit > 9_999_999_999:
            raise ValueError
    except ValueError:
        deposit = None
        err["deposit_amount"] = "Урьдчилгааг тоогоор оруулна уу (0 ба түүнээс их)."
    if len(v["notes"]) > 1000:
        err["notes"] = "Тэмдэглэл 1000 тэмдэгтээс ихгүй."
    data = {
        "guest_name": v["guest_name"],
        "phone": v["phone"],
        "reservation_date": v["reservation_date"],
        "start_time": v["start_time"][:5],
        "guest_count": count,
        "seating": v["seating"],
        "seat_label": v["seat_label"] or None,
        "status": v["status"],
        "deposit_amount": deposit,
        "notes": v["notes"] or None,
    }
    return data, err


def validate_staff(form: dict[str, str]) -> tuple[dict, dict[str, str]]:
    v = {k: (form.get(k) or "").strip() for k, *_ in STAFF_FIELDS}
    err: dict[str, str] = {}
    if not v["full_name"]:
        err["full_name"] = "Овог нэрийг оруулна уу."
    elif len(v["full_name"]) > 120:
        err["full_name"] = "Нэр хэт урт байна (120 тэмдэгтээс ихгүй)."
    if v["position"] not in STAFF_POSITIONS:
        err["position"] = "Албан тушаалаа сонгоно уу."
    if not PHONE_RE.match(v["phone"]):
        err["phone"] = "Утасны дугаараа зөв оруулна уу (6–20 цифр)."
    if v["shift"] not in SHIFTS:
        err["shift"] = "Ээлжээ сонгоно уу."
    if v["status"] not in STAFF_STATUS:
        err["status"] = "Төлөвөө сонгоно уу."
    if v["hired_at"] and not _valid_date(v["hired_at"]):
        err["hired_at"] = "Огноо буруу байна."
    data = {
        "full_name": v["full_name"],
        "position": v["position"],
        "phone": v["phone"],
        "shift": v["shift"],
        "status": v["status"],
        "hired_at": v["hired_at"] or None,
    }
    return data, err


def render_form(fields, values: dict, errors: dict[str, str], action: str,
                submit: str, cancel: str) -> str:
    parts = []
    if errors:
        parts.append(alert("Маягтад алдаа байна. Улаан тэмдэглэсэн талбаруудыг засна уу."))
    parts.append(f'<form class="record-form" method="post" action="{e(action)}" novalidate>')
    parts.append('<div class="form-grid">')
    for name, label, ftype, options, required, hint in fields:
        val = values.get(name)
        val = "" if val is None else str(val)
        if ftype == "time":
            val = val[:5]
        if ftype == "number" and name == "deposit_amount" and val:
            try:
                f = float(val)
                val = str(int(f)) if f == int(f) else str(f)
            except ValueError:
                pass
        err = errors.get(name, "")
        req = " required" if required else ""
        star = ' <span class="req" aria-hidden="true">*</span>' if required else ""
        invalid = ' aria-invalid="true"' if err else ""
        wide = " field-wide" if ftype == "textarea" else ""
        parts.append(f'<div class="field{wide}{" has-error" if err else ""}">')
        parts.append(f'<label for="f-{name}">{e(label)}{star}</label>')
        if ftype == "select":
            opts = "".join(
                f'<option value="{e(k)}"{" selected" if k == val else ""}>{e(lbl)}</option>'
                for k, lbl in options.items()
            )
            parts.append(f'<select id="f-{name}" name="{name}"{req}{invalid}>{opts}</select>')
        elif ftype == "textarea":
            parts.append(f'<textarea id="f-{name}" name="{name}" rows="3" maxlength="1000"{invalid}>{e(val)}</textarea>')
        else:
            extra = ' min="1" max="200" step="1"' if name == "guest_count" else (
                ' min="0" step="1"' if name == "deposit_amount" else "")
            parts.append(f'<input id="f-{name}" type="{ftype}" name="{name}" value="{e(val)}"{req}{invalid}{extra}>')
        if err:
            parts.append(f'<span class="field-error">{e(err)}</span>')
        elif hint:
            parts.append(f'<span class="field-hint">{e(hint)}</span>')
        parts.append("</div>")
    parts.append("</div>")
    parts.append(f'<div class="form-actions"><button class="btn-primary btn-inline" type="submit">{e(submit)}</button>'
                 f'<a class="btn-link btn-plain" href="{e(cancel)}">Болих</a></div>')
    parts.append("</form>")
    return "".join(parts)


RECORD_FLASH = {
    "created": ("ok", "Амжилттай нэмлээ."),
    "updated": ("ok", "Өөрчлөлтийг хадгаллаа."),
    "deleted": ("ok", "Амжилттай устгалаа."),
    "notfound": ("warn", "Мэдээлэл олдсонгүй. Өөр хүн устгасан байж магадгүй."),
    "error": ("warn", "Алдаа гарлаа. Дахин оролдоно уу."),
}


def flash_html(code: str) -> str:
    if code not in RECORD_FLASH:
        return ""
    kind, msg = RECORD_FLASH[code]
    return f'<p class="notice notice-{kind}" role="status">{e(msg)}</p>'


def select_html(name: str, label: str, options: dict[str, str], current: str) -> str:
    opts = '<option value="">Бүгд</option>' + "".join(
        f'<option value="{e(k)}"{" selected" if k == current else ""}>{e(v)}</option>'
        for k, v in options.items()
    )
    return (f'<div class="field"><label for="flt-{name}">{e(label)}</label>'
            f'<select id="flt-{name}" name="{name}">{opts}</select></div>')


def row_actions(base: str, rid: str) -> str:
    rid = e(rid)
    return (f'<div class="actions"><a class="btn-sm btn-edit" href="{base}/{rid}/edit">Засах</a>'
            f'<a class="btn-sm btn-delete" href="{base}/{rid}/delete">Устгах</a></div>')


def reservations_list(rows: list[dict] | None, q: str, date: str, status: str,
                      flash: str = "", error: str = "") -> str:
    filters = f"""<form class="filters" method="get" action="/admin/reservations" role="search">
  <div class="field field-grow"><label for="flt-q">Хайх (нэр эсвэл утас)</label>
    <input id="flt-q" type="search" name="q" value="{e(q)}" maxlength="60" placeholder="Жишээ: Номин эсвэл 9900"></div>
  <div class="field"><label for="flt-date">Огноо</label>
    <input id="flt-date" type="date" name="date" value="{e(date)}"></div>
  {select_html("status", "Төлөв", {k: v[0] for k, v in RES_STATUS.items()}, status)}
  <div class="filter-actions"><button class="btn-sm btn-approve" type="submit">Шүүх</button>
    <a class="btn-sm btn-edit" href="/admin/reservations">Цэвэрлэх</a></div>
</form>"""
    head = f"""<div class="toolbar">{flash_html(flash)}
  <a class="btn-primary btn-inline" href="/admin/reservations/new">+ Шинэ захиалга</a></div>"""
    if error:
        return head + filters + alert(error)
    rows = rows or []
    body = table(
        ["Огноо, цаг", "Зочин, утас", "Хүн", "Ширээ / VIP", "Төлөв", "Урьдчилгаа", "Тэмдэглэл", "Үйлдэл"],
        [[
            f'{fmt_date(r.get("reservation_date"))}<span class="sub">{fmt_time(r.get("start_time"))}</span>',
            f'<strong>{e(r.get("guest_name"))}</strong><span class="sub">{e(r.get("phone"))}</span>',
            e(r.get("guest_count")),
            e(SEATING.get(r.get("seating"), r.get("seating")))
            + (f'<span class="sub">{e(r.get("seat_label"))}</span>' if r.get("seat_label") else ""),
            badge(r.get("status"), RES_STATUS),
            fmt_money(r.get("deposit_amount")),
            e(r.get("notes")) if r.get("notes") else DASH,
            row_actions("/admin/reservations", r.get("id", "")),
        ] for r in rows],
        "Захиалга олдсонгүй." if (q or date or status) else "Одоогоор захиалга байхгүй байна.",
    )
    count = f'<p class="result-count">{len(rows)} захиалга</p>' if rows else ""
    return head + filters + count + body


def staff_list(rows: list[dict] | None, q: str, status: str, flash: str = "", error: str = "") -> str:
    filters = f"""<form class="filters" method="get" action="/admin/staff" role="search">
  <div class="field field-grow"><label for="flt-q">Хайх (нэр эсвэл утас)</label>
    <input id="flt-q" type="search" name="q" value="{e(q)}" maxlength="60" placeholder="Жишээ: Саруул эсвэл 9900"></div>
  {select_html("status", "Төлөв", {k: v[0] for k, v in STAFF_STATUS.items()}, status)}
  <div class="filter-actions"><button class="btn-sm btn-approve" type="submit">Хайх</button>
    <a class="btn-sm btn-edit" href="/admin/staff">Цэвэрлэх</a></div>
</form>"""
    head = f"""<div class="toolbar">{flash_html(flash)}
  <a class="btn-primary btn-inline" href="/admin/staff/new">+ Шинэ ажилтан</a></div>"""
    if error:
        return head + filters + alert(error)
    rows = rows or []
    body = table(
        ["Овог нэр", "Албан тушаал", "Утас", "Ээлж", "Төлөв", "Ажилд орсон", "Үйлдэл"],
        [[
            f'<strong>{e(r.get("full_name"))}</strong>',
            e(STAFF_POSITIONS.get(r.get("position"), r.get("position"))),
            e(r.get("phone")) if r.get("phone") else DASH,
            e(SHIFTS.get(r.get("shift"), r.get("shift"))) if r.get("shift") else DASH,
            badge(r.get("status"), STAFF_STATUS),
            fmt_date(r.get("hired_at")),
            row_actions("/admin/staff", r.get("id", "")),
        ] for r in rows],
        "Ажилтан олдсонгүй." if (q or status) else "Одоогоор ажилтны мэдээлэл байхгүй байна.",
    )
    count = f'<p class="result-count">{len(rows)} ажилтан</p>' if rows else ""
    return head + filters + count + body


def delete_confirm(kind: str, summary: str, action: str, cancel: str) -> str:
    return f"""<section class="confirm-panel" role="alertdialog" aria-labelledby="confirm-title">
  <h2 id="confirm-title">Устгах уу?</h2>
  <p>Дараах {e(kind)} бүрмөсөн устгагдана:</p>
  <p class="confirm-target">{summary}</p>
  <p>Устгасны дараа буцааж сэргээх боломжгүй.</p>
  <form method="post" action="{e(action)}" class="form-actions">
    <button class="btn-danger" type="submit">Тийм, устгах</button>
    <a class="btn-link btn-plain" href="{e(cancel)}">Үгүй, буцах</a>
  </form>
</section>"""


# Нөөц бүрийн тохиргоо (зам → тохиргоо)
RESOURCES = {
    "reservations": {
        "nav": "reservations",
        "title": "Захиалга",
        "noun": "захиалга",
        "description": "Ширээ болон VIP өрөөний захиалга. Нэмэх, засах, устгах, хайх, огноо ба төлөвөөр шүүх.",
        "fields": RES_FIELDS,
        "validate": validate_reservation,
        "new_title": "Шинэ захиалга",
        "edit_title": "Захиалга засах",
        "defaults": {"seating": "table", "status": "pending", "deposit_amount": "0", "guest_count": "2"},
        "summary": lambda r: (f'<strong>{e(r.get("guest_name"))}</strong> · {e(r.get("phone"))} · '
                              f'{fmt_date(r.get("reservation_date"))} {fmt_time(r.get("start_time"))}'),
    },
    "staff": {
        "nav": "staff",
        "title": "Ажилтан",
        "noun": "ажилтан",
        "description": "Ажилтнуудын жагсаалт. Нэмэх, засах, устгах, нэр эсвэл утсаар хайх.",
        "fields": STAFF_FIELDS,
        "validate": validate_staff,
        "new_title": "Шинэ ажилтан",
        "edit_title": "Ажилтны мэдээлэл засах",
        "defaults": {"position": "waiter", "shift": "day", "status": "active"},
        "summary": lambda r: (f'<strong>{e(r.get("full_name"))}</strong> · '
                              f'{e(STAFF_POSITIONS.get(r.get("position"), r.get("position")))} · '
                              f'{e(r.get("phone") or "")}'),
    },
}
RESOURCE_PATH = re.compile(r"^/admin/(reservations|staff)(?:/(new)|/([0-9a-f-]{36})/(edit|delete))?$")


# зам → (түлхүүр, гарчиг, тайлбар, өгөгдөл ачаалагч, HTML үүсгэгч)
ADMIN_PAGES = {
    "/admin": ("dashboard", "Хянах самбар",
               "Өнөөдрийн захиалга, хүлээгдэж буй захиалга болон ойрын арга хэмжээ.",
               None, None),
    "/admin/content": ("content", "Контент",
                       "Сошиал болон вэбсайтад нийтлэх постын ноорог, төлөвлөгөө.",
                       lambda c, t: auth.list_content_drafts(c, t), content_body),
    "/admin/facebook": ("facebook", "Facebook",
                        "Facebook хуудастай холбогдох хэсэг.",
                        None, lambda: coming_soon_body("Facebook")),
    "/admin/chat": ("chat", "Чат",
                    "Үйлчлүүлэгчтэй харилцах чатын хэсэг.",
                    None, lambda: coming_soon_body("Чат")),
    "/admin/bookings": ("bookings", "Захиалга",
                        "Ширээ, VIP өрөө болон бусад захиалгын жагсаалт. Сүүлийн огноо эхэндээ.",
                        lambda c, t: auth.list_bookings(c, t), bookings_body),
    "/admin/events": ("events", "Арга хэмжээ",
                      "Төлөвлөсөн болон өнгөрсөн арга хэмжээний жагсаалт.",
                      lambda c, t: auth.list_events(c, t), events_body),
}


def error_page(status: int, message: str) -> str:
    return page(
        "Алдаа",
        f"""
<main class="login">
  {logo("login-logo", 400)}
  <div class="login-form">
    <h1>{status}</h1>
    <p>{e(message)}</p>
    <p><a href="/">Нүүр хуудас руу буцах</a></p>
  </div>
</main>""",
        body_class="login-body",
    )


# ---------------------------------------------------------------- Handler
class Handler(BaseHTTPRequestHandler):
    server_version = "MBK"
    sys_version = ""

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    # --- Log: зөвхөн арга, зам, статус ---
    def log_request(self, code="-", size="-") -> None:
        path = urlsplit(self.path).path if hasattr(self, "path") else "-"
        log.info("%s %s %s %s", self.client_address[0], getattr(self, "command", "-"), path, code)

    def log_error(self, format, *args) -> None:
        log.warning("%s хүсэлтийн алдаа", self.client_address[0])

    def log_message(self, format, *args) -> None:
        pass

    # --- Туслах ---
    def _send(self, status: int, body: str | bytes = "", headers: dict[str, str] | None = None,
              content_type: str = "text/html; charset=utf-8",
              cache: str = "no-store") -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        # Manrope фонтыг Google Fonts-оос ачаална
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # "no-referrer" бол хөтөч POST-д Origin: null илгээж, нэвтрэлт 403 болдог.
        # "same-origin": гадны сайт руу referrer илгээхгүй, өөр дээрээ Origin зөв явна.
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, location: str, cookie: str | None = None) -> None:
        headers = {"Location": location}
        if cookie:
            headers["Set-Cookie"] = cookie
        self._send(303, "", headers)

    def _cookie(self, sid: str) -> str:
        secure = "; Secure" if self.app.cookie_secure else ""
        return f"{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Strict{secure}"

    def _clear_cookie(self) -> str:
        secure = "; Secure" if self.app.cookie_secure else ""
        return f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"

    def _sid(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = SimpleCookie(raw)
        except CookieError:
            return None
        m = jar.get(COOKIE_NAME)
        return m.value if m and m.value else None

    def _current_session(self) -> tuple[str, Session] | None:
        sid = self._sid()
        if not sid:
            return None
        s = self.app.sessions.get(sid)
        if s is None:
            return None
        # Access token дуусахаас 60 сек өмнө шинэчилнэ
        if time.time() > s.tokens.expires_at - 60:
            try:
                s.tokens = auth.refresh(self.app.client, s.tokens.refresh_token)
            except auth.SessionExpired:
                self.app.sessions.delete(sid)
                return None
        return sid, s

    def _same_origin(self) -> bool:
        """CSRF хамгаалалт: POST хүсэлт зөвхөн энэ сайтаас ирсэн байх."""
        host = self.headers.get("Host", "")
        allowed = {f"http://{host}", f"https://{host}"}
        origin = self.headers.get("Origin")
        if origin:
            return origin in allowed
        referer = self.headers.get("Referer", "")
        return any(referer.startswith(a + "/") for a in allowed)

    def _form(self) -> dict[str, str] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length == 0:
            return {}
        if length < 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    # --- Чиглүүлэлт ---
    def do_GET(self) -> None:
        self._dispatch(self._get)

    def do_HEAD(self) -> None:
        self._dispatch(self._get)

    def do_POST(self) -> None:
        self._dispatch(self._post)

    def _dispatch(self, fn) -> None:
        try:
            fn(urlsplit(self.path).path)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Хөтөч хариуг хүлээлгүй холболтоо хаасан — алдаа биш
            self.close_connection = True
        except Exception as exc:  # Дэлгэрэнгүйг хэрэглэгчид харуулахгүй
            log.error("Дотоод алдаа: %s", type(exc).__name__)
            try:
                self._send(500, error_page(500, "Дотоод алдаа гарлаа."))
            except Exception:
                pass

    def _get(self, path: str) -> None:
        if path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            self._send(200, (STATIC_DIR / name).read_bytes(), content_type=ctype,
                       cache="public, max-age=3600")
            return
        if path == "/":
            self._redirect("/admin" if self._current_session() else "/login")
            return
        if path == "/login":
            if self._current_session():
                self._redirect("/admin")
            else:
                self._send(200, login_page())
            return
        if path == "/admin" or path.startswith("/admin/"):
            self._admin(path)
            return
        self._send(404, error_page(404, "Хуудас олдсонгүй."))

    def _post(self, path: str) -> None:
        # Биеийг эхлээд уншина — уншаагүй өгөгдөлтэй холболтыг хаавал
        # Windows дээр хариу хүрэхгүй тасардаг.
        form = self._form()
        if form is None:
            self.close_connection = True
        if not self._same_origin():
            self._send(403, error_page(403, "Хүсэлтийг зөвшөөрөхгүй."))
            return
        if path == "/login":
            self._login(form)
        elif path == "/logout":
            self._logout()
        elif path == "/admin/content/status":
            self._content_status(form or {})
        elif RESOURCE_PATH.match(path):
            self._resource(path, form or {})
        else:
            self._send(404, error_page(404, "Хуудас олдсонгүй."))

    # --- Захиалга / Ажилтан: GET ба POST ---
    def _resource(self, path: str, form: dict[str, str] | None = None) -> None:
        current = self._current_session()
        if current is None:
            self._redirect("/login", cookie=self._clear_cookie() if self._sid() else None)
            return
        sid, s = current
        m = RESOURCE_PATH.match(path)
        table_name, is_new, rid, action = m.group(1), m.group(2), m.group(3), m.group(4)
        cfg = RESOURCES[table_name]
        base = f"/admin/{table_name}"
        client, token, email = self.app.client, s.tokens.access_token, s.tokens.email
        is_post = self.command == "POST"

        def show(status: int, title: str, body: str, description: str = "") -> None:
            self._send(status, shell(cfg["nav"], email, title, description or cfg["description"], body))

        try:
            # ---- Жагсаалт ----
            if not is_new and not rid:
                if is_post:
                    self._send(405, error_page(405, "Зөвшөөрөгдөөгүй үйлдэл."))
                    return
                q = parse_qs(urlsplit(self.path).query)
                term = (q.get("q") or [""])[0][:60]
                status = (q.get("status") or [""])[0]
                date = (q.get("date") or [""])[0] if table_name == "reservations" else ""
                statuses = RES_STATUS if table_name == "reservations" else STAFF_STATUS
                status = status if status in statuses else ""
                date = date if date and _valid_date(date) else ""
                flash = (q.get("msg") or [""])[0]
                filters = {"status": status}
                if table_name == "reservations":
                    filters["reservation_date"] = date
                try:
                    rows = auth.list_records(client, token, table_name, term, filters)
                    err = ""
                except auth.DataError as exc:
                    rows, err = None, str(exc)
                if table_name == "reservations":
                    body = reservations_list(rows, term, date, status, flash, err)
                else:
                    body = staff_list(rows, term, status, flash, err)
                show(502 if err else 200, cfg["title"], body)
                return

            # ---- Шинэ ----
            if is_new:
                if not is_post:
                    show(200, cfg["new_title"],
                         render_form(cfg["fields"], cfg["defaults"], {}, f"{base}/new", "Хадгалах", base))
                    return
                data, errors = cfg["validate"](form or {})
                if errors:
                    show(400, cfg["new_title"],
                         render_form(cfg["fields"], form or {}, errors, f"{base}/new", "Хадгалах", base))
                    return
                try:
                    auth.create_record(client, token, table_name, data)
                except auth.DataError as exc:
                    show(502, cfg["new_title"], alert(str(exc))
                         + render_form(cfg["fields"], form or {}, {}, f"{base}/new", "Хадгалах", base))
                    return
                log.info("%s: шинэ мөр нэмэв", table_name)
                self._redirect(f"{base}?msg=created")
                return

            # ---- Засах / Устгах (ID-тай) ----
            try:
                record = auth.get_record(client, token, table_name, rid)
            except auth.NotFound:
                self._redirect(f"{base}?msg=notfound")
                return
            except auth.DataError as exc:
                show(502, cfg["title"], alert(str(exc)))
                return

            if action == "edit":
                url = f"{base}/{rid}/edit"
                if not is_post:
                    show(200, cfg["edit_title"],
                         render_form(cfg["fields"], record, {}, url, "Өөрчлөлтийг хадгалах", base))
                    return
                data, errors = cfg["validate"](form or {})
                if errors:
                    show(400, cfg["edit_title"],
                         render_form(cfg["fields"], form or {}, errors, url, "Өөрчлөлтийг хадгалах", base))
                    return
                try:
                    auth.update_record(client, token, table_name, rid, data)
                except auth.NotFound:
                    self._redirect(f"{base}?msg=notfound")
                    return
                except auth.DataError as exc:
                    show(502, cfg["edit_title"], alert(str(exc))
                         + render_form(cfg["fields"], form or {}, {}, url, "Өөрчлөлтийг хадгалах", base))
                    return
                log.info("%s: мөр засав", table_name)
                self._redirect(f"{base}?msg=updated")
                return

            # action == "delete"
            url = f"{base}/{rid}/delete"
            if not is_post:
                show(200, f"{cfg['title']} устгах",
                     delete_confirm(cfg["noun"], cfg["summary"](record), url, base),
                     "Устгахаас өмнө баталгаажуулна уу.")
                return
            try:
                auth.delete_record(client, token, table_name, rid)
                msg = "deleted"
            except auth.NotFound:
                msg = "notfound"
            except auth.DataError:
                msg = "error"
            log.info("%s: устгах — %s", table_name, msg)
            self._redirect(f"{base}?msg={msg}")
        except auth.SessionExpired:
            self.app.sessions.delete(sid)
            self._redirect("/login", cookie=self._clear_cookie())

    def _content_status(self, form: dict[str, str]) -> None:
        """«Батлах» / «Татгалзах»: зөвхөн «Хүлээгдэж буй» постын төлөвийг солино."""
        current = self._current_session()
        if current is None:
            self._redirect("/login", cookie=self._clear_cookie() if self._sid() else None)
            return
        sid, s = current
        to_status = REVIEW_ACTIONS.get(form.get("action", ""))
        if to_status is None:
            self._redirect("/admin/content?msg=error")
            return
        try:
            changed = auth.set_draft_status(self.app.client, s.tokens.access_token,
                                            form.get("id", ""), "review", to_status)
            msg = to_status if changed else "stale"
        except auth.SessionExpired:
            self.app.sessions.delete(sid)
            self._redirect("/login", cookie=self._clear_cookie())
            return
        except auth.StatusNotAllowed:
            msg = "migrate"
        except auth.DataError:
            msg = "error"
        log.info("Постын төлөв: %s", msg)
        # POST → redirect → GET: хуудсыг refresh хийхэд дахин илгээгдэхгүй
        self._redirect(f"/admin/content?msg={msg}")

    # --- Хуудсууд ---
    def _admin(self, path: str) -> None:
        current = self._current_session()
        if current is None:
            self._redirect("/login", cookie=self._clear_cookie() if self._sid() else None)
            return
        sid, s = current
        path = path.rstrip("/") or "/admin"
        if RESOURCE_PATH.match(path):
            self._resource(path)
            return
        page_def = ADMIN_PAGES.get(path)
        if page_def is None:
            self._send(404, shell("", s.tokens.email, "Хуудас олдсонгүй",
                                  "Ийм хуудас байхгүй байна.",
                                  '<a class="btn-link" href="/admin">Хянах самбар руу буцах</a>'))
            return
        key, title, description, loader, renderer = page_def
        client, token = self.app.client, s.tokens.access_token
        try:
            if key == "dashboard":
                body = self._dashboard(client, token)
                status = 200
            elif loader is None:
                body, status = renderer(), 200
            else:
                extra = {}
                if key == "content":
                    q = parse_qs(urlsplit(self.path).query)
                    extra["flash"] = (q.get("msg") or [""])[0]
                try:
                    body, status = renderer(loader(client, token), **extra), 200
                except auth.DataError as err:
                    body, status = renderer(None, str(err), **extra), 502
            self._send(status, shell(key, s.tokens.email, title, description, body))
        except auth.SessionExpired:
            self.app.sessions.delete(sid)
            self._redirect("/login", cookie=self._clear_cookie())

    @staticmethod
    def _dashboard(client, token: str) -> str:
        """Хэсэг бүрийг тусад нь ачаална. Алдаа гарвал тэр хэсэгт л мессеж — тоо зохиохгүй."""
        today = today_ub()

        def load(fn, *args):
            try:
                return fn(client, token, *args)
            except auth.DataError as err:
                return str(err)

        return dashboard_body(
            today,
            load(auth.todays_reservations, today),
            load(auth.pending_reservations),
            load(auth.upcoming_events, today),
        )

    def _login(self, form: dict[str, str] | None) -> None:
        ip = self.client_address[0]
        if form is None:
            self._send(400, login_page("Хүсэлт буруу байна."))
            return
        email = form.get("email", "").strip()[:254]
        password = form.get("password", "")
        if self.app.limiter.blocked(ip):
            self._send(429, login_page("Хэт олон буруу оролдлого. 5 минутын дараа дахин оролдоно уу.", email))
            return
        if not email or not password or len(password) > 200:
            self._send(400, login_page("Имэйл болон нууц үгээ оруулна уу.", email))
            return

        try:
            tokens = auth.sign_in(self.app.client, email, password)
        except auth.AuthError as err:
            if err.status == 401:
                self.app.limiter.fail(ip)
            self._send(err.status, login_page(err.user_message, email))
            return
        finally:
            password = ""  # noqa: F841 — нууц үгийг санах ойд удаан байлгахгүй

        try:
            admin = auth.is_admin(self.app.client, tokens.access_token, tokens.user_id)
        except auth.AuthError as err:
            auth.sign_out(self.app.client, tokens.access_token)
            self._send(err.status, login_page(err.user_message, email))
            return
        if not admin:
            auth.sign_out(self.app.client, tokens.access_token)
            self.app.limiter.fail(ip)
            self._send(403, login_page("Энэ хэрэглэгчид админ эрх байхгүй.", email))
            return

        # Хуучин сесс байвал устгаад, үргэлж ШИНЭ сессийн ID өгнө
        old = self._sid()
        if old:
            self.app.sessions.delete(old)
        self.app.limiter.reset(ip)
        sid = self.app.sessions.create(tokens)
        log.info("Админ нэвтэрлээ")
        self._redirect("/admin", cookie=self._cookie(sid))

    def _logout(self) -> None:
        sid = self._sid()
        if sid:
            s = self.app.sessions.delete(sid)
            if s:
                auth.sign_out(self.app.client, s.tokens.access_token)
        self._redirect("/login", cookie=self._clear_cookie())


class _Server(ThreadingHTTPServer):
    # Windows дээр SO_REUSEADDR нь хоёр процесс нэг портыг зэрэг эзлэх боломж олгодог
    # (хуучин сервер хүсэлтийг "хулгайлж" болно). Тиймээс унтраана.
    allow_reuse_address = os.name != "nt"
    daemon_threads = True


def make_server(app: App, host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    server = _Server((host, port), Handler)
    server.app = app  # type: ignore[attr-defined]
    return server

"""Одоогийн Handler-ийг (http.server) WSGI апп болгож gunicorn дээр ажиллуулах адаптер.

Бүх логик (нэвтрэлт, CSRF, сесс, хуудас) web.Handler-т хэвээр үлдэнэ. Энэ модуль
зөвхөн WSGI хүсэлтийг HTTP хүсэлт болгон Handler-т өгч, хариуг нь буцааж хөрвүүлнэ.

Анхаар: сесс санах ойд хадгалагддаг тул gunicorn-ыг ЗААВАЛ 1 worker-оор
(олон thread-тэй) ажиллуулна. Тохиргоо: gunicorn.conf.py
"""

from __future__ import annotations

import io
import os
from types import SimpleNamespace
from urllib.parse import quote

from .web import MAX_BODY, App, Handler

# Хариунаас хасах толгойнууд: WSGI сервер өөрөө тавина / hop-by-hop
_DROP = {"connection", "keep-alive", "transfer-encoding", "date", "server",
         "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade"}
_STATUS_TEXT = {200: "OK", 303: "See Other", 400: "Bad Request", 401: "Unauthorized",
                403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
                429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway",
                503: "Service Unavailable", 501: "Not Implemented"}


def _client_ip(environ: dict, trust_proxy: bool) -> str:
    if trust_proxy:
        # Render-ийн proxy жинхэнэ IP-г X-Forwarded-For-ийн ТӨГСГӨЛД нэмдэг.
        # Эхний утгыг хэрэглэгч хуурамчаар бичиж болох тул сүүлийнхийг авна.
        xff = environ.get("HTTP_X_FORWARDED_FOR", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return environ.get("REMOTE_ADDR", "0.0.0.0")


def _target(environ: dict) -> str:
    raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if raw:
        return raw
    path = (environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")) or "/"
    path = quote(path.encode("latin-1"), safe="/:@!$&'()*+,;=-._~%")
    qs = environ.get("QUERY_STRING", "")
    return path + ("?" + qs if qs else "")


def create_wsgi_app(app: App, trust_proxy: bool | None = None):
    if trust_proxy is None:
        trust_proxy = os.environ.get("TRUST_PROXY") == "1"
    server = SimpleNamespace(app=app)

    def application(environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        # --- WSGI → HTTP хүсэлт ---
        lines = [f"{method} {_target(environ)} HTTP/1.0"]
        for key, value in environ.items():
            if key.startswith("HTTP_") and key not in ("HTTP_CONTENT_LENGTH", "HTTP_CONTENT_TYPE"):
                name = key[5:].replace("_", "-").title()
                lines.append(f"{name}: {value}")
        if environ.get("CONTENT_TYPE"):
            lines.append(f"Content-Type: {environ['CONTENT_TYPE']}")
        body = b""
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > 0:
            lines.append(f"Content-Length: {length}")
            if length <= MAX_BODY:
                body = environ["wsgi.input"].read(length)
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

        # --- Handler-ийг сокетгүйгээр ажиллуулах ---
        h = Handler.__new__(Handler)
        h.rfile = io.BytesIO(raw)
        h.wfile = io.BytesIO()
        h.client_address = (_client_ip(environ, trust_proxy), 0)
        h.server = server
        h.request = None
        h.close_connection = True
        h.handle_one_request()

        # --- HTTP хариу → WSGI ---
        out = h.wfile.getvalue()
        head, _, resp_body = out.partition(b"\r\n\r\n")
        head_lines = head.decode("latin-1").split("\r\n")
        try:
            code = int(head_lines[0].split()[1])
        except (IndexError, ValueError):
            code, head_lines, resp_body = 500, ["HTTP/1.0 500"], b"Internal Server Error"
        headers = []
        for line in head_lines[1:]:
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() not in _DROP:
                headers.append((name.strip(), value.strip()))
        start_response(f"{code} {_STATUS_TEXT.get(code, 'OK')}", headers)
        return [resp_body]

    return application

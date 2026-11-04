"""Render (gunicorn) дээр ажиллуулах эхлэлийн файл.

Ажиллуулах:  gunicorn wsgi:application
Тохиргоо (порт, worker, thread) gunicorn.conf.py-д байна.

Render-ийн Environment хэсэгт тохируулах хувьсагч:
  SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY  — заавал
  COOKIE_SECURE=1                         — HTTPS дээр cookie-г хамгаална
  TRUST_PROXY=1                           — Render-ийн proxy-оос жинхэнэ IP авна
SUPABASE_SECRET_KEY-г Render-д ОРУУЛАХГҮЙ (апп ашигладаггүй).
"""

from __future__ import annotations

import logging
import os
import sys

from backend.config import ConfigError, load_config
from backend.supabase_client import SupabaseClient
from backend.web import App
from backend.wsgi_adapter import create_wsgi_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                    stream=sys.stdout)

try:
    _config = load_config()
except ConfigError as err:
    # Түлхүүрийн утгыг хэвлэхгүй — зөвхөн юу дутуу байгааг хэлнэ
    logging.critical("Тохиргооны алдаа: %s", err)
    raise SystemExit(1)

application = create_wsgi_app(
    App(client=SupabaseClient(_config), cookie_secure=os.environ.get("COOKIE_SECURE") == "1")
)

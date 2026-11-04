"""MBK Lounge админ самбарыг ажиллуулна.

Ажиллуулах:  python app.py
Дараа нь хөтөчөөр:  http://127.0.0.1:8000
"""

from __future__ import annotations

import logging
import os
import sys

from backend.config import ConfigError, load_config
from backend.supabase_client import SupabaseClient
from backend.web import App, make_server


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        config = load_config()
    except ConfigError as err:
        print(f"Тохиргооны алдаа: {err}")
        return 1

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    # HTTPS дээр байршуулахдаа COOKIE_SECURE=1 тохируулна
    cookie_secure = os.environ.get("COOKIE_SECURE") == "1"

    app = App(client=SupabaseClient(config), cookie_secure=cookie_secure)
    try:
        server = make_server(app, host, port)
    except OSError:
        print(
            f"АЛДАА: {port} порт аль хэдийн ашиглагдаж байна. Өмнө асаасан серверээ "
            "(өөр терминал дээрх python app.py) Ctrl+C-ээр зогсоогоод дахин оролдоно уу."
        )
        return 1
    print(f"MBK Lounge админ: http://{host}:{port}  (зогсоох: Ctrl+C)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

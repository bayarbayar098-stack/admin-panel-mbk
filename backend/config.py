"""Supabase тохиргоог .env файлаас (эсвэл системийн орчны хувьсагчаас) уншина.

Дүрэм:
- Түлхүүрийг кодонд шууд бичихгүй, зөвхөн .env / орчны хувьсагчаас уншина.
- Түлхүүрийг хэзээ ч print, log, алдааны мессежид оруулахгүй.
- "sb_secret_" болон service_role түлхүүрийг хүлээн авахгүй.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

URL_VAR = "SUPABASE_URL"
KEY_VAR = "SUPABASE_PUBLISHABLE_KEY"


class ConfigError(Exception):
    """Тохиргооны алдаа. Мессежид нууц утга хэзээ ч орохгүй."""


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    # utf-8-sig: Windows Notepad-ийн BOM-ыг арилгана
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        if name.startswith("export "):
            name = name[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name] = value
    return values


def _normalize_url(raw: str) -> str:
    url = raw.strip().rstrip("/")
    # Хэрэглэгч REST endpoint-ийг хуулсан бол Project URL болгож засна
    for suffix in ("/rest/v1", "/auth/v1"):
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc or parts.path not in ("", "/"):
        raise ConfigError(
            f"{URL_VAR} буруу хэлбэртэй байна. "
            "Жишээ: https://your-project-ref.supabase.co"
        )
    return f"https://{parts.netloc}"


def _jwt_role(token: str) -> str | None:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


def _classify_key(key: str) -> str:
    if key.startswith("sb_secret_"):
        raise ConfigError(
            f"{KEY_VAR}-д SECRET түлхүүр (sb_secret_...) оруулсан байна. "
            "Энэ түлхүүр RLS-ийг тойрдог тул ашиглахыг хориглоно. "
            "Supabase → Project Settings → API Keys хэсгээс 'sb_publishable_' "
            "гэж эхэлсэн түлхүүрийг оруулна уу."
        )
    if key.startswith("sb_publishable_"):
        return "publishable"
    if key.startswith("eyJ"):
        role = _jwt_role(key)
        if role == "anon":
            return "legacy anon"
        if role == "service_role":
            raise ConfigError(
                f"{KEY_VAR}-д service_role түлхүүр оруулсан байна. "
                "Үүнийг ашиглахыг хориглоно — publishable түлхүүр оруулна уу."
            )
    raise ConfigError(
        f"{KEY_VAR}-ийн хэлбэр танигдсангүй. 'sb_publishable_' гэж эхлэх ёстой."
    )


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    # repr=False: print(config) хийсэн ч түлхүүр харагдахгүй
    publishable_key: str = field(repr=False)
    key_type: str = "publishable"


def load_config(env_file: Path = ENV_FILE) -> SupabaseConfig:
    file_values = _parse_env_file(env_file)

    def get(name: str) -> str:
        # Системийн орчны хувьсагч (хостинг дээр) эхэнд, дараа нь .env
        return (os.environ.get(name) or file_values.get(name) or "").strip()

    raw_url, key = get(URL_VAR), get(KEY_VAR)
    missing = [n for n, v in ((URL_VAR, raw_url), (KEY_VAR, key)) if not v]
    if missing:
        where = ".env файл олдсонгүй" if not env_file.is_file() else ".env файлд"
        raise ConfigError(f"{where}: дутуу хувьсагч — {', '.join(missing)}")

    url = _normalize_url(raw_url)
    key_type = _classify_key(key)
    return SupabaseConfig(url=url, publishable_key=key, key_type=key_type)

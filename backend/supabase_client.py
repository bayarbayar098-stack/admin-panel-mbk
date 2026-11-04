"""Supabase REST/Auth руу СЕРВЕР талаас хандах жижиг клиент (зөвхөн стандарт сан).

Түлхүүр зөвхөн HTTP толгойд (header) явна; хариу, алдаанд хэзээ ч буцаагдахгүй.
Админы өгөгдөлд хандахдаа нэвтэрсэн админы access_token (JWT)-ийг дамжуулна —
RLS бодлого тэр токеноор админ эсэхийг шалгана.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import SupabaseConfig, load_config


@dataclass
class SupabaseResponse:
    status: int
    data: Any

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class SupabaseClient:
    def __init__(self, config: SupabaseConfig | None = None, timeout: float = 10.0):
        self._config = config or load_config()
        self._timeout = timeout

    @property
    def url(self) -> str:
        return self._config.url

    def request(
        self,
        method: str,
        path: str,
        *,
        access_token: str | None = None,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> SupabaseResponse:
        if not path.startswith("/"):
            path = "/" + path
        req_headers = {
            "apikey": self._config.publishable_key,
            "Accept": "application/json",
        }
        if access_token:
            req_headers["Authorization"] = f"Bearer {access_token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(
            self._config.url + path, data=data, headers=req_headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return SupabaseResponse(resp.status, _decode(resp.read()))
        except urllib.error.HTTPError as err:
            return SupabaseResponse(err.code, _decode(err.read()))
        except urllib.error.URLError as err:
            # Зөвхөн шалтгааныг буцаана; толгой (түлхүүр) орохгүй
            raise ConnectionError(f"Supabase руу холбогдож чадсангүй: {err.reason}") from None
        except OSError as err:  # timeout, socket алдаа
            raise ConnectionError(
                f"Supabase руу холбогдож чадсангүй: {type(err).__name__}"
            ) from None

    # Тохиромжтой туслах функцууд
    def rest(self, method: str, table_query: str, **kwargs) -> SupabaseResponse:
        return self.request(method, "/rest/v1/" + table_query.lstrip("/"), **kwargs)

    def auth(self, method: str, path: str, **kwargs) -> SupabaseResponse:
        return self.request(method, "/auth/v1/" + path.lstrip("/"), **kwargs)


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode("utf-8", "replace")

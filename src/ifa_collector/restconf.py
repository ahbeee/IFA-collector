from __future__ import annotations

import base64
import json
import ssl
from urllib import error, request


class RestconfClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        path_prefix: str = "/restconf/data",
        verify_tls: bool = False,
        timeout: float = 10,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.path_prefix = "/" + path_prefix.strip().lstrip("/")
        self.verify_tls = verify_tls
        self.timeout = float(timeout)

    def get_json(self, path: str) -> dict:
        url = self._url(path)
        req = request.Request(url, headers=self._headers(), method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ssl_context()) as response:
                body = response.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"RESTCONF HTTP {exc.code} for {url}: {details}") from exc
        except Exception as exc:
            raise RuntimeError(f"RESTCONF request failed for {url}: {exc}") from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"RESTCONF invalid JSON from {url}") from exc

    def _url(self, path: str) -> str:
        normalized = path.strip().lstrip("/")
        if normalized.startswith("http://") or normalized.startswith("https://"):
            return normalized
        return f"https://{self.host}:{self.port}{self.path_prefix}/{normalized}"

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        return {
            "Accept": "application/yang-data+json",
            "Authorization": f"Basic {token}",
        }

    def _ssl_context(self):
        return None if self.verify_tls else ssl._create_unverified_context()

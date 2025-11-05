# src/tenantsec/core/graph_client.py
from __future__ import annotations
from typing import Callable, Dict, Iterable, Any
from tenantsec.http.client import HttpClient
from tenantsec.config.loader import get_http_config
from tenantsec.http.throttle import set_max_concurrency

GRAPH_BASE = "https://graph.microsoft.com"

class GraphClient:
    """
    Tiny Graph wrapper. Token is provided lazily via token_provider().
    """
    def __init__(
        self,
        token_provider: Callable[[], str],
        timeout: float | None = None,
        max_retries: int | None = None,
        logger=None,
    ):
        http_cfg = get_http_config()
        to = float(timeout if timeout is not None else http_cfg.get("timeout_seconds", 30))
        mr = int(max_retries if max_retries is not None else http_cfg.get("max_retries", 4))
        set_max_concurrency(int(http_cfg.get("max_concurrency", 6)))

        self._token_provider = token_provider
        self._http = HttpClient(base_url=GRAPH_BASE, timeout=to, max_retries=mr, logger=logger)

    def _auth_headers(self, extra: Dict[str, str] | None = None) -> Dict[str, str]:
        h = {"Authorization": f"Bearer {self._token_provider()}"}
        if extra:
            h.update(extra)
        return h

    def get_json(self, path_or_url: str, *, params: Dict[str, Any] | None = None) -> dict:
        return self._http.get_json(path_or_url, headers=self._auth_headers(), params=params)

    def get_paged_values(
        self,
        path_or_url: str,
        *,
        params: Dict[str, Any] | None = None,
        page_limit: int | None = None
    ) -> Iterable[dict]:
        for page in self._http.get_paged(
            path_or_url, headers=self._auth_headers(), params=params, page_limit=page_limit
        ):
            for item in page.get("value", []):
                yield item

    def post_json(self, path_or_url: str, *, json: Any = None) -> dict:
        return self._http.post_json(path_or_url, headers=self._auth_headers(), json=json)

    def patch_json(self, path_or_url: str, *, json: Any = None) -> dict:
        return self._http.patch_json(path_or_url, headers=self._auth_headers(), json=json)

    def put_json(self, path_or_url: str, *, json: Any = None) -> dict:
        return self._http.put_json(path_or_url, headers=self._auth_headers(), json=json)

    def delete(self, path_or_url: str) -> int:
        return self._http.delete(path_or_url, headers=self._auth_headers())

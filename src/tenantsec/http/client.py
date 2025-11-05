from __future__ import annotations
import json as _json
from typing import Any, Dict, Iterable, Optional
import requests

from tenantsec.http.errors import (
    HttpError, UnauthorizedError, ForbiddenError, NotFoundError,
    ThrottleError, ServerError, NetworkError
)
from tenantsec.http.throttle import (
    ConcurrencyGate, RETRY_STATUSES, compute_sleep_seconds, sleep_backoff
)


class HttpClient:
    def __init__(self, base_url: str = "", timeout: float = 30.0, max_retries: int = 4, logger=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._session = requests.Session()
        self._log = logger  # optional, expects .debug()

    def _full_url(self, url: str) -> str:
        if url.startswith("http://") or url.startswith("https://"):
            return url
        if self.base_url:
            return f"{self.base_url}/{url.lstrip('/')}"
        return url

    def _log_debug(self, msg: str) -> None:
        if self._log:
            try:
                self._log.debug(msg)
            except Exception:
                pass

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None
    ) -> requests.Response:
        full = self._full_url(url)
        last_exc = None
        attempt = 0

        while True:
            try:
                with ConcurrencyGate():
                    self._log_debug(f"HTTP {method.upper()} {full}")
                    resp = self._session.request(
                        method=method.upper(),
                        url=full,
                        headers=headers or {},
                        params=params,
                        json=json,
                        timeout=self.timeout,
                    )
            except requests.exceptions.RequestException as ex:
                last_exc = ex
                if attempt >= self.max_retries:
                    raise NetworkError(-1, full, str(ex))
                sleep_backoff(compute_sleep_seconds(attempt, None))
                attempt += 1
                continue

            if resp.status_code < 400:
                self._log_debug(f"HTTP {resp.status_code} {full}")
                return resp

            # Retryable?
            if resp.status_code in RETRY_STATUSES and attempt < self.max_retries:
                self._log_debug(f"HTTP {resp.status_code} {full} (retry {attempt})")
                sleep_backoff(compute_sleep_seconds(attempt, resp.headers.get("Retry-After")))
                attempt += 1
                continue

            # Map to typed errors
            body_snip = _safe_snip(resp)
            if resp.status_code == 401:
                raise UnauthorizedError(401, full, "Unauthorized", body_snip)
            if resp.status_code == 403:
                raise ForbiddenError(403, full, "Forbidden", body_snip)
            if resp.status_code == 404:
                raise NotFoundError(404, full, "Not Found", body_snip)
            if resp.status_code == 429:
                raise ThrottleError(429, full, "Too Many Requests", body_snip)
            if 500 <= resp.status_code <= 599:
                raise ServerError(resp.status_code, full, "Server error", body_snip)
            raise HttpError(resp.status_code, full, "HTTP error", body_snip)

    # ---------- Convenience helpers ----------
    def get_json(self, url: str, **kwargs) -> dict:
        r = self.request("GET", url, **kwargs)
        return _json.loads(r.text or "{}")

    def post_json(self, url: str, *, headers=None, json=None) -> dict:
        r = self.request("POST", url, headers=headers, json=json)
        return _json.loads(r.text or "{}")

    def patch_json(self, url: str, *, headers=None, json=None) -> dict:
        r = self.request("PATCH", url, headers=headers, json=json)
        return _json.loads(r.text or "{}")

    def put_json(self, url: str, *, headers=None, json=None) -> dict:
        r = self.request("PUT", url, headers=headers, json=json)
        return _json.loads(r.text or "{}")

    def delete(self, url: str, *, headers=None) -> int:
        r = self.request("DELETE", url, headers=headers)
        return r.status_code

    def get_paged(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        page_limit: Optional[int] = None
    ) -> Iterable[dict]:
        """Iterate Graph-style pages. Yields each page dict with a 'value' list."""
        next_url = url
        pages = 0
        while next_url:
            data = self.get_json(next_url, headers=headers, params=params)
            yield data
            pages += 1
            if page_limit and pages >= page_limit:
                break
            next_url = data.get("@odata.nextLink")


def _safe_snip(resp: requests.Response, max_len: int = 400) -> str:
    try:
        txt = resp.text or ""
        return txt[:max_len]
    except Exception:
        return ""

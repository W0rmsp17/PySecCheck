# src/tenantsec/http/throttle.py
import random
import time
import threading

# Statuses we retry
RETRY_STATUSES = {429, 502, 503, 504}

def compute_sleep_seconds(attempt: int, retry_after_header: str | None) -> float:
    # Honor Retry-After (integer seconds)
    if retry_after_header and retry_after_header.isdigit():
        return int(retry_after_header)
    base = min(2 ** attempt, 8)  # 1,2,4,8 cap
    return base * (0.6 + 0.8 * random.random())  # jitter 60–140%

def sleep_backoff(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)

# Global concurrency gate
_MAX_CONCURRENCY = 6
_SEMAPHORE = threading.Semaphore(_MAX_CONCURRENCY)

class ConcurrencyGate:
    def __enter__(self):
        _SEMAPHORE.acquire()
    def __exit__(self, exc_type, exc, tb):
        _SEMAPHORE.release()

def set_max_concurrency(n: int):
    """Call once on startup (graph client init) to adjust gate size."""
    global _MAX_CONCURRENCY, _SEMAPHORE
    _MAX_CONCURRENCY = max(1, int(n))
    _SEMAPHORE = threading.Semaphore(_MAX_CONCURRENCY)

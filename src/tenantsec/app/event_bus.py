# Simple pub/sub
_subs: dict[str, list] = {}

def publish(topic: str, payload=None):
    for h in _subs.get(topic, []):
        try:
            h(payload)
        except Exception:
            pass  # keep UI alive

def subscribe(topic: str, handler):
    _subs.setdefault(topic, []).append(handler)

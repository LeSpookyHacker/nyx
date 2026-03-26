"""Shared rate limiter instance — imported by both main.py and individual routers."""
from fastapi import Request
from slowapi import Limiter


def _real_ip(request: Request) -> str:
    """
    Use the direct TCP peer address for rate limiting, ignoring X-Forwarded-For.
    Trusting X-Forwarded-For without validating the proxy chain allows clients
    to spoof their IP and bypass per-IP rate limits (H1).
    Set this to a reverse-proxy-aware function only if Nyx sits behind a trusted proxy.
    """
    if request.client:
        return request.client.host
    return "unknown"


limiter = Limiter(key_func=_real_ip, default_limits=["300/minute"])

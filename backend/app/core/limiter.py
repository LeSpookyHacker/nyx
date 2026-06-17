"""Shared rate limiter instance — imported by both main.py and individual routers."""
from fastapi import Request
from slowapi import Limiter


def _rate_limit_key(request: Request) -> str:
    """
    Return the client IP for rate limiting using the TRUSTED_PROXY_CIDRS-aware
    helper from security.py (SEC-008).

    Using ``request.client.host`` directly would make all clients share the
    same bucket when Nyx runs behind a reverse proxy (the typical Docker/Nginx
    deployment), because every request would appear to originate from the
    proxy's IP.  ``get_client_ip`` reads X-Forwarded-For only from addresses
    in the configured trusted-proxy CIDR list, so spoofing is still prevented
    while per-client limiting works correctly behind a trusted proxy.
    """
    from app.core.security import get_client_ip
    return get_client_ip(request)


limiter = Limiter(key_func=_rate_limit_key, default_limits=["300/minute"])

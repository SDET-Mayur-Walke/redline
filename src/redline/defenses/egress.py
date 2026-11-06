"""Egress allowlist: which hosts the agent may fetch from or link to.

Only the allowlist check lives here so far; the ingestion scanner uses it for links found in documents. The
fetch_url gate and the reply link/image filter (group 4) build on the same function, so a document, a fetch
and a reply all agree on what "allowed" means.

An entry is a hostname ("help.saffroncart.example", which also allows its subdomains) or a host with a port
("localhost:8000", that port only). Ports matter here: in a lab where everything runs on localhost, a
host-only rule could not tell the store's own pages from any other local listener.
"""

from __future__ import annotations

from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def host_allowed(host: str | None, allowlist: list[str], port: int | None = None) -> bool:
    """True if `host` (on `port`, when given) matches an allowlist entry. Empty allowlist allows nothing."""
    if not host:
        return False
    host = host.lower().rstrip(".")
    for entry in allowlist:
        e_host, _, e_port = entry.lower().partition(":")
        e_host = e_host.rstrip(".")
        if e_port:
            if host == e_host and port is not None and str(port) == e_port:
                return True
        elif host == e_host or host.endswith("." + e_host):
            return True
    return False


def url_allowed(url: str, allowlist: list[str]) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port or DEFAULT_PORTS.get(parts.scheme.lower())
        return host_allowed(parts.hostname, allowlist, port)
    except ValueError:                        # malformed URL or port: not allowed
        return False

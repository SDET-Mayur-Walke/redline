"""Egress allowlist: which hosts the agent may fetch from or link to.

The ingestion scanner uses url_allowed for links found in documents, EgressRule (defenses/policy.py) for
fetch_url, and strip_links below for links and images in replies, so a document, a fetch and a reply all
agree on what "allowed" means.

Why replies: a chat client that renders markdown fetches an image with no click, so an image URL carrying
data is an exfiltration channel; a link is the same leak one click later. strip_links drops images to
unlisted hosts, keeps a link's text but drops its URL, and replaces bare URLs, HTML <img> and <a> the same way.

An entry is a hostname ("help.saffroncart.example", which also allows its subdomains) or a host with a port
("localhost:8000", that port only). Ports matter here: in a lab where everything runs on localhost, a
host-only rule could not tell the store's own pages from any other local listener.
"""

from __future__ import annotations

import re
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


MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")
HTML_IMG = re.compile(r"<img\b[^>]*?src\s*=\s*[\"']?([^\"'\s>]+)[^>]*>", re.I)
HTML_A = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']?([^\"'\s>]+)[^>]*>(.*?)</a>", re.I | re.S)
BARE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"')\]]+", re.I)
IMAGE_REMOVED, LINK_REMOVED = "[image removed]", "[link removed]"


def strip_links(text: str, allowlist: list[str]) -> tuple[str, list[str]]:
    """(text with every image/link to an unlisted host neutralised, the URLs removed)."""
    removed: list[str] = []

    def keep(url: str) -> bool:
        if url_allowed(url, allowlist):
            return True
        removed.append(url)
        return False

    text = MD_IMAGE.sub(lambda m: m.group(0) if keep(m.group(2)) else IMAGE_REMOVED, text)
    text = HTML_IMG.sub(lambda m: m.group(0) if keep(m.group(1)) else IMAGE_REMOVED, text)
    text = MD_LINK.sub(lambda m: m.group(0) if keep(m.group(2)) else m.group(1), text)
    text = HTML_A.sub(lambda m: m.group(0) if keep(m.group(1)) else m.group(2), text)
    text = BARE_URL.sub(lambda m: m.group(0) if keep(m.group(0)) else LINK_REMOVED, text)
    return text, removed

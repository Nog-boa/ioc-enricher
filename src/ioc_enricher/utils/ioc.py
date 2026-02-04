from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})$")
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_common(value: str) -> str:
    return value.strip().strip("<>\"'()[]{}")


def detect_ioc(value: str) -> tuple[str, str, str]:
    """
    Returns (normalized_ioc, ioc_type, error).
    ioc_type is empty when invalid. error is empty when valid.
    """
    raw = _normalize_common(value)
    if not raw:
        return "", "", "empty"

    if _HASH_RE.fullmatch(raw):
        return raw.lower(), "hash", ""

    cve_match = _CVE_RE.fullmatch(raw)
    if cve_match:
        return f"CVE-{cve_match.group(1)}-{cve_match.group(2)}", "cve", ""

    try:
        ip_obj = ipaddress.ip_address(raw)
        return str(ip_obj), "ip", ""
    except ValueError:
        pass

    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return raw, "url", ""

    candidate = raw.rstrip(".")
    if candidate and _DOMAIN_RE.fullmatch(candidate):
        return candidate.lower(), "domain", ""

    return raw, "", "invalid_ioc"

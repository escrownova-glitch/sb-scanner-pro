"""Target parsing shared by scanner front ends.

The scanner appends probe paths to each target, so targets must be clean HTTP(S)
base URLs.  Keeping this validation in one small module makes malformed input fail
closed before any network work is scheduled.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit


def normalize_target(raw: str) -> str:
    """Return a canonical HTTP(S) target or raise ``ValueError``."""
    value = str(raw).strip()
    if not value:
        raise ValueError("target is empty")
    if any(ord(ch) < 32 for ch in value) or any(ch.isspace() for ch in value):
        raise ValueError("target contains whitespace or control characters")
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError(f"invalid URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("embedded credentials are not allowed")
    if not parsed.hostname:
        raise ValueError("target has no hostname")
    if parsed.query or parsed.fragment:
        raise ValueError("query strings and fragments are not valid base targets")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target has an invalid port") from exc

    host = parsed.hostname.rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("target hostname is invalid") from exc
        labels = host.split(".")
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("target hostname is invalid")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        if any(set(label) - allowed or label.startswith("-") or label.endswith("-")
               for label in labels):
            raise ValueError("target hostname is invalid")
    else:
        host = ip.compressed

    if ":" in host:  # IPv6 literals require brackets in URLs.
        host = f"[{host}]"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


def parse_targets(lines) -> tuple[list[str], list[tuple[str, str]]]:
    """Normalize and deduplicate input while retaining validation errors."""
    valid: list[str] = []
    invalid: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in lines:
        raw = str(item).strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            target = normalize_target(raw)
        except ValueError as exc:
            invalid.append((raw, str(exc)))
            continue
        if target not in seen:
            seen.add(target)
            valid.append(target)
    return valid, invalid

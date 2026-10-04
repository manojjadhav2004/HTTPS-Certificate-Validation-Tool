"""Safe parsing of the user's input (hostname, host:port or https:// URL)."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

DEFAULT_PORT = 443
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class InvalidTargetError(ValueError):
    """Raised when the hostname / URL / port given by the user is not acceptable."""


def _check_port(port) -> int:
    if isinstance(port, bool):
        raise InvalidTargetError("Port must be a number between 1 and 65535.")
    if isinstance(port, str) and port.strip().isdigit():
        port = int(port.strip())
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise InvalidTargetError("Port must be a number between 1 and 65535.")
    return port


def _check_hostname(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise InvalidTargetError("No hostname given.")
    try:
        ipaddress.ip_address(host)  # IPv4 / IPv6 literal is fine
        return host
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")  # internationalised names -> xn--...
    except UnicodeError:
        raise InvalidTargetError(f"'{host[:60]}' is not a valid hostname.") from None
    if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
        raise InvalidTargetError(f"'{host[:60]}' is not a valid hostname.")
    return host


def parse_target(raw, port=None) -> tuple[str, int]:
    """Return (hostname, port). Raises InvalidTargetError for bad input.

    Accepts: example.com, example.com:8443, https://example.com/path
    Rejects: other schemes (http://, ftp://), whitespace/control characters,
    user-info (user@host) and overlong input.
    """
    if not isinstance(raw, str):
        raise InvalidTargetError("Target must be text.")
    text = raw.strip()
    if not text:
        raise InvalidTargetError("Please enter a hostname or an https:// URL.")
    if len(text) > 2048:
        raise InvalidTargetError("Input is too long.")
    if any(ch.isspace() or ord(ch) < 32 for ch in text):
        raise InvalidTargetError("Input must not contain spaces or control characters.")

    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme.lower() != "https":
            raise InvalidTargetError("Only https:// URLs are supported.")
        netloc = parts.netloc
    else:
        netloc = re.split(r"[/?#]", text, maxsplit=1)[0]

    if not netloc or "@" in netloc:
        raise InvalidTargetError("Could not read a hostname from the input.")
    try:
        parsed = urlsplit("//" + netloc)
        host = parsed.hostname
        url_port = parsed.port
    except ValueError:
        raise InvalidTargetError("Could not read hostname/port from the input.") from None
    if not host:
        raise InvalidTargetError("Could not read a hostname from the input.")

    final_port = _check_port(port if port is not None else (url_port or DEFAULT_PORT))
    return _check_hostname(host), final_port

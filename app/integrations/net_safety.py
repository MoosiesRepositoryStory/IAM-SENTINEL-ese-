"""Outbound URL safety for the webhook adapter (§7.5).

A webhook target is admin-configured, not arbitrary user input — but this
app's public-demo posture (docs/ARCHITECTURE_SPEC.md §13.6) hands out a
shared admin login for recruiter convenience, so "admin-configured" can't be
trusted the way it would be in a closed deployment. Without a guard here, a
public admin session can turn this server into an open SSRF proxy against
loopback services, RFC1918-internal hosts, or cloud metadata endpoints
(169.254.169.254) — genuine infrastructure risk that has nothing to do with
this app's simulated IAM data.

The check resolves the hostname exactly once and validates the RESOLVED IP,
never the hostname string itself — decimal/hex/octal-encoded loopback
addresses (e.g. ``2130706433`` for ``127.0.0.1``) are exactly what plain
string/regex matching on the hostname would miss, and DNS/``getaddrinfo``
resolution normalizes all of those forms before we ever see the result.
That same validated IP is then what the outbound connection dials — pinned
via a custom ``http.client`` connection — instead of letting a second,
independent DNS lookup happen at connect time, which is what closes the
DNS-rebinding gap (a hostname that resolves safely at check-time but
differently at connect-time).

Uses stdlib ``http.client`` directly rather than ``urllib.request`` for one
more reason beyond pinning: ``urlopen``'s default opener follows redirects
automatically, which would silently re-run DNS resolution (and the safety
check) against a *second*, unvalidated URL. Plain ``http.client`` never
follows a ``Location`` header on its own, so a 3xx response is just another
non-2xx status to ``WebhookAdapter`` — already rejected by its existing
``status >= 300`` check, no separate redirect-handling code needed.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlsplit

from app.integrations.base import IntegrationError

CONNECT_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 1_000_000

_ALLOWED_SCHEMES = {"http", "https"}


def _reject(reason: str) -> None:
    raise IntegrationError(f"Webhook target rejected: {reason}")


def _is_unsafe_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for loopback/private/link-local/reserved/multicast/unspecified —
    i.e. anything that isn't a routable, public destination. Also unwraps an
    IPv4-mapped IPv6 address (``::ffff:127.0.0.1``) and checks the address it
    actually maps to, since the unsafe target is the same either way."""
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved \
            or addr.is_multicast or addr.is_unspecified:
        return True
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped is not None and _is_unsafe_address(mapped)


def resolve_safe_target(url: str) -> tuple[str, str, int, str]:
    """Validate ``url``'s shape (scheme, no embedded credentials, has a host)
    and return ``(scheme, hostname, port, path_and_query)``. Raises
    ``IntegrationError`` for anything malformed or unsupported. Does not
    touch the network — see :func:`resolve_pinned_ip` for the DNS step."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES:
        _reject(f"unsupported URL scheme {parts.scheme or '(none)'!r} (only http/https allowed)")
    if parts.username or parts.password:
        _reject("URLs with embedded credentials are not allowed")
    hostname = parts.hostname
    if not hostname:
        _reject("URL is missing a host")
    assert hostname is not None  # narrows for mypy after _reject (raises)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return parts.scheme, hostname, port, path


def resolve_pinned_ip(hostname: str) -> str:
    """Resolve ``hostname`` once and return the IP to connect to, having
    verified it isn't loopback/private/link-local/reserved/multicast.
    Raises ``IntegrationError`` on resolution failure or an unsafe result."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        _reject(f"could not resolve host {hostname!r}: {exc}")
    if not infos:
        _reject(f"could not resolve host {hostname!r}")
    ip_text = str(infos[0][4][0])
    addr = ipaddress.ip_address(ip_text)
    if _is_unsafe_address(addr):
        _reject(f"host {hostname!r} resolves to a disallowed address ({ip_text})")
    return ip_text


class _PinnedHTTPConnection(HTTPConnection):
    """An ``HTTPConnection`` that dials a pre-resolved, pre-validated IP
    instead of re-resolving ``host`` itself at connect time — see the module
    docstring for why that matters (DNS rebinding)."""

    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip
        self._pinned_ssl_context = ssl.create_default_context()

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # server_hostname keeps SNI + certificate hostname verification
        # pinned to the real domain even though the TCP connection dialed
        # the validated IP directly.
        self.sock = self._pinned_ssl_context.wrap_socket(sock, server_hostname=self.host)


def open_pinned_connection(
    scheme: str, hostname: str, port: int, pinned_ip: str, timeout: float
) -> HTTPConnection:
    if scheme == "https":
        return _PinnedHTTPSConnection(hostname, port, pinned_ip, timeout)
    return _PinnedHTTPConnection(hostname, port, pinned_ip, timeout)

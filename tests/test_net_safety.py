"""Outbound URL safety tests for the webhook SSRF guard (§7.5 hardening).

All DNS resolution here is monkeypatched — offline and deterministic, no
real network lookups — matching this project's established "no real
network/CDN dependency in tests" posture (vendored JS libs, moto for AWS).
"""

from __future__ import annotations

import pytest
from app.integrations.base import IntegrationError
from app.integrations.net_safety import resolve_pinned_ip, resolve_safe_target


def _fake_getaddrinfo(ip: str):
    def _fake(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return [(2, 1, 6, "", (ip, 0))]

    return _fake


# ---- resolve_safe_target: URL shape, no network -----------------------------


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://host/x", "host/x"])
def test_rejects_unsupported_schemes(url) -> None:
    with pytest.raises(IntegrationError, match="unsupported URL scheme"):
        resolve_safe_target(url)


def test_rejects_embedded_credentials() -> None:
    with pytest.raises(IntegrationError, match="embedded credentials"):
        resolve_safe_target("http://user:pass@example.com/hooks")


def test_rejects_missing_host() -> None:
    with pytest.raises(IntegrationError, match="missing a host"):
        resolve_safe_target("http:///hooks")


def test_accepts_well_formed_https_url_with_path_and_query() -> None:
    scheme, host, port, path = resolve_safe_target("https://example.com:8443/hooks?x=1")
    assert (scheme, host, port, path) == ("https", "example.com", 8443, "/hooks?x=1")


def test_default_ports_applied_when_unspecified() -> None:
    assert resolve_safe_target("http://example.com/hooks")[2] == 80
    assert resolve_safe_target("https://example.com/hooks")[2] == 443


# ---- resolve_pinned_ip: resolution + address-class checks -------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # private (RFC1918)
        "172.16.0.5",
        "192.168.1.1",
        "169.254.169.254",  # link-local / cloud metadata
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "::1",  # loopback (v6)
        "fc00::1",  # unique local (private, v6)
        "fe80::1",  # link-local (v6)
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6 loopback
    ],
)
def test_rejects_unsafe_resolved_addresses(monkeypatch, ip) -> None:
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo(ip))
    with pytest.raises(IntegrationError, match="disallowed address"):
        resolve_pinned_ip("whatever.example")


def test_accepts_a_public_looking_resolved_address(monkeypatch) -> None:
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert resolve_pinned_ip("example.com") == "93.184.216.34"


def test_decimal_encoded_loopback_is_caught_via_the_resolved_ip_not_the_hostname_string(monkeypatch) -> None:
    """Regardless of what obfuscated form a hostname/URL used (decimal, hex,
    octal IP encodings), the check inspects what it actually RESOLVES to —
    simulated here by making a plausible-looking hostname resolve to
    loopback, exactly the class of bypass that string-matching the hostname
    itself would miss."""
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(IntegrationError, match="disallowed address"):
        resolve_pinned_ip("2130706433")


def test_resolution_failure_is_a_clean_rejection(monkeypatch) -> None:
    def _raise(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise OSError("Name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", _raise)
    with pytest.raises(IntegrationError, match="could not resolve"):
        resolve_pinned_ip("nonexistent.invalid")

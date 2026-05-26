"""Tests for the network guard module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import dns.resolver
import pytest

from easm.network_guard import resolve_and_validate, _is_public_ip, GuardResult


class TestIsPublicIp:
    def test_public_ips(self):
        assert _is_public_ip("8.8.8.8") is True
        assert _is_public_ip("1.1.1.1") is True
        assert _is_public_ip("93.184.216.34") is True

    def test_private_ips(self):
        assert _is_public_ip("10.0.0.1") is False
        assert _is_public_ip("172.16.0.1") is False
        assert _is_public_ip("192.168.1.1") is False

    def test_loopback(self):
        assert _is_public_ip("127.0.0.1") is False

    def test_link_local(self):
        assert _is_public_ip("169.254.1.1") is False

    def test_reserved(self):
        assert _is_public_ip("0.0.0.0") is False

    def test_multicast(self):
        assert _is_public_ip("224.0.0.1") is False

    def test_invalid(self):
        assert _is_public_ip("not-an-ip") is False


def _mock_answers(ips: list[str]):
    answers = []
    for ip in ips:
        r = MagicMock()
        r.__str__ = lambda self, _ip=ip: _ip
        answers.append(r)
    return answers


def _make_resolver_side_effect(a_ips: list[str] | None, nxdomain: bool = False):
    """Build a side_effect function for mock Resolver().resolve()."""
    def _resolve(hostname, rtype):
        if nxdomain:
            raise dns.resolver.NXDOMAIN()
        if rtype == "A" and a_ips is not None:
            return _mock_answers(a_ips)
        raise dns.resolver.NoAnswer()
    return _resolve


class TestResolveAndValidate:
    @patch("easm.network_guard.dns.resolver.Resolver")
    def test_public_only(self, MockResolver):
        MockResolver.return_value.resolve.side_effect = _make_resolver_side_effect(
            a_ips=["93.184.216.34"],
        )
        result = resolve_and_validate("example.com")
        assert result.safe is True
        assert result.public_ips == ["93.184.216.34"]
        assert result.blocked_ips == []

    @patch("easm.network_guard.dns.resolver.Resolver")
    def test_private_ip_blocked(self, MockResolver):
        MockResolver.return_value.resolve.side_effect = _make_resolver_side_effect(
            a_ips=["192.168.1.1"],
        )
        result = resolve_and_validate("test.local")
        assert result.safe is False
        assert "192.168.1.1" in result.blocked_ips

    @patch("easm.network_guard.dns.resolver.Resolver")
    def test_mixed_public_private_blocked(self, MockResolver):
        MockResolver.return_value.resolve.side_effect = _make_resolver_side_effect(
            a_ips=["93.184.216.34", "10.0.0.1"],
        )
        result = resolve_and_validate("example.com")
        assert result.safe is False
        assert "10.0.0.1" in result.blocked_ips
        assert "93.184.216.34" in result.public_ips

    @patch("easm.network_guard.dns.resolver.Resolver")
    def test_nxdomain(self, MockResolver):
        MockResolver.return_value.resolve.side_effect = _make_resolver_side_effect(
            a_ips=None, nxdomain=True,
        )
        result = resolve_and_validate("example.com")
        assert result.safe is False
        assert result.ips == []

    @patch("easm.network_guard.dns.resolver.Resolver")
    def test_loopback_blocked(self, MockResolver):
        MockResolver.return_value.resolve.side_effect = _make_resolver_side_effect(
            a_ips=["127.0.0.1"],
        )
        result = resolve_and_validate("test.local")
        assert result.safe is False
        assert "127.0.0.1" in result.blocked_ips

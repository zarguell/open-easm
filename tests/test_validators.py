"""Tests for domain validation."""

from __future__ import annotations

import pytest

from easm.validators import normalize_domain


class TestNormalizeDomain:
    def test_strips_whitespace(self):
        assert normalize_domain("  example.com  ") == "example.com"

    def test_lowercases(self):
        assert normalize_domain("EXAMPLE.COM") == "example.com"

    def test_strips_trailing_dot(self):
        assert normalize_domain("example.com.") == "example.com"

    def test_subdomain(self):
        assert normalize_domain("www.example.com") == "www.example.com"

    def test_multi_level(self):
        assert normalize_domain("deep.sub.example.co.uk") == "deep.sub.example.co.uk"

    def test_invalid_empty(self):
        with pytest.raises(ValueError, match="Invalid domain"):
            normalize_domain("")

    def test_invalid_single_word(self):
        with pytest.raises(ValueError, match="Invalid domain"):
            normalize_domain("localhost")

    def test_invalid_ip(self):
        with pytest.raises(ValueError, match="Invalid domain"):
            normalize_domain("192.168.1.1")

    def test_invalid_special_chars(self):
        with pytest.raises(ValueError, match="Invalid domain"):
            normalize_domain("exa$mple.com")

    def test_invalid_spaces(self):
        with pytest.raises(ValueError, match="Invalid domain"):
            normalize_domain("exa mple.com")

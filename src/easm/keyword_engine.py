# src/easm/keyword_engine.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from easm.config import TargetConfig


@dataclass
class KeywordMatch:
    keyword: str
    match_type: str
    severity: str
    context: str


CONTEXT_WINDOW = 100


class KeywordEngine:
    def __init__(
        self, target: TargetConfig, custom_patterns: list[dict[str, Any]] | None = None
    ) -> None:
        self._keywords: list[str] = target.match_rules.keywords
        self._domains: list[str] = target.match_rules.domains
        self._patterns: list[tuple[re.Pattern[str], str, str]] = []
        for pat in (custom_patterns or []):
            compiled = re.compile(pat["pattern"], re.IGNORECASE)
            self._patterns.append((compiled, pat.get("severity", "high"), pat.get("label", "")))

    def match(self, text: str) -> list[KeywordMatch]:
        results: list[KeywordMatch] = []
        seen: set[tuple[str, str, int]] = set()

        text_lower = text.lower()

        for keyword in self._keywords:
            kw_lower = keyword.lower()
            idx = text_lower.find(kw_lower)
            if idx != -1:
                key = ("exact", kw_lower, idx)
                if key not in seen:
                    seen.add(key)
                    start = max(0, idx - CONTEXT_WINDOW)
                    end = min(len(text), idx + len(keyword) + CONTEXT_WINDOW)
                    context = text[start:end]
                    results.append(KeywordMatch(
                        keyword=keyword,
                        match_type="exact",
                        severity="medium",
                        context=context,
                    ))

        for domain in self._domains:
            d_lower = domain.lower()
            idx = text_lower.find(d_lower)
            if idx != -1:
                key = ("domain", d_lower, idx)
                if key not in seen:
                    seen.add(key)
                    start = max(0, idx - CONTEXT_WINDOW)
                    end = min(len(text), idx + len(domain) + CONTEXT_WINDOW)
                    context = text[start:end]
                    results.append(KeywordMatch(
                        keyword=domain,
                        match_type="domain",
                        severity="medium",
                        context=context,
                    ))

        for compiled, severity, label in self._patterns:
            for m in compiled.finditer(text):
                key = ("regex", m.group(), m.start())
                if key not in seen:
                    seen.add(key)
                    start = max(0, m.start() - CONTEXT_WINDOW)
                    end = min(len(text), m.end() + CONTEXT_WINDOW)
                    context = text[start:end]
                    results.append(KeywordMatch(
                        keyword=label or m.group(),
                        match_type="regex",
                        severity=severity,
                        context=context,
                    ))

        return results

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class KeywordMatch:
    keyword: str
    keyword_type: str
    matched_text: str
    severity: str
    context: str = ""


class KeywordEngine:
    def __init__(self, target_config: Any):
        self._patterns: list[tuple[re.Pattern, str, str, str]] = []
        self._build_library(target_config)

    def _build_library(self, target_config: Any) -> None:
        match_rules = target_config.match_rules

        for domain in match_rules.domains:
            escaped = re.escape(domain)
            pattern = re.compile(
                r'(?:^|[\s\.:/])(' + escaped + r'|[\w\-\.]+\.' + escaped + r')(?=[\s\.:\?/]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((pattern, domain, "domain", "high"))

            email_pattern = re.compile(
                r'[\w\.\-]+@' + escaped + r'(?=[\s:\?/;,]|$)',
                re.IGNORECASE,
            )
            self._patterns.append((email_pattern, f"@{domain}", "email", "high"))

        for keyword in match_rules.keywords:
            escaped = re.escape(keyword)
            pattern = re.compile(
                re.escape(keyword),
                re.IGNORECASE,
            )
            self._patterns.append((pattern, keyword, "keyword", "medium"))

        for kp in match_rules.keyword_patterns:
            try:
                compiled = re.compile(kp.pattern, re.IGNORECASE)
                self._patterns.append((compiled, kp.pattern, kp.type, kp.severity))
            except re.error:
                pass

    def match(self, text: str) -> list[KeywordMatch]:
        results: list[KeywordMatch] = []
        seen: set[tuple[str, str, str]] = set()

        for pattern, keyword, keyword_type, severity in self._patterns:
            for match_obj in pattern.finditer(text):
                matched_text = match_obj.group(0).strip().lstrip("./:")
                dedup_key = (keyword_type, matched_text, keyword)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                start = max(0, match_obj.start() - 40)
                end = min(len(text), match_obj.end() + 40)
                context = text[start:end].strip()

                results.append(KeywordMatch(
                    keyword=keyword,
                    keyword_type=keyword_type,
                    matched_text=matched_text,
                    severity=severity,
                    context=context,
                ))

        return results

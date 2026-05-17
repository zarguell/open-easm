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
        pass

    def match(self, text: str) -> list[KeywordMatch]:
        return []

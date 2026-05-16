from abc import ABC, abstractmethod
from typing import Any


class PivotHandler(ABC):
    pivot_type: str
    source_name: str

    @abstractmethod
    async def execute(self, job: dict, pool) -> list[dict[str, Any]]:
        pass

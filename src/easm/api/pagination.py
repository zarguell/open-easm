from __future__ import annotations

from typing import Any


class PaginatedQuery:
    """Builder for cursor-based paginated PostgreSQL queries.

    Handles the common pattern of building WHERE clauses with $N
    parameter placeholders and cursor-based LIMIT pagination.
    """

    def __init__(
        self,
        table: str,
        fields: str = "*",
        order_by: str = "id DESC",
        cursor_field: str = "id",
        cursor_cast: str = "::uuid",
    ) -> None:
        self._table = table
        self._fields = fields
        self._order_by = order_by
        self._cursor_field = cursor_field
        self._cursor_cast = cursor_cast
        self._conditions: list[str] = []
        self._params: list[Any] = []
        self._idx = 0

    def add_filter(self, column: str, value: Any, cast: str = "") -> PaginatedQuery:
        """Add an equality filter if value is not None/empty."""
        if value is None:
            return self
        if isinstance(value, str) and not value.strip():
            return self
        self._idx += 1
        self._conditions.append(f"{column} = ${self._idx}{cast}")
        self._params.append(value)
        return self

    def add_range(self, column: str, op: str, value: Any, cast: str = "") -> PaginatedQuery:
        """Add a range filter (>=, <=, <, >) if value is not None/empty."""
        if value is None:
            return self
        if isinstance(value, str) and not value.strip():
            return self
        self._idx += 1
        self._conditions.append(f"{column} {op} ${self._idx}{cast}")
        self._params.append(value)
        return self

    def add_ilike(self, column: str, value: str | None) -> PaginatedQuery:
        """Add a case-insensitive LIKE filter."""
        if not value:
            return self
        self._idx += 1
        self._conditions.append(f"{column} ILIKE ${self._idx}")
        self._params.append(f"%{value}%")
        return self

    def add_cursor(self, cursor: str | None) -> PaginatedQuery:
        """Add cursor-based pagination (id < cursor)."""
        if cursor:
            self._idx += 1
            self._conditions.append(
                f"{self._cursor_field} < ${self._idx}{self._cursor_cast}"
            )
            self._params.append(cursor)
        return self

    def build(self, limit: int) -> tuple[str, list[Any]]:
        """Build the final SQL query and parameter list.

        Returns (query, params) where params includes limit+1 for
        has_more detection (fetch one extra row).
        """
        self._idx += 1
        where = (
            f"WHERE {' AND '.join(self._conditions)}"
            if self._conditions
            else ""
        )
        query = (
            f"SELECT {self._fields} FROM {self._table} "
            f"{where} "
            f"ORDER BY {self._order_by} "
            f"LIMIT ${self._idx}"
        )
        self._params.append(limit + 1)
        return query, self._params

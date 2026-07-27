"""Pagination helpers: cursor-based query builder and a unified response envelope.

The ``PaginatedResponse`` model is the standard envelope returned by every
list endpoint in the API. ``PaginatedQuery`` is a small builder used by some
routes to assemble parameterised cursor-based SQL.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard envelope for all paginated list endpoints.

    Fields:
        items: The page of results (typed by the generic parameter).
        total: Total number of records matching the current filters.
        next_cursor: Opaque cursor for the next page, or ``None`` when the
            end of the result set has been reached.
    """

    items: list[T]
    total: int
    next_cursor: str | None = None


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
        """Initialise the query builder with table and ordering defaults."""
        self._table = table
        self._fields = fields
        self._order_by = order_by
        self._cursor_field = cursor_field
        self._cursor_cast = cursor_cast
        self._conditions: list[str] = []
        self._params: list[Any] = []
        self._idx = 0

    def add_filter(self, column: str, value: Any, cast: str = "") -> PaginatedQuery:  # noqa: ANN401
        """Add an equality filter if value is not None/empty."""
        if value is None:
            return self
        if isinstance(value, str) and not value.strip():
            return self
        self._idx += 1
        self._conditions.append(f"{column} = ${self._idx}{cast}")
        self._params.append(value)
        return self

    def add_range(self, column: str, op: str, value: Any, cast: str = "") -> PaginatedQuery:  # noqa: ANN401
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
        # Parameterised via $N placeholders; values never interpolated.
        query = (
            f"SELECT {self._fields} FROM {self._table} "  # noqa: S608
            f"{where} "
            f"ORDER BY {self._order_by} "
            f"LIMIT ${self._idx}"
        )
        self._params.append(limit + 1)
        return query, self._params

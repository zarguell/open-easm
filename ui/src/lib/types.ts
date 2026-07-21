/**
 * Shared API types.
 *
 * PaginatedResponse is the standard envelope returned by every backend list
 * endpoint (see src/easm/api/pagination.py). API client hooks parse this
 * envelope at the boundary and expose whichever subset (items, total,
 * next_cursor) their consumers need.
 */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  next_cursor: string | null
}

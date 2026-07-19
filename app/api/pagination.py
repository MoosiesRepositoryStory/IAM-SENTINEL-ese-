"""Shared ``?limit=&offset=`` pagination (§10.4) for every list endpoint —
one convention across /accounts, /runs, /findings, /principals, /compliance,
/checks rather than each route inventing its own. Total count rides in the
``X-Total-Count`` response header (not the body), so a paginated list's JSON
is just the array of items — a plain client doesn't need to unwrap an
envelope to get at the data it asked for.
"""

from __future__ import annotations

from marshmallow import Schema, fields, validate

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


class PaginationArgsSchema(Schema):
    limit = fields.Integer(
        load_default=DEFAULT_LIMIT, validate=validate.Range(min=1, max=MAX_LIMIT)
    )
    offset = fields.Integer(load_default=0, validate=validate.Range(min=0))


def total_count_headers(total: int) -> dict[str, str]:
    return {"X-Total-Count": str(total)}

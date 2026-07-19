"""Standard error envelope (§10.4): every /api/ response's error shape is
``{"error": {"code", "message", "details"}}`` — regardless of whether it came
from an explicit :class:`ApiError`, a flask-smorest/webargs validation
failure, an unmatched route, or an unhandled exception. Registered once from
``app.api.init_api`` and scoped to ``/api/`` paths only, so it doesn't change
the HTML app's own (default Flask) error pages.
"""

from __future__ import annotations

from flask import Flask, current_app, jsonify, request
from werkzeug.exceptions import HTTPException


class ApiError(Exception):
    """Raise directly from a route/decorator for a specific status+code+message
    (e.g. 401 unauthorized, 404 not_found) — plain ``Exception``, not
    ``HTTPException``, so it can carry the envelope's exact shape without
    fighting Werkzeug's own exception formatting."""

    def __init__(self, status_code: int, code: str, message: str, details: object = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def _is_api_path() -> bool:
    return request.path.startswith("/api/")


def _envelope(code: str, message: str, details: object = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _handle_api_error(exc: ApiError):
        return jsonify(_envelope(exc.code, exc.message, exc.details)), exc.status_code

    @app.errorhandler(HTTPException)
    def _handle_http_exception(exc: HTTPException):
        if not _is_api_path():
            return exc  # HTML app: let Flask's normal error page render
        # webargs/flask-smorest attach validation failures as `exc.data["messages"]`
        # on a 422 UnprocessableEntity — surface them as `details` rather than
        # losing them behind a generic message.
        details = None
        data = getattr(exc, "data", None)
        if isinstance(data, dict):
            details = data.get("messages") or data.get("errors")
        code = (exc.name or "error").lower().replace(" ", "_")
        return jsonify(_envelope(code, exc.description or code, details)), exc.code or 500

    @app.errorhandler(Exception)
    def _handle_unexpected(exc: Exception):
        if not _is_api_path():
            raise exc
        current_app.logger.exception("Unhandled /api/ error")
        return jsonify(_envelope("internal_error", "An unexpected error occurred.")), 500

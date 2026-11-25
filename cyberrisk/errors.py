from __future__ import annotations


class AppError(Exception):
    status, code = 500, "internal_error"

    def __init__(self, message: str, details=None):
        super().__init__(message)
        self.message, self.details = message, details


class Invalid(AppError):
    status, code = 422, "validation_error"


class NotFound(AppError):
    status, code = 404, "not_found"


class Conflict(AppError):
    status, code = 409, "conflict"


class Unauthorized(AppError):
    status, code = 401, "unauthorized"


class Forbidden(AppError):
    status, code = 403, "forbidden"


class RateLimited(AppError):
    status, code = 429, "rate_limited"

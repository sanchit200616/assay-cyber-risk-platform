"""Server-side RBAC. Deny by default: unknown roles/permissions grant nothing."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

_ANALYST = {"vendors.read", "assets.read", "assessments.read", "findings.write", "evidence.write", "intel.read",
            "intel.collect", "rag.query", "workflows.read", "workflows.write", "reports.read", "dashboard.read", "jobs.read"}
_ASSESSOR = _ANALYST | {"vendors.write", "assets.write", "assessments.write", "assessments.run", "reports.write"}
_ADMIN = _ASSESSOR | {"documents.write", "audit.read", "users.manage", "apikeys.manage", "jobs.run", "metrics.read"}

ROLE_PERMISSIONS = {"analyst": frozenset(_ANALYST), "assessor": frozenset(_ASSESSOR), "admin": frozenset(_ADMIN)}
ALL_PERMISSIONS = frozenset(_ADMIN)


@dataclass(frozen=True)
class Principal:
    id: str
    email: str
    role: str
    permissions: FrozenSet[str] = field(default_factory=frozenset)
    via: str = "token"

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def principal_for_role(user_id: str, email: str, role: str, via: str = "token") -> Principal:
    return Principal(user_id, email, role, ROLE_PERMISSIONS.get(role, frozenset()), via)

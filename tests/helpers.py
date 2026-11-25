import json
import sys
import pathlib
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cyberrisk.api import App
from cyberrisk.config import load_settings
from cyberrisk.db import Database
from cyberrisk.service import Platform

NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
PW = {"admin": "admin-pass-1234", "assessor": "assessor-pass-1234", "analyst": "analyst-pass-1234"}


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += timedelta(seconds=seconds)


class Env:
    """Isolated in-memory platform + API, three users, controllable clock."""

    def __init__(self, extra_env=None, seed_users=True):
        env = {"APP_ENV": "test", "DATABASE_URL": "sqlite:///:memory:", "SECRET_KEY": "k" * 40, "JOB_BACKOFF_BASE_SECONDS": "2",
               "JOB_BACKOFF_CAP_SECONDS": "10", "RATE_LIMIT_PER_MINUTE": "100000"}
        env.update(extra_env or {})
        self.settings = load_settings(env)
        self.db = Database(":memory:")
        self.db.migrate()
        self.clock = Clock()
        self.p = Platform(self.db, self.settings, clock=self.clock)
        self.app = App(self.p, self.settings)
        self.tokens = {}
        if seed_users:
            for role in PW:
                self.p.create_user(f"{role}@test.example", PW[role], role, actor="test")
                self.tokens[role] = self.login(f"{role}@test.example", PW[role])[1]["access_token"]

    def call(self, method, path, role=None, body=None, headers=None, token=None, raw=False, ip="127.0.0.1"):
        h = dict(headers or {})
        tok = token or (self.tokens.get(role) if role else None)
        if tok:
            h["Authorization"] = "Bearer " + tok
        data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        status, rh, rb = self.app.handle(method, path, h, data, ip)
        if raw:
            return status, rh, rb
        return status, (json.loads(rb) if rb and rh.get("Content-Type", "").startswith("application/json") else rb)

    def login(self, email, password):
        return self.call("POST", "/api/v1/auth/login", body={"email": email, "password": password})

    # convenience builders
    def vendor(self, role="assessor", **kw):
        d = {"name": "Acme Test Vendor", "category": "SaaS", "domain": "acme-test.example", "criticality": "high", "synthetic": True}
        d.update(kw)
        s, b = self.call("POST", "/api/v1/vendors", role, d)
        assert s == 201, b
        return b

    def assessment(self, vendor_id, role="assessor"):
        s, b = self.call("POST", "/api/v1/assessments", role, {"vendor_id": vendor_id, "title": "Test assessment"})
        assert s == 201, b
        return b

    def finding(self, asm_id, role="analyst", **kw):
        d = {"title": "Test finding", "factor": "vulnerability", "severity": "high", "source": "unit", "confidence": 0.8,
             "observed_at": "2026-11-10T00:00:00Z"}
        d.update(kw)
        s, b = self.call("POST", f"/api/v1/assessments/{asm_id}/findings", role, d)
        assert s == 201, b
        return b


def seeded_env(**kw):
    from cyberrisk.seed import seed_demo
    e = Env(seed_users=False, **kw)
    out = seed_demo(e.p, PW)
    for role in PW:
        e.tokens[role] = e.login(f"{role}@demo.example", PW[role])[1]["access_token"]
    e.seed = out
    return e

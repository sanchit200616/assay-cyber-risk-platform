"""Threaded stdlib HTTP server adapter around App.handle()."""
from __future__ import annotations

import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .api import App
from .config import Settings, load_settings
from .db import Database
from .jobs import Worker
from .observability import configure_logging, event
from .service import Platform


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Assay"
        sys_version = ""

        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > app.s.max_body_bytes:
                body, status, headers = b'{"error":{"code":"payload_too_large","message":"request body too large"}}', 413, {"Content-Type": "application/json"}
                self.close_connection = True
            else:
                body_in = self.rfile.read(length) if length else b""
                status, headers, body = app.handle(self.command, self.path, dict(self.headers.items()), body_in, self.client_address[0])
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = _serve

        def log_message(self, *args):  # structured access logging happens in App.handle
            pass

    return Handler


def build_platform(settings: Settings, migrate: bool = True) -> Platform:
    db = Database(settings.database_path)
    if migrate:
        db.migrate()
    return Platform(db, settings)


def serve(settings: Settings | None = None, with_worker: bool = True):
    settings = settings or load_settings()
    configure_logging(logging.INFO)
    platform = build_platform(settings)
    if settings.secret_is_ephemeral:
        event("config.warning", message="SECRET_KEY not set: using an ephemeral key (tokens die on restart). Set SECRET_KEY for stable sessions.")
    app = App(platform, settings)
    worker = Worker(platform.jobs, platform.handlers()) if with_worker else None
    if worker:
        worker.start()
    httpd = ThreadingHTTPServer((settings.host, settings.port), make_handler(app))
    event("server.start", host=settings.host, port=settings.port, env=settings.app_env)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        if worker:
            worker.stop()
        platform.db.close()
        event("server.stopped")

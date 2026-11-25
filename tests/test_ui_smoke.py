import pathlib
import shutil
import subprocess
import threading
import unittest
from http.server import ThreadingHTTPServer

from tests.helpers import *  # noqa
from cyberrisk.server import make_handler

ROOT = pathlib.Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which("node"), "node not installed")
class UiSmoke(unittest.TestCase):
    def run_as(self, role):
        e = seeded_env()
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(e.app))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            out = subprocess.run(["node", str(ROOT / "tests/ui_smoke.js"), str(httpd.server_address[1]), f"{role}@demo.example", PW[role],
                                  e.seed["vendors"][0], e.seed["assessment_id"], role], capture_output=True, text=True, timeout=60)
        finally:
            httpd.shutdown(); httpd.server_close()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_admin_views_render(self):
        self.run_as("admin")

    def test_analyst_views_respect_permissions(self):
        self.run_as("analyst")

    def test_ui_never_uses_innerhtml(self):
        src = (ROOT / "cyberrisk/web/app.js").read_text()
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(banned, src)


if __name__ == "__main__":
    unittest.main()

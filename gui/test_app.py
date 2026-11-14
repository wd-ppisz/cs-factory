#!/usr/bin/env python3
"""Quick GUI test (CI dev stage) - Flask test client, no network and no OIDC.

Requires flask and authlib (python3-flask / python3-authlib on Debian).
Run from the repository root: python3 -m unittest gui/test_app.py
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("FACTORY_REPO", str(ROOT))
# hermetic: an empty artifacts directory instead of the production one
os.environ.setdefault("FACTORY_ARTIFACTS", tempfile.mkdtemp(prefix="cs-factory-test-"))
os.environ.setdefault("FACTORY_AUTH_DISABLED", "1")
os.environ.setdefault("FLASK_SECRET", "test")
# hermetic: never pick up a real runtime credentials file
os.environ.setdefault("CS_CREDS_FILE", str(Path(tempfile.mkdtemp(prefix="cs-factory-creds-")) / "none.json"))
sys.path.insert(0, str(ROOT / "gui"))

import app as gui  # noqa: E402


class Healthz(unittest.TestCase):
    def setUp(self):
        self.c = gui.app.test_client()

    def test_plain(self):
        r = self.c.get("/healthz")
        self.assertEqual((r.status_code, r.data), (200, b"ok\n"))

    def test_verbose_for_deploy(self):
        r = self.c.get("/healthz?verbose=1")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d["busy"], 0)
        self.assertRegex(d["running_commit"], r"^([0-9a-f]{40})?$")

    def test_busy_counts_unfinished(self):
        with gui._lock:
            gui._jobs.extend([{"state": "building image"}, {"state": "PASS"}, {"state": "ERROR: x"}])
        try:
            self.assertEqual(json.loads(self.c.get("/healthz?verbose=1").data)["busy"], 1)
        finally:
            with gui._lock:
                del gui._jobs[-3:]

    def test_version_from_file(self):
        self.assertEqual(gui.release_version(), (ROOT / "VERSION").read_text().strip())

    def test_dashboard_renders(self):
        # auth disabled in the test - we only check that the view does not crash
        r = self.c.get("/")
        self.assertIn(r.status_code, (200, 302))

    def test_missing_config_is_reported(self):
        # no site-specific defaults: an unconfigured GUI says what is missing
        if gui.GITLAB_URL:
            self.skipTest("GITLAB_URL set in the environment")
        r = self.c.get("/")
        self.assertIn(b"Configuration incomplete", r.data)
        self.assertIn(b"GITLAB_URL", r.data)


class SafeUrl(unittest.TestCase):
    """B310: the GUI opener never reads local files and never goes to ftp."""

    def test_file_rejected(self):
        with self.assertRaises(ValueError):
            gui.cs.safe_urlopen("file:///etc/passwd", timeout=1)

    def test_request_file_rejected(self):
        import urllib.request
        with self.assertRaises(ValueError):
            gui.cs.safe_urlopen(urllib.request.Request("file:///etc/passwd"), timeout=1)

    def test_no_file_or_ftp_handler(self):
        import urllib.error
        import urllib.request
        # even when the scheme check is bypassed (e.g. a redirect) - no handler
        for url in ("file:///etc/passwd", "ftp://example.invalid/x"):
            with self.assertRaises(urllib.error.URLError):
                gui.cs._OPENER.open(urllib.request.Request(url), timeout=1)


if __name__ == "__main__":
    unittest.main()

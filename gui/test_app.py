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
        self.assertIn(b"ARTIFACTS_BASE_URL", r.data)

    def test_gitlab_is_optional(self):
        # standalone mode: no GitLab is not a configuration error, and no CI link
        if gui.GITLAB_URL:
            self.skipTest("GITLAB_URL set in the environment")
        r = self.c.get("/")
        self.assertNotIn(b"GITLAB_URL", r.data)
        self.assertNotIn(b'href="/ci"', r.data)


class Standalone(unittest.TestCase):
    """Docker release: manifests from the wizard go to CSF_LOCAL_DISTROS."""

    def setUp(self):
        self.c = gui.app.test_client()
        self.local = Path(tempfile.mkdtemp(prefix="cs-factory-local-"))
        self._old = gui.LOCAL_DISTROS
        gui.LOCAL_DISTROS = self.local

    def tearDown(self):
        gui.LOCAL_DISTROS = self._old

    def _data(self, slug):
        return {"slug": slug, "name": "Test Linux 1", "url": "https://example.invalid/x.qcow2", "sums_url": "",
                "sha": "a" * 64, "disk": "10G", "epel": "false",
                "pkgs": ["qemu-guest-agent", "fail2ban"], "ostype": "Other Linux (64-bit)"}

    def test_save_local_manifest(self):
        d = self._data("testlinux-1")
        r = gui.app.test_request_context("/new")
        with r:
            gui._save_local_manifest(d, gui.render_manifest(d, "t"))
        p = self.local / "testlinux-1.yaml"
        self.assertTrue(p.is_file())
        self.assertIn('cs_ostype: "Other Linux (64-bit)"', p.read_text())
        self.assertIn("testlinux-1", gui.list_manifests())
        self.assertEqual(gui.manifest_path("testlinux-1"), p)
        self.assertEqual(gui.manifest_field("testlinux-1", "cs_ostype"), "Other Linux (64-bit)")

    def test_builtin_cannot_be_replaced(self):
        d = self._data("debian-13")
        with gui.app.test_request_context("/new"):
            out = gui._save_local_manifest(d, "x")
        self.assertIn("built-in distribution", out if isinstance(out, str) else out[0])
        self.assertFalse((self.local / "debian-13.yaml").exists())

    def test_builtin_wins_over_local(self):
        (self.local / "debian-13.yaml").write_text('name: "shadow"\n')
        self.assertEqual(gui.manifest_path("debian-13"), ROOT / "distros" / "debian-13.yaml")

    def test_manifest_path_rejects_traversal(self):
        self.assertIsNone(gui.manifest_path("../etc/passwd"))


class WizardValidation(unittest.TestCase):
    """Values end up inside a YAML manifest - no field may smuggle in keys."""

    def _form(self, **kw):
        f = {"slug": "testlinux-1", "name": "Test Linux 1",
             "url": "https://example.invalid/x.qcow2", "sha": "a" * 64,
             "packages": "qemu-guest-agent\nfail2ban", "disk_size": "10G"}
        f.update(kw)
        return f

    def _errors(self, **kw):
        # network checks are skipped once a syntax error is found; for the
        # valid baseline they would hit example.invalid - stub them out
        orig = gui._http
        gui._http = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
        try:
            return gui.validate_form(self._form(**kw))[1]
        finally:
            gui._http = orig

    def test_sums_url_injection_rejected(self):
        errs = self._errors(sums_url='https://e.invalid/SUMS"\nepel: true')
        self.assertTrue(any("Checksum file URL" in e for e in errs), errs)

    def test_ostype_injection_rejected(self):
        errs = self._errors(cs_ostype='Linux"\npackages: []')
        self.assertTrue(any("OS type" in e for e in errs), errs)


class BuildPipeline(unittest.TestCase):
    def test_find_env_by_content_not_name(self):
        b = Path(tempfile.mkdtemp(prefix="cs-factory-build-"))
        old = gui.BUILDS
        gui.BUILDS = b
        try:
            # display name "Ubuntu 26.04" -> file name differs from the slug ubuntu-26.04
            e = b / "template-ubuntu-26_04-v1_2.env"
            e.write_text("TEMPLATE_NAME=Template Ubuntu 26.04 v1.2\nIMG=/x\nDISTRO=ubuntu-26.04\nVERSION=1.2\n")
            (b / "template-debian-13-v1_2.env").write_text("DISTRO=debian-13\nVERSION=1.2\n")
            self.assertEqual(gui._find_build_env("ubuntu-26.04", "1.2", 0), e)
            self.assertIsNone(gui._find_build_env("ubuntu-26.04", "1.3", 0))
        finally:
            gui.BUILDS = old

    def test_publish_moves_image_and_rewrites_img(self):
        b = Path(tempfile.mkdtemp(prefix="cs-factory-build-"))
        a = Path(tempfile.mkdtemp(prefix="cs-factory-arts-"))
        old = gui.ARTIFACTS
        gui.ARTIFACTS = a
        try:
            img = b / "template-x-v1_0.qcow2"
            img.write_bytes(b"qcow")
            env = b / "template-x-v1_0.env"
            env.write_text(f"TEMPLATE_NAME=Template X v1.0\nIMG={img}\nDISTRO=x\nVERSION=1.0\n")
            dst = gui._publish(env, img)
            self.assertEqual(dst.read_bytes(), b"qcow")
            self.assertFalse(img.exists())
            self.assertIn(f"IMG={dst}", (a / env.name).read_text())
            self.assertEqual([p.name for p in a.glob(".*")], [])   # no leftovers
        finally:
            gui.ARTIFACTS = old


class LocalLogin(unittest.TestCase):
    """FACTORY_ADMIN_PASSWORD: the simple alternative to OIDC."""

    def setUp(self):
        self.c = gui.app.test_client()
        self.saved = (gui.AUTH_DISABLED, gui.LOCAL_LOGIN, gui.ADMIN_PASSWORD)
        gui.AUTH_DISABLED, gui.LOCAL_LOGIN, gui.ADMIN_PASSWORD = False, True, "s3cret-pass-123"
        gui._login_fails.clear()
        gui.app.config["SESSION_COOKIE_SECURE"] = False

    def tearDown(self):
        gui.AUTH_DISABLED, gui.LOCAL_LOGIN, gui.ADMIN_PASSWORD = self.saved
        gui._login_fails.clear()

    def test_redirects_to_login(self):
        r = self.c.get("/settings")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_wrong_password(self):
        r = self.c.post("/login", data={"user": "admin", "password": "nope"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.c.get("/").status_code, 302)

    def test_good_password_and_next(self):
        self.c.get("/settings")              # remembers next=/settings
        r = self.c.post("/login", data={"user": "admin", "password": "s3cret-pass-123"})
        self.assertEqual((r.status_code, r.headers["Location"]), (302, "/settings"))
        self.assertEqual(self.c.get("/").status_code, 200)

    def test_lockout(self):
        gui._login_fails.extend([__import__("time").time()] * gui.LOGIN_MAX_FAILS)
        r = self.c.post("/login", data={"user": "admin", "password": "s3cret-pass-123"})
        self.assertEqual(r.status_code, 429)

    def test_no_open_redirect(self):
        with gui.app.test_request_context("/"):
            for bad in ("//evil.example", "https://evil.example", "/\\evil"):
                gui.session["next"] = bad
                self.assertEqual(gui._safe_next(), "/")


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

#!/usr/bin/env python3
"""cs-factory - operator GUI for the CloudStack template factory.

Goal: an operator WITHOUT technical knowledge adds a distribution and builds a
template from the browser only. No hand-editing YAML, no git, no SSH.

Layers (typical deployment):
  operator -> your reverse proxy / edge (TLS, optional IP allowlist)
           -> nginx on the factory host :80 (proxy_buffering off - SSE)
           -> gunicorn 127.0.0.1:8500 (gthread, --timeout 0)
           -> Flask + Authlib OIDC (any OIDC provider, group-based access)

What it does:
  * Distribution WIZARD - form fields (not YAML) + content validation:
    checks HTTP reachability of the image and the checksum file, presence of an
    entry for the file in the checksums, enforces qemu-guest-agent + fail2ban,
    suggests a standard package set. Save = manifest commit to GitLab via API ->
    the child pipeline builds it on its own.
  * LOCAL BUILD (on this host) from any manifest - with a live log view.
  * LIVE CI VIEW - pipelines, jobs and traces from the GitLab API.
  * Artifacts (qcow2) are served by nginx under /artifacts/ (URL for register.sh).

All site-specific settings (OIDC, GitLab, CloudStack, artifact URL) come from
the environment (/etc/cs-factory/gui.env). There are no built-in defaults for
them; missing values are reported in the GUI.
"""
import html
import json
import os
import queue
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, request, session, url_for, Response
from werkzeug.middleware.proxy_fix import ProxyFix

import cs

REPO = Path(os.environ.get("FACTORY_REPO", "/srv/cs-factory/repo"))
BUILDS = REPO / "build"
LOGS = BUILDS / "logs"
# Artifacts = images that PASSED the gate (published by `make publish` from CI
# and by local builds).
ARTIFACTS = Path(os.environ.get("FACTORY_ARTIFACTS", "/srv/cs-factory/artifacts"))
# URL from which the CloudStack SSVM downloads the image - typically an INTERNAL
# address reachable from the secondary storage VM, not the public GUI URL.
ARTIFACTS_BASE_URL = os.environ.get("ARTIFACTS_BASE_URL", "").rstrip("/")

EXTERNAL_URL = os.environ.get("EXTERNAL_URL", "").rstrip("/")
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
REQUIRED_GROUP = os.environ.get("REQUIRED_GROUP", "admins")
AUTH_DISABLED = os.environ.get("FACTORY_AUTH_DISABLED") == "1"   # dev/bootstrap only

GITLAB_URL = os.environ.get("GITLAB_URL", "").rstrip("/")
# numeric project ID or full path ("group/project")
GITLAB_PROJECT = os.environ.get("GITLAB_PROJECT", "")
GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN", "")
GITLAB_BRANCH = os.environ.get("GITLAB_BRANCH", "main")
# optional commit author e-mail for manifests saved from the GUI; empty = GitLab
# uses the token owner's identity
GITLAB_COMMIT_EMAIL = os.environ.get("GITLAB_COMMIT_EMAIL", "")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32).hex())
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax")

OIDC_CONFIGURED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and EXTERNAL_URL)

oauth = OAuth(app)
if OIDC_CONFIGURED:
    # NOTE: we do not request a "groups" scope - many providers (e.g. Keycloak)
    # have no such client scope. The `groups` claim should come from a
    # group-membership mapper configured on the client.
    oauth.register("oidc", client_id=OIDC_CLIENT_ID, client_secret=OIDC_CLIENT_SECRET,
                   server_metadata_url=OIDC_ISSUER + "/.well-known/openid-configuration",
                   client_kwargs={"scope": "openid profile email"})

_jobs: list[dict] = []
_q: "queue.Queue[dict]" = queue.Queue()
_lock = threading.Lock()

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")
VER_RE = re.compile(r"^[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^([0-9a-f]{64}|[0-9a-f]{128})$")
SIZE_RE = re.compile(r"^[0-9]{1,3}[GM]$")
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,60}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,40}$")

STD_PACKAGES = ["qemu-guest-agent", "fail2ban", "chrony", "curl", "jq", "python3"]


def release_version() -> str:
    """Template release number - SINGLE source of truth: the VERSION file in the
    repository (the same one read by the Makefile, ci/gen-child.sh and register.sh).

    The number in the form is the one under which the build stores the artifact
    and under which the template lands in CloudStack. A hard-coded value would
    mean that after bumping VERSION an operator builds NEW content under an OLD
    name and overwrites the artifact of an already registered template.
    Read on every request, because the repository is updated underneath the
    running service (git pull from CI) - restarting the GUI requires root and
    cannot be a precondition.
    """
    try:
        w = (REPO / "VERSION").read_text().strip()
    except OSError:
        return "1.0"
    return w if VER_RE.match(w) else "1.0"


MUST_HAVE = ("qemu-guest-agent", "fail2ban")


def missing_config() -> list[str]:
    """Names of site-specific settings that are not configured."""
    out = []
    if not AUTH_DISABLED:
        for name, val in (("OIDC_ISSUER", OIDC_ISSUER), ("OIDC_CLIENT_ID", OIDC_CLIENT_ID),
                          ("EXTERNAL_URL", EXTERNAL_URL)):
            if not val:
                out.append(name)
    for name, val in (("GITLAB_URL", GITLAB_URL), ("GITLAB_PROJECT", GITLAB_PROJECT),
                      ("GITLAB_TOKEN", GITLAB_TOKEN), ("ARTIFACTS_BASE_URL", ARTIFACTS_BASE_URL)):
        if not val:
            out.append(name)
    if not cs.creds()["api_url"]:
        out.append("CS_API_URL")
    return out


# ---------- helpers --------------------------------------------------------

def list_manifests() -> list[str]:
    return sorted(p.stem for p in (REPO / "distros").glob("*.yaml"))


def manifest_field(distro: str, key: str) -> str:
    """Reads a single field from a manifest (no pyyaml dependency)."""
    p = REPO / "distros" / f"{distro}.yaml"
    if not p.exists():
        return ""
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}:"):
            v = line.split(":", 1)[1].strip()
            # a quoted value may be followed by a comment:
            #   cs_ostype: "Debian GNU/Linux 12 (64-bit)"  # CS 4.22 has no ...
            m = re.match(r'^"([^"]*)"', v)
            return m.group(1) if m else v.split("#")[0].strip()
    return ""


def list_artifacts() -> list[dict]:
    """Finished images (after PASS) from the artifacts directory."""
    out = []
    if not ARTIFACTS.is_dir():
        return out
    for p in sorted(ARTIFACTS.glob("*.qcow2"), key=lambda x: x.stat().st_mtime, reverse=True):
        env = p.with_suffix(".env")
        meta = {}
        if env.exists():
            for line in env.read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    meta[k.strip()] = v.strip()
        tname = meta.get("TEMPLATE_NAME", "")
        # DISTRO from .env - the file slug is NOT reversible to a manifest name
        # (e.g. "openSUSE Leap 16.0" -> template-opensuse-leap-16_0-v1_0)
        distro = meta.get("DISTRO", "")
        if not distro:  # artifacts built before DISTRO was added to .env
            m = re.match(r"^template-(.+)-v[0-9]+_[0-9]+$", p.stem)
            cand = m.group(1) if m else ""
            known = list_manifests()
            distro = cand if cand in known else next(
                (k for k in known if cand.startswith(k)), "")
        out.append({"file": p.name, "size_mb": round(p.stat().st_size / 1048576),
                    "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime)),
                    "template_name": tname or p.stem, "distro": distro,
                    "ostype": manifest_field(distro, "cs_ostype") if distro else ""})
    return out


def _http(url: str, method: str = "GET", token: bool = False,
          data: bytes | None = None, timeout: int = 20):
    req = urllib.request.Request(url, method=method, data=data)
    if token:
        req.add_header("PRIVATE-TOKEN", GITLAB_TOKEN)
    if data:
        req.add_header("Content-Type", "application/json")
    # http/https only, also after redirects - see cs.safe_urlopen
    return cs.safe_urlopen(req, timeout=timeout)


def _gitlab_project_api() -> str:
    if not (GITLAB_URL and GITLAB_PROJECT):
        raise RuntimeError("GitLab is not configured (set GITLAB_URL and GITLAB_PROJECT in gui.env)")
    return f"{GITLAB_URL}/api/v4/projects/{urllib.parse.quote(GITLAB_PROJECT, safe='')}"


def gitlab(path: str, method: str = "GET", payload: dict | None = None):
    url = _gitlab_project_api() + path
    data = json.dumps(payload).encode() if payload else None
    with _http(url, method=method, token=True, data=data, timeout=25) as r:
        body = r.read()
    return json.loads(body) if body else {}


def sums_lookup(sums_url: str, filename: str) -> str | None:
    """Find a file's hash in a checksum file. Three formats: GNU (2 spaces),
    GNU binary (hash *file), BSD tag (SHA256 (file) = hash)."""
    with _http(sums_url, timeout=25) as r:
        text = r.read(4_000_000).decode("utf-8", "replace")
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] in ("SHA256", "SHA512") and p[1] == f"({filename})":
            return p[-1]
        if len(p) >= 2 and (p[1] == filename or p[1] == "*" + filename):
            return p[0]
        if len(p) == 2 and p[1].lstrip("*").endswith("/" + filename):
            return p[0]
    return None


def validate_form(f) -> tuple[dict, list[str]]:
    """Returns (data, errors). Validates CONTENT, not just syntax."""
    err: list[str] = []
    slug = (f.get("slug") or "").strip().lower()
    name = (f.get("name") or "").strip()
    url = (f.get("url") or "").strip()
    sums_url = (f.get("sums_url") or "").strip()
    sha = (f.get("sha") or "").strip().lower()
    disk = (f.get("disk_size") or "10G").strip().upper()
    epel = "true" if f.get("epel") else "false"
    pkgs_raw = (f.get("packages") or "").replace(",", "\n").split("\n")
    pkgs = [p.strip() for p in pkgs_raw if p.strip()] or list(STD_PACKAGES)

    if not SLUG_RE.match(slug):
        err.append("Technical name: lowercase letters/digits/dot/hyphen, e.g. ubuntu-26.04.")
    if slug.startswith("custom-"):
        err.append("The custom- prefix is reserved for one-off builds.")
    if not NAME_RE.match(name):
        err.append("Display name is required (it becomes part of the CloudStack template name).")
    if not SIZE_RE.match(disk):
        err.append("Disk size as number+G/M, e.g. 10G.")
    else:
        # policy: no template goes below 10G - a disk that is too small shows up to
        # the user as a "system" problem during the first operations on the VM
        disk_g = int(disk[:-1]) if disk.endswith("G") else int(disk[:-1]) // 1024
        if disk_g < 10:
            err.append(f"Disk {disk} is too small - the minimum is 10G. A smaller disk "
                       "runs out of space right after the machine starts.")
    bad = [p for p in pkgs if not PKG_RE.match(p)]
    if bad:
        err.append("Invalid package names: " + ", ".join(bad[:5]))
    missing = [p for p in MUST_HAVE if p not in pkgs]
    if missing:
        err.append("Missing mandatory supervision-layer packages: " + ", ".join(missing)
                   + " (without them the template will not pass validation).")
    if not re.match(r"^https://[^\s'\"]+\.(qcow2|img|raw)$", url):
        err.append("Image URL must be https and end with .qcow2/.img/.raw.")
    if sha and not SHA_RE.match(sha):
        err.append("Checksum: 64 characters (sha256) or 128 (sha512), [0-9a-f] only.")
    if not sha and not sums_url:
        err.append("Provide the checksum file URL (recommended) or enter the checksum manually.")
    if sums_url and not sums_url.startswith("https://"):
        err.append("Checksum file URL must be https.")

    # reachability check: the image and the checksum file MUST exist, and the
    # checksums MUST contain an entry for this file - otherwise the build would
    # only fail later on the runner
    if not err:
        try:
            with _http(url, method="HEAD", timeout=25) as r:
                size = int(r.headers.get("Content-Length") or 0)
            if size and size < 20_000_000:
                err.append(f"The image looks too small ({size} B) - is this really a cloud image?")
        except Exception as e:  # noqa: BLE001
            err.append(f"Cannot fetch the image headers: {e}")
        if sums_url:
            fn = os.path.basename(urllib.parse.urlparse(url).path)
            try:
                got = sums_lookup(sums_url, fn)
                if not got:
                    err.append(f"The checksum file has no entry for {fn} - "
                               "check that it lives in the same directory as the image.")
                elif sha and got.lower() != sha:
                    err.append("The checksum you entered differs from the one in the upstream checksum file.")
            except Exception as e:  # noqa: BLE001
                err.append(f"Cannot fetch the checksum file: {e}")

    return ({"slug": slug, "name": name, "url": url, "sums_url": sums_url, "sha": sha,
             "disk": disk, "epel": epel, "pkgs": pkgs}, err)


def render_manifest(d: dict, author: str) -> str:
    lines = [f'name: "{d["name"]}"',
             f'# added from the cs-factory GUI by {author} ({time.strftime("%Y-%m-%d %H:%M")})',
             '# "current" policy: the URL points to the latest/current variant, integrity',
             '# is verified against the upstream checksum file; cache refreshed after 90 days',
             f'url: "{d["url"]}"']
    if d["sums_url"]:
        lines.append(f'sums_url: "{d["sums_url"]}"')
    if d["sha"]:
        lines.append(f'{"sha512" if len(d["sha"]) == 128 else "sha256"}: "{d["sha"]}"')
    lines += [f'epel: {d["epel"]}', f'disk_size: "{d["disk"]}"', "packages:"]
    lines += [f"  - {p}" for p in d["pkgs"]]
    return "\n".join(lines) + "\n"


# ---------- local build queue ----------------------------------------------

def _run(job: dict) -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f"{job['id']}.log"
    job["log"] = str(log)
    # The disk size from the form is passed to build.sh via an environment
    # variable - empty field = build.sh uses the value from the manifest (the usual case).
    env = dict(os.environ)
    if job.get("disk"):
        env["CSF_DISK_SIZE"] = job["disk"]

    with open(log, "w") as f:
        def sh(cmd: list[str]) -> int:
            f.write(f"\n$ {' '.join(cmd)}\n")
            f.flush()
            return subprocess.run(cmd, cwd=REPO, env=env,
                                  stdout=f, stderr=subprocess.STDOUT).returncode

        # The checkout on this host has NO auto-sync (no timer, no cron), so without
        # this the operator clicks "Build" and gets code from arbitrarily many
        # commits ago - and the log would not tell. A failed pull does not block
        # the build, but it must be visible: the built commit goes into the job.
        job["state"] = "updating repository"
        if sh(["git", "pull", "--ff-only"]) != 0:
            f.write("!! git pull failed - building from the local version (see commit below)\n")
            f.flush()
        try:
            job["commit"] = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO,
                                           capture_output=True, text=True).stdout.strip()
        except Exception:  # noqa: BLE001 - missing git must not break the build
            job["commit"] = "?"
        f.write(f"# building commit: {job['commit']}\n")
        f.flush()

        if job.get("kind") == "e2e":
            # Test on a LIVE machine: deploys a VM from a temporary template, checks
            # the full feature set and cleans up after itself. Run from here, NOT
            # from CI, because a CI job runs as the runner user - and the CloudStack
            # API keys stay with the `factory` user, not in the code-building environment.
            job["state"] = "e2e test on a live VM"
            sel = (["--artifact", job["artifact"]] if job.get("artifact")
                   else ["--distro", job["distro"]])
            rc = sh(["python3", "e2e/tier3-features.py"] + sel)
            job["state"] = "PASS" if rc == 0 else "FAIL"
            job["finished"] = time.strftime("%H:%M:%S")
            return

        job["state"] = "building image"
        rc = sh(["./build.sh", job["distro"], job["version"]])
        if rc == 0:
            job["state"] = "validating"
            img = ""
            # NOTE the name: `env` above holds the environment passed to sh();
            # shadowing it with a path broke validation (TypeError on env=Path)
            # exactly when the build SUCCEEDED - making PASS unreachable.
            envfile = BUILDS / f"template-{job['distro']}-v{job['version'].replace('.', '_')}.env"
            if envfile.exists():
                for line in envfile.read_text().splitlines():
                    if line.startswith("IMG="):
                        img = line.split("=", 1)[1]
            rc = sh(["e2e/validate-offline.sh", img]) if img else 1
        job["state"] = "PASS" if rc == 0 else "FAIL"
        job["finished"] = time.strftime("%H:%M:%S")


def _worker() -> None:
    while True:
        job = _q.get()
        try:
            _run(job)
        except Exception as e:  # noqa: BLE001
            job["state"] = f"ERROR: {e}"


threading.Thread(target=_worker, daemon=True).start()


def _enqueue(distro: str, version: str, who: str, disk: str = "", kind: str = "build",
             artifact: str = "") -> None:
    with _lock:
        job = {"id": len(_jobs) + 1, "distro": distro, "version": version, "kind": kind,
               "disk": disk, "artifact": artifact, "state": "queued", "who": who}
        _jobs.append(job)
        _q.put(job)


# ---------- auth -----------------------------------------------------------

def current_user() -> dict | None:
    if AUTH_DISABLED:
        return {"name": "dev (auth disabled)", "groups": [REQUIRED_GROUP]}
    return session.get("user")


def require_admin(fn):
    def wrap(*a, **kw):
        u = current_user()
        if not u:
            session["next"] = request.path
            return redirect(url_for("login"))
        if REQUIRED_GROUP not in (u.get("groups") or []):
            return page("Access denied", f"""<div class=card><h2>Access denied</h2>
<p>Account <b>{html.escape(str(u.get('name')))}</b> is not a member of the group
<code>{html.escape(REQUIRED_GROUP)}</code>, which is required to manage templates.</p>
<p class=note>Ask an administrator to add you to that group in your identity
provider, then <a href="/logout">log out and try again</a>.</p></div>"""), 403
        return fn(*a, **kw)
    wrap.__name__ = fn.__name__
    return wrap


def _oidc_missing_page():
    missing = [n for n, v in (("OIDC_ISSUER", OIDC_ISSUER), ("OIDC_CLIENT_ID", OIDC_CLIENT_ID),
                              ("EXTERNAL_URL", EXTERNAL_URL)) if not v]
    return page("Sign-in not configured", f"""<div class=card><h2>Sign-in not configured</h2>
<div class=err>OIDC login is not configured. Missing: <code>{html.escape(', '.join(missing))}</code>.</div>
<p class=note>Set these variables in <code>/etc/cs-factory/gui.env</code> and restart the
<code>cs-factory-gui</code> service.</p></div>""", nav=False), 503


@app.get("/login")
def login():
    if not OIDC_CONFIGURED:
        return _oidc_missing_page()
    return oauth.oidc.authorize_redirect(EXTERNAL_URL + "/callback")


@app.get("/callback")
def callback():
    if not OIDC_CONFIGURED:
        return _oidc_missing_page()
    token = oauth.oidc.authorize_access_token()
    info = token.get("userinfo") or oauth.oidc.userinfo(token=token)
    session["user"] = {"name": info.get("preferred_username") or info.get("email") or "?",
                       "groups": info.get("groups") or info.get("roles") or []}
    return redirect(session.pop("next", "/"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------- views ----------------------------------------------------------

CSS = """
:root{--bg:#0f1722;--card:#18222f;--line:#26354a;--fg:#e8eef6;--mut:#8aa0b8;
      --blue:#2f7fd1;--ok:#2ea66b;--warn:#d9a441;--err:#d65a5a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:12px 20px;background:linear-gradient(90deg,#0d6daa,#154f7f,#182c4d);
       display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header h1{font-size:16px;font-weight:600;margin:0}
header .u{color:#cfe0f0;font-size:12px;margin-left:auto}
header a{color:#fff;border:1px solid #ffffff55;border-radius:6px;padding:3px 10px;
         font-size:12px;text-decoration:none}
.wrap{max-width:1080px;margin:18px auto;padding:0 12px;display:grid;
      grid-template-columns:1fr 1fr;gap:16px}
.wrap.one{grid-template-columns:1fr}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card.span{grid-column:1/-1}
.card h2{font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px;margin:0 0 12px}
.feed{height:340px;overflow:auto;background:#0b1320;border:1px solid var(--line);
      border-radius:8px;padding:10px;font-family:ui-monospace,Consolas,monospace;font-size:13px;
      white-space:pre-wrap}
label{color:var(--mut);font-size:12px;display:block;margin:10px 0 3px}
input,select,textarea{background:#0b1320;border:1px solid var(--line);color:var(--fg);
      border-radius:7px;padding:8px;font-size:13px;width:100%;font-family:inherit}
textarea{font-family:ui-monospace,Consolas,monospace;min-height:120px}
button{background:var(--blue);color:#fff;border:0;border-radius:7px;padding:8px 14px;
       font-size:13px;cursor:pointer}
button.ghost{background:#22344a}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{text-align:left;padding:5px 6px;border-bottom:1px solid var(--line)}
a{color:#7ec0ff}
.y{color:var(--ok)}.n{color:var(--err)}.w{color:var(--warn)}
.note{color:var(--mut);font-size:12px}
.banner{background:#3a2a12;border:1px solid #6b4f1f;color:#ffd27a;border-radius:8px;
        padding:10px 14px;font-size:13px;margin-bottom:12px}
.err{background:#3a1616;border:1px solid #6b2020;color:#ff9b9b;border-radius:8px;
     padding:10px 14px;font-size:13px;margin-bottom:12px}
.ok{background:#12301f;border:1px solid #1f5c39;color:#7be0a0;border-radius:8px;
    padding:10px 14px;font-size:13px;margin-bottom:12px}
code{background:#0b1320;border:1px solid var(--line);border-radius:4px;padding:0 4px}
ol.steps{padding-left:1.2rem}ol.steps li{margin:.5rem 0}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:860px){.wrap{grid-template-columns:1fr}.row2{grid-template-columns:1fr}}
"""


def page(title: str, body: str, wide: bool = False, nav: bool = True) -> str:
    u = current_user()
    who = (f'<span class=u>{html.escape(str(u.get("name")))} '
           f'&middot; <a href="/logout">log out</a></span>') if u else ""
    links = ('<a href="/">dashboard</a><a href="/new">new distribution</a><a href="/ci">CI status</a>'
             '<a href="/settings">settings</a><a href="/help">help</a>'
             '<a href="/artifacts/">artifacts</a>') if nav else ""
    missing = missing_config() if nav else []
    warn = (f'<div class="card span"><div class=banner>Configuration incomplete - missing: '
            f'<code>{html.escape(", ".join(missing))}</code>. Set them in '
            f'<code>/etc/cs-factory/gui.env</code> and restart the service; the related '
            f'features stay unavailable until then.</div></div>') if missing else ""
    return f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{html.escape(title)} - cs-factory</title><style>{CSS}</style>
<header><h1>cs-factory - CloudStack template factory</h1>
{links}{who}</header>
<div class="wrap{' one' if wide else ''}">{warn}{body}</div>"""


@app.get("/")
@require_admin
def index():
    rows = []
    for j in reversed(_jobs[-15:]):
        cls = {"PASS": "y", "FAIL": "n"}.get(j["state"], "w")
        dsk = f" &middot; disk {html.escape(j['disk'])}" if j.get("disk") else ""
        rows.append(f"<tr><td>{j['id']}</td><td>{html.escape(j['distro'])} v{j['version']}"
                    f"<br><span class=note>code: {html.escape(j.get('commit') or '-')}{dsk}</span></td>"
                    f"<td class={cls}>{html.escape(j['state'])}</td><td>{j.get('finished','')}</td>"
                    f"<td><a href='/log/{j['id']}'>log</a></td></tr>")
    opts = "".join(f"<option>{m}</option>" for m in list_manifests())
    dmap = json.dumps({m: (manifest_field(m, "disk_size") or "10G") for m in list_manifests()})
    mlinks = " &middot; ".join(f"<a href='/manifest/{m}'>{m}</a>" for m in list_manifests())

    arows = []
    for a in list_artifacts():
        ost = html.escape(a["ostype"] or "-")
        warn = "" if a["ostype"] else " <span class=w>(no cs_ostype in the manifest)</span>"
        arows.append(f"""<tr><td><b>{html.escape(a['template_name'])}</b><br>
<span class=note>{html.escape(a['file'])} &middot; {a['size_mb']} MB &middot; {a['mtime']}</span></td>
<td class=note>OS type: {ost}{warn}</td>
<td><form method=post action="/register" style="display:flex;gap:6px;align-items:center">
<input type=hidden name=file value="{html.escape(a['file'])}">
<label style="margin:0" title="Requires an API account with administrator rights - a regular account can only create private templates."><input type=checkbox name=ispublic value=1 style="width:auto">
 visible to everyone (requires an admin account)</label>
<button>Register in CloudStack</button></form>
<form method=post action="/e2e" style="margin-top:6px">
<input type=hidden name=distro value="{html.escape(a['distro'])}">
<input type=hidden name=file value="{html.escape(a['file'])}">
<button title="Deploys a machine from a temporary template, checks the full feature set and cleans up after itself. Nothing is left in CloudStack.">E2E test on a live VM</button>
</form></td></tr>""")
    arts = (f"""<div class=banner>Below are the images that <b>passed the validation gate</b>
(PASS) - only those end up here. Registration creates a template in CloudStack
in the <b>ROOT</b> domain (main view, not a project), with password reset
enabled and the supervision channel attached.</div>
<table><tr><th>template</th><th>parameters</th><th></th></tr>{''.join(arows)}</table>"""
            if arows else
            """<p class=note>No finished images yet. Build a template (panel above or CI) -
after a PASS it will appear here with a registration button.</p>""")

    return page("Dashboard", f"""
<div class="card span"><h2>What do you want to do?</h2>
<div class=row2>
<div><b>Add a new distribution</b><p class=note>The wizard walks you through a
form (no YAML), checks it and saves it to the repository -
CI builds the template automatically.</p><a href="/new"><button>Open the wizard</button></a></div>
<div><b>Build a template now (on this host)</b>
<form method=post action="/build">
<label>distribution</label><select name=distro id=bdistro>{opts}</select>
<label>template version (goes into the name "Template ... vX.Y")</label>
<input name=version value="{release_version()}" pattern="[0-9]+\\.[0-9]+">
<label>disk size <span class=note>- leave empty to use the manifest value</span></label>
<input name=disk_size id=bdisk pattern="[0-9]+[GgMm]" placeholder="from manifest">
<p class=note style="margin:4px 0 0">Minimum <b>10G</b>. An increase applies to this
single build only - the manifest in the repository stays unchanged.</p>
<button style="margin-top:10px">Build locally</button></form></div>
</div>
<p class=note style="margin-top:12px">Manifests in the repository: {mlinks}</p></div>

<div class="card"><h2>Recent local builds</h2>
<table><tr><th>#</th><th>what</th><th>state</th><th>finished</th><th></th></tr>
{''.join(rows) or '<tr><td colspan=5 class=note>none - nothing has been built yet</td></tr>'}</table>
<p class=note>PASS = the template passed the gate and can be registered in CloudStack.
FAIL = not fit for use (details in the log).</p></div>

<div class="card"><h2>CI status (GitLab)</h2><div id=ci class=note>loading...</div>
<p class=note><a href="/ci">full live view &rarr;</a></p></div>

<div class="card span"><h2>Finished templates - CloudStack registration</h2>
{arts}</div>
<script>
// Disk size hint = the value from the selected distribution's manifest.
// The operator sees what they will get BEFORE clicking - without opening YAML.
const DISKS={dmap};
function refreshDisk(){{
  const d=document.getElementById('bdistro').value;
  document.getElementById('bdisk').placeholder=(DISKS[d]||'10G')+' (from manifest)';
}}
document.getElementById('bdistro').addEventListener('change',refreshDisk);
refreshDisk();
fetch('/api/ci').then(r=>r.json()).then(d=>{{
  const el=document.getElementById('ci');
  if(d.error){{el.textContent='unavailable: '+d.error;return}}
  el.innerHTML=d.pipelines.slice(0,3).map(p=>
    `<div>#${{p.id}} <b class="${{p.status=='success'?'y':(p.status=='failed'?'n':'w')}}">${{p.status}}</b>
     <span class=note>${{p.ref}} ${{(p.sha||'').slice(0,8)}}</span></div>`).join('');
}}).catch(e=>document.getElementById('ci').textContent='unavailable');
</script>""")


@app.get("/new")
@require_admin
def new(prefill: dict | None = None, errors: list[str] | None = None, okmsg: str = ""):
    d = prefill or {}
    errs = ("<div class=err><b>Please fix the following:</b><ul>"
            + "".join(f"<li>{html.escape(e)}</li>" for e in (errors or [])) + "</ul></div>") if errors else ""
    ok = f"<div class=ok>{okmsg}</div>" if okmsg else ""
    return page("New distribution", f"""
<div class="card span"><h2>New distribution wizard</h2>{ok}{errs}
<div class=banner>Fill in the fields - no YAML or git knowledge needed. After saving,
the manifest lands in the repository and CI builds and checks the template on its own.
Not sure where to get the URLs? <a href="/help">See the step-by-step help</a>.</div>
<form method=post action="/new">
<div class=row2>
<div><label>Technical name (manifest file name, no spaces)</label>
<input name=slug placeholder="ubuntu-26.04" value="{html.escape(d.get('slug',''))}" required></div>
<div><label>Display name (becomes part of the CloudStack template name)</label>
<input name=name placeholder="Ubuntu 26.04" value="{html.escape(d.get('name',''))}" required></div>
</div>
<label>Cloud image URL ("current"/"release" variant - not a dated one)</label>
<input name=url placeholder="https://cloud-images.ubuntu.com/releases/resolute/release/ubuntu-26.04-server-cloudimg-amd64.img"
 value="{html.escape(d.get('url',''))}" required>
<label>Upstream checksum file URL (SHA256SUMS / SHA512SUMS / .CHECKSUM - from the same directory)</label>
<input name=sums_url placeholder="https://cloud-images.ubuntu.com/releases/resolute/release/SHA256SUMS"
 value="{html.escape(d.get('sums_url',''))}">
<div class=row2>
<div><label>Pinned checksum (optional - pins a specific build)</label>
<input name=sha placeholder="empty = taken from the checksum file" value="{html.escape(d.get('sha',''))}"></div>
<div><label>Template disk size (minimum 10G)</label>
<input name=disk_size value="{html.escape(d.get('disk','10G'))}" pattern="([1-9][0-9]{{1,2}})G"
 title="Minimum 10G - a smaller disk runs out of space right after the machine starts."></div>
</div>
<label><input type=checkbox name=epel style="width:auto" {'checked' if d.get('epel')=='true' else ''}>
 RHEL family (Rocky/Alma) - add the EPEL repository</label>
<label>Packages to install (one per line; suggestion = standard set)</label>
<textarea name=packages>{html.escape(chr(10).join(d.get('pkgs') or STD_PACKAGES))}</textarea>
<p class=note><code>qemu-guest-agent</code> and <code>fail2ban</code> are mandatory -
they are the supervision and security layer; without them the template will not pass the checks.</p>
<div style="margin-top:12px;display:flex;gap:10px">
<button name=action value=check class=ghost>Only check</button>
<button name=action value=save>Check and save to repository</button></div>
</form></div>""", wide=True)


@app.post("/new")
@require_admin
def new_post():
    d, errs = validate_form(request.form)
    if errs:
        return new(prefill=d, errors=errs)
    if request.form.get("action") == "check":
        return new(prefill=d, okmsg="Everything checks out - the image and the checksum file "
                                    "are reachable and the packages look correct. "
                                    "You can save to the repository.")

    who = str((current_user() or {}).get("name", "?"))
    body = render_manifest(d, who)
    path = urllib.parse.quote(f"distros/{d['slug']}.yaml", safe="")
    payload = {"branch": GITLAB_BRANCH, "content": body,
               "commit_message": f"feat(distros): {d['slug']} - added from the cs-factory GUI by {who}",
               "author_name": f"cs-factory ({who})"}
    if GITLAB_COMMIT_EMAIL:
        payload["author_email"] = GITLAB_COMMIT_EMAIL
    try:
        try:
            gitlab(f"/repository/files/{path}", "POST", payload)
            action = "created"
        except urllib.error.HTTPError as e:
            if e.code != 400:
                raise
            gitlab(f"/repository/files/{path}", "PUT", payload)
            action = "updated"
    except Exception as e:  # noqa: BLE001
        return new(prefill=d, errors=[f"Saving to the repository failed: {e}. "
                                      "The manifest was NOT saved - report this to an administrator."])
    (REPO / "distros" / f"{d['slug']}.yaml").write_text(body)   # visible locally right away
    return new(okmsg=f"Manifest <code>distros/{html.escape(d['slug'])}.yaml</code> {action} "
                     f"in the repository. CI is building the template - "
                     f'<a href="/ci">watch the live status</a>.')


@app.post("/build")
@require_admin
def build():
    distro = request.form.get("distro", "")
    version = request.form.get("version", "")
    disk = (request.form.get("disk_size") or "").strip().upper()
    if distro not in list_manifests() or not VER_RE.match(version):
        return "bad parameters", 400
    # Empty field = size from the manifest (build.sh reads it). Filled = override
    # for THIS build; the 10G minimum applies just like in the manifest, so the
    # field can enlarge the disk but cannot bypass the policy.
    if disk:
        if not SIZE_RE.match(disk):
            return page("Error", "<div class=card><h2>Invalid disk size</h2>"
                        "<p>Enter a number and a unit, e.g. <code>20G</code>.</p>"
                        "<a href='/'><button>Back</button></a></div>"), 400
        disk_g = int(disk[:-1]) if disk.endswith("G") else int(disk[:-1]) // 1024
        # The floor is the LARGER of the two: the global minimum and the manifest
        # size. The 10G threshold alone is not enough - a distribution may declare
        # more, and entering a smaller number would silently build a template below
        # its own requirement (build.sh enforces the same on its side).
        mdisk = (manifest_field(distro, "disk_size") or "10G").upper()
        mdisk_g = int(mdisk[:-1]) if mdisk.endswith("G") else int(mdisk[:-1]) // 1024
        floor_g = max(10, mdisk_g)
        if disk_g < floor_g:
            why = ("The minimum is <b>10G</b>." if floor_g == 10 else
                   f"This distribution's manifest declares <b>{html.escape(mdisk)}</b>, "
                   "and the field can only enlarge the disk.")
            return page("Error", f"<div class=card><h2>Disk {html.escape(disk)} is too small</h2>"
                        f"<p>{why} A smaller disk runs out of space right after the "
                        "machine starts, and to the user it looks like a system failure, "
                        "not a setting.</p>"
                        "<a href='/'><button>Back</button></a></div>"), 400
    _enqueue(distro, version, str((current_user() or {}).get("name", "?")), disk)
    return redirect(url_for("index"))


@app.post("/e2e")
@require_admin
def e2e():
    """Feature test on a live machine. Deploys a VM from a TEMPORARY template and
    cleans up - nothing is left in CloudStack; this is a test, not a registration."""
    distro = request.form.get("distro", "")
    fname = os.path.basename(request.form.get("file", ""))
    if distro not in list_manifests():
        return "unknown distribution", 400
    # Test EXACTLY the artifact the operator clicked next to - one distribution
    # may have several image versions.
    if fname and not (ARTIFACTS / fname).is_file():
        return "unknown artifact", 400
    _enqueue(distro, "-", str((current_user() or {}).get("name", "?")),
             kind="e2e", artifact=fname)
    return redirect(url_for("index"))


@app.post("/register")
@require_admin
def register():
    fn = (request.form.get("file") or "").strip()
    ispublic = bool(request.form.get("ispublic"))
    art = next((a for a in list_artifacts() if a["file"] == fn), None)
    if not art:
        return page("Registration", "<div class=card><div class=err>No such artifact."
                                    "</div><p><a href='/'>&larr; back</a></p></div>"), 404

    def fail(msg: str, hint: str = ""):
        return page("Registration", f"""<div class="card span"><h2>Registration failed</h2>
<div class=err>{html.escape(msg)}</div>{f'<p class=note>{hint}</p>' if hint else ''}
<p><a href="/">&larr; back to dashboard</a></p></div>""", wide=True)

    if not ARTIFACTS_BASE_URL:
        return fail("ARTIFACTS_BASE_URL is not configured.",
                    "Set it in <code>/etc/cs-factory/gui.env</code> to the URL from which "
                    "the CloudStack secondary storage VM can download artifacts, then restart the service.")
    if not cs.configured():
        return fail("The GUI has no CloudStack API configuration.",
                    "Set the API URL and keys on the <a href='/settings'>Settings</a> page, or "
                    "CS_API_URL, CS_API_KEY and CS_SECRET_KEY in <code>/etc/cs-factory/gui.env</code>.")
    if not art["ostype"]:
        return fail(f"Manifest {art['distro']} has no cs_ostype field.",
                    "Fill in the OS type in the manifest.")
    try:
        ostypeid = cs.find_ostype_id(art["ostype"])
        if not ostypeid:
            return fail(f"CloudStack does not know the OS type: {art['ostype']}",
                        "Choose an existing type in the manifest (cs_ostype field).")
        zones = cs.zones()
        if not zones:
            return fail("CloudStack returned no available zone.")
        zoneid = zones[0]["id"]
        url = f"{ARTIFACTS_BASE_URL}/{art['file']}"
        r = cs.register_template(name=art["template_name"], url=url, ostypeid=ostypeid,
                                 zoneid=zoneid, ispublic=ispublic,
                                 extraconfig=cs.CSF_INSPECT_CHANNEL)
        tpl = (r.get("template") or [{}])
        tpl = tpl[0] if isinstance(tpl, list) else tpl
    except cs.CSError as e:
        if "Only private Templates" in str(e):
            return fail("CloudStack did not allow creating a template visible to everyone.",
                        "The factory API account is a regular user - uncheck the "
                        "visibility option and register the template as private, "
                        "or ask an administrator for an API account with admin rights "
                        "(then the template can be public).")
        return fail(str(e), "Check that the API account may register templates "
                            "and that the artifact URL is reachable from CloudStack.")
    except Exception as e:  # noqa: BLE001
        return fail(f"Unexpected error: {e}")

    return page("Registration", f"""<div class="card span"><h2>Template registered</h2>
<div class=ok><b>{html.escape(art['template_name'])}</b> was sent to CloudStack
(ROOT domain{', visible to everyone' if ispublic else ''}).</div>
<table>
<tr><td>ID</td><td><code>{html.escape(str(tpl.get('id','-')))}</code></td></tr>
<tr><td>zone</td><td>{html.escape(str(zones[0].get('name','-')))}</td></tr>
<tr><td>OS type</td><td>{html.escape(art['ostype'])}</td></tr>
<tr><td>image source</td><td><code>{html.escape(url)}</code></td></tr>
</table>
<p class=note>CloudStack downloads the image in the background - in its template view
it first appears as "Not Ready", and once copied to storage as ready to use.</p>
<p class=note>The template carries the supervision channel <code>org.csfactory.support.0</code>.
Accounts that will create machines from this template must have
<code>enable.additional.vm.configuration</code> enabled - otherwise the machine will not start.</p>
<p><a href="/">&larr; back to dashboard</a></p></div>""", wide=True)


@app.get("/log/<int:jid>")
@require_admin
def log(jid: int):
    for j in _jobs:
        if j["id"] == jid:
            p = Path(j.get("log", ""))
            body = html.escape(p.read_text(errors="replace")[-60000:]) if p.exists() else "(empty so far)"
            live = j["state"] not in ("PASS", "FAIL") and not str(j["state"]).startswith("ERROR")
            return page(f"Build log #{jid}", f"""
<div class="card span"><h2>Build #{jid} - {html.escape(j['distro'])} v{j['version']}
 &middot; <span class="{'w' if live else ('y' if j['state']=='PASS' else 'n')}">{html.escape(str(j['state']))}</span></h2>
<div class=feed id=f>{body}</div>
<p class=note>{'Refreshes every 3 s.' if live else 'Build finished.'}</p></div>
{'<script>setTimeout(()=>location.reload(),3000)</script>' if live else ''}""", wide=True)
    return "no such job", 404


@app.get("/manifest/<name>")
@require_admin
def manifest(name: str):
    if not SLUG_RE.match(name) or name not in list_manifests():
        return "no such manifest", 404
    body = html.escape((REPO / "distros" / f"{name}.yaml").read_text())
    return page(f"Manifest {name}", f"""<div class="card span">
<h2>distros/{html.escape(name)}.yaml</h2><div class=feed>{body}</div>
<p class=note>Changes to existing manifests are made in the repository
(or via the wizard - it saves a new version of the same file).</p></div>""", wide=True)


# ---------- live CI view ---------------------------------------------------

@app.get("/api/ci")
@require_admin
def api_ci():
    try:
        pipes = gitlab("/pipelines?per_page=5")
        out = []
        for p in pipes:
            jobs = []
            try:
                for j in gitlab(f"/pipelines/{p['id']}/jobs?per_page=30"):
                    jobs.append({"id": j["id"], "name": j["name"], "status": j["status"],
                                 "duration": j.get("duration")})
                for b in gitlab(f"/pipelines/{p['id']}/bridges?per_page=10"):
                    dp = (b.get("downstream_pipeline") or {}).get("id")
                    if dp:
                        for j in gitlab(f"/pipelines/{dp}/jobs?per_page=30"):
                            jobs.append({"id": j["id"], "name": "-> " + j["name"],
                                         "status": j["status"], "duration": j.get("duration")})
            except Exception:  # noqa: BLE001 - pipeline without jobs/bridges
                pass
            out.append({"id": p["id"], "status": p["status"], "ref": p.get("ref"),
                        "sha": p.get("sha"), "jobs": sorted(jobs, key=lambda x: x["id"])})
        return {"pipelines": out}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


@app.get("/api/ci/job/<int:jid>")
@require_admin
def api_job_trace(jid: int):
    try:
        url = f"{_gitlab_project_api()}/jobs/{jid}/trace"
        with _http(url, token=True, timeout=25) as r:
            txt = r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    txt = re.sub(r"\x1b\[[0-9;]*m", "", txt)
    txt = re.sub(r"^\S+Z [0-9A-Z]{3} ?", "", txt, flags=re.M)   # runner timestamps
    return {"trace": txt[-60000:]}


@app.get("/ci")
@require_admin
def ci():
    return page("CI status", """
<div class="card span"><h2>GitLab pipelines - live</h2>
<div class=banner>Every manifest change is built here. Green "success" on
all jobs = templates ready. Click a job to see its log.</div>
<div id=pipes class=note>loading...</div></div>
<div class="card span"><h2>Selected job log</h2>
<div class=feed id=trace>(click a job above)</div></div>
<script>
let cur=null;
const cls=s=>s=='success'?'y':(s=='failed'?'n':'w');
function draw(d){
  const el=document.getElementById('pipes');
  if(d.error){el.textContent='GitLab unavailable: '+d.error;return}
  el.innerHTML=d.pipelines.map(p=>`<div style="margin:10px 0">
    <div>pipeline #${p.id} <b class="${cls(p.status)}">${p.status}</b>
      <span class=note>${p.ref||''} ${(p.sha||'').slice(0,8)}</span></div>
    <table>${p.jobs.map(j=>`<tr><td><a href="#" onclick="pick(${j.id});return false">${j.name}</a></td>
      <td class="${cls(j.status)}">${j.status}</td>
      <td class=note>${j.duration?Math.round(j.duration)+'s':''}</td></tr>`).join('')}</table></div>`).join('');
}
function pick(id){cur=id;loadTrace()}
function loadTrace(){
  if(!cur)return;
  fetch('/api/ci/job/'+cur).then(r=>r.json()).then(d=>{
    const t=document.getElementById('trace');
    t.textContent=d.error?('cannot fetch the log: '+d.error):d.trace;
    t.scrollTop=t.scrollHeight;
  }).catch(()=>{});
}
function tick(){fetch('/api/ci').then(r=>r.json()).then(draw).catch(()=>{});loadTrace()}
tick();setInterval(tick,5000);
</script>""", wide=True)


@app.get("/settings")
@require_admin
def settings(msg: str = "", err: str = ""):
    c = cs.creds()
    if not c["api_url"]:
        probe = "<span class=w>API URL not set</span> - template registration is unavailable"
    elif c["api_key"] and c["secret"]:
        try:
            zs = cs.zones()
            probe = (f"<span class=y>connection works</span> - visible zones: "
                     f"{html.escape(', '.join(z['name'] for z in zs)) or '(none)'}")
        except cs.CSError as e:
            probe = f"<span class=n>connection failed</span>: {html.escape(str(e))[:200]}"
    else:
        probe = "<span class=w>keys not set</span> - template registration is unavailable"

    banner = f"<div class=ok>{msg}</div>" if msg else ""
    banner += f"<div class=err>{html.escape(err)}</div>" if err else ""
    return page("Settings", f"""
<div class="card span"><h2>CloudStack access</h2>{banner}
<div class=banner>The factory uses these keys to <b>register finished templates</b>.
The secret key is stored on the server and is <b>never shown back</b> -
below you only see its fingerprint, which lets you confirm the right one was entered.
Generate keys in CloudStack: <i>Accounts &rarr; account &rarr; View Users &rarr; user &rarr;
Generate Keys</i>. For templates to be "visible to everyone", the account needs
administrator rights.</div>
<table>
<tr><td>state</td><td>{probe}</td></tr>
<tr><td>API URL</td><td><code>{html.escape(c['api_url'] or '-')}</code></td></tr>
<tr><td>API key</td><td><code>{html.escape(c['api_key'][:8] + '...') if c['api_key'] else '-'}</code>
 <span class=note>(fingerprint {cs.fingerprint(c['api_key'])})</span></td></tr>
<tr><td>secret key</td><td><span class=note>fingerprint {cs.fingerprint(c['secret'])}</span></td></tr>
<tr><td>settings source</td><td class=note>{html.escape(c['source'])}</td></tr>
</table>

<form method=post action="/settings" style="margin-top:16px">
<label>CloudStack API URL</label>
<input name=api_url value="{html.escape(c['api_url'])}" placeholder="https://cloudstack.example.com/client/api" required>
<div class=row2>
<div><label>API Key</label>
<input name=api_key autocomplete=off placeholder="paste the API key" required></div>
<div><label>Secret Key</label>
<input name=secret type=password autocomplete=new-password placeholder="paste the secret key" required></div>
</div>
<p class=note>After saving, the factory checks the connection right away. If the test fails,
the previous settings are kept - you will not lose a working configuration.</p>
<div style="display:flex;gap:10px">
<button name=action value=test class=ghost>Only test the connection</button>
<button name=action value=save>Save and test</button></div>
</form>
<p class=note style="margin-top:14px">Keep a copy of these keys in your secret store -
the file on the server is a working copy, not the source of truth.</p>
</div>

<div class="card span"><h2>Other settings (read-only)</h2>
<table>
<tr><td>GUI URL</td><td><code>{html.escape(EXTERNAL_URL or '-')}</code></td></tr>
<tr><td>OIDC issuer</td><td><code>{html.escape(OIDC_ISSUER or '-')}</code></td></tr>
<tr><td>required group</td><td><code>{html.escape(REQUIRED_GROUP)}</code></td></tr>
<tr><td>manifest repository</td><td><code>{html.escape(GITLAB_URL or '-')}</code> &middot; project
 {html.escape(GITLAB_PROJECT or '-')} &middot; branch {html.escape(GITLAB_BRANCH)}
 &middot; token {'<span class=y>set</span>' if GITLAB_TOKEN else '<span class=n>missing</span>'}</td></tr>
<tr><td>artifacts directory</td><td><code>{html.escape(str(ARTIFACTS))}</code></td></tr>
<tr><td>artifacts URL for CloudStack</td><td><code>{html.escape(ARTIFACTS_BASE_URL or '-')}</code>
 <span class=note>(the SSVM downloads images from here)</span></td></tr>
</table>
<p class=note>An administrator changes these values in <code>/etc/cs-factory/gui.env</code>
on the factory host (requires a service restart).</p></div>""", wide=True)


@app.post("/settings")
@require_admin
def settings_post():
    api_url = (request.form.get("api_url") or "").strip()
    api_key = (request.form.get("api_key") or "").strip()
    secret = (request.form.get("secret") or "").strip()
    action = request.form.get("action")

    if not api_url.startswith("https://"):
        return settings(err="The API URL must start with https://")
    if len(api_key) < 20 or len(secret) < 20:
        return settings(err="The keys look incomplete - paste the full values "
                            "generated in CloudStack.")

    # Test BEFORE saving, with the explicitly supplied credentials - the saved
    # configuration stays untouched, so a failed attempt breaks nothing.
    try:
        zones = cs.test_creds(api_url, api_key, secret)
    except cs.CSError as e:
        return settings(err=f"Connection test failed: {e} "
                            "- settings were NOT changed.")

    if action == "test":
        return settings(msg="Connection works - visible zones: "
                            + html.escape(", ".join(zones))
                            + ". Settings have not been saved yet.")

    cs.save_creds(api_url, api_key, secret)
    who = str((current_user() or {}).get("name", "?"))
    # the service journal gets WHO and the fingerprint - never the value
    print(f"[settings] {who} changed the CloudStack keys "
          f"(api_key {cs.fingerprint(api_key)}, secret {cs.fingerprint(secret)})", flush=True)
    return settings(msg="Saved. Connection verified - visible zones: "
                        + html.escape(", ".join(zones))
                        + ". Remember to keep a copy in your secret store.")


@app.get("/help")
@require_admin
def help_page():
    return page("Help", """
<div class="card span"><h2>How to add a new distribution - step by step</h2>
<div class=banner>You do everything from this site. No git, SSH or YAML
knowledge required. Time: about 5 minutes + build time (a dozen or so minutes).</div>
<ol class=steps>
<li><b>Find the "cloud image" download page of your distribution.</b>
Look for a directory named <code>current</code>, <code>latest</code> or
<code>release</code> - this way the factory always picks up the current image.
Typical URLs:
<ul>
<li>Ubuntu: <code>https://cloud-images.ubuntu.com/releases/&lt;release-name&gt;/release/</code>
(e.g. <code>noble</code> = 24.04, <code>resolute</code> = 26.04)</li>
<li>Debian: <code>https://cloud.debian.org/images/cloud/&lt;name&gt;/latest/</code></li>
<li>Rocky: <code>https://dl.rockylinux.org/pub/rocky/&lt;version&gt;/images/x86_64/</code>
(file with <code>.latest.</code> in its name)</li>
<li>openSUSE: <code>https://download.opensuse.org/distribution/leap/&lt;version&gt;/appliances/</code></li>
</ul></li>
<li><b>Copy two URLs from the same directory:</b> the image file
(<code>.qcow2</code> or <code>.img</code> - the "genericcloud"/"server-cloudimg" variant,
NOT "nocloud") and the checksum file (<code>SHA256SUMS</code>,
<code>SHA512SUMS</code> or <code>....CHECKSUM</code>).</li>
<li><b>Open the <a href="/new">wizard</a></b> and paste both URLs. The technical name
is the file name (e.g. <code>ubuntu-26.04</code>); the display name becomes part of the
template name in CloudStack (e.g. "Ubuntu 26.04" &rarr; <i>Template Ubuntu 26.04 v""" + release_version() + """</i>;
the release number comes from the <code>VERSION</code> file in the repository).</li>
<li><b>Click "Only check".</b> The factory checks that the image and the checksum
file exist, that the checksums contain an entry for this file, and that the package list makes sense.
If something is wrong you get a concrete message about what to fix.</li>
<li><b>Click "Check and save to repository".</b> This saves the manifest
and starts the build in CI. Progress: <a href="/ci">CI status</a>.</li>
<li><b>Wait for "success" and pick up the template</b> from <a href="/artifacts/">artifacts</a>.
That URL is what you give CloudStack when registering the template.</li>
</ol>
<h2 style="margin-top:20px">Good to know</h2>
<ul>
<li><b>Mandatory packages</b> - <code>qemu-guest-agent</code> (fsfreeze for snapshots
and backup; <b>without</b> access to the tenant's system - exec, files, SSH keys and passwords
are blocked) and <code>fail2ban</code> (SSH protection). The wizard enforces them.
The security patch automation (<code>unattended-upgrades</code> /
<code>dnf-automatic</code> / <code>os-update</code>) is added by the factory itself.</li>
<li><b>Ubuntu 26.04</b> ships <code>sudo-rs</code> by default, which may not work with
centralized identity setups (e.g. SSSD) - adjust it on the running machine if needed.</li>
<li><b>Image freshness</b> - a downloaded image is fetched again once it is older
than 3 months, so templates do not sit on a stale system.</li>
<li><b>Disk always at least 10 GB</b> - a deliberate decision: with a smaller disk
a quickly deployed machine runs out of space during its first operations, and it looks
like a system failure rather than a configuration issue. Three places enforce this:
the wizard, the manifest lint in CI and the check of the finished image.</li>
<li><b>Local build vs CI</b> - a local build (button on the dashboard) is for a
quick check of one thing here and now; CI builds all distributions
after every change and is the source of truth.</li>
<li><b>What PASS/FAIL means</b> - after the build the image goes through an automatic
check (among others: can the password be reset from CloudStack, are SSH host keys
unique per machine, is supervision enabled). FAIL = such a template is not registered.</li>
</ul>
<p class=note>Technical details and design decisions: <code>README.md</code> in the
project repository.</p></div>""",
                wide=True)


def _commit_at_start() -> str:
    """Commit this process loaded its code from. The on-disk checkout moves
    underneath the running service (`git pull` before a build), so "what is in
    the repo" does not tell what is running - the CI deploy (ci/factory-deploy.sh)
    compares against THIS value."""
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                              text=True, timeout=10, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


RUNNING_COMMIT = _commit_at_start()
_FINAL = ("PASS", "FAIL")


@app.get("/healthz")
def healthz():
    if request.args.get("verbose") == "1":
        with _lock:
            busy = sum(1 for j in _jobs
                       if j["state"] not in _FINAL and not str(j["state"]).startswith("ERROR"))
        return Response(json.dumps({"ok": True, "running_commit": RUNNING_COMMIT, "busy": busy}) + "\n",
                        mimetype="application/json")
    return Response("ok\n", mimetype="text/plain")

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
import hmac
import html
import json
import os
import queue
import re
import shutil
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
# GitLab is OPTIONAL. Without it the factory runs standalone (e.g. the Docker
# release): the wizard saves manifests to LOCAL_DISTROS and templates are built
# from the dashboard; the CI view is hidden.
GITLAB_CONFIGURED = bool(GITLAB_URL and GITLAB_PROJECT and GITLAB_TOKEN)

# Directory for manifests added from the GUI in standalone mode. Shipped
# manifests (REPO/distros) always win - a local file cannot shadow them.
LOCAL_DISTROS = Path(os.environ["CSF_LOCAL_DISTROS"]) if os.environ.get("CSF_LOCAL_DISTROS") else None

# Local sign-in with a single admin password - the simple alternative to OIDC
# (one operator, lab, small team). Ignored when OIDC is configured.
ADMIN_PASSWORD = os.environ.get("FACTORY_ADMIN_PASSWORD", "")

# Where the operator changes settings and how the service is restarted - differs
# between the host install (gui.env + systemd) and the Docker release (.env + compose).
CONFIG_HINT = os.environ.get("FACTORY_CONFIG_HINT", "/etc/cs-factory/gui.env")
RESTART_HINT = os.environ.get("FACTORY_RESTART_HINT", "restart the cs-factory-gui service")
# `git pull` before a local build only makes sense on a git checkout (host install).
GIT_PULL = os.environ.get("FACTORY_GIT_PULL", "1") == "1"
# Zone to register templates in (by name); empty = the first available zone.
CS_ZONE = os.environ.get("CS_ZONE", "").strip()
# Attach the csf-inspect virtio-serial channel at registration (needs account
# settings in CloudStack, see the docs); "off" registers without it.
INSPECT_CHANNEL = os.environ.get("CSF_INSPECT_CHANNEL", "on") != "off"
# Product release shown in the footer (set in the Docker image).
PRODUCT_RELEASE = os.environ.get("CSF_RELEASE", "")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32).hex())
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# Secure cookies whenever the GUI is served over https (the normal case). A lab
# on plain http (no TLS proxy yet) would otherwise never keep a session - the
# browser drops Secure cookies on http. FACTORY_COOKIE_SECURE overrides.
COOKIE_SECURE = os.environ.get(
    "FACTORY_COOKIE_SECURE", "0" if EXTERNAL_URL.startswith("http://") else "1") == "1"
app.config.update(SESSION_COOKIE_SECURE=COOKIE_SECURE, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax")

OIDC_CONFIGURED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and EXTERNAL_URL)
LOCAL_LOGIN = bool(ADMIN_PASSWORD) and not OIDC_CONFIGURED

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
# CloudStack OS type description, e.g. "Debian GNU/Linux 12 (64-bit)"
OSTYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()/+,-]{0,80}$")

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
    oidc = (("OIDC_ISSUER", OIDC_ISSUER), ("OIDC_CLIENT_ID", OIDC_CLIENT_ID),
            ("EXTERNAL_URL", EXTERNAL_URL))
    if not AUTH_DISABLED:
        if any(v for _, v in oidc[:2]):
            # OIDC chosen (partly configured) - name exactly what is missing
            out += [n for n, v in oidc if not v]
        elif not ADMIN_PASSWORD:
            out.append("FACTORY_ADMIN_PASSWORD (or OIDC_ISSUER/OIDC_CLIENT_ID/EXTERNAL_URL)")
    gitlab_vars = (("GITLAB_URL", GITLAB_URL), ("GITLAB_PROJECT", GITLAB_PROJECT),
                   ("GITLAB_TOKEN", GITLAB_TOKEN))
    # GitLab is optional: only a PARTIAL configuration is an error
    if any(v for _, v in gitlab_vars):
        out += [n for n, v in gitlab_vars if not v]
    if not ARTIFACTS_BASE_URL:
        out.append("ARTIFACTS_BASE_URL")
    if not cs.creds()["api_url"]:
        out.append("CS_API_URL")
    return out


# ---------- helpers --------------------------------------------------------

def _manifest_dirs() -> list[Path]:
    return [REPO / "distros"] + ([LOCAL_DISTROS] if LOCAL_DISTROS else [])


def builtin_manifests() -> set[str]:
    return {p.stem for p in (REPO / "distros").glob("*.yaml")}


def list_manifests() -> list[str]:
    return sorted({p.stem for d in _manifest_dirs() if d.is_dir() for p in d.glob("*.yaml")})


def manifest_path(distro: str) -> Path | None:
    """Shipped manifest first, then the local (GUI-added) one - same order as build.sh."""
    if not SLUG_RE.match(distro):
        return None
    for d in _manifest_dirs():
        p = d / f"{distro}.yaml"
        if p.is_file():
            return p
    return None


def manifest_field(distro: str, key: str) -> str:
    """Reads a single field from a manifest (no pyyaml dependency)."""
    p = manifest_path(distro)
    if not p:
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
    ostype = (f.get("cs_ostype") or "").strip()
    epel = "true" if f.get("epel") else "false"
    pkgs_raw = (f.get("packages") or "").replace(",", "\n").split("\n")
    pkgs = [p.strip() for p in pkgs_raw if p.strip()] or list(STD_PACKAGES)

    if not SLUG_RE.match(slug):
        err.append("Technical name: lowercase letters/digits/dot/hyphen, e.g. ubuntu-26.04.")
    if slug.startswith("custom-"):
        err.append("The custom- prefix is reserved for one-off builds.")
    if not NAME_RE.match(name):
        err.append("Display name is required (it becomes part of the CloudStack template name).")
    if ostype and not OSTYPE_RE.match(ostype):
        err.append("CloudStack OS type: letters, digits, spaces and ._()/+,- only, "
                   "e.g. Debian GNU/Linux 12 (64-bit).")
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
    # Same character rules as the image URL: the value is written into the
    # manifest between quotes - a quote or a line break would inject YAML keys.
    if sums_url and not re.match(r"^https://[^\s'\"]+$", sums_url):
        err.append("Checksum file URL must be https, without spaces or quotes.")

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
             "disk": disk, "epel": epel, "pkgs": pkgs, "ostype": ostype}, err)


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
    if d.get("ostype"):
        # the OS type CloudStack shows for the template (registration needs it)
        lines.append(f'cs_ostype: "{d["ostype"]}"')
    lines += [f'epel: {d["epel"]}', f'disk_size: "{d["disk"]}"', "packages:"]
    lines += [f"  - {p}" for p in d["pkgs"]]
    return "\n".join(lines) + "\n"


# ---------- local build queue ----------------------------------------------

def _find_build_env(distro: str, version: str, since: float) -> Path | None:
    """The descriptor build.sh wrote for THIS build. Its file name comes from the
    template display name ("Ubuntu 26.04" -> template-ubuntu-26_04-v1_2.env), NOT
    from the manifest slug, so it is found by content (DISTRO + VERSION) and age."""
    best = None
    for p in BUILDS.glob("*.env"):
        try:
            if p.stat().st_mtime < since:
                continue
            meta = dict(l.split("=", 1) for l in p.read_text().splitlines() if "=" in l)
        except OSError:
            continue
        if meta.get("DISTRO") == distro and meta.get("VERSION") == version:
            if best is None or p.stat().st_mtime > best.stat().st_mtime:
                best = p
    return best


def _publish(envfile: Path, img: Path) -> Path:
    """Moves a PASSING image and its descriptor into the artifacts directory.
    Written under a temporary name and renamed, so the artifacts list (and the
    CloudStack SSVM downloading from it) never sees a half-copied file."""
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    dst = ARTIFACTS / img.name
    tmp = ARTIFACTS / f".{img.name}.part"
    shutil.copyfile(img, tmp)
    tmp.chmod(0o644)
    os.replace(tmp, dst)
    meta = [l for l in envfile.read_text().splitlines() if not l.startswith("IMG=")]
    meta.append(f"IMG={dst}")
    tmpe = ARTIFACTS / f".{envfile.name}.part"
    tmpe.write_text("\n".join(meta) + "\n")
    tmpe.chmod(0o644)
    os.replace(tmpe, ARTIFACTS / envfile.name)
    img.unlink(missing_ok=True)   # the working copy is ~1 GB; the artifact is the copy that counts
    return dst


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

        def note(msg: str) -> None:
            f.write(msg + "\n")
            f.flush()

        # On a host install the checkout has NO auto-sync (no timer, no cron), so
        # without this the operator clicks "Build" and gets code from arbitrarily
        # many commits ago - and the log would not tell. A failed pull does not
        # block the build, but it must be visible: the built commit goes into the
        # job. The Docker image carries its code baked in (FACTORY_GIT_PULL=0).
        if GIT_PULL:
            job["state"] = "updating repository"
            if sh(["git", "pull", "--ff-only"]) != 0:
                note("!! git pull failed - building from the local version (see commit below)")
        job["commit"] = _code_version(short=True) or "?"
        note(f"# building code: {job['commit']}")

        if job.get("kind") == "e2e":
            # Test on a LIVE machine: deploys a VM from a temporary template, checks
            # the full feature set and cleans up after itself. Run from here, NOT
            # from CI, because a CI job runs as the runner user - and the CloudStack
            # API keys stay with the GUI user, not in the code-building environment.
            job["state"] = "e2e test on a live VM"
            sel = (["--artifact", job["artifact"]] if job.get("artifact")
                   else ["--distro", job["distro"]])
            rc = sh(["python3", "e2e/tier3-features.py"] + sel)
            job["state"] = "PASS" if rc == 0 else "FAIL"
            job["finished"] = time.strftime("%H:%M:%S")
            return

        # The same gate as `make release`: build -> offline validation -> boot
        # test -> publication. Only an image that passed all of it reaches the
        # artifacts list (and with it the "Register in CloudStack" button).
        started = time.time() - 1
        job["state"] = "building image"
        rc = sh(["./build.sh", job["distro"], job["version"]])
        envfile = img = None
        if rc == 0:
            envfile = _find_build_env(job["distro"], job["version"], started)
            if envfile:
                for line in envfile.read_text().splitlines():
                    if line.startswith("IMG="):
                        img = Path(line.split("=", 1)[1])
            if not (img and img.is_file()):
                note("!! build.sh finished but its image descriptor (.env) was not found")
                rc = 1
        if rc == 0:
            job["state"] = "validating (offline gate)"
            rc = sh(["e2e/validate-offline.sh", str(img)])
        if rc == 0:
            job["state"] = "boot test"
            rc = sh(["e2e/smoke-boot.sh", str(img)])
        if rc == 0:
            job["state"] = "publishing"
            try:
                dst = _publish(envfile, img)
                note(f"published: {dst}")
            except OSError as e:
                note(f"!! publication failed: {e}")
                rc = 1
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


def _auth_missing_page():
    missing = [n for n, v in (("OIDC_ISSUER", OIDC_ISSUER), ("OIDC_CLIENT_ID", OIDC_CLIENT_ID),
                              ("EXTERNAL_URL", EXTERNAL_URL)) if not v]
    return page("Sign-in not configured", f"""<div class=card><h2>Sign-in not configured</h2>
<div class=err>No sign-in method is configured. Set <code>FACTORY_ADMIN_PASSWORD</code>
(single admin password) or configure OIDC (missing: <code>{html.escape(', '.join(missing))}</code>).</div>
<p class=note>Set them in <code>{html.escape(CONFIG_HINT)}</code> and {html.escape(RESTART_HINT)}.</p></div>""",
                nav=False), 503


def _safe_next() -> str:
    nxt = str(session.pop("next", "/") or "/")
    # local paths only - never an open redirect to another host
    return nxt if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt else "/"


# Local-login brute-force brake: failures are counted per process (one worker);
# after LOGIN_MAX_FAILS within LOGIN_WINDOW s further attempts are refused.
LOGIN_MAX_FAILS, LOGIN_WINDOW = 10, 300
_login_fails: list[float] = []


def _login_form(err: str = "", code: int = 200):
    e = f"<div class=err>{html.escape(err)}</div>" if err else ""
    return page("Sign in", f"""<div class=card><h2>Sign in</h2>{e}
<form method=post action="/login">
<label>user</label><input name=user value="admin" autocomplete=username>
<label>password</label><input name=password type=password autocomplete=current-password required autofocus>
<button style="margin-top:12px">Sign in</button></form>
<p class=note>Single administrator account (<code>FACTORY_ADMIN_PASSWORD</code>).</p></div>""",
                nav=False), code


@app.get("/login")
def login():
    if OIDC_CONFIGURED:
        return oauth.oidc.authorize_redirect(EXTERNAL_URL + "/callback")
    if LOCAL_LOGIN:
        return _login_form()
    return _auth_missing_page()


@app.post("/login")
def login_post():
    if not LOCAL_LOGIN:
        return "local sign-in is not enabled", 404
    now = time.time()
    with _lock:
        _login_fails[:] = [x for x in _login_fails if now - x < LOGIN_WINDOW]
        locked = len(_login_fails) >= LOGIN_MAX_FAILS
    if locked:
        return _login_form("Too many failed attempts - wait a few minutes and try again.", 429)
    user = (request.form.get("user") or "").strip()
    pw = request.form.get("password") or ""
    ok = hmac.compare_digest(user.encode(), b"admin") & hmac.compare_digest(
        pw.encode(), ADMIN_PASSWORD.encode())
    if not ok:
        with _lock:
            _login_fails.append(now)
        time.sleep(1)
        print(f"[login] failed local sign-in from {request.remote_addr}", flush=True)
        return _login_form("Wrong user or password.", 401)
    nxt = _safe_next()
    session.clear()   # fresh session on privilege change
    session["user"] = {"name": "admin", "groups": [REQUIRED_GROUP]}
    return redirect(nxt)


@app.get("/callback")
def callback():
    if not OIDC_CONFIGURED:
        return _auth_missing_page()
    token = oauth.oidc.authorize_access_token()
    info = token.get("userinfo") or oauth.oidc.userinfo(token=token)
    session["user"] = {"name": info.get("preferred_username") or info.get("email") or "?",
                       "groups": info.get("groups") or info.get("roles") or []}
    return redirect(_safe_next())


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
    links = ('<a href="/">dashboard</a><a href="/new">new distribution</a>'
             + ('<a href="/ci">CI status</a>' if GITLAB_CONFIGURED else '')
             + '<a href="/settings">settings</a><a href="/help">help</a>'
             '<a href="/artifacts/">artifacts</a>') if nav else ""
    missing = missing_config() if nav else []
    warn = (f'<div class="card span"><div class=banner>Configuration incomplete - missing: '
            f'<code>{html.escape(", ".join(missing))}</code>. Set them in '
            f'<code>{html.escape(CONFIG_HINT)}</code> and {html.escape(RESTART_HINT)}; the related '
            f'features stay unavailable until then.</div></div>') if missing else ""
    foot = (f'<p class=note style="text-align:center">CloudStack Template Factory'
            f'{" " + html.escape(PRODUCT_RELEASE) if PRODUCT_RELEASE else ""}</p>')
    return f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{html.escape(title)} - CloudStack Template Factory</title><style>{CSS}</style>
<header><h1>CloudStack Template Factory</h1>
{links}{who}</header>
<div class="wrap{' one' if wide else ''}">{warn}{body}</div>{foot}"""


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

    ci_card = ("""<div class="card"><h2>CI status (GitLab)</h2><div id=ci class=note>loading...</div>
<p class=note><a href="/ci">full live view &rarr;</a></p></div>""" if GITLAB_CONFIGURED else
               """<div class="card"><h2>Where do templates go?</h2><p class=note>A build that
passes every check appears below under <b>Finished templates</b>, with a button that
registers it in CloudStack. The image itself is served under
<a href="/artifacts/">/artifacts/</a> - CloudStack downloads it from there.</p></div>""")
    return page("Dashboard", f"""
<div class="card span"><h2>What do you want to do?</h2>
<div class=row2>
<div><b>Add a new distribution</b><p class=note>The wizard walks you through a
form (no YAML) and checks it before saving{" - CI then builds the template automatically" if GITLAB_CONFIGURED else "; then build it here"}.</p>
<a href="/new"><button>Open the wizard</button></a></div>
<div><b>Build a template now (on this host)</b>
<p class=note style="margin:4px 0 0">Build &rarr; offline validation gate &rarr; boot test &rarr;
publication. Takes about 10-30 minutes; only a PASS is published.</p>
<form method=post action="/build">
<label>distribution</label><select name=distro id=bdistro>{opts}</select>
<label>template version (goes into the template name "... vX.Y")</label>
<input name=version value="{release_version()}" pattern="[0-9]+\\.[0-9]+">
<label>disk size <span class=note>- leave empty to use the manifest value</span></label>
<input name=disk_size id=bdisk pattern="[0-9]+[GgMm]" placeholder="from manifest">
<p class=note style="margin:4px 0 0">Minimum <b>10G</b>. An increase applies to this
single build only - the manifest in the repository stays unchanged.</p>
<button style="margin-top:10px">Build locally</button></form></div>
</div>
<p class=note style="margin-top:12px">Available manifests: {mlinks}</p></div>

<div class="card"><h2>Recent local builds</h2>
<table><tr><th>#</th><th>what</th><th>state</th><th>finished</th><th></th></tr>
{''.join(rows) or '<tr><td colspan=5 class=note>none - nothing has been built yet</td></tr>'}</table>
<p class=note>PASS = the template passed the gate and can be registered in CloudStack.
FAIL = not fit for use (details in the log).</p></div>

{ci_card}

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
if(document.getElementById('ci'))fetch('/api/ci').then(r=>r.json()).then(d=>{{
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
    save_note = ("After saving, the manifest lands in the repository and CI builds and "
                 "checks the template on its own." if GITLAB_CONFIGURED else
                 "After saving, the distribution appears on the dashboard, where you build it.")
    return page("New distribution", f"""
<div class="card span"><h2>New distribution wizard</h2>{ok}{errs}
<div class=banner>Fill in the fields - no YAML or git knowledge needed. {save_note}
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
<label>CloudStack OS type (as listed in CloudStack, e.g. <i>Debian GNU/Linux 12 (64-bit)</i>;
needed to register the template)</label>
<input name=cs_ostype list=ostypes placeholder="Ubuntu 24.04 LTS" value="{html.escape(d.get('ostype',''))}">
{_ostype_datalist()}
<label><input type=checkbox name=epel style="width:auto" {'checked' if d.get('epel')=='true' else ''}>
 RHEL family (Rocky/Alma) - add the EPEL repository</label>
<label>Packages to install (one per line; suggestion = standard set)</label>
<textarea name=packages>{html.escape(chr(10).join(d.get('pkgs') or STD_PACKAGES))}</textarea>
<p class=note><code>qemu-guest-agent</code> and <code>fail2ban</code> are mandatory -
they are the supervision and security layer; without them the template will not pass the checks.</p>
<div style="margin-top:12px;display:flex;gap:10px">
<button name=action value=check class=ghost>Only check</button>
<button name=action value=save>Check and save</button></div>
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
    if not GITLAB_CONFIGURED:
        return _save_local_manifest(d, body)
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
    try:
        (REPO / "distros" / f"{d['slug']}.yaml").write_text(body)   # visible locally right away
    except OSError:
        pass   # read-only code directory: the next CI deploy brings it
    return new(okmsg=f"Manifest <code>distros/{html.escape(d['slug'])}.yaml</code> {action} "
                     f"in the repository. CI is building the template - "
                     f'<a href="/ci">watch the live status</a>.')


def _save_local_manifest(d: dict, body: str):
    """Standalone mode: the manifest goes to LOCAL_DISTROS (a persistent volume).
    Shipped manifests cannot be overwritten - they belong to the release."""
    if not LOCAL_DISTROS:
        return new(prefill=d, errors=["No GitLab repository and no local manifest directory "
                                      "(CSF_LOCAL_DISTROS) are configured - nowhere to save."])
    if d["slug"] in builtin_manifests():
        return new(prefill=d, errors=[f"'{d['slug']}' is a built-in distribution of this release "
                                      "and cannot be replaced - choose another technical name "
                                      f"(e.g. {d['slug']}-custom)."])
    LOCAL_DISTROS.mkdir(parents=True, exist_ok=True)
    dst = LOCAL_DISTROS / f"{d['slug']}.yaml"
    action = "updated" if dst.exists() else "saved"
    tmp = LOCAL_DISTROS / f".{d['slug']}.yaml.part"
    tmp.write_text(body, encoding="utf-8")
    os.replace(tmp, dst)
    slug = html.escape(d["slug"])
    return new(okmsg=f"""Distribution <code>{slug}</code> {action}. Build it now:
<form method=post action="/build" style="display:inline">
<input type=hidden name=distro value="{slug}">
<input type=hidden name=version value="{html.escape(release_version())}">
<button>Build {slug} v{html.escape(release_version())}</button></form>""")


_ostype_cache: dict = {"at": 0.0, "html": ""}


def _ostype_datalist() -> str:
    """Suggestions for the OS type field from CloudStack (cached 10 min; empty
    when CloudStack is not configured or unreachable - the field stays free text)."""
    if not cs.configured():
        return ""
    now = time.time()
    if now - _ostype_cache["at"] > 600:
        try:
            names = sorted({o.get("description", "") for o in cs.os_types()} - {""})
            _ostype_cache["html"] = ("<datalist id=ostypes>" + "".join(
                f"<option value=\"{html.escape(n)}\">" for n in names) + "</datalist>")
        except Exception:  # noqa: BLE001 - suggestions are a convenience only
            _ostype_cache["html"] = ""
        _ostype_cache["at"] = now
    return _ostype_cache["html"]


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
                    f"Set it in <code>{html.escape(CONFIG_HINT)}</code> to the URL from which "
                    f"the CloudStack secondary storage VM can download artifacts, then {html.escape(RESTART_HINT)}.")
    if not cs.configured():
        return fail("The GUI has no CloudStack API configuration.",
                    "Set the API URL and keys on the <a href='/settings'>Settings</a> page, or "
                    f"CS_API_URL, CS_API_KEY and CS_SECRET_KEY in <code>{html.escape(CONFIG_HINT)}</code>.")
    if not art["ostype"]:
        return fail(f"Manifest {art['distro']} has no cs_ostype field.",
                    "Open the wizard, enter the CloudStack OS type and save the distribution again.")
    try:
        ostypeid = cs.find_ostype_id(art["ostype"])
        if not ostypeid:
            return fail(f"CloudStack does not know the OS type: {art['ostype']}",
                        "Choose an existing type in the manifest (cs_ostype field).")
        zones = cs.zones()
        if not zones:
            return fail("CloudStack returned no available zone.")
        if CS_ZONE:
            zones = [z for z in zones if z.get("name") == CS_ZONE]
            if not zones:
                return fail(f"CloudStack has no available zone named '{CS_ZONE}' (CS_ZONE).",
                            "Check the zone name in CloudStack or clear CS_ZONE to use the first zone.")
        zoneid = zones[0]["id"]
        url = f"{ARTIFACTS_BASE_URL}/{art['file']}"
        r = cs.register_template(name=art["template_name"], url=url, ostypeid=ostypeid,
                                 zoneid=zoneid, ispublic=ispublic,
                                 extraconfig=cs.CSF_INSPECT_CHANNEL if INSPECT_CHANNEL else None)
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
{"""<p class=note>The template carries the supervision channel <code>org.csfactory.support.0</code>.
Accounts that will create machines from this template must have
<code>enable.additional.vm.configuration</code> enabled - otherwise the machine will not start.</p>""" if INSPECT_CHANNEL else ""}
<p><a href="/">&larr; back to dashboard</a></p></div>""", wide=True)


@app.get("/log/<int:jid>")
@require_admin
def log(jid: int):
    for j in _jobs:
        if j["id"] == jid:
            p = Path(j.get("log", ""))
            raw = p.read_text(errors="replace")[-60000:] if p.exists() else "(empty so far)"
            # colour codes from the gate scripts are noise in the browser
            body = html.escape(re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw))
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
    mp = manifest_path(name)
    if not mp:
        return "no such manifest", 404
    body = html.escape(mp.read_text())
    origin = "built-in (part of this release)" if name in builtin_manifests() else "added from the GUI"
    return page(f"Manifest {name}", f"""<div class="card span">
<h2>{html.escape(name)}.yaml &middot; {origin}</h2><div class=feed>{body}</div>
<p class=note>To change a distribution, open the wizard and save it again under the same
technical name (built-in distributions are changed in the project repository).</p></div>""", wide=True)


# ---------- live CI view ---------------------------------------------------

@app.get("/api/ci")
@require_admin
def api_ci():
    if not GITLAB_CONFIGURED:
        return {"error": "GitLab integration is not configured (optional)"}
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
    if not GITLAB_CONFIGURED:
        return page("CI status", """<div class="card span"><h2>CI status</h2>
<p class=note>The GitLab integration is optional and not configured. Without it,
templates are built from the <a href="/">dashboard</a>. See the documentation
("GitLab integration") to connect a GitLab project.</p></div>""", wide=True)
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
<tr><td>sign-in</td><td>{'OIDC' if OIDC_CONFIGURED else ('local admin password' if LOCAL_LOGIN else ('<span class=n>disabled (FACTORY_AUTH_DISABLED)</span>' if AUTH_DISABLED else '<span class=n>not configured</span>'))}</td></tr>
<tr><td>manifest repository</td><td>{(f"<code>{html.escape(GITLAB_URL)}</code> &middot; project {html.escape(GITLAB_PROJECT)} &middot; branch {html.escape(GITLAB_BRANCH)}") if GITLAB_CONFIGURED else ('standalone - local manifests in <code>' + html.escape(str(LOCAL_DISTROS or '-')) + '</code>')}</td></tr>
<tr><td>registration zone</td><td>{html.escape(CS_ZONE or 'first available')} &middot; inspection channel {'on' if INSPECT_CHANNEL else 'off'}</td></tr>
<tr><td>artifacts directory</td><td><code>{html.escape(str(ARTIFACTS))}</code></td></tr>
<tr><td>artifacts URL for CloudStack</td><td><code>{html.escape(ARTIFACTS_BASE_URL or '-')}</code>
 <span class=note>(the SSVM downloads images from here)</span></td></tr>
</table>
<p class=note>An administrator changes these values in <code>{html.escape(CONFIG_HINT)}</code>
(then {html.escape(RESTART_HINT)}).</p></div>""", wide=True)


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
<li><b>Click "Check and save".</b> """ + (
    """This saves the manifest to the repository and starts the build in CI.
Progress: <a href="/ci">CI status</a>.</li>
<li><b>Wait for "success".</b> The template appears on the dashboard under
<i>Finished templates</i>.</li>""" if GITLAB_CONFIGURED else
    """The distribution is saved and a <b>Build</b> button appears. Click it (or pick the
distribution on the <a href="/">dashboard</a>). The build runs through the offline gate and a
boot test; follow it with the <i>log</i> link.</li>
<li><b>Wait for PASS.</b> The template appears on the dashboard under
<i>Finished templates</i>.</li>""") + """
<li><b>Click "Register in CloudStack".</b> CloudStack downloads the image from
<a href="/artifacts/">/artifacts/</a> and the template becomes ready a few minutes later.</li>
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
""" + ("""<li><b>Local build vs CI</b> - a local build (button on the dashboard) is for a
quick check of one thing here and now; CI builds all distributions
after every change and is the source of truth.</li>""" if GITLAB_CONFIGURED else "") + """
<li><b>What PASS/FAIL means</b> - after the build the image goes through an automatic
check (among others: can the password be reset from CloudStack, are SSH host keys
unique per machine, is supervision enabled). FAIL = such a template is not registered.</li>
</ul>
<p class=note>Full documentation: <a href="https://github.com/wd-ppisz/cs-factory/tree/main/docs">docs/</a>
in the project repository (installation, GUI guide, configuration, troubleshooting).</p></div>""",
                wide=True)


def _code_version(short: bool = False) -> str:
    """Commit of the code on disk: the git checkout on a host install, or the
    commit baked into the Docker image (CSF_COMMIT)."""
    try:
        v = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                           text=True, timeout=10, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        v = os.environ.get("CSF_COMMIT", "")
    return v[:12] if short else v


def _commit_at_start() -> str:
    """Commit this process loaded its code from. The on-disk checkout moves
    underneath the running service (`git pull` before a build), so "what is in
    the repo" does not tell what is running - the CI deploy (ci/factory-deploy.sh)
    compares against THIS value."""
    return _code_version()


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

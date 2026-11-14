"""Minimal signed CloudStack API client (stdlib only: HMAC-SHA1 over a sorted query).

Used by the GUI to register finished templates. Deliberately WITHOUT projectid:
a production template is meant to land in the ROOT domain (main view), not in a
single project.
"""
import base64
import hashlib
import hmac
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Credentials can come from TWO places:
#  1) a runtime file written from the GUI ("Settings" page) - takes precedence,
#     because a change must take effect immediately, without restarting the
#     service (a restart requires root);
#  2) environment variables from /etc/cs-factory/gui.env (bootstrap at install time).
# Runtime file: 0600, owned by `factory`. The secret NEVER goes back to the browser -
# the GUI only shows a fingerprint (sha256[:10]).
CREDS_FILE = Path(os.environ.get("CS_CREDS_FILE", "/var/lib/cs-factory/cs-creds.json"))

# No built-in default: the API endpoint is site-specific and must be configured
# (CS_API_URL in gui.env or the "Settings" page).
DEFAULT_API_URL = os.environ.get("CS_API_URL", "")


class CSError(RuntimeError):
    pass


# HTTP(S)-ONLY opener. The default `urllib.request.urlopen` also handles file://
# and ftp://, and a redirect from https can downgrade to ftp://. The GUI fetches
# operator-supplied URLs (image, checksum file, CloudStack API) - form validation
# requires https://, but that is one layer; this is the second: without file/ftp
# handlers no URL or redirect can read a file from the factory host's disk
# (e.g. /etc/cs-factory/gui.env with secrets). Bandit B310.
_OPENER = urllib.request.OpenerDirector()
for _h in (urllib.request.HTTPHandler, urllib.request.HTTPSHandler,
           urllib.request.HTTPRedirectHandler, urllib.request.HTTPDefaultErrorHandler,
           urllib.request.HTTPErrorProcessor,
           # without this an unhandled scheme (e.g. ftp:// from a redirect) would
           # return None instead of raising; UnknownHandler raises URLError
           urllib.request.UnknownHandler):
    _OPENER.add_handler(_h())


def safe_urlopen(req, timeout: float):
    """`urlopen` restricted to http/https (also after redirects)."""
    url = req.full_url if isinstance(req, urllib.request.Request) else str(req)
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"URL scheme not allowed: {url[:60]}")
    return _OPENER.open(req, timeout=timeout)


def _from_file() -> dict:
    try:
        return json.loads(CREDS_FILE.read_text())
    except Exception:  # noqa: BLE001 - missing/corrupt file simply means "not set"
        return {}


def creds() -> dict:
    f = _from_file()
    return {
        "api_url": f.get("api_url") or DEFAULT_API_URL,
        "api_key": f.get("api_key") or os.environ.get("CS_API_KEY", ""),
        "secret": f.get("secret") or os.environ.get("CS_SECRET_KEY", ""),
        "source": "GUI" if f.get("api_key") else ("gui.env file" if os.environ.get("CS_API_KEY") else "none"),
    }


def fingerprint(value: str) -> str:
    """Fingerprint of a secret to display in the GUI - never the value itself."""
    return hashlib.sha256(value.encode()).hexdigest()[:10] if value else "-"


def save_creds(api_url: str, api_key: str, secret: str) -> None:
    CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CREDS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"api_url": api_url, "api_key": api_key, "secret": secret}))
    tmp.chmod(stat.S_IRUSR | stat.S_IWUSR)          # 0600 before the file becomes visible
    tmp.replace(CREDS_FILE)
    CREDS_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)   # and after the swap (in case umask/FS interfered)


def configured() -> bool:
    c = creds()
    return bool(c["api_url"] and c["api_key"] and c["secret"])


def call(command: str, **params) -> dict:
    c = creds()
    if not c["api_url"]:
        raise CSError("CloudStack API URL is not configured - set CS_API_URL or use the Settings page")
    if not (c["api_key"] and c["secret"]):
        raise CSError("CloudStack API keys are missing - set them on the Settings page")
    return call_with(c, command, **params)


def call_with(c: dict, command: str, **params) -> dict:
    """Call with EXPLICITLY supplied credentials - lets new keys be tested
    without touching the saved configuration (test before save)."""
    API_URL, API_KEY, SECRET = c["api_url"], c["api_key"], c["secret"]
    if not API_URL:
        raise CSError("CloudStack API URL is not configured")
    q = {"command": command, "apiKey": API_KEY, "response": "json"}
    q.update({k: str(v) for k, v in params.items() if v is not None})
    # CloudStack signature: pairs sorted by key, values urlencoded, and the WHOLE
    # string lowercased only for the HMAC computation (lowercasing just the keys
    # gives 401 "unable to verify user credentials and/or request signature").
    query = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in sorted(q.items()))
    sig = base64.b64encode(
        hmac.new(SECRET.encode(), query.lower().encode(), hashlib.sha1).digest()).decode()
    body_data = (query + "&signature=" + urllib.parse.quote(sig, safe="")).encode()
    req = urllib.request.Request(
        API_URL, data=body_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with safe_urlopen(req, timeout=60) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise CSError(f"CloudStack rejected the request ({e.code}): {detail}") from e
    except Exception as e:  # noqa: BLE001
        raise CSError(f"CloudStack unreachable: {e}") from e
    data = json.loads(body or b"{}")
    key = command.lower() + "response"
    return data.get(key, data)


def os_types() -> list[dict]:
    r = call("listOsTypes")
    return r.get("ostype", [])


def find_ostype_id(name: str) -> str | None:
    """Match by OS type description (exact first, then 'starts with')."""
    types = os_types()
    for o in types:
        if o.get("description", "").lower() == name.lower():
            return o["id"]
    for o in types:
        if o.get("description", "").lower().startswith(name.lower()):
            return o["id"]
    return None


def zones() -> list[dict]:
    return call("listZones", available="true").get("zone", [])


def test_creds(api_url: str, api_key: str, secret: str) -> list[str]:
    """Checks the supplied credentials (returns zone names). Raises CSError on
    failure. Does not touch the saved configuration."""
    r = call_with({"api_url": api_url, "api_key": api_key, "secret": secret},
                  "listZones", available="true")
    return [z["name"] for z in r.get("zone", [])]


def register_template(*, name: str, url: str, ostypeid: str, zoneid: str,
                      ispublic: bool = True, extraconfig: str | None = None,
                      projectid: str | None = None) -> dict:
    """Registers in the ROOT domain (no projectid is a deliberate choice for
    production templates: they should be visible in the main view, not in a
    single project).

    `projectid` is passed ONLY by the e2e test, which registers a TEMPORARY
    template and deletes it right away: a private template from ROOT is invisible
    to a VM inside a project (CloudStack answers 531), and a public one requires
    an admin account.

    passwordenabled=true pairs with the cloud-init invariant set_passwords=always
    (password reset from CloudStack on every boot).
    """
    params = {
        "name": name, "displaytext": name, "url": url,
        "hypervisor": "KVM", "format": "QCOW2",
        "ostypeid": ostypeid, "zoneid": zoneid,
        "passwordenabled": "true", "isdynamicallyscalable": "true",
        "requireshvm": "true", "ispublic": "true" if ispublic else "false",
        "details[0].rootDiskController": "virtio",
    }
    if extraconfig:
        params["details[0].extraconfig-1"] = extraconfig
    if projectid:
        params["projectid"] = projectid
    return call("registerTemplate", **params)


# virtio-serial channel for the csf-inspect inspection agent.
# Injected into the template details -> copied into every VM's details at deploy.
#
# The XML must be RAW, NOT url-encoded: CloudStack DECODES the `extraconfig` API
# parameter on write, but copies the template detail value into the VM VERBATIM.
# Encoded XML therefore reached the domain definition as the text `%3Cdevices%3E...`,
# libvirt ignored it and the channel was never created (the VM booted normally -
# a silent failure). The HTTP transport encodes it once on its own.
#
# Requires on the CloudStack side (Account scope): enable.additional.vm.configuration=true
# and allow.additional.vm.configuration.list.kvm listing EVERY nested tag.
CSF_INSPECT_CHANNEL = ('<devices><channel type="unix">'
                       '<target type="virtio" name="org.csfactory.support.0"/></channel></devices>')

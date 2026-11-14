#!/usr/bin/env python3
"""Tier-3: full feature test of a template on a LIVE machine in CloudStack.

What CANNOT be checked offline (the `validate-offline.sh` gate only inspects the
image contents): whether the datasource actually talks to the Virtual Router,
whether user-data runs, whether the password can be reset, whether host keys
SURVIVE a reboot, whether the csf-inspect channel appears in the machine and
whether the watchdog is armed.

Flow for each artifact:
  1. registers a TEMPORARY template (name with the E2E prefix + run stamp),
  2. waits until the SSVM downloads the image,
  3. creates an ephemeral SSH key pair and deploys a machine with user-data,
  4. checks the full feature set inside the guest,
  5. stops the machine, resets the password via the API, starts it again,
  6. checks invariants visible only after a reboot (host keys, password),
  7. **CLEANS UP EVERYTHING** — machine (expunge), template, key pair — also when
     the test failed or was interrupted (finally + --cleanup-only mode).

Nothing stays in CloudStack: this is a test, not a deployment. Production
registration is a separate, deliberate decision (`register.sh` / the GUI button).

CloudStack resources are looked up by NAME and must be provided explicitly
(command-line option or environment variable):
  --network  / CSF_CS_NETWORK            guest network (required; must be reachable
                                         over SSH from the machine running this test)
  --zone     / CSF_CS_ZONE               zone (optional; empty = the only/first available)
  --offering / CSF_CS_SERVICE_OFFERING   service offering (optional; empty = smallest
                                         offering with fixed CPU/RAM)
  --project  / CSF_CS_PROJECT            project (optional; empty = no project)
Artifacts: FACTORY_ARTIFACTS (directory), ARTIFACTS_BASE_URL (URL the SSVM downloads
from; required).

Usage:
  ./tier3-features.py --all                      # all artifacts that passed
  ./tier3-features.py --distro debian-13         # one
  ./tier3-features.py --cleanup-only             # clean up after an interrupted run
"""
import argparse
import base64
import secrets
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "gui"))
import cs  # noqa: E402  — CloudStack client shared with the GUI

# Line-by-line output: when redirected to a file (that is how the GUI runs it)
# a block buffer would hold all progress until the end of the run — a live view
# would show an empty log for many minutes.
sys.stdout.reconfigure(line_buffering=True)

ARTIFACTS = Path(os.environ.get("FACTORY_ARTIFACTS", "/srv/cs-factory/artifacts"))
ARTIFACTS_BASE_URL = os.environ.get("ARTIFACTS_BASE_URL", "").rstrip("/")
# Network/offering/zone/project by NAME, not by id, so the script can be run
# without copying UUIDs around. The network must be reachable from this machine
# (SSH into the guest). Values come from CLI options or the environment (see main()).
NET_NAME = os.environ.get("CSF_CS_NETWORK", "")
# CUSTOM offerings have no CPU/RAM in the offering itself — they are passed at
# deploy time (two parameters are enough when the offering has cpuspeed).
OFFERING_NAME = os.environ.get("CSF_CS_SERVICE_OFFERING", "")
E2E_CPU = os.environ.get("E2E_CPU", "2")
E2E_RAM_MB = os.environ.get("E2E_RAM_MB", "2048")
ZONE_NAME = os.environ.get("CSF_CS_ZONE", "")               # empty = the only available one
# If the test network belongs to a project, the whole test runs in the project
# context: including the template, because a private template from ROOT is
# invisible to a machine in a project (CloudStack answers 531).
PROJECT_NAME = os.environ.get("CSF_CS_PROJECT", "")
PROJECT_ID = ""
# The first boot can be long: `csf-firstboot` runs a system update, which crawls
# under TCG. 420 s was not enough for openSUSE and Rocky 9/10.
SSH_TIMEOUT = int(os.environ.get("E2E_SSH_TIMEOUT", "900"))

MARK = "csf-e2e"          # marker in names — --cleanup-only cleans up by it
USERDATA_MARKER = "/run/csf-e2e-userdata-ok"
CHANNEL_DEV = "/dev/virtio-ports/org.csfactory.support.0"
# The default user of a cloud image depends on the distribution; tried in order.
# The CORRECT user MUST come first and the list must be short: each attempt with a
# wrong account is a failed login, and the template has fail2ban (maxretry=5), whose
# ignoreip need not cover the machine running this test. openSUSE Leap 16 has
# `default_user: sles` in cloud.cfg — the former ["opensuse", "root"] gave 2 failures
# every 10 s, a ban after ~25 s and "port 22 answered, then connection refused".
#
# NOTE: on Rocky 10 and openSUSE Leap 16 the fail2ban ban was only a CONSEQUENCE,
# not the cause. The cause was in cloud-init:
# `DataSourceCloudStack._get_domainname()` asks for a DHCP lease, and both images
# had NO dhclient — only `dhcpcd`, which they do not run (NetworkManager manages
# the network). cloud-init calls `dhcpcd --dumplease`, gets "dhcpcd is not running"
# and aborts the WHOLE `init` stage with NoDHCPLeaseError. Effects:
#   - the SSH key from CloudStack does not reach authorized_keys -> "Permission denied
#     (publickey)" -> more test attempts -> ban -> symptom "port went silent",
#   - user-data does not run at all (the `init` stage modules never start),
#   - on Rocky 10 right after that exception `sshd.service` reports FAILED and port 22
#     is dead from boot; on openSUSE sshd starts normally and the port is open.
#     Mechanism read from the image's units: the drop-in
#     `sshd-keygen@.service.d/disable-sshd-keygen-if-cloud-init-active.conf` disables
#     the host key generator when cloud-init is active — the keys are then created
#     only by the `ssh` module of the init stage, which never runs after the exception.
# Ruled out by measurement: SELinux (relabel did not help, zero AVCs in the boot log),
# CPU model (guests get Haswell-noTSX-IBRS, i.e. x86-64-v3) and the watchdog
# (the machines never rebooted during ~910 s).
# Rocky 8/9 pass tier3 because they have the `dhcp-client` package (dhclient) and
# return from the ISC branch. Debian 13 has only `dhcpcd`, but never gets there —
# the networkd lease carries `DOMAINNAME` and the function returns earlier.
# Fix: Rocky 10 — `upgrade_packages: [cloud-init]` (a cloud-init build carrying the
# upstream fix #6554), openSUSE — the `dhcp-client` package +
# `cloudinit_dhcp_client_priority: [dhclient]`. The defect class is caught offline by
# e2e/probe-ds-cloudstack.py (via validate-offline.sh).
# `dhcp_client_priority` pointing at a client ABSENT from the image (the
# `cloudstack_datasource_network` mode from Ubuntu 22.04) does NOT fix this defect —
# `Distro.dhcp_client` filters the list by class names KNOWN to cloud-init, not by
# binary presence, and ends with `raise NoDHCPLeaseMissingDhclientError`, which is
# raised from the `self.distro.dhcp_client.client_name` line in a `LOG.debug` in
# `_get_domainname()` without any guard (also after fix #6554). A PRESENT client
# (dhclient on openSUSE) fixes it: without a lease it returns `{}`.
# That is why the user list stays SHORT — with this defect every extra attempt only
# speeds up the ban and obscures the symptom.
SSH_USER_CANDIDATES = {
    "debian": ["debian"], "ubuntu": ["ubuntu"], "rocky": ["rocky", "cloud-user"],
    "opensuse": ["sles"],
}

G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
N = "\033[0m"


class Result:
    def __init__(self):
        self.checks: list[tuple[bool, str]] = []

    def ok(self, msg):
        self.checks.append((True, msg))
        print(f"  {G}OK  {N} {msg}")

    def no(self, msg):
        self.checks.append((False, msg))
        print(f"  {R}FAIL{N} {msg}")

    def check(self, cond, msg_ok, msg_no=None):
        self.ok(msg_ok) if cond else self.no(msg_no or msg_ok)

    def warn(self, msg):
        """A limitation of the ENVIRONMENT, not a template defect — visible, but does
        not spoil the result. Otherwise the test would shout the same for every distro."""
        print(f"  {Y}WARN{N} {msg}")

    @property
    def failed(self):
        return [m for good, m in self.checks if not good]


def log(msg):
    print(f">> {msg}", flush=True)


def async_result(jobid, timeout=900, desc="async job"):
    """Waits for the result of a CloudStack async job (jobstatus: 0=running,
    1=OK, 2=error). One query per iteration — no double polling."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        j = cs.call("queryAsyncJobResult", jobid=jobid)
        st = j.get("jobstatus")
        if st == 1:
            return j.get("jobresult") or {}
        if st == 2:
            raise RuntimeError(f"{desc}: CloudStack returned an error: "
                               f"{json.dumps(j.get('jobresult'))[:300]}")
        time.sleep(8)
    raise TimeoutError(f"{desc}: no result after {timeout}s")


def wait_for(fn, timeout, desc, interval=10):
    """Waits for a condition. Returns the value or raises — with an EXPLICIT time in
    the message, so "does not work" is not confused with "not there yet"."""
    start = time.monotonic()
    last = None
    while time.monotonic() - start < timeout:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise TimeoutError(f"{desc}: not reached after {timeout}s (last state: {last!r})")


# ---------- CloudStack: resource lookup by name ------------------------------

def pcall(command, **params):
    """API call in the project context (if set). Resources of the test machine —
    network, keypair, the machine itself, template — live in the project."""
    if PROJECT_ID:
        params.setdefault("projectid", PROJECT_ID)
    return cs.call(command, **params)


def find_project():
    if not PROJECT_NAME:
        return ""
    for p in cs.call("listProjects", listall="true").get("project", []):
        if p["name"] == PROJECT_NAME:
            return p["id"]
    raise SystemExit(f"project {PROJECT_NAME!r} not found (--project / CSF_CS_PROJECT)")


def find_zone():
    zones = cs.call("listZones", available="true").get("zone", [])
    if ZONE_NAME:
        zones = [z for z in zones if z["name"] == ZONE_NAME]
    if not zones:
        raise SystemExit(f"zone not found (--zone / CSF_CS_ZONE={ZONE_NAME!r})")
    return zones[0]


def find_network(zoneid):
    if not NET_NAME:
        raise SystemExit("no test network given: set --network or CSF_CS_NETWORK to the name of "
                         "a CloudStack network reachable over SSH from this machine")
    nets = pcall("listNetworks", zoneid=zoneid, listall="true").get("network", [])
    exact = [n for n in nets if n["name"] == NET_NAME]
    if not exact:
        raise SystemExit(f"network {NET_NAME!r} not found; available: "
                         + ", ".join(n["name"] for n in nets))
    return exact[0]


def find_offering():
    offs = cs.call("listServiceOfferings").get("serviceoffering", [])
    if OFFERING_NAME:
        hit = [o for o in offs if o["name"] == OFFERING_NAME]
        if not hit:
            raise SystemExit(f"offering {OFFERING_NAME!r} not found; available: "
                             + ", ".join(o["name"] for o in offs))
        return hit[0]
    usable = [o for o in offs if o.get("cpunumber") and o.get("memory")]
    if not usable:
        raise SystemExit("no offering with fixed CPU/RAM — name one with --offering / "
                         "CSF_CS_SERVICE_OFFERING")
    return sorted(usable, key=lambda o: (o["cpunumber"], o["memory"]))[0]


# ---------- SSH -------------------------------------------------------------

def ssh_base(key_path, known_hosts):
    return ["ssh", "-i", str(key_path), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]


def ssh_try(ip, user, key_path, known_hosts, cmd, timeout=60):
    p = subprocess.run(ssh_base(key_path, known_hosts) + [f"{user}@{ip}", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def port_open(ip, port=22, timeout=5):
    """Does the port accept connections at all? Distinguishes "sshd did not start"
    from "sshd runs but does not let us in" — without it both look identical."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ping_answers(ip, timeout=2):
    """Does the machine answer ICMP? This SEPARATES two entirely different failures
    that look the same on port 22 ("Connection refused"):
      - no ping  -> the guest did not boot, has no network or is rebooting,
      - ping OK  -> the system is ALIVE with a TCP/IP stack, only sshd is not running.
    Without this measurement the diagnosis goes astray: Rocky 10 was reported as
    "sshd did not start or the machine did not reach multi-user", while the machine
    pinged, had port 9090 (cockpit) open and multi-user.target reached — ONLY sshd
    failed, because cloud-init aborted the `init` stage on NoDHCPLeaseError (see the
    comment at SSH_USER_CANDIDATES). The search went towards boot and CPU model
    instead of a single service."""
    return subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                          capture_output=True).returncode == 0


def wait_ssh(ip, users, key_path, known_hosts):
    """Waits for SSH and determines which user we log in as.

    On failure the message MUST say what is going on: whether the machine is alive
    at all (ping), whether port 22 is silent (sshd itself is down), or whether it
    answers but rejects the key (cloud-init did not inject it, or the user differs).
    Without that, "did not come up in 900s" leads to no hypothesis."""
    deadline = time.monotonic() + SSH_TIMEOUT
    last_error = ""
    port_seen = False
    ping_seen = False
    while time.monotonic() < deadline:
        if port_open(ip):
            port_seen = True
        if not ping_seen and ping_answers(ip):
            ping_seen = True
        for u in users:
            try:
                rc, out, err = ssh_try(ip, u, key_path, known_hosts, "echo ready", timeout=20)
                if rc == 0 and "ready" in out:
                    return u
                if err.strip():
                    last_error = f"{u}: {err.strip().splitlines()[-1][:160]}"
            except subprocess.TimeoutExpired:
                last_error = f"{u}: ssh did not answer within 20 s"
        time.sleep(10)
    pings = ping_answers(ip)
    state = ("port 22 ANSWERS, so sshd is running — the problem is with letting us in"
             if port_open(ip) else
             ("port 22 is SILENT now, although it answered earlier — most often fail2ban "
              "banned the test address after failed logins (wrong user?), less often the "
              "service died or the machine is rebooting"
              if port_seen else "port 22 SILENT the whole time"))
    # Ping adds a distinction that port 22 alone cannot give.
    state += ("; the machine ANSWERS ping, so the system is alive and has a network — the "
              "failure concerns sshd ITSELF (check `systemctl status sshd` and "
              "`cloud-init status --long`: if the `init` stage failed on NoDHCPLeaseError, "
              "no host keys were created)"
              if pings else
              ("; the machine does NOT answer ping (it did earlier) — rebooting "
               "or network down" if ping_seen else
               "; the machine does NOT answer ping the whole time — it did not boot, has no "
               "network or did not reach multi-user"))
    raise TimeoutError(f"SSH to {ip} did not come up within {SSH_TIMEOUT}s "
                       f"(users: {users}; {state}; last error — {last_error or 'none'})")


def wait_cloud_init(ip, user, key, kh, timeout=900):
    """Waits until cloud-init finishes. Without it the test RACES: sshd starts
    earlier than the `final` stage, so `runcmd` from user-data may not have run yet
    and the probe reports "user-data did not run" on a healthy template.

    We POLL instead of calling `cloud-init status --wait`: the blocking call hung for
    10 minutes in a single `ssh` and said NOTHING about what it was waiting on. Here
    each attempt has its own limit and the state goes to the log — the first boot can
    be long, because `csf-firstboot` runs a system update and may compete with the
    last cloud-init stage for the package manager lock."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            _, out, _ = ssh_try(ip, user, key, kh,
                                # exit code 2 = finished with warnings (cloud-init >= 23.4) —
                                # still a result, not "no answer"
                                "s=$(cloud-init status 2>/dev/null); echo \"${s:-status: none}\"",
                                timeout=45)
        except subprocess.TimeoutExpired:
            out = "status: no answer"
        last = (out or "").strip()
        if any(w in last for w in ("done", "error", "disabled", "degraded")):
            return last
        log(f"cloud-init still working ({last or 'no answer'}) — waiting")
        time.sleep(15)
    return last or "no answer"


def host_key_fingerprints(ip, known_hosts_dir):
    """Host key fingerprints — compared BEFORE and AFTER the reboot (invariant 4)."""
    p = subprocess.run(["ssh-keyscan", "-T", "15", "-t", "rsa,ecdsa,ed25519", ip],
                       capture_output=True, text=True, timeout=60)
    tmp = Path(known_hosts_dir) / f"keys-{time.time_ns()}"
    tmp.write_text(p.stdout)
    f = subprocess.run(["ssh-keygen", "-lf", str(tmp)], capture_output=True, text=True)
    return sorted(line.split()[1] for line in f.stdout.splitlines() if line.strip())


# ---------- in-guest probe ----------------------------------------------------

PROBE = r"""
set +e
# We log in as the cloud image's default user, but part of the state is visible
# only as root: the fail2ban control socket is 0600 root, and /var/log/cloud-init.log
# can be 0640 root:adm (on RHEL/SUSE the user is not in `adm`). Without this the test
# would report "no sshd jail" on a perfectly healthy template.
SUDO=""; sudo -n true 2>/dev/null && SUDO="sudo -n"
echo "sudo_available=$( [ -n "$SUDO" ] && echo yes || echo no )"
echo "cloud_id=$(cloud-id 2>/dev/null || echo NONE)"
echo "userdata=$( [ -f %(marker)s ] && echo yes || echo no )"
echo "channel=$( [ -e %(chan)s ] && echo yes || echo no )"
echo "qga_active=$(systemctl is-active qemu-guest-agent 2>/dev/null)"
QGACONF=$(cat /etc/qemu/qemu-ga.conf /etc/sysconfig/qemu-ga 2>/dev/null)
echo "qga_blocks_exec=$(echo "$QGACONF" | grep -q 'guest-exec' && echo yes || echo no)"
echo "qga_blocks_ssh=$(echo "$QGACONF" | grep -q 'guest-ssh-add-authorized-keys' && echo yes || echo no)"
echo "qga_blocks_password=$(echo "$QGACONF" | grep -q 'guest-set-user-password' && echo yes || echo no)"
# Ordering cycle = systemd drops a RANDOM job (once cloud-final, once csf-firstboot).
# Counted in the journal of the CURRENT boot — every boot draws again.
echo "cycles=$($SUDO journalctl -b -o cat 2>/dev/null | grep -ci 'ordering cycle')"
# uid/gid from outside the image = ownership leaked from the build machine (virt-customize --copy-in)
echo "foreign=$($SUDO find /etc /usr/local /var/lib/csf -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l)"
AUTO=none
for t in apt-daily-upgrade.timer dnf-automatic-install.timer os-update.timer; do
  [ "$(systemctl is-enabled "$t" 2>/dev/null)" = enabled ] && AUTO="$t"
done
echo "auto=$AUTO"
echo "uu=$(apt-config dump 2>/dev/null | grep -c 'APT::Periodic::Unattended-Upgrade "1"')"
echo "firstboot_flag=$( [ -e /var/lib/csf/firstboot.done ] && echo yes || echo no )"
# Password in a VPC with a redundant VR: cloud-init asks for the password at the
# address found via `data-server`; if the name does not resolve, it takes the router's
# own address from the DHCP lease, while the password server listens only on the VIP
# (gateway).
echo "data_server=$(getent hosts data-server 2>/dev/null | awk '{print $1; exit}')"
echo "gateway=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
echo "wdog_module=$(lsmod | grep -qw i6300esb && echo yes || echo no)"
echo "wdog_dev=$( [ -e /dev/watchdog0 ] && echo yes || echo no )"
echo "wdog_systemd=$(systemctl show -p RuntimeWatchdogUSec --value 2>/dev/null)"
echo "f2b_active=$(systemctl is-active fail2ban 2>/dev/null)"
echo "f2b_sshd=$($SUDO fail2ban-client status sshd >/dev/null 2>&1 && echo yes || echo no)"
echo "f2b_ignoreip=$($SUDO grep -h '^ignoreip' /etc/fail2ban/jail.local 2>/dev/null | head -1 | cut -c1-160)"
echo "root_kb=$(df -k --output=size / | tail -1 | tr -d ' ')"
echo "disk_bytes=$(lsblk -bdno NAME,SIZE -e 7,11 2>/dev/null | sort -k2 -n | tail -1 | awk '{print $2}')"
echo "setpw_always=$($SUDO grep -c 'Running module set.passwords.*frequency always' /var/log/cloud-init.log 2>/dev/null)"
echo "ssh_always=$($SUDO grep -c 'Running module ssh[ (].*frequency always' /var/log/cloud-init.log 2>/dev/null)"
echo "firstboot=$(systemctl is-enabled csf-firstboot 2>/dev/null)"
# The API returning a password proves nothing inside the guest. We compare a
# SIGNATURE of the password hashes before and after the reset — it must change.
# The hashes themselves never leave the machine (we only send a digest).
# NOTE: ONLY root and the image's default user: hashing the WHOLE /etc/shadow gave
# false positives, because `csf-firstboot` updates the system on first boot and
# may add system accounts — the signature changed without a reset.
echo "shadow_sig=$($SUDO awk -F: -v u="$(id -un)" '$1=="root"||$1==u {print $1":"$2}' /etc/shadow 2>/dev/null | sha256sum | cut -c1-16)"
# Password path diagnostics — ONLY occurrence counters, no raw log lines: they could
# carry the password itself, and the test log ends up in files and the GUI.
CIL=/var/log/cloud-init.log
echo "pw_server=$($SUDO grep -ci 'password server' $CIL 2>/dev/null)"
echo "pw_saved=$($SUDO grep -ci 'saved_password' $CIL 2>/dev/null)"
echo "pw_chpasswd=$($SUDO grep -ci 'chpasswd' $CIL 2>/dev/null)"
echo "pw_error=$($SUDO grep -ciE '(error|fail|unable).{0,40}password|password.{0,40}(error|fail|unable)' $CIL 2>/dev/null)"
echo "ci_dns=$($SUDO grep -c 'via data-server DNS entry' $CIL 2>/dev/null)"
echo "ci_lease=$($SUDO grep -c 'via networkd_leases\|via dhclient' $CIL 2>/dev/null)"
echo "ci_pw_fail=$($SUDO grep -c 'Failed to fetch password' $CIL 2>/dev/null)"
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
""" % {"marker": USERDATA_MARKER, "chan": CHANNEL_DEV}


def probe(ip, user, key, kh):
    rc, out, err = ssh_try(ip, user, key, kh, PROBE, timeout=120)
    if rc != 0:
        raise RuntimeError(f"probe did not run (rc={rc}): {err.strip()[:300]}")
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


# ---------- cleanup -----------------------------------------------------------

def _still_there(kind, ident):
    """Does the object STILL exist? Cleanup must look at the effect, not at the
    API accepting the request."""
    try:
        if kind == "vm":
            return any(v["id"] == ident for v in
                       pcall("listVirtualMachines", id=ident).get("virtualmachine", []))
        if kind == "template":
            return any(t["id"] == ident for t in
                       pcall("listTemplates", templatefilter="self", id=ident).get("template", []))
        return any(k["name"] == ident for k in
                   pcall("listSSHKeyPairs").get("sshkeypair", []))
    except Exception:  # noqa: BLE001 — no answer != object gone
        return True


def cleanup(vmid=None, templateid=None, keyname=None, quiet=False):
    """Cleans up and VERIFIES that it did. Each step separately, so a failure of
    one does not leave the rest behind.

    NOTE: CloudStack accepting the request proves nothing: `deleteTemplate`
    returned a `jobid` and the template stayed — because the SSVM was still
    downloading the image (several templates from earlier runs survived "cleanup").
    So we wait for the job result, verify with a listing and retry once.
    """
    tasks = (
        ("machine", "vm", vmid,
         lambda: cs.call("destroyVirtualMachine", id=vmid, expunge="true")),
        ("template", "template", templateid,
         lambda: cs.call("deleteTemplate", id=templateid)),
        ("key pair", "keypair", keyname,
         lambda: pcall("deleteSSHKeyPair", name=keyname)),
    )
    for desc, kind, ident, fn in tasks:
        if not ident:
            continue
        for attempt in (1, 2):
            try:
                r = fn()
                if isinstance(r, dict) and r.get("jobid"):
                    async_result(r["jobid"], timeout=300, desc=f"deleting: {desc}")
            except Exception as e:  # noqa: BLE001 — cleanup must not crash the test
                print(f"  {Y}WARN{N} deletion failed ({desc}, attempt {attempt}): {e}")
            # verification: the object must DISAPPEAR from the listing, not just be reported
            if gone(kind, ident):
                if not quiet:
                    log(f"cleaned up: {desc}")
                break
            if attempt == 2:
                print(f"  {Y}WARN{N} {desc} STILL exists after two attempts "
                      f"({ident}) — clean up manually: --cleanup-only --force")


def gone(kind, ident, timeout=120):
    """True when the object DISAPPEARED from the listing. Checks right away, then waits —
    deletion in CloudStack is asynchronous, so a momentary presence is not a failure yet."""
    deadline = time.monotonic() + timeout
    while True:
        if not _still_there(kind, ident):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(10)


STAMP_RE = re.compile(r"(\d{8})$")


def stamp_age_minutes(name):
    """Object age read from the RUN STAMP in the name (MMDDHHMM).
    Returns None when the name carries no stamp — such an object is treated as
    foreign and not touched without --force."""
    m = STAMP_RE.search(name)
    if not m:
        return None
    try:
        t = time.strptime(f"{time.localtime().tm_year}{m.group(1)}", "%Y%m%d%H%M")
    except ValueError:
        return None
    age = (time.time() - time.mktime(t)) / 60
    return max(age, 0.0)   # a stamp "from the future" (year boundary) = fresh


def sweep(min_age_min=30, only_stamp="", force=False):
    """Cleans up objects after an INTERRUPTED run.

    NOTE: this is an IRREVERSIBLE operation (expunge), so by default it touches only
    objects OLDER than `min_age_min` whose name carries a run stamp. Otherwise a
    cleanup started during another test would delete its machine from under it —
    and tests may run in parallel for several distributions. `--stamp` targets a
    specific run, `--force` removes the age threshold.
    """
    n = skipped = 0

    def qualifies(name):
        nonlocal skipped
        if MARK not in name:
            return False
        age = stamp_age_minutes(name)
        if only_stamp:
            return name.endswith(only_stamp)
        if force:
            return True
        if age is None:
            log(f"skipping {name} — name without a run stamp (use --force)")
            skipped += 1
            return False
        if age < min_age_min:
            log(f"skipping {name} — {int(age)} min old, threshold is {min_age_min} min "
                "(may belong to a running test; --force or --stamp)")
            skipped += 1
            return False
        return True

    for vm in pcall("listVirtualMachines", listall="true").get("virtualmachine", []):
        if qualifies(vm.get("name", "")):
            log(f"deleting machine {vm['name']}")
            cs.call("destroyVirtualMachine", id=vm["id"], expunge="true")
            n += 1
    for t in pcall("listTemplates", templatefilter="self", listall="true").get("template", []):
        if qualifies(t.get("name", "")):
            log(f"deleting template {t['name']}")
            cs.call("deleteTemplate", id=t["id"])
            n += 1
    for k in pcall("listSSHKeyPairs").get("sshkeypair", []):
        if qualifies(k.get("name", "")):
            log(f"deleting key pair {k['name']}")
            pcall("deleteSSHKeyPair", name=k["name"])
            n += 1
    log(f"objects cleaned up: {n}" + (f", skipped: {skipped}" if skipped else ""))
    return n


# ---------- main scenario -----------------------------------------------------

def manifest_value(distro, key):
    # shipped manifest first, then one added from the GUI (CSF_LOCAL_DISTROS)
    m = REPO / "distros" / f"{distro}.yaml"
    if not m.exists() and os.environ.get("CSF_LOCAL_DISTROS"):
        m = Path(os.environ["CSF_LOCAL_DISTROS"]) / f"{distro}.yaml"
    if not re.match(r"^[a-z0-9][a-z0-9._-]*$", distro) or not m.exists():
        return ""
    for line in m.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}:"):
            v = line.split(":", 1)[1].strip()
            q = re.match(r'^"([^"]*)"', v)
            return q.group(1) if q else v.split("#")[0].strip()
    return ""


def artifacts(only_distro=None, only_file=None):
    """A filter on a SPECIFIC file takes precedence: one distribution may have
    several artifact versions (v1_0, v1_1), and the GUI button refers to one
    row — without this a click on one image would test all of them."""
    out = []
    for env in sorted(ARTIFACTS.glob("*.env")):
        d = dict(l.split("=", 1) for l in env.read_text().splitlines() if "=" in l)
        qcow = env.with_suffix(".qcow2")
        if not qcow.exists():
            continue
        if only_file and qcow.name != only_file:
            continue
        if only_distro and d.get("DISTRO") != only_distro:
            continue
        out.append({"distro": d.get("DISTRO", ""), "name": d.get("TEMPLATE_NAME", ""),
                    "file": qcow.name, "version": d.get("VERSION", "")})
    return out


def run_one(art, zone, net, off, stamp, keep_on_fail=False) -> Result:
    r = Result()
    distro = art["distro"]
    family = distro.split("-")[0]
    users = SSH_USER_CANDIDATES.get(family, [family, "cloud-user", "root"])
    ostype = manifest_value(distro, "cs_ostype")
    want_disk = manifest_value(distro, "disk_size") or "10G"
    want_disk_g = int(want_disk[:-1]) if want_disk.endswith("G") else int(want_disk[:-1]) // 1024

    # CloudStack allows ONLY letters, digits and hyphens in a machine name —
    # the slug `ubuntu-22.04` has a dot and deploy failed with error 431. Sanitized
    # once, for all three resources.
    slug = re.sub(r"[^a-z0-9-]+", "-", distro.lower()).strip("-")
    tpl_name = f"{MARK}-{slug}-{stamp}"
    vm_name = f"{MARK}-{slug}-{stamp}"[:63].strip("-")
    key_name = f"{MARK}-{stamp}"
    vmid = tplid = None
    key_created = False
    tmp = tempfile.mkdtemp(prefix="csf-e2e-")
    kh = str(Path(tmp) / "known_hosts")

    try:
        ostypeid = cs.find_ostype_id(ostype)
        if not ostypeid:
            r.no(f"OS type {ostype!r} does not exist in CloudStack")
            return r

        log(f"registering temporary template {tpl_name}")
        reg = cs.register_template(
            name=tpl_name, url=f"{ARTIFACTS_BASE_URL}/{art['file']}",
            ostypeid=ostypeid, zoneid=zone["id"], ispublic=False,
            extraconfig=cs.CSF_INSPECT_CHANNEL, projectid=PROJECT_ID or None)
        tplid = (reg.get("template") or [{}])[0].get("id")
        if not tplid:
            r.no(f"template registration returned no id: {json.dumps(reg)[:200]}")
            return r

        log("waiting for the SSVM to download the image")
        wait_for(lambda: next((t for t in pcall("listTemplates", templatefilter="self",
                                                id=tplid).get("template", [])
                               if t.get("isready")), None),
                 timeout=1500, desc="template ready")
        r.ok("template downloaded by the SSVM (the image is reachable at the artifacts URL)")

        log("creating an ephemeral SSH key pair")
        kp = pcall("createSSHKeyPair", name=key_name)
        key_created = True
        priv = Path(tmp) / "id"
        priv.write_text(kp["keypair"]["privatekey"])
        priv.chmod(0o600)

        ud = ("#cloud-config\nruncmd:\n  - [ touch, %s ]\n" % USERDATA_MARKER)
        log(f"deploying machine {vm_name}")
        deploy_args = dict(zoneid=zone["id"], templateid=tplid,
                           serviceofferingid=off["id"], networkids=net["id"],
                           name=vm_name, displayname=vm_name, keypair=key_name,
                           userdata=base64.b64encode(ud.encode()).decode())
        if off.get("iscustomized"):
            # offering without built-in CPU/RAM — without these two parameters deploy
            # fails with "Need to specify custom parameter values"
            deploy_args["details[0].cpuNumber"] = E2E_CPU
            deploy_args["details[0].memory"] = E2E_RAM_MB
        dep = pcall("deployVirtualMachine", **deploy_args)
        vmid = dep.get("id") or (dep.get("virtualmachine") or {}).get("id")
        if not vmid and dep.get("jobid"):
            # deploy is asynchronous — the machine id may only be in the job result
            vmid = (async_result(dep["jobid"], desc="machine deploy")
                    .get("virtualmachine") or {}).get("id")
        if not vmid:
            r.no("got no machine id from deploy")
            return r

        vm = wait_for(lambda: next((v for v in pcall("listVirtualMachines", id=vmid)
                                    .get("virtualmachine", []) if v.get("state") == "Running"), None),
                      timeout=900, desc="machine Running")
        ip = vm["nic"][0]["ipaddress"]
        r.ok(f"machine is up ({ip})")

        t0 = time.monotonic()
        user = wait_ssh(ip, users, priv, kh)
        r.ok(f"SSH with the CloudStack key works (user {user}, "
             f"waited {int(time.monotonic() - t0)} s)")
        ci = wait_cloud_init(ip, user, priv, kh)
        r.check("done" in ci, f"cloud-init finished ({ci})",
                f"cloud-init did not finish: {ci!r}")
        fp_before = host_key_fingerprints(ip, tmp)

        d = probe(ip, user, priv, kh)
        r.check(d.get("cloud_id") == "cloudstack",
                "datasource = CloudStack (VR authoritative)",
                f"datasource = {d.get('cloud_id')!r}, expected 'cloudstack'")
        r.check(d.get("userdata") == "yes",
                "user-data from the VR ran (marker in place)",
                "user-data did NOT run — marker missing")
        r.check(d.get("channel") == "yes",
                f"csf-inspect channel present ({CHANNEL_DEV})",
                f"channel {CHANNEL_DEV} MISSING — check extraconfig and CloudStack global settings")
        r.check(d.get("qga_active") == "active", "qemu-guest-agent running",
                f"qemu-guest-agent: {d.get('qga_active')!r}")
        r.check(d.get("qga_blocks_exec") == "yes", "QGA blocks guest-exec",
                "QGA does NOT block guest-exec — the supervision layer has a hole")
        # Boundary: the provider must not log into the customer's system.
        # guest-ssh-* and guest-set-user-password (+ NOPASSWD sudo of the default
        # user) gave root from the hypervisor. The effect on a LIVE agent is measured
        # by smoke-boot (qga-probe.py); here — the configuration in the registered
        # template.
        r.check(d.get("qga_blocks_ssh") == "yes", "QGA blocks guest-ssh-* (no key injection)",
                "QGA does NOT block guest-ssh-* — a key can be added to the customer's machine from the hypervisor")
        r.check(d.get("qga_blocks_password") == "yes", "QGA blocks guest-set-user-password",
                "QGA does NOT block guest-set-user-password — the customer's password can be set from the hypervisor")
        r.check(d.get("cycles") == "0", "no unit ordering cycles on first boot",
                f"systemd broke an ordering cycle ({d.get('cycles')}x) — drops a random job "
                "(cloud-final or csf-firstboot)")
        r.check(d.get("foreign") == "0", "no files with uid/gid from outside the image (/etc, /usr/local, /var/lib/csf)",
                f"{d.get('foreign')} files with uid/gid from outside the image — ownership leaked from the build machine")
        auto = d.get("auto", "none")
        r.check(auto != "none", f"automatic security updates enabled ({auto})",
                "automatic security updates DISABLED — customer machine without patches")
        if auto == "apt-daily-upgrade.timer":
            r.check((d.get("uu") or "0") != "0", 'apt-config dump: Unattended-Upgrade "1"',
                    'apt-config dump: Unattended-Upgrade "0" — the timer runs but installs nothing')
        # Password in a VPC with a redundant VR: the tier gateway is the VRRP VIP, and
        # the systemvm password server listens only on it. cloud-init finds it only
        # via the `data-server` name; without it, it takes SERVER_ADDRESS from the DHCP
        # lease = the router's own address and the password from deploy/reset/reinstall
        # never arrives.
        gateway = net.get("gateway") or d.get("gateway", "")
        r.check(bool(gateway) and d.get("data_server") == gateway,
                f"data-server resolves to the network gateway ({gateway})",
                f"data-server = {d.get('data_server') or 'DOES NOT RESOLVE'}, network gateway = {gateway} — "
                "cloud-init will take the router address from the lease and the password will not arrive (redundant VR)")
        r.check(int(d.get("ci_dns") or 0) >= 1,
                "cloud-init found the metadata server \"via data-server DNS entry\"",
                f"cloud-init did NOT use data-server (from lease: {d.get('ci_lease')}x) — in a VPC with a redundant VR the password will not arrive")
        r.check(int(d.get("ci_pw_fail") or 0) == 0, "no \"Failed to fetch password\" in the cloud-init log",
                f"\"Failed to fetch password\" in the cloud-init log ({d.get('ci_pw_fail')}x) — the CloudStack password did not arrive")
        r.check(d.get("wdog_module") == "yes", "i6300esb watchdog module loaded",
                "i6300esb module missing")
        r.check(d.get("wdog_dev") == "yes", "/dev/watchdog0 present", "/dev/watchdog0 missing")
        r.check((d.get("wdog_systemd") or "0") not in ("0", ""),
                f"systemd armed the watchdog (RuntimeWatchdogUSec={d.get('wdog_systemd')})",
                "systemd did NOT arm the watchdog (RuntimeWatchdogUSec=0)")
        r.check(d.get("f2b_active") == "active", "fail2ban running", f"fail2ban: {d.get('f2b_active')!r}")
        r.check(d.get("f2b_sshd") == "yes", "fail2ban has the sshd jail", "sshd jail missing")
        r.check(bool(d.get("f2b_ignoreip")), f"fail2ban ignoreip set ({d.get('f2b_ignoreip','')[:60]}...)",
                "fail2ban WITHOUT ignoreip — management networks may get banned")
        r.check(d.get("firstboot") in ("enabled", "static", "enabled-runtime"),
                f"csf-firstboot enabled ({d.get('firstboot')})",
                f"csf-firstboot: {d.get('firstboot')!r}")

        root_kb = int(d.get("root_kb") or 0)
        disk_b = int(d.get("disk_bytes") or 0)
        disk_g = round(disk_b / 1024**3, 1) if disk_b else 0
        r.check(disk_g >= want_disk_g - 0.1,
                f"disk {disk_g} GiB (manifest: {want_disk})",
                f"disk {disk_g} GiB < declared {want_disk}")
        share = (root_kb * 1024 / disk_b * 100) if disk_b else 0
        r.check(share >= 70,
                f"root {round(root_kb/1048576,1)} GiB = {round(share)}% of the disk (grown correctly)",
                f"root is only {round(share)}% of the disk — the wrong partition was grown")

        log("stopping the machine and resetting the password via the API (CloudStack mechanism)")
        cs.call("stopVirtualMachine", id=vmid)
        wait_for(lambda: next((v for v in pcall("listVirtualMachines", id=vmid)
                               .get("virtualmachine", []) if v.get("state") == "Stopped"), None),
                 timeout=600, desc="machine Stopped")
        rp = cs.call("resetPasswordForVirtualMachine", id=vmid)
        newpass = ((rp.get("virtualmachine") or {}).get("password")
                   or (rp.get("jobresult") or {}).get("virtualmachine", {}).get("password"))
        if not newpass and rp.get("jobid"):
            newpass = (async_result(rp["jobid"], timeout=600, desc="password reset")
                       .get("virtualmachine") or {}).get("password")
        r.check(bool(newpass), "CloudStack returned a new password (password server on the VR)",
                "password reset returned no password")

        cs.call("startVirtualMachine", id=vmid)
        wait_for(lambda: next((v for v in pcall("listVirtualMachines", id=vmid)
                               .get("virtualmachine", []) if v.get("state") == "Running"), None),
                 timeout=900, desc="machine Running again")
        wait_ssh(ip, [user], priv, kh)
        wait_cloud_init(ip, user, priv, kh)

        fp_after = host_key_fingerprints(ip, tmp)
        r.check(fp_before and fp_before == fp_after,
                "host keys IDENTICAL after reboot (invariant 4: ssh != always)",
                f"host keys CHANGED after reboot — the ssh module runs with 'always'"
                f" (before: {len(fp_before)}, after: {len(fp_after)})")

        d2 = probe(ip, user, priv, kh)
        r.check(d2.get("boot_id") != d.get("boot_id"), "the machine actually rebooted",
                "boot_id unchanged — no reboot happened, the results below are invalid")
        changed = bool(d2.get("shadow_sig")) and d2.get("shadow_sig") != d.get("shadow_sig")
        # No "environment limitation" exception here. A former condition looked for a
        # "Password" network service, which CloudStack does NOT have (the password
        # server belongs to the UserData service of the (Vpc)VirtualRouter) — so it was
        # always false and the password reset ended with a warning in EVERY network.
        # An unchanged /etc/shadow is a template defect.
        r.check(changed,
                "the password in /etc/shadow ACTUALLY changed after the CloudStack reset",
                "passwords in /etc/shadow unchanged — the API reset did not reach the machine; "
                f"data-server={d2.get('data_server') or 'does not resolve'}, "
                f"\"Failed to fetch password\"={d2.get('ci_pw_fail')}, "
                f"password-server={d2.get('pw_server')}, saved_password={d2.get('pw_saved')}, "
                f"chpasswd={d2.get('pw_chpasswd')}, errors={d2.get('pw_error')}")
        r.check(d2.get("cycles") == "0", "no unit ordering cycles after reboot",
                f"systemd broke an ordering cycle after reboot ({d2.get('cycles')}x)")
        r.check(int(d2.get("ci_pw_fail") or 0) == 0, "no \"Failed to fetch password\" after the reset",
                f"\"Failed to fetch password\" after the reset ({d2.get('ci_pw_fail')}x)")
        if d2.get("firstboot_flag") != "yes":
            r.warn("csf-firstboot did not set its flag before the reboot — the update did not "
                   "finish in time or failed (it retries on the next boot; check the journal)")
        r.check(int(d2.get("setpw_always") or 0) >= 2,
                "set_passwords ran AGAIN after the reboot (invariant 3: always)",
                f"set_passwords did not run again (occurrences in the log: {d2.get('setpw_always')})")
        r.check(int(d2.get("ssh_always") or 0) == 0,
                "the ssh module does NOT run with 'always' (invariant 4 in the configuration)",
                f"the ssh module runs with 'always' — {d2.get('ssh_always')} occurrences in the log")
        return r

    finally:
        # On failure the machine is often the ONLY evidence. Default cleanup deleted
        # it BEFORE anyone saw the error message, so after a failed run nothing could
        # be inspected in the guest — only the "did not come up in 900s" log remained.
        # --keep-on-fail keeps everything (machine + template + key) and PRINTS how to
        # clean up. By default nothing changes: the test still leaves no garbage in
        # CloudStack.
        # NOTE: no `return` in this block: return in `finally` SWALLOWS an in-flight
        # exception, so a failed run would report as passed.
        failed_run = r.failed or sys.exc_info()[0] is not None
        if keep_on_fail and failed_run:
            log(f"{Y}KEEPING the machine for inspection{N} (--keep-on-fail): "
                f"vm={vmid} template={tplid} key={key_name if key_created else '-'}")
            log(f"   private key: {tmp}/id   (delete the directory afterwards)")
            log(f"   clean up: {sys.argv[0]} --cleanup-only --stamp {stamp} --force")
        else:
            log("cleaning up after the test")
            # keyname only when the key was ACTUALLY created in this run — otherwise
            # a failed start would delete a key belonging to someone else
            cleanup(vmid=vmid, templateid=tplid,
                    keyname=key_name if key_created else None)
            subprocess.run(["rm", "-rf", tmp], check=False)


def main():
    global PROJECT_ID, NET_NAME, ZONE_NAME, OFFERING_NAME, PROJECT_NAME
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="all artifacts in the directory")
    ap.add_argument("--distro", help="one distribution (manifest slug)")
    ap.add_argument("--artifact", help="one SPECIFIC artifact file (.qcow2 name)")
    ap.add_argument("--zone", default=ZONE_NAME,
                    help="CloudStack zone name (env CSF_CS_ZONE; empty = the only/first available)")
    ap.add_argument("--network", default=NET_NAME,
                    help="CloudStack guest network name, reachable over SSH from this machine "
                         "(env CSF_CS_NETWORK; required to run tests)")
    ap.add_argument("--offering", default=OFFERING_NAME,
                    help="service offering name (env CSF_CS_SERVICE_OFFERING; empty = smallest "
                         "offering with fixed CPU/RAM)")
    ap.add_argument("--project", default=PROJECT_NAME,
                    help="CloudStack project name (env CSF_CS_PROJECT; empty = no project)")
    ap.add_argument("--cleanup-only", action="store_true",
                    help="only clean up objects carrying the e2e marker and exit")
    ap.add_argument("--stamp", default="",
                    help="clean up ONLY this run (MMDDHHMM stamp from the name)")
    ap.add_argument("--min-age", type=int, default=30, metavar="MIN",
                    help="when cleaning up, skip objects younger than this many minutes (default 30)")
    ap.add_argument("--force", action="store_true",
                    help="clean up without the age threshold — may delete resources of a RUNNING test")
    ap.add_argument("--keep-on-fail", action="store_true",
                    help="on FAILURE keep the machine, template and key for inspection "
                         "(post-mortem); clean up later with --cleanup-only --stamp <stamp>")
    a = ap.parse_args()
    ZONE_NAME, NET_NAME, OFFERING_NAME, PROJECT_NAME = a.zone, a.network, a.offering, a.project

    if not cs.configured():
        raise SystemExit("no CloudStack API keys — set them on the Configuration screen of the GUI")

    PROJECT_ID = find_project()
    if PROJECT_ID:
        log(f"project: {PROJECT_NAME}")

    if a.cleanup_only:
        sweep(min_age_min=a.min_age, only_stamp=a.stamp, force=a.force)
        return 0
    if not (a.all or a.distro or a.artifact):
        ap.error("give --all, --distro <slug> or --artifact <file.qcow2>")
    if not NET_NAME:
        ap.error("no test network: set --network or CSF_CS_NETWORK")
    if not ARTIFACTS_BASE_URL:
        ap.error("ARTIFACTS_BASE_URL is not set — the URL under which the SSVM can download "
                 "the artifacts (e.g. https://factory.example.com/artifacts)")

    arts = artifacts(a.distro, a.artifact)
    if not arts:
        raise SystemExit(f"no matching artifacts in {ARTIFACTS} "
                         f"(distro={a.distro!r}, artifact={a.artifact!r})")

    zone = find_zone()
    net = find_network(zone["id"])
    off = find_offering()
    # Run stamp: random infix + MMDDHHMM. The minute alone is not enough — two runs
    # started in the same minute (e.g. CLI next to the GUI) would get the same
    # resource names, and cleaning up one would delete the other's key.
    # The eight digits STAY AT THE END, because sweep() computes object age from them.
    stamp = f"{secrets.token_hex(2)}-{time.strftime('%m%d%H%M')}"
    log(f"zone {zone['name']}, network {net['name']}, offering {off['name']}, stamp {stamp}")

    summary = []
    for art in arts:
        print(f"\n{'='*72}\n{art['name']}  ({art['file']})\n{'='*72}")
        try:
            res = run_one(art, zone, net, off, stamp, keep_on_fail=a.keep_on_fail)
            summary.append((art["name"], res.failed))
        except Exception as e:  # noqa: BLE001 — one distribution must not kill the run
            print(f"  {R}ERROR{N} {e}")
            summary.append((art["name"], [f"exception: {e}"]))

    print(f"\n{'='*72}\nSUMMARY\n{'='*72}")
    bad = 0
    for name, failed in summary:
        if failed:
            bad += 1
            print(f"{R}FAIL{N} {name}: " + "; ".join(failed))
        else:
            print(f"{G}PASS{N} {name}")
    print(f"\npassed: {len(summary)-bad}/{len(summary)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

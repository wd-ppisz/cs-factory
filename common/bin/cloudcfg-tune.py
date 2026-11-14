#!/usr/bin/env python3
"""Safe edit of /etc/cloud/cloud.cfg — NO sed, keeps the full module list.

Built-in defaults:
  * set_passwords -> [set_passwords, always]  (CloudStack password reset works on every boot)
  * ssh           -> 'ssh' (NOT always)       (host keys generated once per instance)
  * ssh_deletekeys: true                       (fresh, unique keys per instance)

Optional (enabled from the manifest, mutually exclusive):
  * `--datasource-network`: network.dhcp_client_priority -> DHCP clients that are NOT
    in the image, i.e. CloudStack datasource detection only after the network is up;
  * `--dhcp-client-priority=a,b`: network.dhcp_client_priority -> an explicit client
    list, EACH must be in the image (otherwise the build fails — init would not start).

Why this exists: a manual `sed` on cloud.cfg can break the YAML and silently disable
the modules that process user-data.
"""
import os
import sys

import yaml

CFG = "/etc/cloud/cloud.cfg"

with open(CFG) as f:
    c = yaml.safe_load(f) or {}


def _name(m):
    return m[0] if isinstance(m, list) else m


def tune(key):
    if key not in c or not isinstance(c[key], list):
        return
    out = []
    for m in c[key]:
        n = _name(m)
        if n in ("set-passwords", "set_passwords"):
            out.append([n, "always"])
        elif n == "ssh":
            out.append("ssh")            # also normalises [ssh, always] -> ssh
        else:
            out.append(m)
    c[key] = out


for k in ("cloud_config_modules", "cloud_init_modules", "cloud_final_modules"):
    tune(k)

c["ssh_deletekeys"] = True
c.setdefault("ssh_genkeytypes", ["rsa", "ecdsa", "ed25519"])

# --- CloudStack password in a VPC with a redundant VR -------------------------------
# Observed on Ubuntu 22.04 (cloud-init 26.1): `DataSourceCloudStackLocal` brings up an
# ephemeral network in init-local with its own DHCP client and asks for the Virtual
# Router address via `get_vr_address()`. The first branch (name `data-server` = router
# VIP) has NO chance: there is no resolver yet in init-local, so `getaddrinfo` fails
# and the log says "DNS Entry data-server not found". The next branches take
# `dhcp-server-identifier` FROM THE EPHEMERAL LEASE, which is the address of ONE
# router, not the VIP. Metadata and user-data answer on both, but the systemvm
# password server listens ONLY on the VIP — hence "Failed to fetch password from
# virtual router" and a deploy/reset password that never reaches /etc/shadow.
#
# When the image has NO client cloud-init can use, init-local ends with
# `NoDHCPLeaseError` ("Unable to obtain a DHCP lease"), and the datasource is detected
# in init-network — there the network is up, `data-server` resolves to the VIP and the
# password arrives (exactly how Ubuntu 24.04/26.04 behave, where
# `dhcpcd --dumplease` fails once the process is killed). So we set the client list
# to the clients the image does not have: same effect, but DELIBERATE and visible in
# the configuration.
#
# ONLY for images with systemd-networkd. `DataSourceCloudStack._get_domainname()`
# calls `self.distro.dhcp_client.client_name` in its last branch in a plain
# `LOG.debug`, OUTSIDE `suppress` — so without a DHCP client
# `NoDHCPLeaseMissingDhclientError` propagates through `get_hostname(fqdn=True)` and
# aborts the WHOLE init stage. The first branch of that function saves us: the domain
# from the networkd lease. An image on NetworkManager (Rocky, openSUSE) has no such
# protection and would get "init does not start at all" instead of "password does
# not arrive". The `validate-offline.sh` gate requires networkd with this setting.
#
# The OPPOSITE mode, `--dhcp-client-priority=` (openSUSE Leap 16): an explicitly named
# client that IS in the image. There `_get_domainname()` picked `dhcpcd` (first in
# cloud-init's code), which NetworkManager does not run — `dhcpcd --dumplease` ends
# with `NoDHCPLeaseError`, which aborts the init stage. dhclient without a lease
# returns `{}` and the stage passes. The safety condition is the absence of
# `DataSourceCloudStackLocal` in the image — otherwise init-local would take the
# address of ONE router from the dhclient lease; the validate-offline.sh gate checks it.
DHCP_CLIENTS = ("dhclient", "dhcpcd", "udhcpc")   # names cloud-init understands
SEARCH_PATHS = ("/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin")


def present(client):
    return any(os.path.exists(os.path.join(d, client)) for d in SEARCH_PATHS)


def set_priority(clients):
    # `dhcp_client_priority` is read by the distro from the system_info SECTION
    # (cloud-init: distros/__init__.py, util.get_cfg_by_path(self._cfg, ("network", ...))).
    sysinfo = c["system_info"] if isinstance(c.get("system_info"), dict) else c.setdefault("system_info", {})
    network = sysinfo.setdefault("network", {})
    network["dhcp_client_priority"] = clients


PRIO = [a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--dhcp-client-priority=")]
if PRIO and "--datasource-network" in sys.argv[1:]:
    sys.exit("cloudcfg-tune: --datasource-network (clients ABSENT) and --dhcp-client-priority "
             "(clients PRESENT) are mutually exclusive — fix the manifest")

if "--datasource-network" in sys.argv[1:]:
    absent = [k for k in DHCP_CLIENTS if not present(k)]
    if not absent:
        # The image has every client — the workaround would do nothing, and silent
        # acceptance would leave a template with a broken password reset. Fail hard.
        sys.exit("cloudcfg-tune: the image has EVERY DHCP client known to cloud-init "
                 f"({', '.join(DHCP_CLIENTS)}) — the datasource cannot be moved to "
                 "init-network by configuration alone; fix the manifest or the layer")
    set_priority(absent)
    print("cloudcfg-tune: datasource after network — dhcp_client_priority = "
          f"{absent} (clients absent from the image)")

if PRIO:
    clients = [k for k in PRIO[-1].split(",") if k]
    unknown = [k for k in clients if k not in DHCP_CLIENTS]
    missing = [k for k in clients if k in DHCP_CLIENTS and not present(k)]
    if not clients or unknown or missing:
        # A missing client on the list = `NoDHCPLeaseMissingDhclientError` from the
        # unprotected line of `_get_domainname()` and an aborted init stage. Such an
        # image is not released.
        sys.exit(f"cloudcfg-tune: dhcp_client_priority {clients} — unknown to cloud-init: "
                 f"{unknown or 'none'}, missing from the image: {missing or 'none'}; "
                 "add the client package to packages in the manifest")
    set_priority(clients)
    print(f"cloudcfg-tune: dhcp_client_priority = {clients} (clients present in the image)")

with open(CFG, "w") as f:
    try:
        yaml.safe_dump(c, f, default_flow_style=False, sort_keys=False)
    except TypeError:
        # PyYAML < 5.1 does not know `sort_keys` (Rocky 8 = python 3.6) and raises
        # TypeError, killing the whole build. Write without that argument: map keys
        # get sorted alphabetically, which is HARMLESS — cloud-init reads cloud.cfg by
        # key name, and module order lives in LISTS, which sort_keys does not touch.
        yaml.safe_dump(c, f, default_flow_style=False)

print("cloudcfg-tune: cloud.cfg updated (set_passwords=always, ssh!=always)")

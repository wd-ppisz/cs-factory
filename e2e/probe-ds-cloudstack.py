#!/usr/bin/env python3
"""Functional probe of cloud-init FROM THE IMAGE: does the init stage survive the
absence of a DHCP lease.

Run by e2e/validate-offline.sh INSIDE THE GUEST (guestfish on a qcow2 overlay, chroot)
with the interpreter from the /usr/bin/cloud-init shebang — Rocky 8 has
platform-python 3.6 there, so this code is Python 3.6 compatible.
Printed messages are ASCII ONLY (plus stdout switched to ASCII with backslashreplace
below): guestfsd sets LC_ALL=C in the helper appliance, and Python 3.6 has no UTF-8
mode — `print` of a non-ASCII character raised UnicodeEncodeError and the gate gave
a "no verdict" FAIL on a healthy Rocky 8.
Prints "OK ..." / "FAIL ..." lines for the `verdict()` function; other lines are context.

Why: `DataSourceCloudStack.get_hostname(fqdn=True)` calls `_get_domainname()`, which,
after the distro's lease lookups fail, reaches for `distro.dhcp_client`. On Rocky 10
(cloud-init 24.4-7.el10) and openSUSE Leap 16 (25.1.3) that was `dhcpcd`, which
NetworkManager does not run: `dhcpcd --dumplease` -> "dhcpcd is not running" ->
unhandled `NoDHCPLeaseError` -> the WHOLE init stage aborted (no SSH keys, user-data,
password). The templates still passed `validate` and `smoke` — smoke boots with the
NoCloud datasource, so it never touches CloudStack code.

The probe calls the REAL function from the image on a REAL distro object (configuration
from /etc/cloud, DHCP clients present in the image). No DHCP client runs in the chroot.
It differs from a live machine in one detail: the guestfish appliance (without
--network) has only `lo`, so `distro.fallback_interface` is None and
`Dhcpcd.get_newest_lease(None)` does NOT start dhcpcd (subp rejects a None argument) —
it ends with the same `NoDHCPLeaseError` that "dhcpcd is not running" gives live.
dhclient and udhcpc do not use the interface. Context lines "Did not find a fallback
interface..." and "Running invalid command: [... None]" are expected in the output.

Scope: the `get_hostname(fqdn=True)` -> `_get_domainname()` path. We do NOT check
`get_vr_address()` with an unresolvable `data-server` name — tier3 treats that
condition as a network failure for every distribution anyway (the residual Rocky 10
risk is described in distros/rocky-10.yaml).

`--networkd`: image with systemd-networkd. In CloudStack the networkd lease carries the
domain (the VR's DHCP provides domain-name), and `_get_domainname()` returns from it in
the first branch — we simulate that, since there is no lease offline. The result
WITHOUT simulation is printed as context.
"""
import io
import sys
from unittest import mock

try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="ascii",
                                  errors="backslashreplace", line_buffering=True)
except (AttributeError, ValueError):   # stdout without a binary buffer — leave as is
    pass

NETWORKD = "--networkd" in sys.argv[1:]

try:
    from cloudinit import stages
    from cloudinit import version as ci_version
    from cloudinit.net import dhcp
    from cloudinit.sources import DataSourceCloudStack as M
except Exception as e:  # noqa: BLE001 — any import error is an image defect
    print("FAIL cannot import cloud-init from the image: %r" % (e,))
    sys.exit(0)

CLS = M.DataSourceCloudStack
version = getattr(ci_version, "version_string", lambda: "?")()
if not callable(getattr(CLS, "_get_domainname", None)):
    # Rocky 8 (23.4): FQDN does not reach for a DHCP lease at all.
    print("OK cloud-init %s: DataSourceCloudStack without _get_domainname() - FQDN does not "
          "reach for a DHCP lease" % version)
    sys.exit(0)

try:
    distro = stages.Init(ds_deps=[]).distro
except Exception as e:  # noqa: BLE001
    print("FAIL cannot build distro from the image configuration (/etc/cloud): %r" % (e,))
    sys.exit(0)

try:
    client = distro.dhcp_client.client_name
except dhcp.NoDHCPLeaseError as e:   # includes NoDHCPLeaseMissingDhclientError
    client = "NONE (%s)" % type(e).__name__
print("cloud-init %s; DHCP client chosen by cloud-init: %s; systemd-networkd: %s"
      % (version, client, "yes" if NETWORKD else "no"))


def domain(simulate_networkd):
    """Call the function from the image. Returns (result, exception)."""
    ds = object.__new__(CLS)
    ds.distro = distro
    if simulate_networkd:
        patch = mock.patch.object(dhcp, "networkd_get_option_from_leases",
                                  lambda *a, **k: "csf-probe.invalid")
    else:
        patch = mock.patch.object(dhcp, "networkd_get_option_from_leases",
                                  lambda *a, **k: None)
    try:
        with patch:
            return ds._get_domainname(), None
    except Exception as e:  # noqa: BLE001 — any exception aborts the init stage
        return None, e


result, error = domain(NETWORKD)
if error is None:
    source = ("with a domain from the systemd-networkd lease (simulated)" if NETWORKD
              else "without a DHCP lease")
    print("OK _get_domainname() %s returns %r - get_hostname(fqdn=True) will not abort "
          "the init stage" % (source, result))
else:
    print("FAIL _get_domainname() raises %s: %s - get_hostname(fqdn=True) will abort the WHOLE "
          "cloud-init init stage (no SSH keys, user-data or CloudStack password)"
          % (type(error).__name__, error))

if NETWORKD:
    result_without, error_without = domain(False)
    # Not a verdict: in CloudStack the lease does carry the domain. A hint for whoever
    # reads the log — does the image survive without it, or ONLY thanks to it.
    if error_without is not None:
        print("   NOTE: without a domain in the networkd lease _get_domainname() would raise %s"
              % type(error_without).__name__)
    else:
        print("   without a domain in the networkd lease _get_domainname() would return %r"
              % (result_without,))

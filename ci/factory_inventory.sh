#!/bin/sh
# Factory host inventory for the CVE controller. Runs on the factory runner
# (shell executor ON the factory host), so it describes exactly the machine that
# builds templates and serves the GUI. Installs nothing and changes nothing.
#
# Output:
#   factory-rootfs/         - minimal "rootfs" for `trivy rootfs`: os-release
#                             + /var/lib/dpkg/status. dpkg packages only: the GUI's
#                             Python dependencies (flask, authlib, gunicorn) are
#                             Debian packages, so they are covered here; scanning
#                             dist-info would yield false positives from PyPI
#                             databases on Debian-patched versions.
#   inventory.json          - host identity, time, package count, status digest,
#                             kernel and reboot need (the controller verifies all of it).
set -eu

OUT="${1:-factory-rootfs}"
rm -rf "$OUT"
mkdir -p "$OUT/etc" "$OUT/var/lib/dpkg"
# /etc/os-release is a symlink to ../usr/lib/os-release - copy the CONTENT.
# Trivy detects Debian by /etc/debian_version, NOT by os-release: without it the
# report has Family="none", zero packages and zero CVEs (and the controller
# rightly refuses to evaluate it).
cp -L /etc/os-release "$OUT/etc/os-release"
cp /etc/debian_version "$OUT/etc/debian_version"
cp /var/lib/dpkg/status "$OUT/var/lib/dpkg/status"

INSTALLED="$(dpkg-query -W -f='${db:Status-Abbrev}\n' | grep -c '^ii')"
SHA="$(sha256sum "$OUT/var/lib/dpkg/status" | cut -d' ' -f1)"
# newest installed kernel vs running one - a kernel fix only applies after a reboot
NEWEST_KERNEL="$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\n' 'linux-image-[0-9]*' 2>/dev/null \
  | awk '$2=="ii"{sub(/^linux-image-/,"",$1); print $1}' | sort -V | tail -1)"
RUNNING="$(uname -r)"
REBOOT=false
[ -e /run/reboot-required ] && REBOOT=true
[ -n "$NEWEST_KERNEL" ] && [ "$NEWEST_KERNEL" != "$RUNNING" ] && REBOOT=true

python3 - "$INSTALLED" "$SHA" "$RUNNING" "$NEWEST_KERNEL" "$REBOOT" <<'PY'
import datetime, json, socket, sys
installed, sha, running, newest, reboot = sys.argv[1:]
doc = {
    "schema": "cs-factory-inventory/v1",
    "host": socket.getfqdn(),
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "installed_packages": int(installed),
    "dpkg_status_sha256": sha,
    "running_kernel": running,
    "newest_installed_kernel": newest or None,
    "reboot_required": reboot == "true",
}
json.dump(doc, open("inventory.json", "w"), indent=2)
print(json.dumps(doc, indent=2))
PY

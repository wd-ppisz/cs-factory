#!/usr/bin/env bash
# Local smoke test (NoCloud, WITHOUT CloudStack): confirms that user-data actually
# RUNS end-to-end (that was the regression). The CloudStack datasource + password reset
# via the VR cannot be checked locally -> tier2-cloudstack.sh (staging).
#
# Host key stability is checked STRUCTURALLY offline (ssh != always),
# so there is no fragile boot-twice here.
#
# Requires: qemu-system-x86_64, python3, and cloud-image-utils (cloud-localds) or genisoimage.
# Usage: ./smoke-boot.sh build/template-debian-13-v1_1.qcow2
set -euo pipefail
IMG="${1:?usage: smoke-boot.sh <image.qcow2>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT

# Port 0 = the server picks a FREE port and reports it in the .port file. A fixed
# port collided when the runner ran two builds in parallel: the second server could
# not bind, the beacon had nowhere to go and smoke-boot reported "user-data did NOT
# run" on a perfectly healthy image.
python3 "$HERE/mock-vr/beacon-server.py" "${SMOKE_PORT:-0}" "$T/beacons.log" & SRV_PID=$!
for _ in $(seq 1 50); do [ -s "$T/beacons.log.port" ] && break; sleep 0.2; done
PORT="$(cat "$T/beacons.log.port" 2>/dev/null || true)"
[ -n "$PORT" ] || { echo "FAIL: beacon server did not start (no port)"; exit 1; }
echo ">> beacon server on port $PORT"

# Probe INSIDE THE GUEST — what the offline gate cannot see, because it only shows
# up at boot:
#  * unit ordering cycles: systemd breaks them by dropping a RANDOM job; on a
#    customer machine this once dropped cloud-final (user-data did not run at all),
#    and csf-firstboot on the next boot. A single boot may hit the "good" half of
#    the draw, so we count journal messages, not just the beacon;
#  * files without an owner in /etc, /usr/local, /var/lib/csf — seen through the
#    image's REAL /etc/passwd (a build machine uid may look like "someone" in the image);
#  * whether automatic patching is actually enabled (effective `apt-config dump`,
#    `systemctl is-enabled`), not just described in files.
# Then it waits on the `/wait` valve so the host can query the QEMU agent before
# user-data reaches power_state. The script is delivered via write_files in base64 —
# no quotes nested in YAML and in a heredoc at the same time.
cat > "$T/probe.sh" <<'EOS'
#!/bin/sh
H="http://10.0.2.2:$1"
b64() { head -5 | base64 -w0 | tr '+/' '-_'; }
cycles=$(journalctl -b -o cat 2>/dev/null | grep -ci 'ordering cycle')
cycles_b64=$(journalctl -b -o cat 2>/dev/null | grep -i 'ordering cycle' | b64)
foreign=$(find /etc /usr/local /var/lib/csf -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l)
foreign_b64=$(find /etc /usr/local /var/lib/csf -xdev \( -nouser -o -nogroup \) 2>/dev/null | b64)
auto=none
for t in apt-daily-upgrade.timer dnf-automatic-install.timer os-update.timer; do
  [ "$(systemctl is-enabled "$t" 2>/dev/null)" = enabled ] && auto="$t"
done
uu=$(apt-config dump 2>/dev/null | grep -c 'APT::Periodic::Unattended-Upgrade "1"')
# Watchdog: csf-watchdog.service and cloud-final (i.e. this probe) are BOTH
# After=multi-user.target, so their relative order is not determined —
# without waiting the measurement would be a race, not a test. Wait for the
# unit to finish, then for the device (PID1 opens it only on its next ping).
i=0
while [ "$i" -lt 30 ]; do
  [ "$(systemctl is-active csf-watchdog 2>/dev/null)" = active ] && break
  i=$((i + 1)); sleep 1
done
i=0
while [ "$i" -lt 30 ]; do
  [ -e /dev/watchdog0 ] && break
  i=$((i + 1)); sleep 1
done
# Wait SEPARATELY for PID1 to attach: the device appears when the module loads,
# but systemd opens it only on the next ping of its event loop
# (watchdog_ping() -> open_watchdog()). Measuring right after /dev/watchdog0
# appears would be a race and reject healthy images.
i=0
while [ "$i" -lt 60 ]; do
  journalctl -b -o cat 2>/dev/null | grep -qi 'hardware watchdog' && break
  i=$((i + 1)); sleep 1
done
wdog_module=no; lsmod 2>/dev/null | grep -qw i6300esb && wdog_module=yes
wdog_dev=no; [ -e /dev/watchdog0 ] && wdog_dev=yes
wdog_pid1=no; journalctl -b -o cat 2>/dev/null | grep -qi 'hardware watchdog' && wdog_pid1=yes
curl -s "$H/report?cycles=$cycles&foreign=$foreign&auto=$auto&uu=$uu&cycles_b64=$cycles_b64&foreign_b64=$foreign_b64&wdog_module=$wdog_module&wdog_dev=$wdog_dev&wdog_pid1=$wdog_pid1" >/dev/null || true
i=0
while [ "$i" -lt 200 ]; do
  [ "$(curl -s "$H/wait")" = go ] && break
  i=$((i + 1)); sleep 3
done
EOS
cat > "$T/user-data" <<EOF
#cloud-config
power_state: { mode: poweroff, timeout: 30 }
write_files:
  - path: /var/lib/csf-smoke/probe.sh
    permissions: '0755'
    encoding: b64
    content: $(base64 -w0 "$T/probe.sh")
runcmd:
  - [ sh, -c, "curl -s http://10.0.2.2:${PORT}/beacon?userdata=ok || true" ]
  - [ sh, /var/lib/csf-smoke/probe.sh, "${PORT}" ]
EOF
printf 'instance-id: smoke-001\nlocal-hostname: smoke\n' > "$T/meta-data"

if command -v cloud-localds >/dev/null 2>&1; then
  cloud-localds "$T/seed.iso" "$T/user-data" "$T/meta-data"
else
  genisoimage -quiet -output "$T/seed.iso" -volid cidata -joliet -rock "$T/user-data" "$T/meta-data"
fi

cp --reflink=auto "$IMG" "$T/disk.qcow2"
# The template (INVARIANT 1) deliberately has NO NoCloud in datasource_list — so the
# cidata seed would be ignored and the test would have nothing to measure (confirmed
# live: boot to login prompt, zero beacons). Override ONLY in the throwaway disk copy
# used by this test: 99-zz-* wins lexicographically over 99-csf-*;
# a single line, because ds-identify does not read multi-line arrays.
printf '# smoke test ONLY - this file exists only in a throwaway disk copy\ndatasource_list: [ NoCloud ]\n' > "$T/99-zz-smoke-nocloud.cfg"
# chown 0 0: copy-in carries the file's uid/gid from the machine running the test. The
# guest probe counts files without an owner and caught EXACTLY this file in CI (the
# runner's uid). Locally it may go unnoticed — uid 1000 of the test author often
# matches the default user account created by cloud-init in the image.
guestfish -a "$T/disk.qcow2" -i copy-in "$T/99-zz-smoke-nocloud.cfg" /etc/cloud/cloud.cfg.d/ \
  : chown 0 0 /etc/cloud/cloud.cfg.d/99-zz-smoke-nocloud.cfg >/dev/null
echo ">> boot (NoCloud) ..."
# KVM when available (orders of magnitude faster); without KVM plain TCG — then
# see SMOKE_TIMEOUT below (default 1800 s — rationale next to `timeout`).
# The CPU model MUST be specified — and it MUST be the one production provides.
# The default `qemu64` is x86-64-**v1**. Rocky 9 and openSUSE Leap 16 are compiled
# for **v2** (SSE4.2, POPCNT, SSSE3, SSE4.1), Rocky 10 for **v3** (AVX2, BMI2, FMA).
# On v1: Rocky 10 crashes in GRUB ITSELF (reset loop, since GRUB is also built for
# v3), and Rocky 9 and openSUSE boot the kernel and die at `init` — illegal
# instruction (`pinsrq`, SSE4.1) — i.e. "Kernel panic - not syncing: Attempted to
# kill init!". Rocky 8 works on v1, which is why it alone never broke.
#
# `-cpu max` is the wrong fix in the other direction: a CloudStack host with
# `guest.cpu.mode=custom` but WITHOUT `guest.cpu.model` gives VMs
# `<model>qemu64</model>`, so templates did not boot in production while the gate,
# running with `-cpu max`, was green because it got more than a real VM.
# The gate must never be MORE LENIENT than production. So by default we boot with
# the baseline model of the hypervisor fleet (the oldest CPU in the pool). Set
# SMOKE_CPU to the guest CPU model your CloudStack hosts expose; when the baseline
# is raised, raise THIS and rebuild — a mismatch should hurt here, not in production.
SMOKE_CPU="${SMOKE_CPU:-Haswell-noTSX-IBRS}"
ACCEL=(-cpu "$SMOKE_CPU"); [ -w /dev/kvm ] && ACCEL=(-enable-kvm -cpu "$SMOKE_CPU")
# 1800 s, not 240 and not 900: under TCG (no nested KVM on the build host) the RHEL
# family cannot boot, run cloud-init and power off in four minutes; Rocky 8 failed
# to the SECOND at 240 s with a correctly booting system in the log. A 900 s limit
# failed the same way on openSUSE — exactly 900 s after boot started — while the SAME
# artifact run on an idle host completed the full sequence (cloud-init modules,
# 0 failures, beacon, "reboot: Power down") in 224 s. The difference is purely CPU
# contention when the runner builds many distributions at once — about 4x. 1800 s
# gives 8x headroom over the idle measurement.
# Do not shorten this based on the time of a single build: under load the limit
# cuts off HEALTHY images, and the symptom ("no beacon") looks identical to a real
# user-data regression.
# Run WITHOUT -no-reboot. The RHEL family needs a full SELinux relabel on first
# boot (files were changed offline), and selinux-autorelabel ends with a REBOOT.
# With -no-reboot QEMU died exactly at that moment, and user-data, which runs only
# AFTER the reboot, never had a chance (Rocky 8 relabeling for 9 minutes,
# "Reached target Reboot" and the end). The same Rocky 8 passed tier3 on a live
# CloudStack machine, where the reboot happens normally — so the test's assumption
# was wrong, not the template.
# Reboot loops are bounded by SMOKE_TIMEOUT, and user-data ends with a poweroff.
#
# Channel org.qemu.guest_agent.0 — the same one CloudStack adds to every machine.
# Without it qemu-guest-agent does not start in the guest at all and there would be
# nothing to measure. QEMU runs in the BACKGROUND: the host must query the agent
# while the guest is alive.
QGA_SOCK="$T/qga.sock"
timeout "${SMOKE_TIMEOUT:-1800}" qemu-system-x86_64 ${ACCEL[@]+"${ACCEL[@]}"} -m 2048 -smp 2 -nographic \
  -drive file="$T/disk.qcow2",if=virtio \
  -drive file="$T/seed.iso",if=virtio,media=cdrom \
  -netdev user,id=n0 -device virtio-net,netdev=n0 \
  -device i6300esb -action watchdog=none \
  -device virtio-serial-pci,id=vs0 \
  -chardev socket,id=qga0,path="$QGA_SOCK",server=on,wait=off \
  -device virtserialport,bus=vs0.0,chardev=qga0,name=org.qemu.guest_agent.0 \
  2>/dev/null &
QEMU_PID=$!

while kill -0 "$QEMU_PID" 2>/dev/null; do
  grep -q '^/report' "$T/beacons.log" 2>/dev/null && break
  sleep 3
done
QGA_RC=none
if grep -q '^/report' "$T/beacons.log" 2>/dev/null; then
  echo ">> guest sent its report — querying the QEMU agent"
  QGA_RC=0
  python3 "$HERE/qga-probe.py" "$QGA_SOCK" 300 >"$T/qga.out" 2>&1 || QGA_RC=$?
fi
touch "$T/beacons.log.go"
wait "$QEMU_PID" || true

fail=0
if grep -q 'userdata=ok' "$T/beacons.log" 2>/dev/null; then
  echo "OK: user-data ran end-to-end"
else
  echo "FAIL: no beacon — user-data did NOT run"
  exit 1
fi

REPORT="$(grep -m1 '^/report' "$T/beacons.log" 2>/dev/null || true)"
if [ -z "$REPORT" ]; then
  echo "FAIL: the guest probe sent no report (cycles / ownership / automatic patching not measured)"
  exit 1
fi
python3 - "$REPORT" <<'PY' || fail=1
import base64, sys, urllib.parse
q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query,
                                                keep_blank_values=True).items()}
def text(k):
    s = q.get(k, "")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode(errors="replace").strip()
    except ValueError:
        return s
bad = 0
def ok(m): print("OK: " + m)
def no(m):
    global bad; bad = 1; print("FAIL: " + m)
if q.get("cycles") == "0":
    ok("no systemd unit ordering cycles")
else:
    no(f"systemd broke an ordering cycle ({q.get('cycles')}x) — it then drops a RANDOM job:\n   "
       + text("cycles_b64").replace("\n", "\n   "))
if q.get("foreign") == "0":
    ok("no files without an owner in /etc, /usr/local, /var/lib/csf")
else:
    no(f"{q.get('foreign')} files with uid/gid from outside the image (leaked from the build machine):\n   "
       + text("foreign_b64").replace("\n", "\n   "))
auto = q.get("auto", "none")
if auto == "none":
    no("automatic patching DISABLED (none of: apt-daily-upgrade / dnf-automatic-install / os-update .timer)")
else:
    ok(f"automatic patching enabled ({auto})")
if auto == "apt-daily-upgrade.timer":
    if q.get("uu", "0") != "0":
        ok('apt-config dump: APT::Periodic::Unattended-Upgrade "1"')
    else:
        no('apt-config dump does NOT give Unattended-Upgrade "1" — the timer runs but installs nothing')
# Watchdog on a LIVE boot, with the same device CloudStack (>=4.11) gives every VM.
# The offline gate sees only the driver FILE — it cannot see that Ubuntu suppresses
# its autoload with a blacklist from the kernel package
# (/usr/lib/modprobe.d/blacklist_linux_*.conf). That is exactly the defect measured
# by tier3: the 26.04 image HAD the file and the PCI alias, yet the guest had neither
# the module nor /dev/watchdog0 — with a green RuntimeWatchdogUSec=30s. This
# measurement catches it without CloudStack, on every build.
if q.get("wdog_module") == "yes":
    ok("i6300esb driver loaded in the guest (the distro blacklist did not win)")
else:
    no("i6300esb module missing on a live boot — the layer's watchdog is dead")
if q.get("wdog_dev") == "yes":
    ok("/dev/watchdog0 exists (PID1 has something to arm)")
else:
    no("/dev/watchdog0 missing — the driver did not find the device or did not load")
if q.get("wdog_pid1") == "yes":
    ok("systemd attached the hardware watchdog ('hardware watchdog' entry in the journal)")
else:
    no("systemd did NOT attach the watchdog — RuntimeWatchdogSec has no effect")
sys.exit(bad)
PY

sed 's/^/   /' "$T/qga.out" 2>/dev/null || true
case "$QGA_RC" in
  0) echo "OK: the QEMU agent gives no access to the system (exec/files/ssh/passwords blocked, fsfreeze works)" ;;
  *) echo "FAIL: QEMU agent — boundary violated or not measured (code: $QGA_RC)"; fail=1 ;;
esac

exit "$fail"

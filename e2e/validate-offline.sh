#!/usr/bin/env bash
# CI gate: validates the BUILT image WITHOUT booting it (guestfish).
# Catches exactly the regression class of a wrong datasource / broken cloud.cfg,
# and violations of the ssh (not always) / password (always) decision.
#
# Requires: libguestfs-tools (guestfish).
# Usage: ./validate-offline.sh build/template-debian-13-v1_1.qcow2
set -euo pipefail
IMG="${1:?usage: validate-offline.sh <image.qcow2>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/usrlib" "$T/qga-dropin-etc" "$T/qga-dropin-usr" "$T/qga-unit-etc" "$T/qga-bin"
mkdir -p "$T/dhcp-clients" "$T/ds-cloudstack"
fail=0
ok() { printf '  \033[32mOK  \033[0m %s\n' "$1"; }
no() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
# Verdict from a check script: "OK ..." / "FAIL ..." lines, everything else is context.
# A script that crashed or produced NOT A SINGLE verdict is a FAIL — a silent check
# is indistinguishable from a check that did not run.
verdict() {
  local n=0 l
  while IFS= read -r l; do
    case "$l" in
      "OK "*)   ok "${l#OK }"; n=$((n + 1)) ;;
      "FAIL "*) no "${l#FAIL }"; n=$((n + 1)) ;;
      "")       ;;
      *)        printf '       %s\n' "$l" ;;
    esac
  done
  [ "$n" -gt 0 ] || no "check script produced no verdict"
}
# QEMU guest agent commands the template MUST block (the agent must not be a way
# into the customer's OS). Same list as in common/finalize.sh and e2e/qga-probe.py
# — here as a REQUIREMENT, not a copy of the implementation.
QGA_BLOCKED="guest-exec guest-exec-status guest-file-open guest-file-read guest-file-write guest-file-close guest-file-seek guest-file-flush guest-ssh-get-authorized-keys guest-ssh-add-authorized-keys guest-ssh-remove-authorized-keys guest-set-user-password guest-get-users"

# one guestfish session, copy out the files we need (missing ones skipped via '- ')
# tar-out with numericowner: uid/gid exactly as stored in the image — not
# translated through /etc/passwd of the machine running the gate.
guestfish --ro -a "$IMG" -i <<EOF >/dev/null 2>&1 || true
- copy-out /etc/cloud/cloud.cfg $T
- copy-out /etc/cloud/cloud.cfg.d $T
- copy-out /etc/fail2ban/jail.local $T
- copy-out /etc/sysconfig/qemu-ga $T
- copy-out /etc/qemu/qemu-ga.conf $T
- glob copy-out /usr/lib/systemd/system/qemu-guest-agent.service $T
- copy-out /etc/systemd/system/qemu-guest-agent.service $T/qga-unit-etc
- copy-out /usr/sbin/qemu-ga $T/qga-bin
- copy-out /usr/bin/qemu-ga $T/qga-bin
- copy-out /etc/systemd/system/qemu-guest-agent.service.d $T/qga-dropin-etc
- copy-out /usr/lib/systemd/system/qemu-guest-agent.service.d $T/qga-dropin-usr
- copy-out /var/lib/csf/enabled-services $T
- copy-out /etc/apt/apt.conf.d $T
- copy-out /var/cache/debconf/config.dat $T
- copy-out /var/lib/dpkg/status $T
- copy-out /etc/dnf/automatic.conf $T
- copy-out /etc/os-update.conf $T
- copy-out /usr/local/sbin/csf-inspect $T
- copy-out /usr/local/sbin/csf-firstboot $T
- copy-out /usr/local/sbin/csf-watchdog $T
- glob copy-out /etc/systemd/system/csf-*.service $T
- copy-out /etc/systemd/system/multi-user.target.wants $T
- copy-out /etc/systemd/system/timers.target.wants $T
- copy-out /etc/systemd/system.conf.d $T
- glob copy-out /usr/lib/udev/rules.d/*qemu-guest-agent*.rules $T
- glob copy-out /etc/systemd/system/*.device.wants $T
- glob copy-out /etc/ssh/ssh_host_* $T
- copy-out /etc/fstab $T
- copy-out /boot/loader/entries $T
- copy-out /usr/lib/systemd/networkd.conf.d $T/usrlib
- glob copy-out /usr/sbin/dhclient $T/dhcp-clients
- glob copy-out /sbin/dhcpcd $T/dhcp-clients
- glob copy-out /usr/sbin/dhcpcd $T/dhcp-clients
- glob copy-out /sbin/udhcpc $T/dhcp-clients
- glob copy-out /usr/bin/udhcpc $T/dhcp-clients
- glob copy-out /usr/lib/python3*/*-packages/cloudinit/sources/DataSourceCloudStack.py $T/ds-cloudstack
- tar-out /etc $T/own-etc.tar numericowner:true
- tar-out /usr/local $T/own-usr-local.tar numericowner:true
- tar-out /var/lib/csf $T/own-var-lib-csf.tar numericowner:true
EOF

DS="$T/cloud.cfg.d/99-csf-cloudstack.cfg"
CC="$T/cloud.cfg"

echo "cloud-init:"
grep -Eq 'datasource_list:[[:space:]]*\[[[:space:]]*CloudStack' "$DS" 2>/dev/null \
  && ok "datasource: CloudStack first" || no "datasource: CloudStack NOT first"
# None is checked OUTSIDE comments (the file header says "'None' deliberately OMITTED")
grep -Ev '^[[:space:]]*#' "$DS" 2>/dev/null | grep -q 'None' \
  && no "datasource list contains None (it should fail loudly)" || ok "datasource list without None"
# set_passwords/ssh checked SEMANTICALLY (pyyaml): cloudcfg-tune dumps [set_passwords, always]
# in block style (2 lines), so a one-line grep lied. Bonus: broken YAML
# (the same regression class) = a loud parser FAIL, not a silent grep success.
CLOUDCFG_VERDICT="$(python3 - "$CC" <<'PYEOF' 2>&1
import sys, yaml
c = yaml.safe_load(open(sys.argv[1])) or {}
mods = [m for k in ("cloud_init_modules", "cloud_config_modules", "cloud_final_modules")
        for m in (c.get(k) or [])]
name = lambda m: m[0] if isinstance(m, list) else m
sp  = [m for m in mods if name(m) in ("set_passwords", "set-passwords")]
ssh = [m for m in mods if name(m) == "ssh"]
print("SP_OK"  if sp and all(isinstance(m, list) and "always" in m for m in sp) else "SP_FAIL")
print("SSH_OK" if ssh and not any(isinstance(m, list) and "always" in m for m in ssh) else "SSH_FAIL")
PYEOF
)" || CLOUDCFG_VERDICT="PARSE_FAIL"
grep -q '^SP_OK$'  <<<"$CLOUDCFG_VERDICT" \
  && ok "set_passwords = always (password reset on every boot)" || no "set_passwords NOT always (or cloud.cfg unparsable)"
grep -q '^SSH_OK$' <<<"$CLOUDCFG_VERDICT" \
  && ok "ssh != always" || no "ssh = always / ssh module missing (host keys!)"

echo "disk size:"
# Check the RESULT, not the manifest declaration: no registered template may have
# a disk < 10G — a disk that small shows up to the user as a "system" problem
# during the very first operations.
VSIZE="$(qemu-img info --output=json "$IMG" 2>/dev/null \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("virtual-size",0))' 2>/dev/null || echo 0)"
MIN_BYTES=$((10 * 1024 * 1024 * 1024))
if [ "${VSIZE:-0}" -ge "$MIN_BYTES" ]; then
  ok "disk $((VSIZE / 1073741824)) GiB (minimum 10 GiB)"
else
  no "disk $((${VSIZE:-0} / 1073741824)) GiB — BELOW the required 10 GiB"
fi

# The root partition size in the ARTIFACT is NOT checked: the factory grows only
# the disk, and cloud-init grows root on first boot. So here we verify what
# actually decides that — whether the growpart/resizefs configuration is present.
# The real root size is measured by tier3 on a LIVE machine, the only
# authoritative place for it.
GROW="$T/cloud.cfg.d/99-csf-cloudstack.cfg"
grep -q '^growpart:' "$GROW" 2>/dev/null   && ok "growpart enabled (root grows on first boot)"   || no "growpart MISSING — the disk grows, root stays small"
grep -Eq '^resize_rootfs:[[:space:]]*(true|noblock)' "$GROW" 2>/dev/null   && ok "resize_rootfs enabled"   || no "resize_rootfs MISSING — the filesystem will not follow the partition"

# Bootability: partitions MUST keep their original numbering. If it changes,
# GRUB looks for its configuration under the old number and ends in "grub rescue>" —
# the image is complete, the gate is green, and the machine does not boot.
# Ubuntu keeps root as p1 with p14/p15/p16 at the front of the disk, so a
# contiguous 1..N sequence from the start is a sign someone renumbered partitions.
PARTS="$(guestfish --ro -a "$IMG" run : part-list /dev/sda 2>/dev/null \
  | grep -oE 'part_num:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | xargs echo)"
ok "partition numbering in the image: ${PARTS:-?}"

# BLS boot entries (RHEL/Rocky/Fedora) MUST point at the root of THIS image.
# When a kernel gets installed during the build, `kernel-install` takes the
# parameters from the environment it runs in — and that is the libguestfs helper
# appliance, not the image being built. Rocky 10 got an entry with a root that
# does NOT exist in the image; the newer kernel wins as default, so GRUB booted
# exactly that entry, dracut waited forever for a missing disk
# ("timeout, still waiting for /dev/disk/by-uuid/..."), and the machine landed
# in emergency mode. The image was complete and the gate was green.
# The source of truth is fstab: all entries must point at the same root.
if [ -d "$T/entries" ]; then
  # Leak marker first: `guestfs_*` appears ONLY on the libguestfs appliance
  # command line. Separate check, because a matching root alone is NOT enough —
  # the same leak brings `selinux=0` and `cgroup_disable=memory`, which would
  # pass unnoticed with an accidentally correct root.
  if grep -rqE 'guestfs_|selinux=0' "$T/entries"/ 2>/dev/null; then
    no "boot entry carries parameters of the build machine (guestfs_/selinux=0)"
  else
    ok "boot entries without build machine parameters"
  fi

  FSTAB_ROOT="$(awk '$1 !~ /^#/ && $2 == "/" {print $1; exit}' "$T/fstab" 2>/dev/null || true)"
  case "${FSTAB_ROOT:-}" in
    UUID=*)
      WANT="${FSTAB_ROOT#UUID=}"
      FOREIGN="$(grep -rhoE 'root=UUID=[0-9a-fA-F-]+' "$T/entries"/ 2>/dev/null \
              | sed 's/root=UUID=//' | sort -u | grep -vix "$WANT" || true)"
      if [ -n "$FOREIGN" ]; then
        no "boot entry points at a root outside the image: $(echo $FOREIGN) (image: $WANT)"
      else
        ok "boot entries point at this image's root ($WANT)"
      fi
      ;;
    "") ok "no /etc/fstab or no entry for / — skipping boot entry check" ;;
    *)  ok "root in fstab not by UUID ($FSTAB_ROOT) — skipping boot entry check" ;;
  esac
else
  # Debian/Ubuntu do not use the BLS layout — a missing directory is normal, but
  # we say so OUT LOUD: a silent gate is indistinguishable from a gate that
  # did not run.
  ok "image without BLS boot entries (grub.cfg layout) — check not applicable"
fi

echo "ssh host keys:"
ls "$T"/ssh_host_* >/dev/null 2>&1 \
  && no "host keys baked into the image" || ok "no baked-in host keys"

echo "services:"
for s in qemu-guest-agent fail2ban csf-inspect csf-firstboot csf-watchdog; do
  grep -qx "$s" "$T/enabled-services" 2>/dev/null \
    && ok "manifest: $s" || no "manifest: $s missing"
  if [ "$s" = qemu-guest-agent ]; then
    # Debian/Ubuntu: unit with an EMPTY [Install] (enable = no-op) — activated via
    # udev SYSTEMD_WANTS (60-qemu-guest-agent.rules). RHEL/Rocky: [Install]
    # WantedBy=dev-virtio...device => symlink in *.device.wants
    # + our own udev rule 99-*. Any of the three paths is accepted.
    if [ -L "$T/multi-user.target.wants/$s.service" ] \
       || ls "$T"/*qemu-guest-agent*.rules >/dev/null 2>&1 \
       || ls "$T"/*.device.wants/qemu-guest-agent.service >/dev/null 2>&1; then
      ok "activation: $s (wants symlink / udev rule / device.wants)"
    else
      no "activation: $s missing (no wants symlink, no udev rule, no device.wants)"
    fi
  else
    [ -L "$T/multi-user.target.wants/$s.service" ] \
      && ok "wants symlink: $s" || no "wants symlink: $s missing (check the location on this distro)"
  fi
done

echo "qemu-guest-agent:"
# The EFFECTIVE block list, i.e. the one the agent actually gets — not whatever
# "sits in some file". The source depends on the unit:
#  * Debian/Ubuntu/SUSE: unit without list arguments -> /etc/qemu/qemu-ga.conf,
#  * RHEL: the unit expands a variable from /etc/sysconfig/qemu-ga — Rocky 9/10
#    `${FILTER_RPC_ARGS}`, Rocky 8 `--blacklist=${BLACKLIST_RPC}`.
# An older version grepped concatenated files. On Rocky 8 it found our
# FILTER_RPC_ARGS line, which the unit never reads, and went green.
# Functionally (live agent) the boundary is additionally checked by smoke-boot.
QGA_VERDICT="$(python3 - "$T" "$QGA_BLOCKED" <<'PYQGA' 2>&1
import os, re, sys
T, required = sys.argv[1], sys.argv[2].split()
def rd(n):
    try:
        return open(os.path.join(T, n), errors="replace").read()
    except OSError:
        return None
# a unit in /etc/systemd/system OVERRIDES the vendor unit from /usr/lib
unit = rd("qga-unit-etc/qemu-guest-agent.service") or rd("qemu-guest-agent.service")
if unit is None:
    print("FAIL /usr/lib/systemd/system/qemu-guest-agent.service missing — cannot tell where the agent gets its configuration")
    sys.exit(0)
execstart = " ".join(l.rstrip("\\").strip() for l in re.sub(r"\\\n", " ", unit).splitlines()
                     if l.strip().startswith("ExecStart"))
# A drop-in may replace ExecStart or EnvironmentFile — then the agent gets a DIFFERENT
# list than the one read below. The check cannot decide such a configuration,
# so it does not let it pass (our images have no QGA drop-ins).
for subdir in ("qga-dropin-etc", "qga-dropin-usr"):
    d = os.path.join(T, subdir, "qemu-guest-agent.service.d")
    for f in sorted(x for x in os.listdir(d) if x.endswith(".conf")) if os.path.isdir(d) else []:
        if re.search(r"^\s*(ExecStart|EnvironmentFile)\s*=", open(os.path.join(d, f), errors="replace").read(), re.M):
            print(f"FAIL drop-in {subdir}/{f} overrides ExecStart/EnvironmentFile of qemu-guest-agent — "
                  "effective block list cannot be determined offline")
            sys.exit(0)
sysconf = rd("qemu-ga") or ""
env = {}
for l in sysconf.splitlines():
    m = re.match(r'^\s*([A-Za-z_]+)=(.*)$', l)
    if m:
        env[m.group(1)] = m.group(2).strip().strip('"')
if "FILTER_RPC_ARGS" in execstart:
    source, v = "sysconfig FILTER_RPC_ARGS", env.get("FILTER_RPC_ARGS", "")
    if "allow-rpcs" in v:
        print("FAIL FILTER_RPC_ARGS still carries the vendor allowlist (--allow-rpcs) — lets set-user-password/get-users through")
    m = re.search(r"--block-rpcs=(\S+)", v)
    blocked = m.group(1).split(",") if m else []
elif "BLACKLIST_RPC" in execstart:
    source, blocked = "sysconfig BLACKLIST_RPC", env.get("BLACKLIST_RPC", "").split(",")
elif re.search(r"(allow-rpcs|block-rpcs|blacklist|\s-[ab]\b)", execstart):
    print(f"FAIL qemu-guest-agent unit passes a list on the command line that the factory does not control: {execstart[:160]}")
    sys.exit(0)
else:
    # The key the agent ACTUALLY reads depends on the version (qga/main.c): 6.2 knows only
    # `blacklist`, 7.2-8.2 `block-rpcs`, but a present `blacklist` (alias) overrides it,
    # 10.0 only `block-rpcs`. The version is recognized by strings in the binary.
    # On Ubuntu 22.04 (6.2) `block-rpcs` was ignored and the agent executed guest-exec.
    binary = b""
    for f in ("qemu-ga",):
        pth = os.path.join(T, "qga-bin", f)
        if os.path.exists(pth):
            binary = open(pth, "rb").read()
    if not binary:
        print("FAIL qemu-ga binary missing in the image (neither /usr/sbin nor /usr/bin) — cannot tell which key it reads")
        sys.exit(0)
    keys = {}
    section = ""
    for l in (rd("qemu-ga.conf") or "").splitlines():
        l = l.strip()
        if l.startswith("["):
            section = l
        elif section == "[general]" and "=" in l:
            k, v = l.split("=", 1)
            # GKeyFile takes the LAST value of a repeated key
            keys[k.strip()] = [x.strip() for x in v.split(",") if x.strip()]
    if b"block-rpcs" not in binary:
        key = "blacklist"
    elif "blacklist" in keys and b"blacklist" in binary:
        key = "blacklist"
    else:
        key = "block-rpcs"
    source = f"/etc/qemu/qemu-ga.conf, key {key}"
    blocked = keys.get(key, [])
print(f"block list source: {source}")
missing = [n for n in required if n not in blocked]
if missing:
    print("FAIL QGA does NOT block: " + ", ".join(missing))
else:
    print(f"OK QGA blocks exec/files/ssh/password/users ({len(required)} commands, {source})")
PYQGA
)" || QGA_VERDICT="${QGA_VERDICT}"$'\n''FAIL QGA check crashed'
verdict <<<"$QGA_VERDICT"

echo "file ownership:"
# `virt-customize --copy-in` carries uid/gid and mode from the BUILD MACHINE into
# the image. Without a fix, files of the common layer arrived as the CI runner's
# uid:gid (an account that does not exist in the image) with mode 664 —
# including systemd units and scripts run as root. Two checks:
#  1) generic: nothing in /etc, /usr/local, /var/lib/csf may have a uid/gid outside
#     /etc/passwd and /etc/group of THIS image (catches any future file),
#  2) common layer: exactly root:root and the expected mode.
OWN_VERDICT="$(python3 - "$T" <<'PYOWN' 2>&1
import os, stat, sys, tarfile
T = sys.argv[1]
def open_tar(n):
    p = os.path.join(T, n)
    if not os.path.exists(p):
        print(f"FAIL guestfish did not export {n} — ownership cannot be checked")
        return None
    return tarfile.open(p)
etc = open_tar("own-etc.tar")
if etc is None:
    sys.exit(0)
strip_dot = lambda n: n[2:] if n.startswith("./") else ("" if n == "." else n)
m = {strip_dot(x.name): x for x in etc.getmembers()}
read = lambda n: etc.extractfile(m[n]).read().decode(errors="replace")
uids = {int(l.split(":")[2]) for l in read("passwd").splitlines() if l.count(":") >= 3}
gids = {int(l.split(":")[2]) for l in read("group").splitlines() if l.count(":") >= 3}
everything = {}
for tn, prefix in (("own-etc.tar", "/etc"), ("own-usr-local.tar", "/usr/local"), ("own-var-lib-csf.tar", "/var/lib/csf")):
    t = etc if tn == "own-etc.tar" else open_tar(tn)
    if t is None:
        continue
    for x in t.getmembers():
        everything[(prefix + "/" + strip_dot(x.name)).rstrip("/")] = x
foreign = [f"{p} ({x.uid}:{x.gid})" for p, x in sorted(everything.items())
           if x.uid not in uids or x.gid not in gids]
if foreign:
    print(f"FAIL {len(foreign)} files with uid/gid from outside the image: " + ", ".join(foreign[:8]))
else:
    print(f"OK no uid/gid from outside the image ({len(everything)} entries in /etc, /usr/local, /var/lib/csf)")
LAYER = {
    "/etc/cloud/cloud.cfg.d/99-csf-cloudstack.cfg": 0o644,
    "/etc/fail2ban/jail.local": 0o644,
    "/usr/local/sbin/csf-inspect": 0o755,
    "/usr/local/sbin/csf-firstboot": 0o755,
    "/usr/local/sbin/csf-watchdog": 0o755,
    "/etc/systemd/system/csf-firstboot.service": 0o644,
    "/etc/systemd/system/csf-inspect.service": 0o644,
    "/etc/systemd/system/csf-watchdog.service": 0o644,
    "/etc/systemd/system.conf.d/10-csf-watchdog.conf": 0o644,
    "/etc/qemu/qemu-ga.conf": 0o644,
}
bad = []
for p, mode in LAYER.items():
    x = everything.get(p)
    if x is None:
        bad.append(f"{p} missing")
    elif (x.uid, x.gid) != (0, 0) or stat.S_IMODE(x.mode) != mode:
        bad.append(f"{p} {x.uid}:{x.gid} {oct(stat.S_IMODE(x.mode))} (expected 0:0 {oct(mode)})")
if bad:
    print("FAIL common layer with wrong owner/mode: " + "; ".join(bad))
else:
    print(f"OK common layer root:root with expected modes ({len(LAYER)} files)")
PYOWN
)" || OWN_VERDICT="${OWN_VERDICT}"$'\n''FAIL ownership check crashed'
verdict <<<"$OWN_VERDICT"

echo "password from CloudStack: password server client:"
# cloud-init (DataSourceCloudStack, versions 23.4-25.3) fetches the password with an
# EXTERNAL `wget` from <VR>:8080. Without wget: "Failed to fetch password" on every
# deploy and reset — measured by tier3 on Rocky 8/9 with a correct data-server.
WGET_PROBE="$(guestfish --ro -a "$IMG" -i is-file /usr/bin/wget followsymlinks:true 2>/dev/null || true)"
[ "$WGET_PROBE" = "true" ] \
  && ok "wget present (/usr/bin/wget) — cloud-init will fetch the password from the VR" \
  || no "/usr/bin/wget MISSING — cloud-init will not fetch the password from CloudStack (deploy/reset/reinstall)"

echo "network: password from CloudStack in a VPC with redundant VR:"
# cloud-init asks for the password at the same address where it found the metadata:
# first the `data-server` name (points at the gateway = the router VIP), and if that
# does not resolve — SERVER_ADDRESS from the DHCP lease, i.e. the router's OWN address.
# In a VPC with a redundant VR the password server listens only on the VIP, so the
# password from deploy/reset/reinstall never arrives. `data-server` resolves only
# through the DHCP search domain, and systemd-networkd takes that only with
# UseDomains=true.
# The rule is based on image FACTS, not on a manifest flag: networkd enabled + systemd
# >= 256 (the version that introduced the global key in networkd.conf) => effective
# UseDomains=true. Older systemd has no such key — tier3 decides there.
NET_VERDICT="$(python3 - "$T" <<'PYNET' 2>&1
import os, re, stat, sys, tarfile
T = sys.argv[1]
FILE = "systemd/networkd.conf.d/50-csf-cloudstack-data-server.conf"
try:
    tar = tarfile.open(os.path.join(T, "own-etc.tar"))
except (OSError, tarfile.TarError):
    print("FAIL /etc export missing — network check cannot run")
    sys.exit(0)
strip = lambda n: n[2:] if n.startswith("./") else n
m = {strip(x.name): x for x in tar.getmembers()}
read = lambda k: tar.extractfile(m[k]).read().decode(errors="replace")
networkd = any(re.match(r"^systemd/system/[^/]+\.wants/systemd-networkd\.(service|socket)$", k) for k in m)
ours = m.get(FILE)
if ours is not None:
    if (ours.uid, ours.gid, stat.S_IMODE(ours.mode)) == (0, 0, 0o644):
        print("OK /etc/" + FILE + " root:root 0644")
    else:
        print(f"FAIL /etc/{FILE} {ours.uid}:{ours.gid} {oct(stat.S_IMODE(ours.mode))} (expected 0:0 0o644)")
if not networkd:
    if ours is not None:
        print("FAIL UseDomains file in an image WITHOUT systemd-networkd — dead configuration (wrong manifest flag)")
    else:
        print("OK image without systemd-networkd — the DHCP search domain is handled by another network manager")
    sys.exit(0)
st = ""
try:
    st = open(os.path.join(T, "status"), errors="replace").read()
except OSError:
    pass
w = re.search(r"^Package: systemd\n(?:[^\n]+\n)*?Version: (\d+)", st, re.M)
if not w:
    print("FAIL systemd-networkd enabled, but the systemd version is unknown (no dpkg status entry)")
    sys.exit(0)
version = int(w.group(1))
# order as in systemd: networkd.conf, then drop-ins sorted by NAME
# (the same name in /etc shadows /usr/lib); the last assignment wins
dropins = {}
ul = os.path.join(T, "usrlib", "networkd.conf.d")
if os.path.isdir(ul):
    for f in [f for f in os.listdir(ul) if f.endswith(".conf")]:   # systemd reads only *.conf from .d
        dropins[f] =("/usr/lib/systemd/networkd.conf.d/" + f, open(os.path.join(ul, f), errors="replace").read())
for k in m:
    if k.startswith("systemd/networkd.conf.d/") and k.endswith(".conf") and m[k].isfile():
        dropins[os.path.basename(k)] = ("/etc/" + k, read(k))
queue = [("/etc/systemd/networkd.conf", read("systemd/networkd.conf") if "systemd/networkd.conf" in m else "")]
queue += [dropins[f] for f in sorted(dropins)]
value, origin = "no (default)", "-"
for path, content in queue:
    section = ""
    for l in content.splitlines():
        l = l.strip()
        if l.startswith("["):
            section = l
        elif section == "[Network]" and re.match(r"^UseDomains\s*=", l):
            value, origin = l.split("=", 1)[1].strip(), path
if version < 256:
    if ours is not None:
        print(f"FAIL systemd {version} < 256 does not know [Network] UseDomains in networkd.conf — the file is just 'Unknown key' in the journal")
    else:
        print(f"OK systemd {version} < 256: no global UseDomains; data-server resolution is measured by tier3")
elif value.lower() in ("yes", "true", "1", "on"):
    # The verdict concerns the DEFAULT global value. Per-interface .network files
    # are generated by cloud-init/netplan only at boot (/run) — they are not in the
    # image; the effect (data-server = gateway) is measured by tier3 on a live VPC machine.
    print(f"OK systemd {version}: global [Network] UseDomains={value} ({origin}); per-interface effect is measured by tier3")
else:
    print(f"FAIL systemd {version} + networkd: UseDomains={value} ({origin}) — data-server will not resolve, "
          "the password request goes to the router's own address (redundant VR). Add networkd_use_domains: true to the manifest")
PYNET
)" || NET_VERDICT="${NET_VERDICT}"$'\n''FAIL network check crashed'
verdict <<<"$NET_VERDICT"

echo "network: which Virtual Router address cloud-init sees in init-local:"
# Second layer of the same issue (measured on Ubuntu 22.04). When
# `DataSourceCloudStackLocal` MANAGES to collect data in init-local, it takes the
# Virtual Router address from `dhcp-server-identifier` of the ephemeral lease — in a
# VPC with a redundant VR that is the address of ONE router, while the password
# server listens on the VIP. The `data-server` name (VIP) resolves only in
# init-network. Way out: an image without a DHCP client cloud-init can use — then
# init-local fails with `NoDHCPLeaseError` and the datasource is detected over the
# network (manifest: `cloudstack_datasource_network: true` -> cloudcfg-tune ->
# dhcp_client_priority).
DHCP_VERDICT="$(python3 - "$T" <<'PYDHCP' 2>&1
import os, re, sys, tarfile, yaml
T = sys.argv[1]
try:
    c = yaml.safe_load(open(os.path.join(T, "cloud.cfg"))) or {}
except Exception as e:  # noqa: BLE001 — an unparsable cloud.cfg already has its own verdict above
    print(f"FAIL cloud.cfg unparsable ({e}) — DHCP client check cannot run")
    sys.exit(0)
nest = c["system_info"] if isinstance(c.get("system_info"), dict) else c
prio = ((nest.get("network") or {}).get("dhcp_client_priority")) or []
cdir = os.path.join(T, "dhcp-clients")
present = set(os.listdir(cdir)) if os.path.isdir(cdir) else set()
src = os.path.join(T, "ds-cloudstack", "DataSourceCloudStack.py")
code = open(src, errors="replace").read() if os.path.isfile(src) else ""
# systemd-networkd is recognized the same way as in the UseDomains check above — by the
# symlink in *.wants in the exported /etc, not by the mere presence of the package.
networkd = False
try:
    with tarfile.open(os.path.join(T, "own-etc.tar")) as tar:
        networkd = any(re.match(r"^(\./)?systemd/system/[^/]+\.wants/systemd-networkd\.(service|socket)$",
                                m.name) for m in tar.getmembers())
except (OSError, tarfile.TarError):
    print("no /etc export — presence of systemd-networkd cannot be checked")
# The single-router address from the lease comes ONLY from `DataSourceCloudStackLocal`
# (ephemeral DHCP in init-local). The string "via ephemeral" used to be the
# discriminator, but it also sits in `get_vr_address()` of 24.4/25.1.3, which have NO
# Local class — so the rule below rejected a fixed openSUSE image (dhclient + explicit
# priority) in which the datasource is detected only in init-network (data-server = VIP).
reads_lease = bool(re.search(r"^class\s+DataSourceCloudStackLocal\b", code, re.M))
print(f"DHCP clients in the image: {', '.join(sorted(present)) or 'NONE'}; "
      f"dhcp_client_priority: {prio or 'not set (order from distro code)'}")
# The client cloud-init will ACTUALLY use: the first PRESENT one from the priority list.
# Two reasons why this check is so restrained — both mistakes were already made
# and caught by measuring real artifacts:
#  * the mere presence of a program decides nothing: `dhcpcd` exists on 24.04/26.04,
#    and there the password path WORKS (cloud-init kills the process, then
#    `dhcpcd --dumplease` answers "dhcpcd is not running" and init-local fails);
#  * without `dhcp_client_priority` in cloud.cfg the order lives in distro code, which
#    we do not read offline — Rocky 9 has `dhclient` and the "ephemeral lease" branch,
#    and tier3 shows PASS. Guessing "the only present client wins" rejected a healthy image.
# So a verdict is issued only when the priority list is visible in the image.
chosen = next((k for k in prio if k in present), None) if prio else None
if prio and chosen is None:
    # This configuration is safe ONLY with systemd-networkd (verified in cloud-init
    # code): `_get_domainname()` references `self.distro.dhcp_client.client_name` in a
    # LOG.debug OUTSIDE `suppress`, so without a DHCP client
    # `NoDHCPLeaseMissingDhclientError` propagates through `get_hostname(fqdn=True)`
    # and aborts the WHOLE init stage. The first branch of that function — the domain
    # from the networkd lease — prevents it, and NetworkManager images (Rocky, openSUSE)
    # do not have it. Turning "password does not arrive" into "init does not start at
    # all" would be worse than the problem.
    if networkd:
        print("OK dhcp_client_priority lists only ABSENT clients — init-local "
              "fails for lack of a lease, and the datasource is detected over the network (data-server = VIP)")
    else:
        print("FAIL dhcp_client_priority without any present DHCP client, and the image has NO "
              "systemd-networkd — `_get_domainname()` reaches for `dhcp_client` outside "
              "`suppress` and the exception aborts the whole cloud-init init stage. The "
              "cloudstack_datasource_network flag is only for images with networkd")
elif not code:
    print("OK DataSourceCloudStack.py not found in the image — the password path is measured by tier3")
elif not reads_lease:
    print("OK image without DataSourceCloudStackLocal — the datasource is detected only "
          "in init-network (data-server = VIP, fallback: gateway); effect measured by tier3")
elif chosen == "dhclient":
    # The advice depends on networkd: without it the cloudstack_datasource_network flag
    # would abort the whole init stage (rule above), and build.sh rejects it together
    # with cloudinit_dhcp_client_priority anyway.
    if networkd:
        advice = ("Add cloudstack_datasource_network: true to the manifest and remove "
                  "cloudinit_dhcp_client_priority if present (build.sh rejects both at once)")
    else:
        advice = ("The image has NO systemd-networkd, so cloudstack_datasource_network will not "
                  "help here (it aborts the whole init stage); another DHCP client or a "
                  "cloud-init fix is needed")
    print("FAIL cloud-init will use `dhclient`, which returns the lease from a FILE even after "
          "the process has exited — in init-local it takes `dhcp-server-identifier`, i.e. the "
          "address of ONE router, and in a VPC with a redundant VR the password never arrives. " + advice)
elif chosen:
    print(f"OK cloud-init will use `{chosen}` — whether this client returns a lease in init-local "
          "is decided by tier3 on a live machine")
else:
    print("OK without dhcp_client_priority in the image the client cloud-init will use "
          f"cannot be determined offline (present: {', '.join(sorted(present)) or 'none'}) "
          "— the password path is measured by tier3")
PYDHCP
)" || DHCP_VERDICT="${DHCP_VERDICT}"$'\n''FAIL DHCP client check crashed'
verdict <<<"$DHCP_VERDICT"

echo "cloud-init: init stage without a DHCP lease (DataSourceCloudStack):"
# A FUNCTIONAL check, not a textual one. Rocky 10 and openSUSE Leap 16 images passed
# `validate` and `smoke`, yet on CloudStack cloud-init aborted the init stage:
# `_get_domainname()` reached for `dhcpcd`, which nobody runs, and the exception
# propagated through `get_hostname(fqdn=True)`. Smoke can never catch this — it boots
# with the NoCloud datasource. The check above reads configuration, but the outcome
# depends on cloud-init's code, the clients in the image and the merged /etc/cloud
# configuration — so e2e/probe-ds-cloudstack.py calls the REAL function from the
# image inside its chroot. A qcow2 overlay, because `upload` needs write access and
# the artifact is read-only.
PROBE_DS="$HERE/probe-ds-cloudstack.py"
if [ ! -f "$PROBE_DS" ]; then
  no "$PROBE_DS missing — init stage check cannot run"
else
  ND=""
  tar -tf "$T/own-etc.tar" > "$T/own-etc.list" 2>/dev/null || true
  grep -Eq '^(\./)?systemd/system/[^/]+\.wants/systemd-networkd\.(service|socket)$' "$T/own-etc.list" \
    && ND="--networkd"
  if ! qemu-img create -f qcow2 -b "$(readlink -f "$IMG")" -F qcow2 "$T/probe.qcow2" >/dev/null 2>"$T/probe.err"; then
    no "could not create qcow2 overlay for the probe: $(head -1 "$T/probe.err")"
  else
    # Interpreter from cloud-init's shebang (Rocky 8: platform-python). The guestfish
    # script goes through printf with a single-quoted format — `$(...)` must reach the
    # GUEST's shell. The probe is uploaded from a copy in $T: guestfish splits
    # arguments on spaces, and the checkout path may contain some (the mktemp path does not).
    cp "$PROBE_DS" "$T/probe-ds.py"
    {
      printf 'upload %s /tmp/csf-probe-ds.py\n' "$T/probe-ds.py"
      # shellcheck disable=SC2016
      printf 'sh "PY=$(sed -n 1s/^#![[:space:]]*//p /usr/bin/cloud-init); ${PY:-python3} -B /tmp/csf-probe-ds.py %s 2>&1 || true"\n' "$ND"
    } > "$T/probe.gf"
    guestfish -a "$T/probe.qcow2" -i < "$T/probe.gf" > "$T/probe.out" 2>&1 || true
    rm -f "$T/probe.qcow2"
    verdict < "$T/probe.out"
  fi
fi

echo "systemd units of the layer:"
# A unit with WantedBy=multi-user.target MUST have an explicit After=multi-user.target.
# Without it the target adds After= on the unit itself, while csf-firstboot is
# After=cloud-final, which is itself After=multi-user.target (Debian 12/13, Ubuntu,
# Rocky 9/10, Leap 16) -> a cycle that systemd breaks by dropping a RANDOM job
# (once cloud-final, once csf-firstboot). On a live boot smoke-boot also counts cycles.
for u in "$T"/csf-*.service; do
  [ -f "$u" ] || { no "no csf-*.service units in /etc/systemd/system"; break; }
  n="$(basename "$u")"
  if grep -Eq '^WantedBy=.*multi-user\.target' "$u"; then
    grep -E '^After=' "$u" | grep -qw 'multi-user\.target' \
      && ok "$n: After=multi-user.target (no cycle with cloud-final)" \
      || no "$n: WantedBy=multi-user.target WITHOUT After=multi-user.target — ordering cycle"
  fi
done
# `apt-get upgrade` without --with-new-pkgs silently holds back the kernel (new ABI
# package) — measured on a customer VM: linux-image-cloud-amd64 not installed.
grep -Eq 'with-new-pkgs' "$T/csf-firstboot" 2>/dev/null \
  && ok "csf-firstboot: apt upgrade with --with-new-pkgs (kernel is not held back)" \
  || no "csf-firstboot: apt upgrade WITHOUT --with-new-pkgs — kernel update will be skipped"

echo "watchdog:"
grep -q 'RuntimeWatchdogSec' "$T/system.conf.d/10-csf-watchdog.conf" 2>/dev/null \
  && ok "systemd RuntimeWatchdogSec (pets /dev/watchdog)" || no "watchdog configuration missing"
grep -q '/usr/local/sbin/csf-watchdog' "$T/csf-watchdog.service" 2>/dev/null \
  && ok "csf-watchdog.service runs /usr/local/sbin/csf-watchdog" \
  || no "no csf-watchdog.service pointing at /usr/local/sbin/csf-watchdog"
grep -q 'MOD=i6300esb' "$T/csf-watchdog" 2>/dev/null && grep -q 'modprobe "$MOD"' "$T/csf-watchdog" 2>/dev/null \
  && ok "csf-watchdog: explicit modprobe i6300esb (bypasses the distro blacklist)" \
  || no "csf-watchdog does not load i6300esb with an explicit modprobe — on Ubuntu the blacklist suppresses autoload"
# Second line of defense inside the guest: the package carrying the module is
# VERSIONED, so after a kernel ABI bump (unattended-upgrades / csf-firstboot) it does
# not arrive on its own. The script must pull it in — otherwise the fix silently
# expires. The gate makes sure this path does not vanish from the layer in a refactor.
grep -q 'linux-modules-extra-\$KVER' "$T/csf-watchdog" 2>/dev/null \
  && ok "csf-watchdog pulls linux-modules-extra for the running kernel (survives ABI changes)" \
  || no "csf-watchdog does NOT pull linux-modules-extra — on Ubuntu the watchdog dies after a kernel update"
# Gate on the EFFECT, not the declaration. `RuntimeWatchdogSec` above only says that
# PID1 SHOULD arm the watchdog — it can arm only a device created by a driver present
# IN THE IMAGE. Measured by tier3 on live CloudStack on Ubuntu 24.04 and 26.04:
# RuntimeWatchdogUSec=30s, yet `lsmod` without i6300esb and no /dev/watchdog0. On
# 22.04/24.04 the cause was the missing driver FILE (it lives in
# linux-modules-extra-<ABI>, which the cloud image lacks) — the same defect class as
# Debian 12's `cloud` kernel (distros/debian-12.yaml). The symptom is silent: the
# layer looks enabled, so an artifact without the driver must not leave the factory.
# A driver built into the kernel (modules.builtin) counts the same as a .ko.
CSF_MOD_PROBE="$(guestfish --ro -a "$IMG" -i 2>/dev/null <<'GFWD' || true
- sh "ls -1 /lib/modules"
echo ---files---
- sh "ls -1 /lib/modules/*/kernel/drivers/watchdog/i6300esb.ko* 2>/dev/null"
echo ---builtin---
- sh "grep -l i6300esb /lib/modules/*/modules.builtin 2>/dev/null"
GFWD
)"
CSF_MOD_VERDICT="$(python3 - "$CSF_MOD_PROBE" <<'PYWD' 2>&1
import sys
parts = sys.argv[1].split("---files---")
kernels = [l.strip() for l in parts[0].splitlines() if l.strip()]
rest = (parts[1] if len(parts) > 1 else "").split("---builtin---")
paths = [l.strip() for l in " ".join(rest).split() if l.strip().startswith("/")]
if not kernels:
    print("FAIL no directory found in /lib/modules — the watchdog driver cannot be checked")
    sys.exit(0)
for k in kernels:
    hits = [s for s in paths if "/" + k + "/" in s]
    if hits:
        print(f"OK i6300esb driver for kernel {k} ({hits[0]})")
    else:
        print(f"FAIL kernel {k} WITHOUT the i6300esb driver — the watchdog has nothing to arm "
              "(apt: install linux-modules-extra-" + k + "; other families: check the image variant)")
PYWD
)" || CSF_MOD_VERDICT="${CSF_MOD_VERDICT}"$'\n''FAIL watchdog driver check crashed'
verdict <<<"$CSF_MOD_VERDICT"

echo "automatic security updates:"
# Gate on the RESULT. The template serves CUSTOMER machines and must deliver a system
# with the native automatic patching enabled. Fleet-host policies (e.g. a
# 99-csf-no-auto-upgrades file, debconf `false`, masked timers) do not belong in
# templates: with them a customer VM had no patching path at all (`apt-config dump`:
# Update-Package-Lists "0", Unattended-Upgrade "0").
#
# The family is decided by `is-file` on the package manager IN THE IMAGE, not by the
# presence of copied files: if copy-out failed, "no apt directory" would read as
# "not Debian" and the gate would pass an image without automatic updates. Masks are
# symlinks to /dev/null — copy-out would dereference them, so we ask for the link
# TARGET (readlink on a non-link fails and prints nothing).
AUTO_PROBE="$(guestfish --ro -a "$IMG" -i 2>/dev/null <<'GFAUTO' || true
is-file /usr/bin/apt-get followsymlinks:true
is-file /usr/bin/dnf followsymlinks:true
is-file /usr/bin/zypper followsymlinks:true
- readlink /etc/systemd/system/apt-daily.timer
- readlink /etc/systemd/system/apt-daily-upgrade.timer
- readlink /etc/systemd/system/dnf-automatic-install.timer
- readlink /etc/systemd/system/os-update.timer
echo ---apt-config---
- command "apt-config dump"
GFAUTO
)"
AUTO_VERDICT="$(python3 - "$T" "$AUTO_PROBE" <<'PYAUTO' 2>&1
import configparser, os, re, sys
T, result = sys.argv[1], sys.argv[2].split("---apt-config---\n")
probe = result[0].splitlines()
aptcfg = result[1] if len(result) > 1 else ""
if len(probe) < 3 or any(p not in ("true", "false") for p in probe[:3]):
    print("FAIL guestfish did not answer which package manager the image uses — nothing to check against")
    sys.exit(0)
apt, dnf, zypper = (p == "true" for p in probe[:3])
if any(l.strip() == "/dev/null" for l in probe[3:]):
    print("FAIL automatic update timer MASKED (symlink to /dev/null in /etc/systemd/system)")
def rd(n):
    try:
        return open(os.path.join(T, n), errors="replace").read()
    except OSError:
        return None
def timer(name):
    if os.path.islink(os.path.join(T, "timers.target.wants", name)):
        print(f"OK {name} enabled (timers.target.wants)")
    else:
        print(f"FAIL {name} not enabled")

if apt:
    if re.search(r"^Package: unattended-upgrades\n(?:[^\n]+\n)*?Status: install ok installed$",
                 rd("status") or "", re.M):
        print("OK unattended-upgrades installed")
    else:
        print("FAIL unattended-upgrades NOT installed (added by build.sh — check the install log)")
    # EFFECTIVE configuration from a real `apt-config dump` run inside the image
    # (guestfish `command`, --ro mode), not from our own file parsing: apt itself
    # resolves the order of apt.conf.d and /etc/apt/apt.conf, the block syntax
    # `APT::Periodic { ... };` and ignored files (Dir::Ignore-Files-Silently).
    effective = {}
    for l in aptcfg.splitlines():
        m = re.match(r'^(APT::Periodic::(?:Enable|Update-Package-Lists|Unattended-Upgrade)) "(.*)";$', l.strip())
        if m:
            effective[m.group(1)] = m.group(2)
    if not re.search(r"^APT::", aptcfg, re.M):
        print("FAIL apt-config dump inside the image did not work — the effective apt configuration cannot be checked")
    else:
        # APT::Periodic::Enable is the master switch: with "0" apt.systemd.daily
        # exits regardless of the other keys. Missing key = default "1".
        enable = effective.get("APT::Periodic::Enable", "1")
        if enable == "0":
            print('FAIL apt-config dump: APT::Periodic::Enable "0" — apt.systemd.daily will do nothing')
        else:
            print(f'OK apt-config dump: APT::Periodic::Enable "{enable}"')
        for key in ("APT::Periodic::Update-Package-Lists", "APT::Periodic::Unattended-Upgrade"):
            val = effective.get(key, "missing")
            if val not in ("", "0", "missing"):
                print(f'OK apt-config dump: {key} "{val}"')
            else:
                print(f'FAIL apt-config dump: {key} = "{val}" — automatic apt updates disabled')
    if os.path.exists(os.path.join(T, "apt.conf.d", "99-csf-no-auto-upgrades")):
        print("FAIL the image contains 99-csf-no-auto-upgrades — a fleet-host policy does not belong in templates")
    m = re.search(r"^Name: unattended-upgrades/enable_auto_updates\n(?:[^\n]+\n)*?Value: (\S+)$",
                  rd("config.dat") or "", re.M)
    if m and m.group(1) == "true":
        print("OK debconf enable_auto_updates = true (postinst will not disable automatic updates)")
    else:
        print(f"FAIL debconf enable_auto_updates = {m.group(1) if m else 'missing'} — reconfiguring the package will disable automatic updates")
    timer("apt-daily.timer")
    timer("apt-daily-upgrade.timer")
elif dnf:
    ac = rd("automatic.conf")
    if ac is None:
        print("FAIL /etc/dnf/automatic.conf missing — dnf-automatic not installed")
    else:
        c = configparser.ConfigParser(interpolation=None, strict=False)
        c.read_string(ac)
        kind = c.get("commands", "upgrade_type", fallback="missing").strip()
        if kind == "security":
            print("OK dnf-automatic: upgrade_type = security")
        else:
            print(f"FAIL dnf-automatic: upgrade_type = {kind} (expected security)")
    timer("dnf-automatic-install.timer")
elif zypper:
    oc = rd("os-update.conf")
    if oc is None:
        print("FAIL /etc/os-update.conf missing — os-update with default settings REBOOTS the machine by itself")
    else:
        env = {}
        for l in oc.splitlines():
            m = re.match(r'^\s*([A-Z_]+)=["\']?([^"\'\s]*)', l)
            if m:
                env[m.group(1)] = m.group(2)
        for k, v in (("UPDATE_CMD", "security"), ("REBOOT_CMD", "none"), ("RESTART_SERVICES", "no")):
            if env.get(k) == v:
                print(f"OK os-update: {k}={v}")
            else:
                print(f"FAIL os-update: {k}={env.get(k, 'default')} (expected {v})")
    timer("os-update.timer")
else:
    print("FAIL image without apt-get, dnf and zypper — unknown family, automatic updates cannot be checked")
PYAUTO
)" || AUTO_VERDICT="${AUTO_VERDICT}"$'\n''FAIL automatic updates check crashed'
verdict <<<"$AUTO_VERDICT"

echo "SELinux: file contexts:"
# The image is built OFFLINE (virt-customize), where no SELinux policy is loaded:
# files coming in via `--copy-in` and files rewritten by package installs end up
# WITHOUT the `security.selinux` attribute. In a guest with SELINUX=enforcing such a
# file is `unlabeled_t`.
# Measured: Rocky 10 images had no attribute even on /etc/passwd and /etc/shadow
# (Rocky 8/9 and openSUSE were correct: passwd_file_t/shadow_t). On such a machine
# `sulogin` got an `unlabeled_t` AVC on /etc/passwd, the machine entered emergency
# mode, and the CloudStack password did not work on the console.
# NOTE: this is NOT why sshd did not start on Rocky 10 — relabeling the image did
# not fix that, and the full boot log had NO AVC at all. sshd was broken by
# cloud-init aborting the `init` stage (see e2e/tier3-features.py, comment at
# SSH_USER_CANDIDATES). This check guards a SEPARATE defect.
# `/.autorelabel` in the image is NOT a safeguard: it was present in all broken
# artifacts. We check the EFFECT in the image, not the intent.
# The decision is based on the MODE from the image, not on the file's presence: with
# SELINUX=disabled contexts do not matter and a FAIL would be false. Debian/Ubuntu
# have no such file at all, so they fall into the first branch.
# The mode is read the way libselinux does it (selinux_getenforcemode): the FIRST
# `SELINUX=` line with a RECOGNIZED value (enforcing/permissive/disabled after leading
# whitespace, as a prefix, case-insensitive) — lines with other values are skipped.
# An older reading (`tr -d` + strict comparison) turned `SELINUX=enforcing # comment`
# into `enforcing#comment`, treated the image as "without SELinux" and skipped the
# whole check, while the system booted in enforcing mode.
# The CSF-END marker distinguishes "file missing" (Debian/Ubuntu: only the marker)
# from "guestfish failed" (no marker) — without it both states gave OK "mode: none"
# and the context check silently did not run.
SEL_RAW="$(guestfish --ro -a "$IMG" -i sh "if [ -e /etc/selinux/config ]; then sed -n 's/^SELINUX=//p' /etc/selinux/config; fi; echo CSF-END" 2>"$T/sel-mode.err" || true)"
SEL_MODE="$(grep -vx 'CSF-END' <<<"$SEL_RAW" | sed 's/^[[:space:]]*//' | tr '[:upper:]' '[:lower:]' \
  | grep -m1 -oE '^(enforcing|permissive|disabled)' || true)"
case "$SEL_MODE" in
  enforcing|permissive) SEL_ACTIVE=1 ;;
  *)                    SEL_ACTIVE=0 ;;
esac
if ! grep -qx 'CSF-END' <<<"$SEL_RAW"; then
  no "could not read the SELinux mode (guestfish: $(head -1 "$T/sel-mode.err" 2>/dev/null)) — context check NOT performed"
elif [ "$SEL_ACTIVE" -eq 0 ]; then
  ok "image without active SELinux (mode: ${SEL_MODE:-none}) — context check not applicable"
else
  # One guestfish session: `getxattrs` does NOT fail when the attribute is missing
  # (unlike `getxattr`), so all files can be checked at once.
  # Two classes, because the impact of a missing context differs DRASTICALLY:
  #  - CRITICAL — account databases. Without a context `unix_chkpwd` cannot read them
  #    in enforcing mode: measured on Rocky 10 (`unlabeled_t` AVC on /etc/passwd,
  #    emergency mode, CloudStack password rejected on the console).
  #  - LAYER — files brought in via `--copy-in`. They used to lack a context on EVERY
  #    SELinux distro without blocking boot (Rocky 8/9 passed tier3), so it was only a
  #    warning. Now common/finalize.sh assigns contexts with `setfiles` at build time —
  #    a missing context means that step did not work, and it is a FAIL (the message
  #    distinguishes the classes).
  SEL_CRIT="/etc/passwd /etc/shadow /etc/group"
  SEL_LAYER="/etc/fail2ban/jail.local /usr/local/sbin/csf-inspect \
/usr/local/sbin/csf-firstboot /usr/local/sbin/csf-watchdog /etc/systemd/system/csf-firstboot.service \
/etc/systemd/system/csf-inspect.service /etc/systemd/system/csf-watchdog.service \
/etc/cloud/cloud.cfg.d/99-csf-cloudstack.cfg"
  SEL_FILES="$SEL_CRIT $SEL_LAYER"
  # NOTE: no explicit `run` — guestfish with `-i` launches the appliance itself, and a
  # second `run` ends with "this function can only be called in the config state"
  # and the WHOLE check would stay silent with "did not read any file".
  # NOTE: the `- ` prefix on getxattrs is mandatory: guestfish without a terminal stops
  # at the FIRST error, and getxattrs on a missing file is an error — without the prefix
  # the check stopped there and nobody checked the remaining files (with jail.local
  # missing, the section printed OK for the layer without checking a single file).
  {
    for p in $SEL_FILES; do
      printf 'echo ###FILE %s\n' "$p"
      printf -- '- getxattrs %s\n' "$p"
    done
  } > "$T/sel.gf"
  # guestfish output goes to a FILE, not through substitution into Python code —
  # otherwise a quote or backslash in a name/context would break the script.
  guestfish --ro -a "$IMG" -i < "$T/sel.gf" > "$T/sel.out" 2>&1 || true
  SEL_RESULT="$(python3 - "$T/sel.out" "$SEL_CRIT" "$SEL_FILES" <<'PYSEL'
import sys

critical = set(sys.argv[2].split())
expected = sys.argv[3].split()
current, has_sel = None, False
missing_ctx, absent, seen = [], [], set()


def close():
    if current is not None and not has_sel:
        missing_ctx.append(current)


for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    if line.startswith("###FILE "):
        close()
        current, has_sel = line.split(None, 1)[1].strip(), False
        seen.add(current)
    elif "security.selinux" in line:
        has_sel = True
    elif "No such file" in line and current:
        # A missing layer file is reported as FAIL by the ownership check (LAYER dict),
        # a missing account database by the parser below. Here it does not count as
        # "without context".
        absent.append(current)
        current, has_sel = None, False
close()

# Completeness: every expected file must have a marker. Without this, a session cut
# short (e.g. a crashed helper appliance) left unreached files outside `missing_ctx`
# and the check printed OK for something it never checked.
unreached = [p for p in expected if p not in seen]
crit_absent = sorted(p for p in absent if p in critical)
crit_unreached = sorted(p for p in unreached if p in critical)
crit_missing = [b for b in missing_ctx if b in critical]
layer_missing = [b for b in missing_ctx if b not in critical]

if not seen:
    print("FAIL guestfish did not read any file — contexts cannot be checked")
else:
    if unreached:
        print("FAIL context check incomplete — guestfish did not reach: "
              + ", ".join(unreached))
    if crit_absent:
        print("FAIL account databases missing in the image: " + ", ".join(crit_absent))
    if crit_missing:
        print("FAIL account databases WITHOUT an SELinux context (unlabeled_t — login "
              "and sshd fail in enforcing mode): " + ", ".join(crit_missing))
    elif not crit_absent and not crit_unreached:
        print(f"OK account databases have an SELinux context ({', '.join(sorted(critical))})")
    if layer_missing:
        print("FAIL layer files without an SELinux context — the `setfiles` step "
              f"in common/finalize.sh did not work: {', '.join(layer_missing)}")
    elif not [p for p in unreached if p not in critical]:
        print("OK layer files have an SELinux context")
PYSEL
)"
  verdict <<<"$SEL_RESULT"
fi

echo "fail2ban / agent:"
# The effective ignoreip of the sshd jail ([sshd] overrides [DEFAULT]) must contain
# CloudStack's link-local range 169.254.0.0/16 (VR password/metadata server);
# operator networks are configurable (CSF_FAIL2BAN_IGNOREIP) and not checked here.
F2B_VERDICT="$(python3 - "$T/jail.local" <<'PYF2B' 2>&1
import configparser, sys
c = configparser.ConfigParser(interpolation=None, strict=False)
try:
    with open(sys.argv[1], errors="replace") as f:
        c.read_file(f)
except (OSError, configparser.Error) as e:
    print(f"FAIL /etc/fail2ban/jail.local missing or unparsable ({e})")
    sys.exit(0)
if not c.has_section("sshd"):
    print("FAIL fail2ban: no [sshd] jail")
    sys.exit(0)
if c.get("sshd", "enabled", fallback="false").strip().lower() in ("true", "yes", "1", "on"):
    print("OK fail2ban: sshd jail enabled")
else:
    print("FAIL fail2ban: sshd jail NOT enabled")
ignoreip = c.get("sshd", "ignoreip", fallback="").split()
if "169.254.0.0/16" in ignoreip:
    print("OK fail2ban ignoreip contains CloudStack link-local 169.254.0.0/16 ("
          + " ".join(ignoreip)[:120] + ")")
else:
    print("FAIL fail2ban ignoreip does not contain 169.254.0.0/16 (CloudStack link-local): "
          + (" ".join(ignoreip) or "missing"))
PYF2B
)" || F2B_VERDICT="${F2B_VERDICT}"$'\n''FAIL fail2ban check crashed'
verdict <<<"$F2B_VERDICT"
[ -s "$T/csf-inspect" ] && ok "csf-inspect present" || no "csf-inspect missing"

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$fail"

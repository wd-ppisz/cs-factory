#!/usr/bin/env bash
# cs-factory — builds a standardised CloudStack/KVM template from an upstream cloud image.
# Offline (virt-customize), no boot. Name: "Template <Distro> <Ver> v<X.Y>".
#
# Requires: libguestfs-tools (virt-customize, virt-sysprep), qemu-img, yq, curl.
# Usage:    ./build.sh debian-13 1.1
#
# Optional environment:
#   CSF_DISK_SIZE            grow the disk beyond the manifest size (never shrinks it)
#   CSF_IMAGE_CACHE          persistent cache directory for upstream source images
#   CSF_IMAGE_MAX_AGE_DAYS   re-download cached source images older than this (default 90)
#   CSF_FAIL2BAN_IGNOREIP    replaces the `ignoreip` line of common/fail2ban/jail.local
#   CSF_TEMPLATE_PREFIX      template name prefix (default "Template"; empty = no prefix)
#   CSF_LOCAL_DISTROS        extra directory with manifests (added from the GUI)
#                            (space-separated addresses/CIDRs, e.g. your admin networks)
set -euo pipefail
# Without this trap an abort via `set -e` is SILENT, and a silent failure cannot be
# diagnosed from the GUI or a CI trace (a failed guestfish call once killed every
# build with no output at all, because its stderr went to /dev/null). The trap turns
# every such exit into a concrete line.
# Handler as a FUNCTION, not an inline body: shellcheck does not see assignments
# inside a trap string and reports SC2154, and `make lint` is a gate. Inside a
# function the failing line number is in ${BASH_LINENO[0]} ($LINENO would point
# into the handler).
# Deliberately WITHOUT `set -E`: with errtrace the trap fires both in the command
# substitution subshell AND in the parent shell, so the message is printed twice
# with two different line numbers. Without it we get one entry pointing at the
# line that actually aborted the script.
_on_err() {
  local rc=$?
  echo "!! build.sh aborted — line ${BASH_LINENO[0]}, exit code $rc" >&2
  exit "$rc"
}
trap _on_err ERR
HERE="$(cd "$(dirname "$0")" && pwd)"

DISTRO="${1:?usage: build.sh <distro> [version]   e.g. build.sh debian-13 1.1}"
VERSION="${2:-1.0}"
case "$DISTRO" in
  ""|.*|*[!a-z0-9._-]*) echo "invalid distribution name: '$DISTRO'" >&2; exit 1 ;;
esac
# Shipped manifests first; then the directory of manifests added from the GUI in
# standalone mode (CSF_LOCAL_DISTROS) - a local file never shadows a shipped one.
M="$HERE/distros/${DISTRO}.yaml"
if [ ! -f "$M" ] && [ -n "${CSF_LOCAL_DISTROS:-}" ]; then
  M="$CSF_LOCAL_DISTROS/${DISTRO}.yaml"
fi
[ -f "$M" ] || { echo "manifest not found: $DISTRO"; exit 1; }

y() { yq -r "$1" "$M"; }
NAME="$(y '.name')"
URL="$(y '.url')"
SHA256="$(y '.sha256 // ""')"
SHA512="$(y '.sha512 // ""')"
SUMS_URL="$(y '.sums_url // ""')"
EPEL="$(y '.epel // false')"
# Growing the root partition AT BUILD TIME — OFF by default, enabled explicitly in
# the manifest with `grow_root_at_build: true`. Needed by openSUSE Leap Minimal-VM
# (no room for packages) and Ubuntu 22.04 (a 2.0 GiB root cannot hold the
# uncompressed linux-modules-extra with the watchdog driver). Rocky 10 broke on it:
# after growing XFS the initramfs could not find root by UUID and the machine
# dropped into emergency mode ("dracut-initqueue: timeout ... Could not boot").
GROW_ROOT="$(y '.grow_root_at_build // false')"
# `[Network] UseDomains=true` for systemd-networkd — only where the manifest asks
# for it (rationale next to the key in distros/debian-13.yaml).
USE_DOMAINS="$(y '.networkd_use_domains // false')"
# Detect the CloudStack datasource only after the network is up — only where the
# manifest asks for it (rationale next to the key in distros/ubuntu-22.04.yaml and in
# common/bin/cloudcfg-tune.py). Without it, in a VPC with a redundant VR the password
# request goes to the address of ONE router from the DHCP lease, while the password
# server listens on the VIP only.
DS_NETWORK="$(y '.cloudstack_datasource_network // false')"
# Explicit DHCP client list for cloud-init — the OPPOSITE logic to DS_NETWORK: clients
# PRESENT in the image (rationale next to the key in distros/opensuse-leap.yaml). A listed
# client missing from the image fails the build in cloudcfg-tune.py, because such an
# image would not get through the init stage.
DHCP_PRIO="$(y '(.cloudinit_dhcp_client_priority // []) | join(",")')"
case "$DHCP_PRIO" in
  *[!a-z,]*) echo "!! cloudinit_dhcp_client_priority: invalid characters in '$DHCP_PRIO' ($M)" >&2; exit 1 ;;
esac
if [ -n "$DHCP_PRIO" ] && [ "$DS_NETWORK" = "true" ]; then
  echo "!! cloudinit_dhcp_client_priority (clients present) and cloudstack_datasource_network" >&2
  echo "   (clients absent) are mutually exclusive — fix $M" >&2
  exit 1
fi
# Packages already present in the source image that must be UPGRADED from the
# repository — `install` leaves them at the image version (rationale next to the key
# in distros/rocky-10.yaml).
UPGRADE="$(y '(.upgrade_packages // []) | join(" ")')"
case "$UPGRADE" in
  *[!a-z0-9\ .+_-]*) echo "!! upgrade_packages: invalid characters in '$UPGRADE' ($M)" >&2; exit 1 ;;
esac
# fail2ban allowlist override — validated here, because it ends up in a guest command.
F2B_IGNOREIP="${CSF_FAIL2BAN_IGNOREIP:-}"
case "$F2B_IGNOREIP" in
  *[!0-9A-Fa-f.:/\ ]*) echo "!! CSF_FAIL2BAN_IGNOREIP: invalid characters in '$F2B_IGNOREIP'" >&2; exit 1 ;;
esac
DISK="$(y '.disk_size // "10G"')"
# Minimum 10G for EVERY template: with a smaller disk a careless deploy runs out of
# space during the user's first operations — the problem then looks like a system
# fault while it is a configuration one.
# The manifest is never edited silently: we raise the size and say so loudly
# (CI lint rejects a manifest below 10G anyway).
MIN_DISK_G=10
to_g() {
  case "$1" in
    *G) echo "${1%G}" ;;
    *M) echo $(( ${1%M} / 1024 )) ;;
    *)  echo 0 ;;
  esac
}
MANIFEST_DISK="$DISK"
MANIFEST_G="$(to_g "$MANIFEST_DISK")"
# Size override from outside the manifest (the "disk size" field in the GUI or a
# one-off CLI build). The parameter can only GROW the disk.
if [ -n "${CSF_DISK_SIZE:-}" ] && [ "$CSF_DISK_SIZE" != "$DISK" ]; then
  echo ">> disk size from parameter: $CSF_DISK_SIZE (manifest says: $MANIFEST_DISK)"
  DISK="$CSF_DISK_SIZE"
fi
DISK_G="$(to_g "$DISK")"
[ "$DISK_G" -gt 0 ] || echo "!! unknown disk size format '$DISK'"
# Floor = the larger of: the global minimum and the size FROM THE MANIFEST. The 10G
# threshold alone is not enough: a distribution may need more (e.g. a 20G manifest),
# and the GUI parameter would then silently SHRINK the disk below what that
# distribution declares as its requirement.
FLOOR_G="$MIN_DISK_G"
[ "$MANIFEST_G" -gt "$FLOOR_G" ] && FLOOR_G="$MANIFEST_G"
if [ "$DISK_G" -lt "$FLOOR_G" ]; then
  echo "!! size $DISK below the required ${FLOOR_G}G (minimum ${MIN_DISK_G}G, manifest ${MANIFEST_DISK}) — raising to ${FLOOR_G}G"
  DISK="${FLOOR_G}G"
  DISK_G="$FLOOR_G"
fi
PKGS="$(yq -r '.packages | join(" ")' "$M")"

# Name prefix is a site choice ("Template Debian 13 v1.2" by default).
PREFIX="${CSF_TEMPLATE_PREFIX-Template}"
case "$PREFIX" in *[!A-Za-z0-9\ ._-]*) echo "!! CSF_TEMPLATE_PREFIX: invalid characters in '$PREFIX'" >&2; exit 1 ;; esac
TEMPLATE_NAME="${PREFIX:+$PREFIX }${NAME} v${VERSION}"
SLUG="$(echo "$TEMPLATE_NAME" | tr ' .' '-_' | tr '[:upper:]' '[:lower:]')"

OUT="$HERE/build"; mkdir -p "$OUT"
# Cache of SOURCE images kept apart from the working directory. A GitLab shell
# executor runs `git clean -ffdx` between jobs and wipes `build/` together with the
# downloaded images — every CI run pulled them again (a ~2 GB Rocky 8 image over a
# slow mirror took most of the job time limit and got the build killed halfway).
# Defaults to `build/` (local dev loop); CI points CSF_IMAGE_CACHE at a persistent path.
CACHE="${CSF_IMAGE_CACHE:-$OUT}"; mkdir -p "$CACHE"
RAW="$CACHE/${DISTRO}.orig.qcow2"
IMG="$OUT/${SLUG}.qcow2"

echo ">> building: $TEMPLATE_NAME"

# Freshness policy: manifests point at the current/latest variant, and a downloaded
# image is refreshed once it is older than CSF_IMAGE_MAX_AGE_DAYS (default 90).
# Integrity: sums_url = the upstream checksum file next to the image (verified AFTER
# EVERY download); pinned sha256/sha512 in the manifest are still supported and take
# precedence (reproducible builds).
MAXAGE="${CSF_IMAGE_MAX_AGE_DAYS:-90}"
if [ -f "$RAW" ] && [ -n "$(find "$RAW" -mtime +"$MAXAGE" -print 2>/dev/null)" ]; then
  echo ">> source image older than ${MAXAGE} days — refreshing from upstream"
  rm -f "$RAW"
fi
# Integrity check as a FUNCTION — it is called twice: once on whatever sits in the
# cache, and again after a download.
verify_checksum() {
  if [ -n "$SHA256" ] && [ "$SHA256" != "null" ]; then
    echo "$SHA256  $RAW" | sha256sum -c - >/dev/null 2>&1
  elif [ -n "$SHA512" ] && [ "$SHA512" != "null" ]; then
    # Debian publishes SHA512SUMS only — hence the sha512 variant in the manifest.
    echo "$SHA512  $RAW" | sha512sum -c - >/dev/null 2>&1
  elif [ -n "$SUMS_URL" ] && [ "$SUMS_URL" != "null" ]; then
    FN="$(basename "$URL")"
    # two checksum file formats: GNU coreutils ("hash  file" / "hash *file")
    # and BSD/Rocky (".CHECKSUM": "SHA256 (file) = hash")
    HASH="$(curl -fsSL --retry 3 "$SUMS_URL" | awk -v f="$FN" '
      ($1=="SHA256" || $1=="SHA512") && $2=="("f")" { print $NF; exit }
      { for (i=2; i<=NF; i++) if ($i==f || $i=="*"f) { print $1; exit } }')"
    case "${#HASH}" in
      64)  echo "$HASH  $RAW" | sha256sum -c - >/dev/null 2>&1 ;;
      128) echo "$HASH  $RAW" | sha512sum -c - >/dev/null 2>&1 ;;
      *)   echo "!! no entry for $FN in $SUMS_URL — aborting" >&2; return 2 ;;
    esac
  else
    echo "!! no sha256/sha512/sums_url in the manifest — SKIPPING verification (fix $M)"
    return 0
  fi
}

# Cache vs the "current" policy: upstream replaces the image under THE SAME URL, so a
# cached file may not match the current checksum file. That is not an error — it
# means a new version was published. A mismatch = download again and re-check; only a
# second failure is a real problem (corrupt download or broken checksum file upstream).
# Without this the build stopped with "computed checksum did NOT match" and needed a
# manual cache wipe.
if [ -f "$RAW" ] && ! verify_checksum; then
  echo ">> cached image checksum does not match upstream"
  echo "   (most likely a new version under the same URL) — downloading again"
  rm -f "$RAW"
fi
[ -f "$RAW" ] || curl -fL --retry 3 -o "$RAW" "$URL"
if ! verify_checksum; then
  echo "!! checksum MISMATCH even after a fresh download — aborting." >&2
  echo "   Check $SUMS_URL and the integrity of $URL." >&2
  exit 1
fi
echo ">> source image integrity confirmed"

# Inspect the image before going further: confirms the file is a complete,
# recognisable OS (not a truncated download) and yields the root partition for the
# log. Partitions are NOT resized here — see below.
#
# `run :` before `inspect-os` is MANDATORY — without a launched appliance guestfish
# fails with "call launch before using this function" (rc=1). A version without
# `run` killed every build, silently: the error went to /dev/null and `set -e`
# aborted on the command substitution, so the message below never got a chance to
# print. Hence stderr now goes to a file and is shown, and the condition checks the
# exit code and emptiness SEPARATELY.
INSPECT_ERR="$OUT/${DISTRO}.inspect-os.err"
if ! ROOTPART="$(guestfish --ro -a "$RAW" run : inspect-os 2>"$INSPECT_ERR" | head -1 | tr -d '\r')" \
   || [ -z "$ROOTPART" ]; then
  echo "!! root partition not detected (guestfish inspect-os) in $RAW" >&2
  sed 's/^/   guestfish: /' "$INSPECT_ERR" >&2
  rm -f "$INSPECT_ERR"
  exit 1
fi
rm -f "$INSPECT_ERR"

# Target size = the larger of: required size and source size (a disk cannot be
# shrunk). The old +1 GiB headroom was needed ONLY by virt-resize, which refused to
# work without free space.
SRC_BYTES="$(qemu-img info --output=json "$RAW" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["virtual-size"])')"
TARGET_G="$(python3 -c "
import math
src=$SRC_BYTES; g=1024**3
print(max($DISK_G, math.ceil(src/g)))")"

# PARTITIONS ARE NOT TOUCHED. Only the disk is grown — the root partition and
# filesystem are grown by cloud-init on first boot (`growpart` + `resizefs`, forced
# explicitly in common/cloud/99-csf-cloudstack.cfg).
#
# Why not `virt-resize`: it copies partitions in OFFSET order and RENUMBERS them on
# the way. Ubuntu images (and Rocky 10 and openSUSE) keep root as p1, `bios_grub` as
# p14, the ESP as p15, `/boot` as p16 — after renumbering (14→1, 15→2, 16→3, 1→4)
# GRUB's `core.img` still says its config lives on gpt16, a partition that no longer
# exists. Result: a complete image, a green offline gate, a correctly grown root
# and… NO BOOT: "error: no such partition / grub rescue>". Seen on 5 of 9
# distributions, confirmed on the CloudStack console AND under local QEMU.
#
# Plain `qemu-img resize` does not touch the partition table, so the bootloader is
# left intact regardless of image layout.
echo ">> growing disk: source $((SRC_BYTES / 1073741824)) GiB -> ${TARGET_G}G"
echo "   (partitions and filesystem will be grown by cloud-init on first boot)"
rm -f "$IMG"
cp --reflink=auto "$RAW" "$IMG"
qemu-img resize "$IMG" "${TARGET_G}G" >/dev/null

# Attempt to grow the root partition IN PLACE — BEST EFFORT, never fails the build.
#
# Why: cloud-init grows root on first boot, so a RUNNING machine does not need it.
# But packages are installed NOW, into a filesystem of the source size, and openSUSE
# Leap Minimal-VM has no room for them ("installing package python313-base needs
# 22MB more space on the / filesystem").
#
# Why `part-resize` and not `virt-resize`: the latter COPIES partitions and RENUMBERS
# them (14→1, 15→2, 16→3, 1→4), so GRUB loses its config ("error: no such
# partition"). `part-resize` changes only the SIZE of the last partition; numbers and
# contents of the others stay.
#
# Why BEST EFFORT: parted refuses on some images ("Not all of the space available ...
# Unable to satisfy all constraints" — it asks an interactive question and fails in
# batch mode). Treating that as fatal broke both Debians, which worked fine. A parted
# refusal only costs build-time headroom, so we say so loudly and carry on.
#
# Pitfalls (both observed): guestfish commands must go via STDIN, because in argv
# `-1` is parsed as an OPTION; and the `-1` sentinel (end of disk) does not work
# anyway — we pass an EXPLICIT end sector, leaving 34 sectors for the backup GPT header.
ROOTNUM="${ROOTPART##*[a-z]}"
LAST_NUM="$(guestfish --ro -a "$IMG" run : part-list /dev/sda 2>/dev/null | python3 -c "
import re, sys
t = sys.stdin.read()
n = re.findall(r'part_num:[^0-9]*([0-9]+)', t)
e = re.findall(r'part_end:[^0-9]*([0-9]+)', t)
print(max(zip(map(int, n), map(int, e)), key=lambda x: x[1])[0] if n else 0)")"

if [ "$GROW_ROOT" != "true" ]; then
  echo ">> not growing partitions at build time (grow_root_at_build != true)"
  echo "   root will grow on first boot via growpart"
elif [ "$ROOTNUM" != "$LAST_NUM" ]; then
  echo ">> root ($ROOTPART) is not the last partition — keeping the source size"
  echo "   (root will grow on first boot; the build has less room for packages)"
else
  guestfish -a "$IMG" <<'GF' >/dev/null 2>&1 || true
run
part-expand-gpt /dev/sda
GF
  DISK_SECT="$(guestfish --ro -a "$IMG" run : blockdev-getsz /dev/sda 2>/dev/null | tr -d '\r')"
  END_SECT=$(( DISK_SECT - 34 ))
  if guestfish -a "$IMG" <<GF >/dev/null 2>&1
run
part-resize /dev/sda $ROOTNUM $END_SECT
GF
  then
    VFS="$(guestfish --ro -a "$IMG" run : vfs-type "$ROOTPART" 2>/dev/null | tr -d '\r')"
    case "$VFS" in
      ext2|ext3|ext4) guestfish -a "$IMG" run : resize2fs "$ROOTPART" >/dev/null 2>&1 || true ;;
      xfs)            guestfish -a "$IMG" run : mount "$ROOTPART" / : xfs-growfs / >/dev/null 2>&1 || true ;;
      btrfs)          guestfish -a "$IMG" run : mount "$ROOTPART" / : btrfs-filesystem-resize / >/dev/null 2>&1 || true ;;
    esac
    echo ">> root partition ($ROOTPART, $VFS) grown in place; numbering UNTOUCHED"
  else
    echo ">> parted refused to grow the partition — continuing with the source size"
    echo "   (this is NOT an error: root will grow on first boot via growpart)"
  fi
fi

# Package installation MUST be a single virt-customize operation together with the
# network setup, because (diagnosed live, guestfs-tools 1.52):
#  1) the appliance does not bring eth0 up (DOWN, no address) — libguestfs SLIRP is
#     net=169.254.2.15/16 (guest .2.15, gw .2.2, DNS .2.3), so we configure it statically;
#  2) the libguestfs daemon swaps/restores /etc/resolv.conf in the guest chroot per
#     operation — a file written in one operation does NOT exist in the next, so a
#     separate "--run-command netsetup" + "--install" cannot work.
# Hence instead of --install: our own distro-aware installer in one run-command
# (same apt/dnf/zypper pattern as csf-firstboot; EPEL added for RHEL).
NETSETUP='ip link set eth0 up 2>/dev/null || true; ip addr replace 169.254.2.15/16 dev eth0 2>/dev/null || true; ip route replace default via 169.254.2.2 2>/dev/null || true; rm -f /etc/resolv.conf; echo "nameserver 169.254.2.3" > /etc/resolv.conf'
# EPEL on a SEPARATE line (reason below, at INSTALLCMD): the old
# `epel-release && dnf install` under `set -e` silently skipped the package
# installation when EPEL itself failed.
EPELCMD=''; [ "$EPEL" = "true" ] && EPELCMD=$'dnf -y install epel-release\n  '
# upgrade_packages from the manifest — per family, each on its own line. A package
# not in the image: dnf fails (the build fails loudly), apt/zypper only report it.
UPG_APT=''; UPG_DNF=''; UPG_ZYP=''
if [ -n "$UPGRADE" ]; then
  UPG_APT="apt-get -q -y -o Dpkg::Options::=--force-confnew install --only-upgrade $UPGRADE"
  UPG_DNF="dnf -y upgrade $UPGRADE"
  UPG_ZYP="zypper -n update -y $UPGRADE"
fi
# The security auto-update mechanism (unattended-upgrades / dnf-automatic / os-update)
# is added HERE, per package manager family, not in the manifests: it is a common
# layer like QGA and fail2ban, so a distribution added from the GUI cannot omit it.
# finalize.sh configures it, validate-offline.sh checks the result.
# `wget` is likewise part of the common layer, not a manifest choice: cloud-init's
# password server client (DataSourceCloudStack.CloudStackPasswordServerClient,
# every version 23.4–25.3) calls an EXTERNAL `wget` on <VR>:8080. An image without
# wget never receives the password from deploy/reset/reinstall — even with a correct
# data-server. GenericCloud Rocky 8/9 images ship without wget ("Failed to fetch
# password", /etc/shadow unchanged); Debian and Ubuntu have it upstream.
# The `i6300esb` watchdog driver is also a common layer, not a manifest item: its
# package name depends on the KERNEL ABI IN THE IMAGE, which the manifest does not
# know. Ubuntu cloud images pull `linux-image-virtual` -> `linux-modules-<ABI>`, while
# the driver lives in `linux-modules-extra-<ABI>-generic` (jammy and noble; in
# resolute/26.04 it moved back into `linux-modules`). Without it Ubuntu 22.04/24.04
# had no i6300esb.ko AT ALL — empty `lsmod`, no /dev/watchdog0, and still
# RuntimeWatchdogUSec=30s: a layer that looks green and guards nothing (the same
# class of defect as Debian 12's `cloud` kernel, see distros/debian-12.yaml).
# There is no firmware-free meta package: the only one pulling the extra modules is
# `linux-image-generic`, which requires `linux-firmware` — +624 MB (noble) /
# +1089 MB (jammy). So we install the VERSIONED package (+107 MB), only when the file
# is actually missing, and only for kernels present in the image. The autoload
# blacklist (a second, independent cause) is handled by
# common/systemd/csf-watchdog.service.
# A failure of this installation FAILS the build at this step. With `|| echo` a dpkg
# "No space left on device" left a broken package in the image and the build went on
# for ~10 more minutes, failing only at the gate, which sees the EFFECT, not the
# cause (virt-customize does not forward command output to the log). Typical cause:
# an image root that is too small — manifest flag `grow_root_at_build: true` (see
# distros/ubuntu-22.04.yaml).
# The package is VERSIONED, so after a kernel ABI bump on the instance
# (unattended-upgrades / csf-firstboot) the new one will not arrive by itself. Hence
# a second line of defence at runtime: /usr/local/sbin/csf-watchdog pulls
# `linux-modules-extra-$(uname -r)` when the module for the running kernel is missing
# at boot — otherwise the fix would silently expire with the first kernel update.
# Every package manager step on a SEPARATE LINE, never `update && install`.
# `set -e` IGNORES the failure of everything but the last element of an AND-OR list
# (POSIX), so a failed `apt-get update` did not fail the step — the install did not
# run and the build continued, until the offline gate caught an image without
# `wget`/QGA/fail2ban. `sh -c 'set -e; if true; then false && echo x; …; fi; rm -f …'`
# exits rc=0; split into separate lines it exits rc=1.
INSTALLCMD='if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -q -y update
  apt-get -q -y -o Dpkg::Options::=--force-confnew install '"$PKGS"' unattended-upgrades wget
  '"$UPG_APT"'
  for KDIR in /lib/modules/*/; do
    [ -d "$KDIR" ] || continue
    KVER="$(basename "$KDIR")"
    if ls "$KDIR"kernel/drivers/watchdog/i6300esb.ko* >/dev/null 2>&1; then continue; fi
    if grep -q i6300esb "$KDIR"modules.builtin 2>/dev/null; then continue; fi
    echo ">> kernel $KVER has no i6300esb driver — installing linux-modules-extra-$KVER"
    if ! apt-get -q -y install "linux-modules-extra-$KVER"; then
      echo "!! linux-modules-extra-$KVER NOT installed — most often no space on the image root (grow_root_at_build)" >&2
      df -h / >&2
      exit 1
    fi
  done
elif command -v dnf >/dev/null 2>&1; then
  '"$EPELCMD"'dnf -y install '"$PKGS"' dnf-automatic wget
  '"$UPG_DNF"'
elif command -v zypper >/dev/null 2>&1; then
  zypper -n --gpg-auto-import-keys refresh
  zypper -n install -y '"$PKGS"' os-update wget
  '"$UPG_ZYP"'
else
  echo "no known package manager" >&2; exit 1
fi
rm -f /etc/resolv.conf'

VC=( virt-customize -a "$IMG" --smp 2 --memsize 2048 )
# set -e: a package manager failure MUST fail the build at this step (zypper once
# failed silently and the build only broke later on --copy-in into a non-existent
# /etc/fail2ban)
VC+=( --run-command "set -e; $NETSETUP; $INSTALLCMD" )
VC+=( --mkdir /var/lib/csf --mkdir /etc/systemd/system.conf.d )

# Common layer files: SOURCE:DIRECTORY-IN-IMAGE:MODE. This table is the ONLY way a
# repo file enters the image — and each one gets an EXPLICIT root:root owner and mode.
# Reason: `--copy-in` (tar underneath) carries the uid/gid and mode of the BUILD
# MACHINE into the image. Built artifacts had files owned by the CI runner's uid/gid
# (an account that does NOT exist in the image) with mode 664 from the checkout
# umask — including systemd units and scripts run as root. That group could write
# root's code, and the first system group created on the instance (e.g. by a package
# install) would get exactly that gid. `--chmod` alone fixed the mode, not the owner.
# The validate-offline.sh gate checks the effect.
LAYER=(
  "common/cloud/99-csf-cloudstack.cfg:/etc/cloud/cloud.cfg.d:0644"
  "common/fail2ban/jail.local:/etc/fail2ban:0644"
  "common/bin/csf-inspect:/usr/local/sbin:0755"
  "common/bin/csf-firstboot:/usr/local/sbin:0755"
  "common/bin/csf-watchdog:/usr/local/sbin:0755"
  # one-shot, removed by finalize.sh after use
  "common/bin/cloudcfg-tune.py:/root:0700"
  "common/systemd/csf-firstboot.service:/etc/systemd/system:0644"
  "common/systemd/csf-inspect.service:/etc/systemd/system:0644"
  "common/systemd/10-csf-watchdog.conf:/etc/systemd/system.conf.d:0644"
  "common/systemd/csf-watchdog.service:/etc/systemd/system:0644"
)
if [ "$USE_DOMAINS" = "true" ]; then
  # The file name is FIXED: machines deployed from older templates can be fixed by
  # hand with the very same file — image and instance stay identical.
  VC+=( --mkdir /etc/systemd/networkd.conf.d )
  LAYER+=( "common/systemd/50-csf-cloudstack-data-server.conf:/etc/systemd/networkd.conf.d:0644" )
fi
for w in "${LAYER[@]}"; do
  IFS=: read -r src dir mode <<<"$w"
  dst="$dir/$(basename "$src")"
  # virt-customize runs operations in command-line order.
  # chown/chmod IN THE GUEST, not `--chown`: in guestfs-tools 1.52.0 (Ubuntu 24.04)
  # the `--chown` parser rejects EVERY argument ("invalid format"); it works only
  # from 1.52.3. The build must not depend on that difference.
  VC+=( --copy-in "$HERE/$src:$dir" --run-command "chown 0:0 '$dst' && chmod $mode '$dst'" )
done
if [ -n "$F2B_IGNOREIP" ]; then
  # Site-specific fail2ban allowlist (e.g. admin/bastion networks) replaces the
  # generic default from common/fail2ban/jail.local. Characters were checked above.
  VC+=( --run-command "sed -i 's|^ignoreip[[:space:]]*=.*|ignoreip = $F2B_IGNOREIP|' /etc/fail2ban/jail.local" )
fi
if [ "$DS_NETWORK" = "true" ]; then
  # Marker for finalize.sh: virt-customize --run passes no arguments or environment
  # to the script, so the manifest flag is passed as a file. finalize.sh removes it
  # itself — no trace of the marker is left in the final image.
  VC+=( --run-command 'touch /root/csf-datasource-network' )
fi
if [ -n "$DHCP_PRIO" ]; then
  # Same marker pattern; content = the list from the manifest (characters checked above).
  VC+=( --run-command "printf '%s\n' '$DHCP_PRIO' > /root/csf-dhcp-client-priority" )
fi
VC+=( --run "$HERE/common/finalize.sh" )
"${VC[@]}"

echo ">> sysprep"
virt-sysprep -a "$IMG" \
  --operations defaults,-ssh-hostkeys,-ssh-userdir \
  --run-command 'cloud-init clean --logs --seed 2>/dev/null || true'

FINAL="$OUT/${SLUG}.qcow2"
qemu-img convert -c -O qcow2 "$IMG" "${FINAL}.tmp" && mv "${FINAL}.tmp" "$FINAL"

# DISTRO in .env: the file slug cannot be mapped back to the manifest name (e.g.
# "openSUSE Leap 16.0" -> template-opensuse-leap-16_0-...), and the GUI needs the
# manifest to read cs_ostype when registering the template in CloudStack.
printf 'TEMPLATE_NAME=%s\nIMG=%s\nDISTRO=%s\nVERSION=%s\n' \
  "$TEMPLATE_NAME" "$FINAL" "$DISTRO" "$VERSION" > "$OUT/${SLUG}.env"
echo ">> done:          $FINAL"
echo ">> template name: $TEMPLATE_NAME"
echo ">> validation:    $HERE/e2e/validate-offline.sh $FINAL"

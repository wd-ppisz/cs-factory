#!/bin/sh
# Runs INSIDE the guest via virt-customize --run. Distro-aware, no sed on cloud.cfg.
# POSIX sh (not bash!): on Ubuntu 24.04 the script runs under dash (guest /bin/sh;
# "set: Illegal option -o pipefail" — Debian did not mind, Ubuntu did). No pipes in
# the script => pipefail is unnecessary.
set -eu

# --- qemu-guest-agent: no access to the tenant's system ---------------------------
# Boundary: the agent serves the platform (fsfreeze for snapshots/backup, ping,
# shutdown, metadata), it is NOT a way into the machine. We block everything that
# gives code execution, file access, login or insight into accounts:
#  * guest-exec*, guest-file-*        — command execution and file read/write,
#  * guest-ssh-*                      — add/remove/read authorized_keys,
#  * guest-set-user-password          — set a password for any account,
#  * guest-get-users                  — who is logged in (data from inside the system).
# guest-ssh-* and guest-set-user-password used to be allowed on purpose (a "service
# key"). Combined with `NOPASSWD:ALL` for the default user
# (/etc/sudoers.d/90-cloud-init-users) that gave anyone with hypervisor access root
# inside the tenant's machine without their knowledge — contrary to the principle
# that platform staff have no login to or access into the tenant's system. The
# effect is gated by smoke-boot (e2e/qga-probe.py): it calls each of these commands
# on a LIVE agent and requires the "has been disabled" refusal.
#
# Mechanism (verified in the package sources):
#  * Debian 13 / Ubuntu 24.04 / Leap 16: the systemd unit does NOT read /etc/default/
#    qemu-guest-agent (a sysvinit relic) nor sysconfig — the only universal way is the
#    qemu-ga config file: <confdir>/qemu-ga.conf ([general] block-rpcs=...), read by
#    default by qemu-ga (qga/main.c). Debian/Ubuntu/SUSE build with confdir=/etc/qemu.
#  * RHEL/Rocky: the unit reads /etc/sysconfig/qemu-ga, but THE VARIABLE DEPENDS ON
#    THE RELEASE. Rocky 9/10: `${FILTER_RPC_ARGS}` (default --allow-rpcs with the
#    vendor list, which LETS THROUGH guest-set-user-password and guest-get-users).
#    Rocky 8 (qemu-ga 6.2): `--blacklist=${BLACKLIST_RPC}` — there FILTER_RPC_ARGS is
#    DEAD. On a Rocky 8 artifact our FILTER_RPC_ARGS line sat in the file while the
#    agent took the vendor list from BLACKLIST_RPC, and the old gate (grep on the file)
#    was green. We set BOTH variables — the one the unit does not use is harmless.
BLOCK="guest-exec,guest-exec-status,guest-file-open,guest-file-read,guest-file-write,guest-file-close,guest-file-seek,guest-file-flush,guest-ssh-get-authorized-keys,guest-ssh-add-authorized-keys,guest-ssh-remove-authorized-keys,guest-set-user-password,guest-get-users"
install -d -m0755 /etc/qemu
# The KEY NAME depends on the agent version (qga/main.c): qemu-ga 6.2 (Ubuntu 22.04)
# knows ONLY `blacklist`, 7.2–8.2 `block-rpcs` (+ `blacklist` as a deprecated alias),
# 10.0 only `block-rpcs`. A live-agent probe in smoke-boot showed that on Ubuntu 22.04
# with `block-rpcs` ALL commands, guest-exec included, were executable — while the old
# gate (grep on the file) was green.
# The version is detected WITHOUT running the binary (virt-customize chroot): the
# string `block-rpcs` is in the binary since 7.2 (--help text), not in 6.2.
QGA_BIN=""
for b in /usr/sbin/qemu-ga /usr/bin/qemu-ga; do [ -f "$b" ] && QGA_BIN="$b" && break; done
QGA_KEY=block-rpcs
if [ -n "$QGA_BIN" ] && ! grep -aq 'block-rpcs' "$QGA_BIN"; then
  QGA_KEY=blacklist
  echo "finalize: qemu-ga without the block-rpcs key (<7.2) — block list under the blacklist key" >&2
fi
printf '[general]\n%s=%s\n' "$QGA_KEY" "$BLOCK" > /etc/qemu/qemu-ga.conf
if [ -f /etc/sysconfig/qemu-ga ]; then                      # RHEL / Rocky
  # Deterministically: delete ALL lines of both variables (the active one may have a
  # different form than a sed on ^FILTER_RPC_ARGS= assumed — that once left the
  # allowlist untouched) and append exactly one correct line each.
  sed -i "/FILTER_RPC_ARGS/d; /BLACKLIST_RPC/d" /etc/sysconfig/qemu-ga
  echo "BLACKLIST_RPC=${BLOCK}" >> /etc/sysconfig/qemu-ga
  echo "FILTER_RPC_ARGS=\"--block-rpcs=${BLOCK}\"" >> /etc/sysconfig/qemu-ga
fi
rm -f /etc/default/qemu-guest-agent   # dead under systemd — do not leave a misleading file

# --- cloud-init: safe tuning -----------------------------------------------------
# The marker is placed by build.sh when the manifest has
# `cloudstack_datasource_network: true` (Ubuntu 22.04: CloudStack password in a VPC
# with a redundant VR — rationale in cloudcfg-tune.py).
DS_ARGS=""
if [ -f /root/csf-datasource-network ]; then
  DS_ARGS="--datasource-network"
  rm -f /root/csf-datasource-network
fi
# Marker `cloudinit_dhcp_client_priority` (openSUSE Leap 16: client PRESENT in the
# image, rationale next to the key in distros/opensuse-leap.yaml). build.sh already
# rejects both markers at once, and cloudcfg-tune.py does so again — independently.
if [ -f /root/csf-dhcp-client-priority ]; then
  DS_ARGS="$DS_ARGS --dhcp-client-priority=$(cat /root/csf-dhcp-client-priority)"
  rm -f /root/csf-dhcp-client-priority
fi
# DS_ARGS deliberately UNQUOTED: when empty it must vanish, not become an empty argument.
# shellcheck disable=SC2086
python3 /root/cloudcfg-tune.py $DS_ARGS
rm -f /root/cloudcfg-tune.py

# --- automatic security updates: ENABLED ---------------------------------------------
# The template is a product for TENANT machines, not a fleet host. An earlier version
# shipped a fleet "no automatic updates" policy here (99-csf-no-auto-upgrades,
# debconf `false`, masked apt-daily*.timer); on a tenant VM `apt-config dump` then
# showed Update-Package-Lists "0", Unattended-Upgrade "0" — a system with NO patch
# path at all, since fleet patching does not cover tenant VMs. Templates therefore
# keep automatic updates ENABLED by default; fleet hosts should get their own update
# policy from configuration management, independent of the image.
#
# Each family uses its native mechanism; the package is added by build.sh (common
# layer, not a manifest choice — a manifest from the GUI cannot "forget" it):
#  * apt:    unattended-upgrades with the distribution's default origins,
#  * dnf:    dnf-automatic, upgrade_type = security, timer dnf-automatic-install,
#  * zypper: os-update, UPDATE_CMD=security.
# Hard boundary: no variant REBOOTS the machine by itself — a reboot after a kernel
# update stays the tenant's decision (their services, their window). Service restarts
# after library updates stay as the distribution ships them: package scripts always
# restart their daemons, and Ubuntu has needrestart in its default mode in the image.
# We do not disable that — an updated library in the memory of an old process patches
# nothing. Where WE add the mechanism (os-update), we pick the conservative variant.
#
# Deliberately WITHOUT `>/dev/null 2>&1`: stderr in /dev/null once cost days of
# broken builds. A failure must be visible in the log, and validate-offline.sh checks
# the EFFECT.
if command -v apt-get >/dev/null 2>&1; then
  # The source image does not have to be a clean upstream: the GUI wizard accepts any
  # qcow2 URL, including an older artifact of this factory. Such an image carries
  # 99-csf-no-auto-upgrades, which, being lexically last in apt.conf.d, overrides
  # 20auto-upgrades with zeros — enabling below would then achieve nothing.
  rm -f /etc/apt/apt.conf.d/99-csf-no-auto-upgrades
  echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' \
    | debconf-set-selections \
    || echo "finalize: WARNING — debconf-set-selections failed" >&2
  # 20auto-upgrades is NOT a dpkg conffile — the package postinst generates it via
  # ucf from the debconf answer. We switch it EXACTLY via its `true` branch
  # (/var/lib/dpkg/info/unattended-upgrades.postinst: ucf --three-way --debconf-ok
  # + ucfr), so the hash in /var/lib/ucf/hashfile matches the file. Not
  # `dpkg-reconfigure` (in the virt-customize chroot it can leave the package
  # half-configured) and not `cat > file` (a stale hash = a conflict on the next
  # package update). UCF_FORCE_CONFFNEW: a file locally changed to zeros (e.g. a
  # source image from an old artifact) must be switched too, not silently kept.
  UUE=/usr/share/unattended-upgrades/20auto-upgrades
  if [ -f "$UUE" ] && command -v ucf >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFNEW=1 ucf --three-way --debconf-ok \
      "$UUE" /etc/apt/apt.conf.d/20auto-upgrades \
      && ucfr unattended-upgrades /etc/apt/apt.conf.d/20auto-upgrades \
      || echo "finalize: WARNING — ucf did not enable 20auto-upgrades" >&2
  else
    echo "finalize: WARNING — $UUE or ucf missing (is unattended-upgrades installed?)" >&2
  fi
  # unmask in case the source image has masks; enable = symlink in timers.target.wants
  systemctl unmask apt-daily.timer apt-daily-upgrade.timer \
    && systemctl enable apt-daily.timer apt-daily-upgrade.timer \
    || echo "finalize: WARNING — apt timers were not enabled" >&2
elif command -v dnf >/dev/null 2>&1; then
  # automatic.conf has a single `upgrade_type = default` assignment in [commands]
  # (checked in Rocky 8/9/10 packages: dnf-automatic 4.7 / 4.14 / 4.20).
  # We replace only that line; the gate reads the file with an INI parser, not grep.
  # `reboot` stays at its default (`never`; dnf 4.7 has no such key and no reboot).
  # The dnf-automatic-install timer forces --installupdates regardless of apply_updates.
  AC=/etc/dnf/automatic.conf
  if [ -f "$AC" ]; then
    sed -i 's/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/' "$AC"
    grep -q '^upgrade_type = security$' "$AC" \
      || echo "finalize: WARNING — upgrade_type in $AC not set to security" >&2
  else
    echo "finalize: WARNING — $AC missing (is dnf-automatic installed?)" >&2
  fi
  systemctl enable dnf-automatic-install.timer \
    || echo "finalize: WARNING — dnf-automatic-install.timer was not enabled" >&2
elif command -v zypper >/dev/null 2>&1; then
  # os-update BY DEFAULT restarts services using old libraries (RESTART_SERVICES=yes)
  # and REBOOTS the machine BY ITSELF (REBOOT_CMD=auto → systemctl reboot) — checked
  # in /usr/libexec/os-update from the Leap 16.0 package. Unacceptable on a tenant
  # machine. /etc/os-update.conf overrides only the given variables (the script
  # sources /usr/share/os-update/os-update.conf and then this file).
  printf '%s\n' '# cs-factory: security updates only, no service restarts, no reboot' \
    'UPDATE_CMD="security"' 'REBOOT_CMD="none"' 'RESTART_SERVICES="no"' > /etc/os-update.conf
  systemctl enable os-update.timer \
    || echo "finalize: WARNING — os-update.timer was not enabled" >&2
fi

# --- BLS boot entries: remove traces of the helper appliance ----------------------
# When a kernel gets installed during the build (RHEL family, BLS layout),
# `kernel-install` creates a new boot entry and takes the kernel parameters from
# /proc/cmdline of the ENVIRONMENT it runs in — which is the libguestfs appliance,
# not the image being built. On a Rocky 10 artifact the entry got the appliance
# command line VERBATIM —
#   panic=1 edd=off udevtimeout=6000 cgroup_disable=memory usbcore.nousb
#   cryptomgr.notests root=UUID=<appliance root> selinux=0 guestfs_network=1
# Three separate kinds of damage, each silent:
#  1) root= points at a disk that does NOT exist in the image — the newer kernel wins
#     as the default, so GRUB boots exactly this entry, dracut waits forever
#     ("timeout, still waiting for /dev/disk/by-uuid/...") and the machine ends up
#     in emergency mode. The image is complete and the gate was green;
#  2) selinux=0 — a template with SELinux DISABLED, contrary to what we declare;
#  3) cgroup_disable=memory — broken memory accounting in cgroups.
# Hence we replace the WHOLE `options` line, not just root=: fixing only root would
# give a machine that boots and hide the other two kinds of damage.
# The reference is an entry consistent with /etc/fstab and free of the `guestfs_` marker.
if [ -d /boot/loader/entries ]; then
  FSTAB_ROOT="$(awk '$1 !~ /^#/ && $2 == "/" {print $1; exit}' /etc/fstab 2>/dev/null || true)"
  REF_OPTS=""
  for e in /boot/loader/entries/*.conf; do
    [ -f "$e" ] || continue
    grep -q 'guestfs_' "$e" && continue
    if [ -n "${FSTAB_ROOT:-}" ] && grep -qF "root=$FSTAB_ROOT" "$e"; then
      REF_OPTS="$(sed -n 's/^options //p' "$e" | head -1)"
      [ -n "$REF_OPTS" ] && break
    fi
  done
  for e in /boot/loader/entries/*.conf; do
    [ -f "$e" ] || continue
    grep -q 'guestfs_' "$e" || continue
    if [ -n "$REF_OPTS" ]; then
      sed -i "s|^options .*|options $REF_OPTS|" "$e"
      # To stderr, NOT stdout: virt-customize does not forward the script's stdout
      # to the CI log (not even "finalize: done" shows up). A fix without a trace
      # forces digging into the finished image to answer "did this even run".
      echo "finalize: fixed kernel parameters in entry $(basename "$e")" >&2
    else
      # Without a reference it is better to REMOVE the entry than to keep it: the
      # remaining entries are correct, so the machine boots the older kernel. Keeping
      # it would mean booting with a root that does not exist — emergency mode.
      rm -f "$e"
      echo "finalize: WARNING — removed entry $(basename "$e"), no reference to fix it from" >&2
    fi
  done
fi

# --- host keys must not ship in the template (sysprep repeats this) ---------------
rm -f /etc/ssh/ssh_host_*

install -d -m0755 /var/lib/csf

# --- services + manifest for the offline validator ---------------------------------
systemctl enable qemu-guest-agent fail2ban csf-inspect csf-firstboot csf-watchdog >/dev/null 2>&1 || true
printf '%s\n' qemu-guest-agent fail2ban csf-inspect csf-firstboot csf-watchdog > /var/lib/csf/enabled-services

# --- SELinux: file contexts assigned AT BUILD TIME ----------------------------------
# MUST be the last step that changes the filesystem. virt-customize works in an
# appliance with selinux=0: files from `--copy-in`, files of packages installed during
# the build and account databases rewritten by their scripts come out WITHOUT the
# `security.selinux` attribute. Rocky 10 ended up with no context on /etc/passwd,
# /etc/shadow and /etc/group — in enforcing mode that is `unlabeled_t`, `sulogin` with
# an AVC and emergency mode (the validate-offline.sh gate stopped the release).
# The layer files (csf-*, units, jail.local, 99-csf-cloudstack.cfg) had no context on
# EVERY distribution with SELinux.
# The `/.autorelabel` that virt-customize drops at the end is no safeguard here: it
# was present in all broken artifacts, and until the first (extra) reboot the machine
# runs with unlabeled files.
# Why `setfiles` and not `restorecon`: in a chroot without a loaded policy restorecon
# exits 0 and labels NOTHING; setfiles reads file_contexts straight from the file.
# The SELinux mode does not matter — correct labels are harmless when `disabled`, and
# spare the tenant a relabel if they enable SELinux. A failure fails the build: an
# image with half-assigned contexts must not leave the factory.
if [ -f /etc/selinux/config ]; then
  SEL_TYPE="$(sed -n '/^SELINUXTYPE=/{s/^SELINUXTYPE=//;s/[[:space:]#].*//;p;q;}' /etc/selinux/config)"
  SEL_FC="/etc/selinux/${SEL_TYPE:-targeted}/contexts/files/file_contexts"
  if [ -f "$SEL_FC" ] && command -v setfiles >/dev/null 2>&1; then
    # Exclusions: appliance pseudo-filesystems and the ESP (vfat has no xattrs).
    SEL_EXCL=""
    # `if`, not `[ … ] && …`: under `set -e` a failing last iteration of an AND-OR
    # list leaves the loop with exit code 1.
    for d in /proc /sys /dev /run /boot/efi; do
      if [ -d "$d" ]; then SEL_EXCL="$SEL_EXCL -e $d"; fi
    done
    # SEL_EXCL deliberately UNQUOTED: a list of "-e dir" pairs.
    # shellcheck disable=SC2086
    setfiles $SEL_EXCL "$SEL_FC" /
    echo "finalize: SELinux contexts assigned (setfiles, policy ${SEL_TYPE:-targeted})" >&2
  else
    echo "finalize: WARNING — /etc/selinux/config exists, but $SEL_FC or setfiles is missing; contexts NOT assigned" >&2
  fi
fi

echo "finalize: done"

#!/bin/sh
# Container entrypoint: prepares the work directories and checks the
# prerequisites that otherwise fail late and obscurely (in the middle of a build).
# Runs as the unprivileged `factory` user - it never changes ownership; it tells
# the operator what to fix instead.
set -eu

W=/srv/cs-factory/work
A=/srv/cs-factory/artifacts
fatal=0

for d in "$W" "$A"; do
  if ! touch "$d/.write-test" 2>/dev/null; then
    echo "!! $d is not writable by uid $(id -u) (factory)." >&2
    echo "   With bind mounts, create the host directory with that owner first, e.g.:" >&2
    echo "   sudo install -d -o 10001 -g 10001 <host-path>" >&2
    fatal=1
  else
    rm -f "$d/.write-test"
  fi
done
[ "$fatal" = 0 ] || exit 1

mkdir -p "$W/build/logs" "$W/distros" "$W/cache/guestfs" "$W/tmp" "$W/state"
chmod 0700 "$W/state"
# leftovers of an interrupted run (the build queue does not survive a restart)
find "$W/tmp" -mindepth 1 -maxdepth 1 -mmin +60 -exec rm -rf {} + 2>/dev/null || true
find "$A" -maxdepth 1 -name '.*.part' -exec rm -f {} + 2>/dev/null || true

if [ ! -e /dev/kvm ]; then
  echo "!! /dev/kvm is not available in the container - builds and boot tests will be" >&2
  echo "   extremely slow or time out. Pass the device (devices: [/dev/kvm]) and enable" >&2
  echo "   virtualization on the host." >&2
elif [ ! -w /dev/kvm ]; then
  echo "!! /dev/kvm exists but is not writable by uid $(id -u). Set KVM_GID in .env to" >&2
  echo "   the group of /dev/kvm on the host:  stat -c %g /dev/kvm" >&2
fi

if [ -z "${EXTERNAL_URL:-}" ]; then
  echo "!! EXTERNAL_URL is not set - the session cookie is marked Secure, so signing in" >&2
  echo "   over plain http (other than localhost) will not stick. Set it in .env." >&2
fi
if [ -z "${FLASK_SECRET:-}" ]; then
  echo "!! FLASK_SECRET is not set - sessions will not survive a restart." >&2
fi

echo "CloudStack Template Factory ${CSF_RELEASE:-dev} (${CSF_COMMIT:-unknown commit})"
exec "$@"

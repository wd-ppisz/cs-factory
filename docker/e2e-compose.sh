#!/usr/bin/env bash
# End-to-end test of the Docker Compose release, exactly as an operator uses it:
#   .env from .env.example -> docker compose up -> sign in -> "Build" in the GUI
#   -> wait for PASS -> the image is listed and downloadable under /artifacts/.
#
# Needs a Linux host with Docker Compose v2.23+ and a usable /dev/kvm.
# Usage:  docker/e2e-compose.sh [distro]        (default: debian-13)
# The image under test: CSF_IMAGE (default: build it from this checkout).
set -euo pipefail
cd "$(dirname "$0")/.."

DISTRO="${1:-debian-13}"
PORT="${E2E_HTTP_PORT:-18080}"
BASE="http://127.0.0.1:$PORT"
DEADLINE_MIN="${E2E_BUILD_MINUTES:-60}"
WORK="$(mktemp -d)"
JAR="$WORK/cookies"
PROJECT="csf-e2e-$$"
ENVF="$WORK/test.env"
PASS="$(head -c 600 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)"

dc() { docker compose -p "$PROJECT" --env-file "$ENVF" "$@"; }
cleanup() {
  rc=$?
  if [ "$rc" != 0 ]; then
    echo "=== FAILED - container logs ==="
    dc logs --no-color --tail 200 || true
    if [ -s "$WORK/log.html" ]; then
      echo "=== last build log ==="
      sed -e 's/<[^>]*>//g' "$WORK/log.html" | tail -120
    fi
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  # data dirs are owned by uid 10001 - remove them from inside a container
  docker run --rm -v "$WORK:/w" --user 0 "${CSF_IMAGE}" sh -c 'rm -rf /w/data' >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

: "${CSF_IMAGE:=cs-factory:e2e}"
export CSF_IMAGE

[ -e /dev/kvm ] || { echo "no /dev/kvm on this host"; exit 1; }

mkdir -p "$WORK/data/work" "$WORK/data/artifacts"
sudo chown 10001:10001 "$WORK/data/work" "$WORK/data/artifacts"

# .env exactly as the installation guide produces it
cp .env.example "$ENVF"
set_env() { sed -i "s|^$1=.*|$1=$2|" "$ENVF"; grep -q "^$1=" "$ENVF" || echo "$1=$2" >> "$ENVF"; }
set_env KVM_GID "$(stat -c %g /dev/kvm)"
set_env FLASK_SECRET "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
set_env FACTORY_ADMIN_PASSWORD "$PASS"
set_env EXTERNAL_URL "$BASE"
set_env ARTIFACTS_BASE_URL "$BASE/artifacts"
set_env CSF_HTTP_BIND 127.0.0.1
set_env CSF_HTTP_PORT "$PORT"
set_env CSF_WORK_DIR "$WORK/data/work"
set_env CSF_ARTIFACTS_DIR "$WORK/data/artifacts"
set_env CSF_IMAGE "$CSF_IMAGE"
# the container settings file (env_file) - never touches an operator's .env
export CSF_ENV_FILE="$ENVF"

dc up -d --no-build --wait --wait-timeout 180
echo "== stack is up"

# --- sign-in ------------------------------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")
[ "$code" = 302 ] || { echo "unauthenticated / returned $code, expected 302"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" \
  --data-urlencode user=admin --data-urlencode password=wrong "$BASE/login")
[ "$code" = 401 ] || { echo "wrong password returned $code, expected 401"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" \
  --data-urlencode user=admin --data-urlencode "password=$PASS" "$BASE/login")
[ "$code" = 302 ] || { echo "sign-in returned $code, expected 302"; exit 1; }
curl -fsS -b "$JAR" "$BASE/" | grep -q "CloudStack Template Factory" \
  || { echo "dashboard does not render after sign-in"; exit 1; }
curl -fsS -b "$JAR" "$BASE/help" | grep -q "step by step" || { echo "help page broken"; exit 1; }
echo "== sign-in OK"

# --- container hardening as deployed --------------------------------------------
[ "$(dc exec -T factory id -u)" = 10001 ] || { echo "factory does not run as uid 10001"; exit 1; }
dc exec -T factory sh -c 'touch /opt/cs-factory/x 2>/dev/null' && { echo "code directory is writable"; exit 1; }
dc exec -T factory sh -c 'test -w /dev/kvm' || { echo "/dev/kvm not writable in the container"; exit 1; }
echo "== container hardening OK"

# --- build through the GUI ------------------------------------------------------
VERSION="$(tr -d '[:space:]' < VERSION)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" \
  --data-urlencode "distro=$DISTRO" --data-urlencode "version=$VERSION" "$BASE/build")
[ "$code" = 302 ] || { echo "/build returned $code"; exit 1; }
echo "== build of $DISTRO v$VERSION queued"

end=$(( $(date +%s) + DEADLINE_MIN * 60 ))
state=""
while :; do
  sleep 30
  curl -fsS -b "$JAR" "$BASE/log/1" > "$WORK/log.html" || true
  state=$(grep -oE 'class="[ywn]">[^<]+</span></h2>' "$WORK/log.html" | sed -E 's/.*">([^<]+)<.*/\1/' || true)
  echo "   $(date +%H:%M:%S) state: ${state:-?}"
  case "$state" in PASS|FAIL|ERROR*) break ;; esac
  [ "$(date +%s)" -lt "$end" ] || { echo "build did not finish within $DEADLINE_MIN min"; exit 1; }
done
[ "$state" = PASS ] || { echo "build finished with $state"; exit 1; }

# Positive control: PASS must come from checks that actually ran. Count the
# verdict lines of the offline gate ("  OK  ...") and the boot test ("OK: ...")
# in the FULL build log (the GUI page shows only its tail) - a PASS without
# them means the gate did not run. Thresholds sit below what a debian-13 build
# produces (67 gate / 9 boot-test results on 2026-11-14).
dc exec -T factory sh -c 'cat /srv/cs-factory/work/build/logs/1.log' \
  | sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' > "$WORK/log.txt"
gate_ok=$(grep -cE '^[[:space:]]+OK[[:space:]]' "$WORK/log.txt" || true)
boot_ok=$(grep -cE '^OK: ' "$WORK/log.txt" || true)
fails=$(grep -cE '^[[:space:]]*FAIL[:[:space:]]' "$WORK/log.txt" || true)
echo "   offline gate: $gate_ok OK, boot test: $boot_ok OK, FAIL lines: $fails"
grep -E '^OK: ' "$WORK/log.txt" | sed 's/^/   /'
if [ "$gate_ok" -lt 50 ] || [ "$boot_ok" -lt 8 ] || [ "$fails" -gt 0 ]; then
  echo "PASS without evidence: too few check results in the build log"; exit 1
fi
echo "== build PASS"

# --- artifact published and downloadable -----------------------------------------
listing=$(curl -fsS "$BASE/artifacts/")
file=$(printf '%s' "$listing" | grep -oE 'href="[^"]+\.qcow2"' | head -1 | sed -E 's/href="([^"]+)"/\1/')
[ -n "$file" ] || { echo "no qcow2 under /artifacts/"; exit 1; }
size=$(curl -fsSI "$BASE/artifacts/$file" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
[ "${size:-0}" -gt 100000000 ] || { echo "artifact $file is too small ($size B)"; exit 1; }
curl -fsS -b "$JAR" "$BASE/" | grep -q "$file" || { echo "artifact not on the dashboard"; exit 1; }
echo "== artifact $file ($((size / 1048576)) MiB) published and served"
echo "E2E PASS"

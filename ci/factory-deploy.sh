#!/bin/bash
# Factory deploy (GUI + repository checkout) on the factory host - CI prod stage.
#
# Installed by gui/install.sh as /usr/local/sbin/cs-factory-deploy
# (root:root 0755) and allowed in sudoers ONLY for gitlab-runner. CI cannot
# replace that copy: a change to this script in the repo only takes effect after
# an administrator re-runs install.sh (the deploy warns about it).
#
# Usage: sudo /usr/local/sbin/cs-factory-deploy <full-sha-of-a-main-commit>
#
# Configuration (read from /etc/cs-factory/gui.env, no built-in defaults):
#   GITLAB_URL           e.g. https://gitlab.example.com
#   GITLAB_PROJECT_PATH  e.g. group/cs-factory
#   GITLAB_TOKEN         token able to read pipelines, jobs and job artifacts
#
# Privilege boundary: ANY job on the factory runner may call this script, also
# from an arbitrary branch, and the `factory` user (GUI) can change its checkout,
# its .git and its configuration. Therefore NOTHING that decides what root does
# comes from the checkout or from the caller:
#   * gate evidence - the script ITSELF asks the GitLab API for a successful
#     `cve_controller` job on main for THIS commit and reads its verdict (PASS,
#     fresh, this commit); the deploy_prod job checks the same, but that check
#     can be bypassed;
#   * membership in main and the files installed as root (unit, nginx) - from a
#     root-owned mirror (/var/lib/cs-factory-deploy/mirror.git), not from the
#     `factory` checkout, which can be tampered with locally;
#   * Python only as `python3 -I` from `/` - `python3 -c` prepends the caller's
#     current directory to sys.path (a planted json.py = code running as root).
#
# What it does after verification:
#   1. moves the checkout /srv/cs-factory/repo (fast-forward, as `factory`) to the
#      commit; a checkout NEWER than the commit = refusal (the GUI runs `git pull`
#      itself before a build) - deploy the latest pipeline;
#   2. restarts the GUI ONLY when gui/ changed relative to the version that is
#      actually running (from /healthz?verbose=1), and ONLY when the build queue
#      in the GUI process is empty - a restart would kill a running build;
#   3. verifies: the GUI responds and reports exactly this commit.
# Exit codes: 0 OK, 1 error/refusal, 75 GUI busy with a build (retry later).
set -euo pipefail
cd /
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP GIT_DIR GIT_WORK_TREE GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT

REPO=/srv/cs-factory/repo
MIRROR=/var/lib/cs-factory-deploy/mirror.git
CREDS=/srv/cs-factory/.git-credentials
ENVF=/etc/cs-factory/gui.env
UNIT=/etc/systemd/system/cs-factory-gui.service
NGINX=/etc/nginx/sites-available/cs-factory
HEALTH='http://127.0.0.1:8500/healthz?verbose=1'
SELF=/usr/local/sbin/cs-factory-deploy
MAX_VERDICT_AGE_H=24

die() { echo "!! $*" >&2; exit "${2:-1}"; }
g() { runuser -u factory -- git -C "$REPO" "$@"; }
# The root mirror authenticates with the token from the `factory` credentials
# file, READ here - not via credential.helper=store, which REWRITES the file
# after a successful fetch (as root, 0600), after which the GUI and the `factory`
# checkout lose access to GitLab. The header goes through GIT_CONFIG_* in the
# root process environment (/proc/<pid>/environ 0400), not argv visible in `ps`.
m() { git --git-dir="$MIRROR" "$@"; }
mirror_auth() {
  local basic
  basic="$(py - "$CREDS" <<'PY'
import base64, sys, urllib.parse
for line in open(sys.argv[1], encoding="utf-8"):
    u = urllib.parse.urlsplit(line.strip())
    if u.scheme == "https" and u.username and u.password:
        raw = f"{urllib.parse.unquote(u.username)}:{urllib.parse.unquote(u.password)}"
        print(base64.b64encode(raw.encode()).decode()); break
PY
)"
  [ -n "$basic" ] || die "no https credentials in $CREDS"
  export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
         GIT_CONFIG_KEY_1=http.extraHeader GIT_CONFIG_VALUE_1="Authorization: Basic $basic"
}
py() { python3 -I "$@"; }
envval() { sed -n "s/^$1=//p" "$ENVF" 2>/dev/null | head -1; }

SHA="${1:-}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || die "pass the full commit sha (40 hex characters)"
[ "$(id -u)" = 0 ] || die "requires root (sudo)"

exec 9>/run/cs-factory-deploy.lock
flock -w 300 9 || die "another deploy has been running for more than 5 min"

# ---- 0. configuration (from the root-owned env file, not from the caller) ----
GITLAB_URL="$(envval GITLAB_URL)"
PROJECT_PATH="$(envval GITLAB_PROJECT_PATH)"
[[ "$GITLAB_URL" =~ ^https://[A-Za-z0-9.:-]+(/[A-Za-z0-9._/-]*)?$ ]] \
  || die "GITLAB_URL missing or invalid in $ENVF (expected https://host[/path])"
GITLAB_URL="${GITLAB_URL%/}"
[[ "$PROJECT_PATH" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+$ ]] \
  || die "GITLAB_PROJECT_PATH missing or invalid in $ENVF (expected group/project)"

# ---- 1. root mirror: membership in main ---------------------------------------
if [ ! -d "$MIRROR" ]; then
  install -d -o root -g root -m0700 "$(dirname "$MIRROR")"
  git init -q --bare "$MIRROR"
fi
( mirror_auth; m fetch -q --prune "$GITLAB_URL/$PROJECT_PATH.git" "+refs/heads/main:refs/heads/main" ) \
  || die "failed to fetch main into the root mirror"
m cat-file -e "${SHA}^{commit}" 2>/dev/null || die "commit $SHA unknown in the mirror - it is not on main"
m merge-base --is-ancestor "$SHA" refs/heads/main || die "commit $SHA is not on main - refusing"

if ! m show "$SHA:ci/factory-deploy.sh" 2>/dev/null | cmp -s - "$SELF"; then
  echo "WARNING: $SELF differs from ci/factory-deploy.sh in $SHA - install the new version (gui/install.sh)"
fi

# ---- 2. gate evidence from the GitLab API (not from the caller) --------------
TOKEN="$(envval GITLAB_TOKEN)"
[ -n "$TOKEN" ] || die "no GITLAB_TOKEN in $ENVF - cannot check the CVE verdict"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# token via a header file (not in argv - visible in ps)
printf 'PRIVATE-TOKEN: %s\n' "$TOKEN" > "$TMP/hdr"
API="$GITLAB_URL/api/v4/projects/$(printf %s "$PROJECT_PATH" | sed 's#/#%2F#g')"
curl -sf -m 30 -H @"$TMP/hdr" "$API/pipelines?sha=$SHA&ref=main&per_page=20" -o "$TMP/pipes.json" \
  || die "GitLab API: cannot fetch the commit's pipelines"
JOB="$(py - "$TMP/pipes.json" "$API" "$TMP/hdr" "$MAX_VERDICT_AGE_H" <<'PY'
import datetime, json, subprocess, sys
pipes, api, hdr, max_h = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
now = datetime.datetime.now(datetime.timezone.utc)
best = None
for p in json.load(open(pipes)):
    out = subprocess.run(["curl", "-sf", "-m", "30", "-H", "@" + hdr,
                          f"{api}/pipelines/{p['id']}/jobs?per_page=100&include_retried=true"],
                         capture_output=True, check=False).stdout
    for j in json.loads(out or b"[]"):
        if j.get("name") != "cve_controller" or j.get("status") != "success" or not j.get("finished_at"):
            continue
        fin = datetime.datetime.fromisoformat(j["finished_at"].replace("Z", "+00:00"))
        if (now - fin).total_seconds() <= max_h * 3600 and (best is None or fin > best[0]):
            best = (fin, j["id"])
print(best[1] if best else "")
PY
)"
[ -n "$JOB" ] || die "no successful cve_controller job on main for $SHA in the last ${MAX_VERDICT_AGE_H} h - re-run the cve jobs"
curl -sf -m 30 -H @"$TMP/hdr" "$API/jobs/$JOB/artifacts/cve-verdict.json" -o "$TMP/verdict.json" \
  || die "cannot fetch the verdict from job $JOB"
py - "$TMP/verdict.json" "$SHA" "$MAX_VERDICT_AGE_H" <<'PY' || die "the CVE verdict from job $JOB does not allow the deploy"
import datetime, json, sys
v = json.load(open(sys.argv[1])); sha = sys.argv[2]; max_h = float(sys.argv[3])
ev = datetime.datetime.fromisoformat(v["evaluated_at"].replace("Z", "+00:00"))
age = (datetime.datetime.now(datetime.timezone.utc) - ev).total_seconds()
ok = v.get("schema") == "cs-factory-cve-verdict/v1" and v.get("passed") is True \
     and v.get("commit") == sha and 0 <= age <= max_h * 3600
print(f"CVE verdict: passed={v.get('passed')} commit={str(v.get('commit'))[:12]} age={age/3600:.1f} h")
sys.exit(0 if ok else 1)
PY
echo "CVE gate confirmed via the API (job $JOB)"

# ---- 3. `factory` checkout ------------------------------------------------------
g fetch -q origin main
[ "$(g symbolic-ref -q --short HEAD || true)" = main ] || die "the checkout is not on branch main"
HEAD_BEFORE="$(g rev-parse HEAD)"
if [ "$HEAD_BEFORE" != "$SHA" ]; then
  if g merge-base --is-ancestor "$SHA" "$HEAD_BEFORE"; then
    die "the checkout ($HEAD_BEFORE) is NEWER than $SHA - deploy the latest pipeline from main"
  fi
  g merge -q --ff-only "$SHA" || die "fast-forward to $SHA impossible (local changes in the checkout?)"
fi
[ "$(g rev-parse HEAD)" = "$SHA" ] || die "the checkout does not point to $SHA after the fast-forward"
echo "checkout: $HEAD_BEFORE -> $SHA"

# ---- 4. GUI: restart only when gui/ changed and the queue is empty -------------
health_json() { curl -sf -m 5 "$HEALTH" || true; }
field() { py -c 'import json,sys
try: print(json.loads(sys.argv[1]).get(sys.argv[2], ""))
except Exception: print("")' "$1" "$2"; }

H="$(health_json)"
RUNNING="$(field "$H" running_commit)"
if [[ "$RUNNING" =~ ^[0-9a-f]{40}$ ]] && m cat-file -e "${RUNNING}^{commit}" 2>/dev/null \
   && m diff --quiet "$RUNNING" "$SHA" -- gui/; then
  echo "gui/ unchanged relative to the running version ${RUNNING:0:12} - no restart"
  RESTART=0
else
  echo "gui/ changed (running: ${RUNNING:-unknown}) - restarting the GUI"
  RESTART=1
fi

if [ "$RESTART" = 1 ]; then
  BUSY="$(field "$H" busy)"
  if [ -n "$BUSY" ] && [ "$BUSY" != 0 ]; then
    die "the GUI has $BUSY build(s) in progress - a restart would interrupt them; retry the deploy later" 75
  fi
  # files for root - from the mirror (commit object), not from the `factory` checkout
  m show "$SHA:gui/cs-factory-gui.service" > "$TMP/unit"
  m show "$SHA:gui/nginx-cs-factory.conf" > "$TMP/nginx"
  if ! cmp -s "$TMP/unit" "$UNIT"; then
    install -m0644 "$TMP/unit" "$UNIT"
    systemctl daemon-reload
    echo "updated the GUI unit"
  fi
  if ! cmp -s "$TMP/nginx" "$NGINX"; then
    cp -p "$NGINX" "$TMP/nginx.prev" 2>/dev/null || true
    install -m0644 "$TMP/nginx" "$NGINX"
    if ! nginx -t; then
      [ -f "$TMP/nginx.prev" ] && install -m0644 "$TMP/nginx.prev" "$NGINX"
      die "the new nginx configuration fails nginx -t - previous one restored, GUI NOT restarted"
    fi
    systemctl reload nginx
    echo "reloaded nginx"
  fi
  systemctl restart cs-factory-gui
fi

H=""
for _ in $(seq 1 30); do
  H="$(health_json)"
  [ -n "$H" ] && break
  sleep 1
done
[ -n "$H" ] || die "the GUI does not respond on $HEALTH after 30 s"
RUNNING="$(field "$H" running_commit)"
if [ "$RESTART" = 1 ]; then
  [ "$RUNNING" = "$SHA" ] || die "the GUI runs commit '${RUNNING}', expected $SHA"
fi
echo "{\"deployed\": \"$SHA\", \"gui_running_commit\": \"$RUNNING\", \"restarted\": $RESTART, \"cve_job\": $JOB}"

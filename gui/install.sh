#!/bin/bash
# Install/update the factory GUI on the factory host. Idempotent. Run as root.
#
# Expects the repository checked out at /srv/cs-factory/repo (owned by `factory`).
# Secrets do NOT live in the repo - they are read from /etc/cs-factory/gui.env
# (0640 root:factory), which this script creates on the first run, taking the
# secret values from stdin:
#   line 1 = OIDC_CLIENT_SECRET (confidential OIDC client of the GUI)
#   line 2 = GITLAB_TOKEN       (project access token: api scope on the manifest project)
# Site-specific settings are taken from the installer's environment on the first
# run (all optional - anything left empty is reported in the GUI and can be
# filled in later in gui.env):
#   EXTERNAL_URL, OIDC_ISSUER, OIDC_CLIENT_ID, REQUIRED_GROUP, GITLAB_URL,
#   GITLAB_PROJECT, GITLAB_PROJECT_PATH, GITLAB_BRANCH, CS_API_URL, ARTIFACTS_BASE_URL
# Example:
#   printf '%s\n%s\n' "$OIDC_SECRET" "$GL_TOKEN" | \
#     EXTERNAL_URL=https://factory.example.com OIDC_ISSUER=https://sso.example.com/realms/example \
#     GITLAB_URL=https://gitlab.example.com GITLAB_PROJECT=group/cs-factory \
#     GITLAB_PROJECT_PATH=group/cs-factory ./gui/install.sh
# Later runs without stdin keep the existing files.
set -euo pipefail
ENVF=/etc/cs-factory/gui.env
BASE=/srv/cs-factory
ARTS="$BASE/artifacts"

# Read stdin ONLY when something is actually missing - otherwise a re-run over
# ssh (stdin = the ssh channel, not a tty) would hang on `read` forever.
OIDC_SECRET=""; GL_TOKEN=""
if [ ! -t 0 ] && [ ! -s "$ENVF" ]; then
  read -r OIDC_SECRET || true
  read -r GL_TOKEN || true
fi

apt-get -qq update
apt-get -qq -y install python3-flask python3-authlib gunicorn nginx >/dev/null

# ovmf (UEFI firmware for guests) comes in as a recommendation of qemu-system-x86,
# but the factory does not use it: builds (libguestfs) and smoke tests boot via
# BIOS. The package may carry unpatched CVEs that would make the CVE controller
# block the deploy for no benefit. Removed + pinned to -1 so the recommendation
# does not come back.
printf 'Package: ovmf\nPin: release *\nPin-Priority: -1\n' > /etc/apt/preferences.d/cs-factory-no-ovmf
if dpkg-query -W -f='${db:Status-Abbrev}' ovmf 2>/dev/null | grep -q '^ii'; then
  apt-get -qq -y purge ovmf >/dev/null
fi

install -d -m0755 /etc/cs-factory
if ! getent group factory >/dev/null; then groupadd -r factory; fi
# GUI runtime state (CloudStack keys set from the Settings page) -
# for the `factory` user only, outside the repo and outside config backups
install -d -o factory -g factory -m0700 /var/lib/cs-factory 2>/dev/null || \
  install -d -m0700 /var/lib/cs-factory
if id gitlab-runner >/dev/null 2>&1; then usermod -aG factory gitlab-runner; fi
chmod 711 "$BASE"

# ---- artifacts directory ----------------------------------------------------
# Finished images (~1 GB each) are published here by CI (`make publish`) and by
# local GUI builds, and served by nginx under /artifacts/. A plain local
# directory works out of the box; for anything beyond a lab you can mount any
# shared/backed-up storage here (NFS, CephFS, a dedicated volume, ...) - with the
# "current" image policy a build cannot be reproduced bit for bit (upstream
# replaces the image under the same URL), so published artifacts are worth keeping.
# If you use a mount, add it to /etc/fstab (with `nofail`) before running this.
install -d -m2775 "$ARTS"
# Writers: CI (gitlab-runner, if present) and the GUI (factory); nginx (www-data)
# reads. setgid - files inherit the factory group.
if id gitlab-runner >/dev/null 2>&1; then
  chown gitlab-runner:factory "$ARTS"
else
  chown factory:factory "$ARTS"
fi
chmod 2775 "$ARTS"

if [ ! -s "$ENVF" ] && [ -n "${OIDC_SECRET}${GL_TOKEN}" ]; then
  umask 077
  cat > "$ENVF" <<EOF
EXTERNAL_URL=${EXTERNAL_URL:-}
OIDC_ISSUER=${OIDC_ISSUER:-}
OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-cs-factory}
OIDC_CLIENT_SECRET=${OIDC_SECRET:-}
REQUIRED_GROUP=${REQUIRED_GROUP:-admins}
GITLAB_URL=${GITLAB_URL:-}
GITLAB_PROJECT=${GITLAB_PROJECT:-}
GITLAB_PROJECT_PATH=${GITLAB_PROJECT_PATH:-}
GITLAB_BRANCH=${GITLAB_BRANCH:-main}
GITLAB_TOKEN=${GL_TOKEN:-}
CS_API_URL=${CS_API_URL:-}
ARTIFACTS_BASE_URL=${ARTIFACTS_BASE_URL:-}
FLASK_SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
EOF
  chown root:factory "$ENVF"; chmod 0640 "$ENVF"
  echo "created $ENVF - review it and fill in any empty values"
elif [ -s "$ENVF" ]; then
  echo "$ENVF already exists - leaving it untouched"
else
  echo "!! $ENVF missing and no secrets on stdin - the GUI will start unconfigured"
fi

# ---- deploy from CI (prod stage) ---------------------------------------------
# gitlab-runner gets sudo for ONE script, whose copy is owned by root.
# CI cannot replace it with a commit - a new version only takes effect after
# this install.sh is re-run. The script itself makes sure it deploys only a
# commit from origin/main.
install -o root -g root -m0755 "$BASE/repo/ci/factory-deploy.sh" /usr/local/sbin/cs-factory-deploy
SUDOERS=/etc/sudoers.d/cs-factory-deploy
printf 'gitlab-runner ALL=(root) NOPASSWD: /usr/local/sbin/cs-factory-deploy\n' > "$SUDOERS.tmp"
chmod 0440 "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null || { rm -f "$SUDOERS.tmp"; echo "!! sudoers file does not pass visudo"; exit 1; }
mv "$SUDOERS.tmp" "$SUDOERS"

install -m0644 "$BASE/repo/gui/cs-factory-gui.service" /etc/systemd/system/
install -m0644 "$BASE/repo/gui/nginx-cs-factory.conf" /etc/nginx/sites-available/cs-factory
ln -sf ../sites-available/cs-factory /etc/nginx/sites-enabled/cs-factory
rm -f /etc/nginx/sites-enabled/default
systemctl daemon-reload
systemctl enable --now cs-factory-gui >/dev/null 2>&1 || true
systemctl restart cs-factory-gui
if nginx -t >/dev/null 2>&1; then systemctl reload nginx; else nginx -t; exit 1; fi

sleep 2
curl -sf -o /dev/null -w "gui healthz: %{http_code}\n" http://127.0.0.1:8500/healthz
echo "install: done"

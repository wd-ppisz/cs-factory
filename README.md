# CloudStack Template Factory

**CloudStack Template Factory** (`cs-factory`) is an **offline builder of
CloudStack/KVM templates**. It takes official upstream cloud images (Debian,
Ubuntu, Rocky Linux, openSUSE Leap), customises them with
libguestfs (`virt-customize`, no boot of the image during the build), adds a
common security and supervision layer, and only publishes images that pass a
validation gate and a real boot test.

Each template is named `Template <Distro> <Version> v<X.Y>`, e.g.
`Template Debian 13 v1.2`.

Operators work in a **web GUI**: build a template, follow its log, add a new
distribution with a form, register finished templates in CloudStack and run a
live test - no YAML, git or SSH.

## Quick start (Docker Compose)

On a Linux host with KVM and Docker Compose v2.23.1+:

```sh
sudo mkdir -p /opt/cs-factory && cd /opt/cs-factory
sudo curl -fsSLO https://raw.githubusercontent.com/wd-ppisz/cs-factory/v1.0.0/docker-compose.yml
sudo curl -fsSL -o .env https://raw.githubusercontent.com/wd-ppisz/cs-factory/v1.0.0/.env.example
sudo chmod 600 .env
sudo install -d -o 10001 -g 10001 data/work data/artifacts
sudo nano .env      # KVM_GID, FLASK_SECRET, FACTORY_ADMIN_PASSWORD, EXTERNAL_URL, ARTIFACTS_BASE_URL
sudo docker compose up -d
```

Then open `EXTERNAL_URL`, sign in as `admin` and build `debian-13`.
The full step-by-step guide is **[docs/installation.md](docs/installation.md)**.

## Documentation

- [Installation](docs/installation.md) - Docker Compose, step by step
- [Using the GUI](docs/gui-guide.md) - every screen and typical tasks
- [Configuration](docs/configuration.md) - all settings
- [CloudStack prerequisites](docs/cloudstack.md) - API account, SSVM access, account settings
- [Troubleshooting](docs/troubleshooting.md)
- [Changelog](CHANGELOG.md)

The rest of this README describes what the factory puts into templates, how it
tests them, and how to run it directly on a host (without Docker).

## What ends up in a template

Every template gets the same **common layer**, regardless of distribution:

- **QEMU guest agent with blocked RPCs** - `guest-exec*`, `guest-file-*`,
  `guest-ssh-*`, `guest-set-user-password` and `guest-get-users` are disabled,
  so the hypervisor operator gets no shell, file or credential access to the
  tenant's system. What the platform needs keeps working: `guest-fsfreeze-*`
  (consistent snapshots and backups), `guest-ping`, `guest-info`, shutdown.
  The mechanism differs per family and the gate checks the **effective** source:
  `/etc/qemu/qemu-ga.conf` (`[general] block-rpcs=...`) on Debian/Ubuntu/SUSE
  (the systemd unit does not read `/etc/default/qemu-guest-agent`, a sysvinit
  leftover), and on RHEL the variable from `/etc/sysconfig/qemu-ga` that the unit
  actually uses - `FILTER_RPC_ARGS` (Rocky 9/10) or `BLACKLIST_RPC` (Rocky 8).
- **Automatic security updates enabled** - `unattended-upgrades` (apt),
  `dnf-automatic` with `upgrade_type = security` (dnf), `os-update` with
  `UPDATE_CMD=security` (zypper). None of them reboots the machine on its own.
- **First-boot update** (`csf-firstboot`) - updates the OS within the current
  release on the first start (apt `upgrade --with-new-pkgs`, otherwise a new
  kernel is held back; dnf `--security` first; zypper `patch`). It runs AFTER
  `multi-user.target` and `cloud-final`, and sets its done-flag only after a
  successful update. `After=multi-user.target` is mandatory: without it there is
  an ordering cycle with `cloud-final.service` and systemd randomly drops one of
  the two jobs.
- **Hardware watchdog** - three parts, because the systemd setting alone is not enough:
  1. `/etc/systemd/system.conf.d/10-csf-watchdog.conf` (`RuntimeWatchdogSec=30s`) -
     PID 1 pets the i6300esb device that CloudStack (>= 4.11) adds to every VM;
  2. **the driver in the image** - on Ubuntu 22.04/24.04 `i6300esb.ko` ships in
     `linux-modules-extra-<ABI>` (cloud images only carry `linux-modules`), so
     `build.sh` installs it when missing; the offline gate checks it is present;
  3. `csf-watchdog.service` - an explicit `modprobe i6300esb`, because Ubuntu
     kernel packages blacklist the module and PCI-ID autoload does not happen;
     if the driver for the running kernel is missing (Ubuntu after an ABI bump),
     it is fetched at boot. A no-op on other families; never fails the boot.
  On the host side set `vm.watchdog.action` in the KVM agent's
  `agent.properties` (the default is `none`).
- **fail2ban** - `sshd` jail with `backend=systemd`. `ignoreip` defaults to
  `127.0.0.1/8 ::1 169.254.0.0/16` (loopback + CloudStack link-local control
  network); set `CSF_FAIL2BAN_IGNOREIP` at build time to add your management networks.
- **Read-only inspection agent** (`csf-inspect`) - answers a fixed set of
  read-only queries (`snapshot|psi|topio|topnet`) on the virtio-serial channel
  `org.csfactory.support.0`. The channel is attached via template `extraconfig`
  (see [Registration](#registration)); without it the agent idles.
- **cloud-init tuned for CloudStack** (`99-csf-cloudstack.cfg`, edited only via
  `cloudcfg-tune.py` with a YAML parser, never with `sed`):
  - `datasource_list: [ CloudStack, ConfigDrive ]` - CloudStack first and **no
    `None`**, so a missing datasource fails loudly instead of silently yielding
    empty user-data;
  - optional manifest flags for known distribution quirks:
    `networkd_use_domains` (adds `UseDomains=true` so `data-server` resolves via
    the DHCP search domain - required for the password server behind a redundant
    VPC router; systemd >= 256), `cloudstack_datasource_network` and
    `cloudinit_dhcp_client_priority` (which DHCP client cloud-init may use during
    datasource discovery), `upgrade_packages` (upgrade packages already present
    in the source image, e.g. a fixed cloud-init).
- **Correct ownership and SELinux labels** - every file from the repo enters the
  image through one table in `build.sh` with explicit `root:root` and mode
  (`--copy-in` would otherwise carry the build host's uid/gid); on SELinux images
  `finalize.sh` relabels with `setfiles` (the libguestfs appliance runs with
  `selinux=0`).

### The four invariants

Checked offline on the image and again on a live VM:

1. **datasource = CloudStack** (`cloud-id` reports `cloudstack`);
2. **user-data is executed** (delivered by the virtual router);
3. **`set_passwords` runs on every boot** (`always`) - a password reset from
   CloudStack works at any time; templates are registered with `passwordenabled=true`;
4. **SSH host keys are generated once per instance** (`ssh` is **not** `always`) -
   no fingerprint churn on reboot, and no keys baked into the template.

## Requirements

Build host: Linux with KVM, `libguestfs-tools`, `qemu-img` / `qemu-system-x86`,
`yq` (the **Python** `yq` - jq wrapper, `apt install yq`; NOT the Go
`mikefarah/yq`), `curl`, `make`, `shellcheck`, Python 3.10+.

- `/boot/vmlinuz-*` must be readable by the build user (supermin needs it);
- the build user must be in the `kvm` group;
- under WSL2, build on the Linux filesystem (ext4), not on `/mnt/c`.

## Building

```sh
make release DISTRO=debian-13          # build + offline gate + smoke boot + publish
# or step by step:
./build.sh debian-13 1.2               # => build/template-debian-13-v1_2.qcow2
./e2e/validate-offline.sh build/template-debian-13-v1_2.qcow2
./e2e/smoke-boot.sh build/template-debian-13-v1_2.qcow2
```

- **Release number** lives in `VERSION` (read by `make`, CI, `register.sh` and
  the GUI). Any change of template content = bump `VERSION` in the same commit;
  rebuilding under the same number overwrites the artifact of an already
  registered template.
- **Manifests** (`distros/*.yaml`) point to the **current/latest** image variant;
  integrity comes from the **upstream checksum file** (`sums_url`), verified
  after every download (GNU `hash  file` / `hash *file` and BSD
  `SHA256 (file) = hash` formats). A cached image is refreshed after
  `CSF_IMAGE_MAX_AGE_DAYS` (default 90). Pinning `sha256:`/`sha512:` in the
  manifest still works and takes precedence - then the build is reproducible.
- **Disk size**: `disk_size` in the manifest, minimum **10G** (enforced by the
  manifest lint, by `build.sh` and by the offline gate on the finished image).
  `CSF_DISK_SIZE=20G ./build.sh ...` enlarges it for one build; it never shrinks.
- `make publish` copies a passing image and its `.env` descriptor to
  `ARTIFACTS_DIR` (default `/srv/cs-factory/artifacts`).

## Test pyramid

1. **`e2e/validate-offline.sh`** - the gate. Inspects the built image without
   booting it: datasource, `set_passwords=always`, `ssh != always`, no host keys,
   enabled services, the EFFECTIVE QGA block list, file ownership, unit
   ordering, `--with-new-pkgs`, `UseDomains`, patch automation per family,
   fail2ban, the `i6300esb` driver for every kernel in the image.
   `e2e/probe-ds-cloudstack.py` runs the real
   `DataSourceCloudStack` domain-name lookup inside the image chroot without a
   DHCP lease - a class of bugs a NoCloud smoke boot cannot see.
2. **`e2e/smoke-boot.sh`** - local QEMU boot (NoCloud) with a guest-agent
   channel and the same `i6300esb` watchdog CloudStack gives every VM. Measures
   on a live boot: user-data execution, no ordering cycles in the journal, no
   unowned files, patch automation active, watchdog module + `/dev/watchdog0`
   armed by PID 1; `e2e/qga-probe.py` calls every blocked agent command and
   requires a "has been disabled" refusal. Part of `make release` - an image
   that passes the offline gate can still be unbootable.
3. **`e2e/tier2-cloudstack.sh`** - acceptance skeleton via `cmk` (partly manual);
   superseded by tier 3.
4. **`e2e/tier3-features.py`** - full feature test on a **live CloudStack VM**.
   Registers a TEMPORARY template, deploys a VM, checks the whole supervision
   layer and the four invariants (including a password reset that must change
   `/etc/shadow` and unchanged host keys after a reboot), and **cleans up
   everything** (VM with expunge, template, key pair) - also after a failure.

   ```sh
   CSF_CS_NETWORK=my-test-net python3 e2e/tier3-features.py --distro debian-13
   python3 e2e/tier3-features.py --all            # every artifact that passed
   python3 e2e/tier3-features.py --cleanup-only   # after an interrupted run
   ```

   Settings: `CSF_CS_NETWORK` (required), `CSF_CS_ZONE`,
   `CSF_CS_SERVICE_OFFERING`, `CSF_CS_PROJECT`, `E2E_CPU`, `E2E_RAM_MB`,
   `E2E_SSH_TIMEOUT`. Run it as the user that holds the CloudStack API keys
   (from the GUI button or the CLI), not from a CI job.

## Registration

```sh
CS_OSTYPEID=<id> CS_ZONEID=<id> ./register.sh \
  https://images.example.com/template-debian-13-v1_2.qcow2 debian-13 1.2
```

`register.sh` (via `cmk`) and the GUI attach the inspection channel in the
template details (`extraconfig`). The XML is passed **raw, not url-encoded** -
CloudStack decodes the API parameter but copies template details into VMs
verbatim. This requires, at account scope:

```
enable.additional.vm.configuration = true
allow.additional.vm.configuration.list.kvm = devices,channel,source,target,address
```

Disable with `CSF_INSPECT_CHANNEL=off ./register.sh ...`.

## Operator GUI

`gui/` is a small Flask application that lets an operator, from the browser only:

- add a distribution with a form-based wizard (no YAML) that validates the
  content - image and checksum file reachable, an entry for the image in the
  checksums, mandatory packages present - and saves the manifest locally
  (standalone) or commits it to a GitLab repository through the API;
- build a template with a live log - the same gate as `make release`: build,
  offline validation, boot test, publication - and run the tier-3 test;
- watch GitLab CI pipelines and job logs live (GitLab mode);
- register finished artifacts in CloudStack (API keys set on the Settings page;
  the secret is never shown back, only a fingerprint).

Screen-by-screen guide: [docs/gui-guide.md](docs/gui-guide.md).

Access is OIDC (any provider) restricted to one group (`REQUIRED_GROUP`, the
`groups` claim), or a single admin password (`FACTORY_ADMIN_PASSWORD`). The
recommended deployment is the Docker Compose release
([docs/installation.md](docs/installation.md)). Alternatively, install
directly on a Debian host with `gui/install.sh` (systemd unit
`cs-factory-gui`, gunicorn on `127.0.0.1:8500`, nginx site `cs-factory` that also
serves `/artifacts/`). Put TLS and network restrictions in front of it.
`/healthz` is the liveness probe; `/healthz?verbose=1` reports the running
commit and the number of busy builds (used by the deploy script).

## Host CVE controller and deploy

`ci/` contains tooling to keep **the factory host itself** patched and to
deploy the GUI safely. It is meant to run **on your own factory host** through a
self-hosted CI runner (e.g. a GitLab Runner with a shell executor), not on
GitHub-hosted runners, because it inspects that host:

1. `ci/factory_inventory.sh` - captures `dpkg/status`, package count, running vs
   newest kernel and reboot need into `inventory.json` + a minimal rootfs;
2. `trivy rootfs --list-all-pkgs` on that rootfs;
3. `ci/cve_controller.py` - evaluates the scan against `ci/cve-policy.json`:
   fixable HIGH/CRITICAL and anything in CISA KEV block, unfixed findings are
   reported, a pending reboot blocks. It **refuses to evaluate** (exit 2) when
   the evidence is not trustworthy: wrong host, stale inventory, Trivy DB or KEV
   older than allowed, a different `dpkg/status` in the scan than in the
   inventory, package coverage below 95%. Exceptions need `cve`, `package`,
   `approved_by`, `reason`, `approved_at`, `expires_at` (max 30 days); KEV
   exceptions additionally need `vex: not_affected` + `justification`.

   **Set `expected_host` in `ci/cve-policy.json`** to the FQDN of your factory
   host (`socket.getfqdn()`); the shipped value `factory.example.com` will
   otherwise make every evaluation fail.
4. `ci/factory-deploy.sh` - installed by `gui/install.sh` as root-owned
   `/usr/local/sbin/cs-factory-deploy`, callable by `gitlab-runner` via sudo.
   It deploys only a commit on `main`, verifies the CVE verdict for that commit
   **itself** through the GitLab API (job `cve_controller`), fast-forwards the
   checkout, restarts the GUI only when `gui/` changed and no build is running
   (exit 75 = busy, retry later), and checks the running commit afterwards.

Formats: `cs-factory-inventory/v1`, `cs-factory-cve-verdict/v1`,
`cs-factory-cve-policy/v1`.

GitHub Actions (`.github/workflows/ci.yml`) runs the portable part: syntax,
shellcheck, manifest lint, unit tests, secret scanning, Trivy misconfiguration
and Bandit.

## Configuration

Build and test (environment variables):

| Variable | Purpose |
|---|---|
| `CSF_DISK_SIZE` | enlarge the disk for one build |
| `CSF_IMAGE_CACHE` | cache directory for upstream images |
| `CSF_IMAGE_MAX_AGE_DAYS` | refresh cached images older than this (default 90) |
| `CSF_FAIL2BAN_IGNOREIP` | replaces fail2ban `ignoreip` (space-separated CIDRs) |
| `CSF_INSPECT_CHANNEL` | `off` disables the inspection channel in `register.sh` |
| `ARTIFACTS_DIR` | `make publish` target (default `/srv/cs-factory/artifacts`) |
| `CSF_CS_*`, `E2E_*` | tier-3 live test settings (see above) |

GUI and deploy (`/etc/cs-factory/gui.env`, created by `gui/install.sh`; no
built-in defaults - the GUI reports anything missing):

| Variable | Purpose |
|---|---|
| `EXTERNAL_URL` | public URL of the GUI (OIDC redirect base) |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | OIDC client |
| `REQUIRED_GROUP` | group required to use the GUI (default `admins`) |
| `GITLAB_URL`, `GITLAB_PROJECT`, `GITLAB_BRANCH`, `GITLAB_TOKEN` | manifest repository (project ID or `group/project`) |
| `GITLAB_PROJECT_PATH` | `group/project`, used by the deploy script |
| `GITLAB_COMMIT_EMAIL` | optional author e-mail for manifest commits |
| `CS_API_URL`, `CS_API_KEY`, `CS_SECRET_KEY` | CloudStack API (can also be set in the GUI) |
| `ARTIFACTS_BASE_URL` | URL from which the CloudStack SSVM downloads artifacts |
| `FLASK_SECRET` | session key (generated by the installer) |
| `FACTORY_REPO`, `FACTORY_ARTIFACTS` | repository checkout and artifacts directory |

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Security issues: see [SECURITY.md](SECURITY.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).

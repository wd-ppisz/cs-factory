# Configuration reference

Every setting of the Docker Compose release lives in **`.env`** next to
`docker-compose.yml` (start from [`.env.example`](../.env.example), which
carries the same comments). After a change run `docker compose up -d` - only
containers whose configuration changed are recreated.

The same variables configure a host install without Docker (`gui/install.sh`,
`/etc/cs-factory/gui.env`), except the *Host integration* section.

- [Host integration](#host-integration)
- [GUI and sign-in](#gui-and-sign-in)
- [CloudStack](#cloudstack)
- [Template build parameters](#template-build-parameters)
- [GitLab integration (optional)](#gitlab-integration-optional)
- [Distributions (manifests)](#distributions-manifests)
- [Fixed paths inside the container](#fixed-paths-inside-the-container)

---

## Host integration

| Variable | Default | Meaning |
|---|---|---|
| `KVM_GID` | **required** | Group id owning `/dev/kvm` on the host (`stat -c %g /dev/kvm`). Added to the container user so it can use KVM without privileges. |
| `CSF_HTTP_BIND` | `0.0.0.0` | Host address the web port listens on. `127.0.0.1` behind a local reverse proxy; a management-network address to keep it off other networks. |
| `CSF_HTTP_PORT` | `8080` | Host port of the GUI and `/artifacts/`. |
| `CSF_WORK_DIR` | `./data/work` | Host directory for the build directory, logs, image cache, GUI-added distributions and GUI-saved CloudStack keys. Must be owned by uid/gid 10001. Needs 10-30 GB. |
| `CSF_ARTIFACTS_DIR` | `./data/artifacts` | Host directory for finished templates (~1 GB each), served read-only under `/artifacts/`. Must be owned by uid/gid 10001. Point it at shared/backed-up storage (NFS, CephFS, a dedicated disk) to keep templates safe. |
| `CSF_IMAGE` | `ghcr.io/wd-ppisz/cs-factory:1.0.0` | Factory image. Pin the version you tested; change it to upgrade. |
| `CSF_WEB_IMAGE` | `nginxinc/nginx-unprivileged:1.30.6-alpine` | nginx image of the `web` service. |
| `CSF_ENV_FILE` | `.env` | Settings file passed to the factory container (used by the test harness; normally leave it). |

**Artifacts on NFS** (example):

```bash
sudo mkdir -p /mnt/templates
echo 'nfs.example.com:/export/templates /mnt/templates nfs defaults,nofail 0 0' | sudo tee -a /etc/fstab
sudo mount /mnt/templates
sudo install -d -o 10001 -g 10001 -m 0755 /mnt/templates/cs-factory
# .env:
CSF_ARTIFACTS_DIR=/mnt/templates/cs-factory
```

The NFS export must allow writes as uid 10001 (no `root_squash` concerns -
the container never writes as root).

## GUI and sign-in

| Variable | Default | Meaning |
|---|---|---|
| `FLASK_SECRET` | **required** | Key that signs GUI sessions: `openssl rand -hex 32`. Changing it signs everyone out. |
| `EXTERNAL_URL` | - | The URL users open, no trailing slash. Required for OIDC (redirect base). Decides the Secure flag of the session cookie: `https://` -> Secure, `http://` -> not. |
| `FACTORY_ADMIN_PASSWORD` | - | Enables the local `admin` account with this password. Ignored when OIDC is configured. |
| `OIDC_ISSUER` | - | OIDC issuer URL (e.g. `https://sso.example.com/realms/main`); discovery document at `/.well-known/openid-configuration`. |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | - | Confidential OIDC client. Redirect URI: `${EXTERNAL_URL}/callback`. |
| `REQUIRED_GROUP` | `admins` | Group required to use the GUI, read from the `groups` (or `roles`) claim. |
| `FACTORY_COOKIE_SECURE` | from `EXTERNAL_URL` | Force the Secure cookie flag (`1`) or not (`0`). |
| `FACTORY_AUTH_DISABLED` | - | `1` disables sign-in completely. **Development only** - anyone who reaches the port controls the factory and the CloudStack keys. |

Sign-in method precedence: OIDC (when `OIDC_ISSUER`, `OIDC_CLIENT_ID` and
`EXTERNAL_URL` are set) -> admin password -> none (the GUI then explains what
to configure).

**OIDC with Keycloak**: create a confidential client, valid redirect URI
`https://factory.example.com/callback`, and a *Group Membership* mapper with
token claim name `groups`, *Full group path* off, added to the ID token and
userinfo. Put the operators in the group named by `REQUIRED_GROUP`.

## CloudStack

| Variable | Default | Meaning |
|---|---|---|
| `CS_API_URL` | - | API endpoint, `https://<cloudstack>/client/api`. |
| `CS_API_KEY`, `CS_SECRET_KEY` | - | API keys. Usually entered on the **settings** page instead (saved keys take precedence). |
| `ARTIFACTS_BASE_URL` | - | URL from which the CloudStack **SSVM** downloads images, i.e. this factory's `/artifacts` as the SSVM reaches it, e.g. `http://10.0.0.5:8080/artifacts`. Required for registration. |
| `CS_ZONE` | first zone | Zone name to register templates in. |
| `CSF_INSPECT_CHANNEL` | `on` | `off` registers templates without the `csf-inspect` virtio-serial channel (no account settings needed then - see [cloudstack.md](cloudstack.md)). |
| `CSF_CS_NETWORK` | - | Live E2E test: network for the test VM (required for the test). |
| `CSF_CS_ZONE` | only zone | Live E2E test: zone name. |
| `CSF_CS_SERVICE_OFFERING` | smallest suitable | Live E2E test: service offering name. |
| `CSF_CS_PROJECT` | - | Live E2E test: project to deploy into. |
| `E2E_CPU`, `E2E_RAM_MB` | `2`, `2048` | Live E2E test: VM size with a custom offering. |
| `E2E_SSH_TIMEOUT` | `900` | Live E2E test: seconds to wait for SSH into the test VM. |

## Template build parameters

| Variable | Default | Meaning |
|---|---|---|
| `CSF_TEMPLATE_PREFIX` | `Template` | Template name = `<prefix> <display name> v<version>`. Empty = no prefix. Letters, digits, space, `._-`. |
| `CSF_FAIL2BAN_IGNOREIP` | `127.0.0.1/8 ::1 169.254.0.0/16` | Networks fail2ban never bans inside the templates (space-separated CIDRs; replaces the default). Keep `169.254.0.0/16` - CloudStack's link-local control network. |
| `CSF_IMAGE_MAX_AGE_DAYS` | `90` | A cached upstream image older than this is downloaded again, so templates do not sit on a stale base. |
| `CSF_DISK_SIZE` | manifest | Disk size for builds started outside the GUI (the GUI has a per-build field). Never shrinks below the manifest/10G minimum. |
| `SMOKE_CPU` | `Haswell-noTSX-IBRS` | CPU model shown to the guest in the boot test. |
| `SMOKE_TIMEOUT` | `1800` | Boot test time limit, seconds. |

The **template release number** (default value of the *template version* field)
comes from the `VERSION` file of the release; the field in the GUI can override
it per build.

## GitLab integration (optional)

Without these the factory runs standalone. With them, the wizard commits new
manifests to a GitLab project (whose CI builds them, see
[README](../README.md#host-cve-controller-and-deploy)) and the **CI status**
view appears.

| Variable | Default | Meaning |
|---|---|---|
| `GITLAB_URL` | - | e.g. `https://gitlab.example.com` |
| `GITLAB_PROJECT` | - | project ID or `group/project` |
| `GITLAB_TOKEN` | - | project access token, scope `api` |
| `GITLAB_BRANCH` | `main` | branch manifests are committed to |
| `GITLAB_COMMIT_EMAIL` | token owner | author e-mail of manifest commits |

Setting only some of the first three is reported as a configuration error.

## Distributions (manifests)

A distribution is a YAML manifest. Built-in ones ship in the image
(`distros/` in the repository); ones added in the GUI are stored in
`CSF_WORK_DIR/distros/`. A built-in name cannot be overridden from the GUI.

```yaml
name: "Debian 13"                       # display name -> "Template Debian 13 v1.2"
cs_ostype: "Debian GNU/Linux 12 (64-bit)"   # CloudStack OS type (registration)
url: "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
sums_url: "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
# sha512: "..."                         # optional pin; then sums_url is not needed
epel: false                             # RHEL family: add EPEL
disk_size: "10G"                        # minimum 10G
packages:
  - qemu-guest-agent                    # mandatory
  - fail2ban                            # mandatory
  - chrony
  - curl
```

Optional flags for known distribution quirks (`networkd_use_domains`,
`cloudstack_datasource_network`, `cloudinit_dhcp_client_priority`,
`upgrade_packages`, `grow_root_at_build`) are explained in the
[README](../README.md#what-ends-up-in-a-template) and next to their use in the
built-in manifests.

## Fixed paths inside the container

Set by the image; listed for troubleshooting. Do not override them in `.env`.

| Variable | Value |
|---|---|
| `FACTORY_REPO` | `/opt/cs-factory` (code, read-only) |
| `FACTORY_ARTIFACTS` | `/srv/cs-factory/artifacts` |
| `CSF_LOCAL_DISTROS` | `/srv/cs-factory/work/distros` |
| `CSF_IMAGE_CACHE` | `/srv/cs-factory/work/cache` |
| `CS_CREDS_FILE` | `/srv/cs-factory/work/state/cs-creds.json` |
| `LIBGUESTFS_BACKEND`, `LIBGUESTFS_CACHEDIR` | `direct`, `/srv/cs-factory/work/cache/guestfs` |
| `TMPDIR`, `HOME` | `/srv/cs-factory/work/tmp`, `/srv/cs-factory/work/state` |

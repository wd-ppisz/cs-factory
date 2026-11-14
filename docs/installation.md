# Installation (Docker Compose)

This guide installs CloudStack Template Factory 1.0 on one Linux host with
Docker Compose. At the end you have the operator GUI running, a first template
built and the factory connected to CloudStack.

Time: about 30 minutes, plus 15-30 minutes for the first template build.

- [1. What you need](#1-what-you-need)
- [2. Prepare the host](#2-prepare-the-host)
- [3. Download the release](#3-download-the-release)
- [4. Configure](#4-configure)
- [5. Start](#5-start)
- [6. First sign-in and first build](#6-first-sign-in-and-first-build)
- [7. Connect CloudStack](#7-connect-cloudstack)
- [8. Production hardening: TLS and network access](#8-production-hardening-tls-and-network-access)
- [Upgrading](#upgrading) · [Backup](#backup) · [Uninstalling](#uninstalling) · [Building the image yourself](#building-the-image-yourself)

---

## 1. What you need

### Host

| | Minimum | Recommended |
|---|---|---|
| CPU | x86_64, 2 cores, **hardware virtualization** (Intel VT-x / AMD-V) | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 40 GB free | 100 GB+ (each template ~1 GB, image cache ~1 GB per distribution) |
| OS | any Linux that runs Docker Engine (Debian 12/13, Ubuntu 22.04/24.04, Rocky 9, ...) | |

Templates are built and boot-tested **inside the container with KVM**, so the
host needs `/dev/kvm`. A virtual machine works too, as long as **nested
virtualization** is enabled for it (in CloudStack/KVM, VMware, Proxmox, Hyper-V).
Without KVM a build either times out or takes hours.

### Software

- **Docker Engine 24+** with the **Compose plugin v2.23.1 or newer**
  (`docker compose version`). Older Compose versions do not understand the
  inline `configs` used by the release.
- `curl` and `openssl` (for the commands below).

### Network

| Direction | What | Why |
|---|---|---|
| out | `ghcr.io`, `docker.io` (HTTPS) | pulling the factory and nginx images |
| out | distribution mirrors (HTTPS): `cloud.debian.org`, `cloud-images.ubuntu.com`, `dl.rockylinux.org`, `download.opensuse.org`, ... | downloading the upstream cloud images |
| out | your CloudStack API (`https://<cloudstack>/client/api`) | registering templates |
| in  | operators -> GUI port (default `8080`) | the web GUI |
| in  | CloudStack **secondary storage VM (SSVM)** -> GUI port, path `/artifacts/` | CloudStack downloads finished images from the factory |

### CloudStack

An API account (API key + secret key) that may register templates. Details,
and the account settings the templates expect, are in [cloudstack.md](cloudstack.md).
You can install and build templates without CloudStack and connect it later.

---

## 2. Prepare the host

**Check virtualization:**

```bash
grep -cE 'vmx|svm' /proc/cpuinfo      # > 0 = the CPU exposes virtualization
ls -l /dev/kvm                         # must exist
```

If `/dev/kvm` is missing, enable VT-x/AMD-V in the BIOS (or nested
virtualization for a VM) and load the module: `sudo modprobe kvm_intel` or
`sudo modprobe kvm_amd`.

**Install Docker Engine** following the official guide for your distribution:
<https://docs.docker.com/engine/install/>. For example on Debian:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Verify:

```bash
docker version --format '{{.Server.Version}}'   # 24 or newer
docker compose version                          # v2.23.1 or newer
```

The commands below use `sudo docker ...`; drop `sudo` if your user is in the
`docker` group.

---

## 3. Download the release

```bash
sudo mkdir -p /opt/cs-factory && cd /opt/cs-factory
sudo curl -fsSLO https://raw.githubusercontent.com/wd-ppisz/cs-factory/v1.0.0/docker-compose.yml
sudo curl -fsSL -o .env https://raw.githubusercontent.com/wd-ppisz/cs-factory/v1.0.0/.env.example
sudo chmod 600 .env
```

The same two files are attached to the
[GitHub release](https://github.com/wd-ppisz/cs-factory/releases/tag/v1.0.0)
(`.env.example` may be shown there as `env.example`).

**Create the data directories.** The factory runs as the unprivileged user
uid/gid **10001**, so it must own them:

```bash
sudo install -d -o 10001 -g 10001 -m 0750 data/work
sudo install -d -o 10001 -g 10001 -m 0755 data/artifacts
```

- `data/work` - build directory, logs, image cache, distributions added in the
  GUI and the CloudStack keys saved from the GUI (keep it private);
- `data/artifacts` - finished templates, served read-only under `/artifacts/`.

To keep templates on shared or backed-up storage (NFS, CephFS, a dedicated
disk), mount it first and point `CSF_ARTIFACTS_DIR` in `.env` at it - see
[configuration.md](configuration.md#host-integration).

---

## 4. Configure

All settings live in `/opt/cs-factory/.env`. The file is commented; the
complete reference is [configuration.md](configuration.md). For a first start
you need five values.

```bash
cd /opt/cs-factory
HOST_IP=10.0.0.5          # <- address of this host that operators and the SSVM reach

sudo sed -i \
  -e "s|^KVM_GID=.*|KVM_GID=$(stat -c %g /dev/kvm)|" \
  -e "s|^FLASK_SECRET=.*|FLASK_SECRET=$(openssl rand -hex 32)|" \
  -e "s|^EXTERNAL_URL=.*|EXTERNAL_URL=http://$HOST_IP:8080|" \
  -e "s|^ARTIFACTS_BASE_URL=.*|ARTIFACTS_BASE_URL=http://$HOST_IP:8080/artifacts|" \
  .env
sudo nano .env            # set FACTORY_ADMIN_PASSWORD (12+ characters)
```

| Variable | Meaning |
|---|---|
| `KVM_GID` | group id of `/dev/kvm` on the host - lets the unprivileged container use KVM |
| `FLASK_SECRET` | random key that signs GUI sessions |
| `FACTORY_ADMIN_PASSWORD` | password of the `admin` account (or configure OIDC instead - [configuration.md](configuration.md#gui-and-sign-in)) |
| `EXTERNAL_URL` | the URL operators type in the browser; with `https://` the session cookie is Secure |
| `ARTIFACTS_BASE_URL` | the URL **the CloudStack SSVM** downloads finished images from |

CloudStack API settings (`CS_API_URL`, keys) can be added now or later in the
GUI - see [step 7](#7-connect-cloudstack).

---

## 5. Start

```bash
cd /opt/cs-factory
sudo docker compose pull
sudo docker compose up -d
sudo docker compose ps
```

Both services must reach `running` and `factory` must report `(healthy)`
within about a minute:

```
NAME                   SERVICE   STATUS
cs-factory-factory-1   factory   Up 40 seconds (healthy)
cs-factory-web-1       web       Up 10 seconds
```

Check the start-up messages - the factory says plainly what is wrong with the
host (permissions of the data directories, `/dev/kvm`, missing settings):

```bash
sudo docker compose logs factory | head -20
curl -s http://127.0.0.1:8080/healthz          # -> ok
```

---

## 6. First sign-in and first build

1. Open `EXTERNAL_URL` (e.g. `http://10.0.0.5:8080`) and sign in as **admin**
   with `FACTORY_ADMIN_PASSWORD`.
2. A yellow banner lists settings that are still missing (typically
   `CS_API_URL` until CloudStack is connected) - that is expected.
3. In **Build a template now**, pick `debian-13`, leave the version and disk
   size as they are and click **Build locally**.
4. Click **log** next to the build in **Recent local builds**. The build goes
   through *building image -> validating -> boot test -> publishing* and ends
   with **PASS** in 15-30 minutes (the first build also downloads the upstream
   image and prepares the libguestfs appliance).
5. The template appears under **Finished templates**, and the image is listed
   at `EXTERNAL_URL/artifacts/`.

The GUI is described screen by screen in [gui-guide.md](gui-guide.md).

---

## 7. Connect CloudStack

1. Prepare an API account and the account settings described in
   [cloudstack.md](cloudstack.md).
2. Put the API endpoint in `.env` and apply it:
   ```bash
   sudo sed -i 's|^CS_API_URL=.*|CS_API_URL=https://cloudstack.example.com/client/api|' .env
   sudo docker compose up -d
   ```
3. In the GUI open **settings**, paste the API key and secret key and click
   **Save and test**. The page shows the zones the account can see.
4. Check that the **SSVM can download from the factory** - from the CloudStack
   management server or the SSVM console:
   ```bash
   curl -sI http://10.0.0.5:8080/artifacts/ | head -1     # HTTP/1.1 200 OK
   ```
5. On the dashboard click **Register in CloudStack** next to the finished
   template. In CloudStack it shows as *Not Ready* while the SSVM downloads it,
   then *Ready*.

---

## 8. Production hardening: TLS and network access

The release serves plain HTTP on one port. For anything beyond a lab:

- **Put TLS in front of the GUI** (reverse proxy on the same host or an
  existing edge) and set `EXTERNAL_URL=https://...`. Example with Caddy on the
  same host:
  ```
  factory.example.com {
      reverse_proxy 127.0.0.1:8080
  }
  ```
  With nginx, forward `Host` and set `X-Forwarded-Proto https`; no other
  special settings are needed.
  When the proxy runs on the same host, set `CSF_HTTP_BIND=127.0.0.1` - but
  keep `/artifacts/` reachable for the SSVM (through the proxy, or by binding
  to the management network address instead).
- **Restrict `/artifacts/`** to the CloudStack management/storage network: it
  has no sign-in by design (the SSVM cannot sign in). Templates contain no
  secrets, but there is no reason to publish them.
- **Use OIDC** for teams (per-user accounts and group-based access) instead of
  the shared admin password - [configuration.md](configuration.md#gui-and-sign-in).
- Keep `.env` at mode `0600`; it holds the session key and passwords.

---

## Upgrading

1. Wait until no build is running (dashboard, or
   `curl -s http://127.0.0.1:8080/healthz?verbose=1` shows `"busy": 0`).
   The build queue lives in memory - a restart drops queued and running builds.
2. Read the [CHANGELOG](../CHANGELOG.md) for the new version.
3. Change the image tag in `.env` (`CSF_IMAGE=ghcr.io/wd-ppisz/cs-factory:<new>`),
   then:
   ```bash
   sudo docker compose pull && sudo docker compose up -d
   ```
4. Compare your `.env` with the new release's `.env.example` for new settings.

Built-in distributions come with the image; distributions you added in the
GUI stay in `data/work/distros`.

## Backup

| What | Where | Needed to |
|---|---|---|
| `.env` | `/opt/cs-factory/.env` | restore the configuration |
| GUI-added distributions | `data/work/distros/` | keep your manifests |
| CloudStack keys saved in the GUI | `data/work/state/cs-creds.json` | (or re-enter them) |
| Finished templates | `data/artifacts/` | re-register without rebuilding |

`data/work/build` and `data/work/cache` can be rebuilt and need no backup.

## Uninstalling

```bash
cd /opt/cs-factory
sudo docker compose down
sudo rm -rf /opt/cs-factory          # removes the data directories too
```

Templates already registered in CloudStack are not affected (CloudStack keeps
its own copy).

## Building the image yourself

```bash
git clone https://github.com/wd-ppisz/cs-factory.git && cd cs-factory
git checkout v1.0.0
cp .env.example .env && chmod 600 .env       # configure as in step 4
sudo install -d -o 10001 -g 10001 data/work data/artifacts
sudo CSF_IMAGE=cs-factory:local docker compose build
sudo CSF_IMAGE=cs-factory:local docker compose up -d
```

(Or set `CSF_IMAGE=cs-factory:local` in `.env`.) The release workflow tests
every image end to end before publishing it: `docker/e2e-compose.sh` runs the
same steps as this guide and builds a real template.

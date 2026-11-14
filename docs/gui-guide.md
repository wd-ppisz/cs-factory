# Using the GUI

The operator GUI lets you build, check and register CloudStack templates from
the browser only - no YAML, git or SSH. This guide walks through every screen
and the typical tasks.

- [Signing in](#signing-in)
- [Dashboard](#dashboard)
- [Building a template](#building-a-template)
- [Build log and results](#build-log-and-results)
- [Adding a distribution (wizard)](#adding-a-distribution-wizard)
- [Registering a template in CloudStack](#registering-a-template-in-cloudstack)
- [Live E2E test](#live-e2e-test)
- [Settings](#settings)
- [Artifacts](#artifacts)
- [CI status (GitLab mode)](#ci-status-gitlab-mode)
- [Typical tasks](#typical-tasks)

The top bar links to every screen: **dashboard, new distribution, settings,
help, artifacts** (plus **CI status** when GitLab is configured). A yellow
**Configuration incomplete** banner names any setting that is still missing
and stays until it is set in `.env`.

---

## Signing in

Depending on the configuration:

- **Admin password** - a sign-in form; user `admin`, password
  `FACTORY_ADMIN_PASSWORD`. After 10 failed attempts within 5 minutes further
  attempts are refused for a few minutes.
- **OIDC** - you are redirected to your identity provider. Access requires
  membership in the group `REQUIRED_GROUP` (default `admins`); without it the
  GUI shows *Access denied* with the account name, so an administrator knows
  whom to add.

**log out** is in the top-right corner.

---

## Dashboard

The start page has four parts:

1. **What do you want to do?**
   - *Add a new distribution* - opens the [wizard](#adding-a-distribution-wizard);
   - *Build a template now* - the [build form](#building-a-template);
   - *Available manifests* - every distribution the factory can build; click
     one to see its manifest (built-in or added from the GUI).
2. **Recent local builds** - the last 15 builds and E2E tests with their state
   and a **log** link.
3. **Where do templates go?** (or **CI status** in GitLab mode).
4. **Finished templates - CloudStack registration** - every image that passed
   all checks, with its OS type and the **Register in CloudStack** and
   **E2E test on a live VM** buttons.

---

## Building a template

In **Build a template now**:

| Field | Meaning |
|---|---|
| distribution | which manifest to build |
| template version | goes into the template name: `Template Debian 13 v1.2`. Defaults to the release in the `VERSION` file. |
| disk size | leave empty to use the manifest value; enter e.g. `20G` to build **this one** template with a bigger disk. It can only enlarge the disk - the minimum is 10 GB or the manifest size, whichever is larger. |

Click **Build locally**. The build is queued; builds run **one at a time**.
Each one goes through four stages, visible as the state:

1. **building image** - downloads the upstream cloud image (cached; checksum
   verified against the distribution's checksum file), customises it offline
   with libguestfs and adds the common security and supervision layer;
2. **validating (offline gate)** - inspects the finished image without booting
   it: CloudStack datasource, password reset on every boot, unique SSH host
   keys per instance, guest-agent restrictions, watchdog driver, automatic
   security updates, file ownership and more;
3. **boot test** - boots the image under QEMU/KVM and checks it live
   (user-data runs, watchdog armed, guest agent refuses blocked commands, no
   systemd ordering cycles);
4. **publishing** - only after all of the above: the image moves to
   `/artifacts/` and appears under **Finished templates**.

A build typically takes 15-30 minutes (more for the RHEL family). The queue
lives in memory: restarting the container drops queued and running builds.

> **Same version = overwrite.** Rebuilding a distribution under the same
> version replaces its artifact (same file name). If a template with that name
> is already registered in CloudStack, build under a **new version** instead
> (e.g. 1.3) so the registered one stays reproducible.

---

## Build log and results

**log** opens the full output of the build, refreshed every 3 seconds while it
runs. The header shows the state:

- **PASS** - the template passed every check and is published;
- **FAIL** - not fit for use; the log says which check failed (look for lines
  starting with `FAIL`, each with a reason). Nothing is published;
- **ERROR: ...** - the job could not run (rare; see the container log).

The first lines of the log show which code built it (`# building code: ...`).

---

## Adding a distribution (wizard)

**new distribution** opens a form that produces a manifest - no YAML needed.
Click **help** in the top bar for where to find the URLs of each distribution.

| Field | What to enter |
|---|---|
| Technical name | file name of the manifest, lowercase, no spaces, e.g. `ubuntu-26.04`. Names of built-in distributions are reserved; `custom-` is reserved too. |
| Display name | goes into the template name, e.g. `Ubuntu 26.04` -> `Template Ubuntu 26.04 v1.2` |
| Cloud image URL | the **current/latest** cloud image (`.qcow2`, `.img` or `.raw`, HTTPS) - the "genericcloud" / "server-cloudimg" variant, not "nocloud" |
| Checksum file URL | `SHA256SUMS` / `SHA512SUMS` / `*.CHECKSUM` from the same directory (recommended) |
| Pinned checksum | optional - pins one exact build of the image (reproducible) instead of following "latest" |
| Template disk size | minimum `10G` |
| CloudStack OS type | the OS type CloudStack will show for the template, e.g. `Debian GNU/Linux 12 (64-bit)`. When CloudStack is connected the field suggests the types it knows. **Needed for registration.** |
| RHEL family | tick for Rocky/Alma to add the EPEL repository |
| Packages | one per line; `qemu-guest-agent` and `fail2ban` are mandatory (supervision and security layer) |

Buttons:

- **Only check** - downloads the image headers and the checksum file and
  verifies: both reachable, the checksum file has an entry for the image, the
  image is not suspiciously small, the fields are valid. Nothing is saved.
- **Check and save** - the same checks, then saves the distribution:
  - standalone (default): to `data/work/distros/`; a **Build** button appears
    right away;
  - GitLab mode: committed to the GitLab project; GitLab CI builds it.

To change a distribution you added, open the wizard, enter the **same
technical name** and save again - it replaces your manifest.

---

## Registering a template in CloudStack

Under **Finished templates**, click **Register in CloudStack** next to an
image. Optionally tick **visible to everyone** (a public template - requires an
API account with administrator rights).

The factory then:

- looks up the OS type from the manifest in CloudStack;
- registers the template in the zone `CS_ZONE` (default: the first available
  zone), in the ROOT domain, as KVM/QCOW2, with **password reset enabled**,
  dynamic scaling and the virtio root disk controller;
- gives CloudStack the image URL `ARTIFACTS_BASE_URL/<file>`;
- attaches the `csf-inspect` supervision channel (unless
  `CSF_INSPECT_CHANNEL=off`).

The result page shows the template ID. In CloudStack the template is *Not
Ready* while the SSVM downloads it, then *Ready*. Prerequisites and the
account settings that machines from these templates need:
[cloudstack.md](cloudstack.md).

Common errors and their fixes are listed on the result page itself and in
[troubleshooting.md](troubleshooting.md#registration).

---

## Live E2E test

**E2E test on a live VM** (next to a finished template) runs the full feature
test against your CloudStack: it registers a **temporary** template, deploys a
VM from it, checks the supervision layer and the four template invariants -
including a password reset that must really change the password and SSH host
keys that must survive a reboot - and then **removes everything** it created
(VM, template, key pair), also after a failure.

It needs CloudStack keys and the `CSF_CS_*` settings (at least
`CSF_CS_NETWORK`) - see [configuration.md](configuration.md#cloudstack). The
result (PASS/FAIL) and its log appear under **Recent local builds**.

---

## Settings

**settings** shows the effective configuration and manages the **CloudStack
API keys**:

- **state** - live connection test (visible zones or the error);
- API URL, API key (first characters + fingerprint), secret key (fingerprint
  only - it is never shown back);
- **Only test the connection** - tests the entered values without saving;
- **Save and test** - tests first and saves only if the test succeeds, so a
  typo never breaks a working configuration. Saved keys are stored in
  `data/work/state/cs-creds.json` (mode 0600) and take precedence over `.env`.

The lower table lists the remaining settings read-only (sign-in method, GUI
URL, manifest source, registration zone, artifact URL); they are changed in
`.env`.

---

## Artifacts

**artifacts** opens the directory listing of `/artifacts/`: every published
image (`.qcow2`) and its descriptor (`.env` with template name, distribution and
version). This is the address CloudStack downloads from; it is also handy for
downloading an image manually.

---

## CI status (GitLab mode)

Only when `GITLAB_URL`, `GITLAB_PROJECT` and `GITLAB_TOKEN` are set. Shows the
last pipelines of the manifest project with their jobs (including child
pipelines) live; click a job to see its log.

---

## Typical tasks

**Build all templates for a new release**
1. Decide the version (e.g. `1.3`).
2. Build each distribution with that version (they queue one after another).
3. Register the new templates; keep or remove the old ones in CloudStack.

**Add a distribution that is not built in**
1. **help** -> find the image and checksum URLs.
2. **new distribution** -> fill in, **Only check**, then **Check and save**.
3. Click **Build**, wait for PASS, register.

**A template needs a bigger disk**
Build it again with *disk size* `20G` and a new version, or permanently: add it
as your own distribution with a larger *Template disk size*.

**Rotate the CloudStack keys**
**settings** -> paste the new keys -> **Save and test**.

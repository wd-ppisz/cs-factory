# Troubleshooting

Start with the container log - the factory reports host problems at start-up
and every build writes a full log:

```bash
cd /opt/cs-factory
sudo docker compose ps
sudo docker compose logs --tail 100 factory
sudo docker compose logs --tail 50 web
ls data/work/build/logs/          # build logs (also in the GUI: "log")
```

- [Start-up](#start-up)
- [Sign-in](#sign-in)
- [Builds](#builds)
- [Registration](#registration)
- [Machines from the templates](#machines-from-the-templates)

## Start-up

**`factory` keeps restarting, log says `... is not writable by uid 10001`**
The data directories must belong to uid/gid 10001:
```bash
sudo chown -R 10001:10001 data/work data/artifacts
```
(Docker creates a missing bind-mount directory as root - create them with
`install -d -o 10001 -g 10001` *before* the first start.)

**`set KVM_GID in .env`** when running `docker compose`
`KVM_GID` is empty. Set it to `stat -c %g /dev/kvm`.

**`error gathering device information while adding custom device "/dev/kvm"`**
The host has no KVM. Enable virtualization (BIOS, or nested virtualization for
a VM) and load `kvm_intel`/`kvm_amd`.

**Log says `/dev/kvm exists but is not writable`**
`KVM_GID` does not match the group of `/dev/kvm`. Fix it and `docker compose up -d`.

**`web` does not start, `factory` is `unhealthy`**
`web` waits for `factory` to be healthy. Look at the factory log; the usual
causes are the two above.

**`docker compose` complains about `configs` / `content`**
Compose is older than v2.23.1. Upgrade the `docker-compose-plugin` package.

## Sign-in

**Sign-in form accepts the password but you land on the form again**
The browser dropped the session cookie: `EXTERNAL_URL` is empty or `https://`
while you use plain `http://`. Set `EXTERNAL_URL` to exactly the URL in the
address bar (or `FACTORY_COOKIE_SECURE=0` for a plain-http lab) and
`docker compose up -d`.

**`Too many failed attempts`**
10 wrong passwords within 5 minutes. Wait 5 minutes (or restart the factory).

**`Sign-in not configured`**
Neither `FACTORY_ADMIN_PASSWORD` nor OIDC is set.

**OIDC: `Access denied ... is not a member of the group`**
The token has no `groups` claim with `REQUIRED_GROUP`. Add a group-membership
mapper to the client (claim name `groups`, *full path* off) and put the user in
the group.

**Everyone is signed out after a restart**
`FLASK_SECRET` is empty, so a new key is generated at every start. Set it.

## Builds

Open the build's **log** and look for lines starting with `FAIL` or `!!`.

**`manifest not found`**
The distribution was renamed or removed. Check *Available manifests* on the
dashboard.

**`checksum MISMATCH even after a fresh download`**
A cached image whose checksum no longer matches upstream is downloaded again
automatically (`cached image checksum does not match upstream` in the log).
If even the fresh download does not match, the manifest points at the wrong
checksum file (or a pinned checksum is outdated) - fix it in the wizard
(**Only check** verifies that the checksum file has an entry for the image).

**Download errors**
The host cannot reach the distribution mirror (proxy, firewall, DNS). Test from
the container:
```bash
sudo docker compose exec factory curl -sI https://cloud.debian.org/ | head -1
```
For an HTTP proxy add `HTTPS_PROXY=http://proxy:3128` (and `NO_PROXY` for
CloudStack) to `.env`.

**libguestfs / supermin errors at the very start of a build**
(`supermin: ... failed`, `could not create appliance`)
- check `/dev/kvm` (see above);
- the appliance is cached in `data/work/cache/guestfs`; delete that directory
  to force a rebuild of it;
- run the libguestfs self-test:
  ```bash
  sudo docker compose exec factory libguestfs-test-tool 2>&1 | tail -20
  ```

**The boot test fails or times out (`no beacon - user-data did NOT run`)**
- without KVM the boot test is far too slow - check `/dev/kvm`;
- an overloaded host (several heavy jobs) can push the guest over the time
  limit; raise `SMOKE_TIMEOUT` if the host is slow but healthy;
- a real failure (the image does not boot, cloud-init broken) is shown in the
  guest console output in the log.

**`No space left on device`**
Images, cache and build directory live in `data/work` and `data/artifacts`.
Remove old artifacts you no longer need and clear the cache:
```bash
sudo rm -rf data/work/cache/*.qcow2 data/work/build/*.qcow2
```

**A build stays in a running state after a restart**
The queue lives in memory; a restart drops running builds. Start the build
again.

## Registration

**`ARTIFACTS_BASE_URL is not configured`** / **`The GUI has no CloudStack API configuration`**
Set the variable in `.env` / the keys on **settings**.

**`CloudStack does not know the OS type`**
The manifest's `cs_ostype` does not exist in your CloudStack. Re-save the
distribution in the wizard with an existing type (the field suggests them).
For built-in distributions use the closest type CloudStack offers by adding
your own copy of the distribution in the wizard.

**`CloudStack did not allow creating a template visible to everyone`**
The API account is not an admin. Register without *visible to everyone*, or use
an admin account.

**Template stays *Not Ready*, or shows a download error in CloudStack**
The SSVM cannot download from `ARTIFACTS_BASE_URL`:
- check the URL from the SSVM (see [cloudstack.md](cloudstack.md#2-the-ssvm-must-reach-the-factory));
- allow private addresses: global setting `secstorage.allowed.internal.download.sites`;
- the firewall must let the SSVM reach `CSF_HTTP_PORT`.

**`CloudStack rejected the request (401)`**
Wrong keys or a clock skew between the factory host and CloudStack. Re-enter
the keys on **settings** (*Only test the connection* shows the error).

## Machines from the templates

**A VM from the template does not start**
The template carries the `csf-inspect` channel and the deploying account does
not allow extra VM configuration. Set the account settings from
[cloudstack.md](cloudstack.md#supervision-channel-csf-inspect), or re-register
the template with `CSF_INSPECT_CHANNEL=off`.

**Reset Password does nothing**
Restart the VM after the reset - the password is applied at boot. The VM needs
its virtual router (password server) reachable.

**Guest hangs are not recovered**
Set `vm.watchdog.action` in the KVM agent's `agent.properties`
([cloudstack.md](cloudstack.md#hardware-watchdog)).

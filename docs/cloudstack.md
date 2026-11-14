# CloudStack prerequisites

What CloudStack needs so the factory can register templates, and what the
**accounts that deploy machines from these templates** need.

## 1. API account for the factory

The factory signs API calls with an API key + secret key.

1. In CloudStack: **Accounts -> (account) -> View Users -> (user) -> Generate Keys**.
2. Enter the keys on the GUI **settings** page (or `CS_API_KEY` /
   `CS_SECRET_KEY` in `.env`), with `CS_API_URL=https://<cloudstack>/client/api`.

Which account:

| Account type | Can register |
|---|---|
| Root/domain **admin** | public templates (*visible to everyone*) and private ones |
| regular **user** | private templates of that account only - leave *visible to everyone* unticked |

The API calls used: `listZones`, `listOsTypes`, `registerTemplate` (and for the
live E2E test additionally templates, VMs, key pairs, networks, offerings).

## 2. The SSVM must reach the factory

CloudStack does not upload anything: the **secondary storage VM** downloads the
image from the URL the factory gives it, `ARTIFACTS_BASE_URL/<file>`.

- `ARTIFACTS_BASE_URL` must be an address **the SSVM can reach** - usually the
  factory host's address on the management/storage network, e.g.
  `http://10.0.0.5:8080/artifacts`. It is often *not* the URL operators use.
- Check from the SSVM (via the console or `ssh -i ~/.ssh/id_rsa.cloud -p 3922 root@<ssvm-link-local-ip>`
  from the KVM host):
  ```bash
  curl -sI http://10.0.0.5:8080/artifacts/ | head -1
  ```
- By default CloudStack refuses downloads from private addresses unless they
  are allowed. If registration ends with a download error, set the global
  setting **`secstorage.allowed.internal.download.sites`** to the factory's
  network (CIDR, e.g. `10.0.0.0/24`) and restart the SSVM (destroy it; CloudStack
  recreates it).
- HTTP is fine for an internal network. For HTTPS the SSVM must trust the
  certificate.

## 3. OS types

Each manifest names a CloudStack OS type in `cs_ostype` (wizard field
*CloudStack OS type*). The GUI matches it against `listOsTypes` (exact match,
then prefix). Use a type your CloudStack version has - a newer distribution may
need the closest older type (e.g. *Debian GNU/Linux 12 (64-bit)* for Debian 13
on CloudStack 4.22).

## 4. Settings for machines deployed from these templates

### Supervision channel (`csf-inspect`)

By default the factory registers templates with an extra virtio-serial channel
(`org.csfactory.support.0`) for the read-only inspection agent. CloudStack only
passes such extra configuration to a VM when the deploying **account** allows it
(Account settings, or the global defaults):

```
enable.additional.vm.configuration = true
allow.additional.vm.configuration.list.kvm = devices,channel,source,target,address
```

Without them, **machines from these templates fail to start**. If you do not
want to change account settings, set `CSF_INSPECT_CHANNEL=off` in `.env`
**before registering** - templates then carry no extra configuration; the agent
inside simply idles.

### Hardware watchdog

Every CloudStack KVM VM gets an `i6300esb` watchdog device; the templates arm
it. What happens when a guest hangs is decided on each **KVM host** in
`/etc/cloudstack/agent/agent.properties`:

```
vm.watchdog.model=i6300esb
vm.watchdog.action=reset      # default is "none" - the watchdog then only logs
```

Restart `cloudstack-agent` after the change.

### Password reset and user-data

Templates are registered with *password enabled*; `set_passwords` runs on every
boot, so **Reset Password** in CloudStack works at any time (the VM must be
restarted for it). User-data is executed on first boot from the virtual router.
Nothing needs configuring for this beyond a working virtual router.

## 5. Live E2E test

The **E2E test on a live VM** button needs, in addition to the API keys:

- `CSF_CS_NETWORK` - a network the test VM can be deployed into, **reachable
  over SSH from the factory host** (the test logs in to check the system);
- optionally `CSF_CS_ZONE`, `CSF_CS_SERVICE_OFFERING`, `CSF_CS_PROJECT`.

The API account must be able to register templates, deploy and expunge VMs and
manage SSH key pairs. The test cleans up after itself; if it was interrupted,
leftovers carry the prefix `csf-e2e` in their names and are removed with:

```bash
sudo docker compose exec factory python3 /opt/cs-factory/e2e/tier3-features.py --cleanup-only
```

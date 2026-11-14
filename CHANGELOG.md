# Changelog

All notable changes to CloudStack Template Factory. Versions follow
[Semantic Versioning](https://semver.org/). The **template** release number
(`VERSION` file, part of every template name) is separate from the product
version below.

## [1.0.0] - 2026-11-14

First public release.

### Added
- **Docker Compose release**: container image `ghcr.io/wd-ppisz/cs-factory`
  (GUI + build toolchain: libguestfs, QEMU/KVM) and an nginx front end serving
  the GUI and `/artifacts/`. Runs unprivileged (uid 10001), read-only root
  filesystem, no capabilities; needs only `/dev/kvm` from the host.
- **Standalone mode**: GitLab is optional. Without it the wizard saves new
  distributions locally and templates are built from the dashboard.
- **Full release pipeline from the GUI**: a local build now runs build ->
  offline validation gate -> boot test -> publication; only a PASS reaches the
  artifacts list.
- **Local sign-in** with a single admin password (`FACTORY_ADMIN_PASSWORD`) as
  an alternative to OIDC, with a brute-force brake.
- Wizard field **CloudStack OS type**, with suggestions from CloudStack.
- Configuration through `.env` only: `CSF_TEMPLATE_PREFIX` (template name
  prefix), `CS_ZONE` (registration zone), `CSF_INSPECT_CHANNEL` now also honoured
  by the GUI, host paths and ports.
- Documentation in `docs/` (installation, GUI guide, configuration, CloudStack
  prerequisites, troubleshooting) and the project wiki.
- Release workflow: image build, Trivy scan with a positive control, SBOM,
  end-to-end test of the Compose stack with a real template build on a KVM
  runner, publication of the tested image.

### Fixed
- A local GUI build of a distribution whose display name differs from its
  technical name (e.g. `ubuntu-26.04`, `opensuse-leap`) always ended in FAIL:
  the GUI looked for the image descriptor under a name derived from the slug.
- Build logs in the GUI no longer show raw terminal colour codes.

### Included from the initial code base
Templates for Debian 12/13, Ubuntu 22.04/24.04/26.04, Rocky Linux 8/9/10 and
openSUSE Leap with the common security and supervision layer, the offline
validation gate, the QEMU boot test, the live tier-3 test, CloudStack
registration and the host CVE controller - see the [README](README.md).

[1.0.0]: https://github.com/wd-ppisz/cs-factory/releases/tag/v1.0.0

# Security policy

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub issues,
discussions or pull requests.

Report them privately through GitHub's private vulnerability reporting:
open the repository's **Security** tab and choose **Report a vulnerability**
(GitHub Security Advisories). Include:

- the affected component (template layer, build scripts, GUI, CVE controller, deploy script),
- the version or commit,
- steps to reproduce or a proof of concept,
- the impact as you understand it.

We aim to acknowledge reports within a few working days and will keep you
informed while a fix is prepared. Once a fix is released we publish an advisory
and credit the reporter unless you prefer to stay anonymous.

## Scope

In scope:

- the template build pipeline (`build.sh`, `common/`, `distros/`) and anything it
  places into a template (QEMU guest agent restrictions, firstboot, watchdog,
  fail2ban, cloud-init configuration, inspection agent);
- the operator GUI (`gui/`), the CVE controller and the deploy script (`ci/`).

Out of scope: vulnerabilities in upstream distributions, cloud images or
third-party packages - please report those to the respective upstream projects.

## Supported versions

Only the latest release on the `main` branch receives security fixes.

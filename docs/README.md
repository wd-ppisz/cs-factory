# CloudStack Template Factory - documentation

| Document | For |
|---|---|
| [Installation](installation.md) | installing release 1.0 with Docker Compose, step by step: host, configuration, first build, CloudStack, TLS, upgrade, backup |
| [Using the GUI](gui-guide.md) | operators: every screen, building, adding distributions, registering, live E2E test |
| [Configuration](configuration.md) | every `.env` setting: host, sign-in (password / OIDC), CloudStack, build parameters, GitLab, manifests |
| [CloudStack prerequisites](cloudstack.md) | API account, SSVM download access, OS types, account settings for the templates, watchdog |
| [Troubleshooting](troubleshooting.md) | start-up, sign-in, build, registration and VM problems |

Background - what goes into a template, the validation gate, the test pyramid
and the host install without Docker - is in the [project README](../README.md).
Changes between versions: [CHANGELOG](../CHANGELOG.md).

The same pages are published in the
[project wiki](https://github.com/wd-ppisz/cs-factory/wiki); this directory is
their source.

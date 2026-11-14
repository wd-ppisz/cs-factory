# Contributing

Thanks for your interest in cs-factory.

- **Issues** - bug reports and feature requests are welcome. For security
  issues follow [SECURITY.md](SECURITY.md) instead.
- **Pull requests** - keep them focused; describe what changes in the built
  templates (if anything) and how you tested it.
- **Language** - code, comments, commit messages and documentation are in English.
- **Checks** - CI must be green: `bash -n` / `shellcheck -S warning`, `py_compile`,
  the unit tests and the scanners (see `.github/workflows/ci.yml`). Locally:

  ```sh
  make lint
  python3 -m unittest ci/test_cve_controller.py
  python3 -m unittest gui/test_app.py   # needs flask + authlib
  ```

- **Template changes** - anything that changes template content must keep the
  offline gate (`e2e/validate-offline.sh`) and the smoke boot
  (`e2e/smoke-boot.sh`) passing (`make release DISTRO=<distro>`), and bump
  `VERSION` in the same commit.
- **Line endings** - LF only (enforced by `.gitattributes`); files are copied
  into Linux images.
- **License** - by contributing you agree that your contributions are licensed
  under the Apache License, Version 2.0.

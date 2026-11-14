# cs-factory — helper targets. Building requires Linux with libguestfs-tools.
# validate-offline.sh is a GATE: exit != 0 => the build does not pass (see the CI config).
DISTRO  ?= debian-13
# release number: the VERSION file (same source as ci/gen-child.sh)
VERSION ?= $(shell tr -d '[:space:]' < VERSION)

# Path of the most recently built image — from the .env file written by build.sh
IMG = $(shell ls -t build/*.env 2>/dev/null | head -1 | xargs -r grep -h '^IMG=' | cut -d= -f2-)

# Artifact directory served over HTTP (/artifacts/) — CloudStack's SSVM downloads the
# image from here when the template is registered. CI publishes ONLY images that
# passed the validation gate.
ARTIFACTS_DIR ?= /srv/cs-factory/artifacts

.PHONY: lint test build validate smoke release publish clean

lint:
	shellcheck -S warning build.sh register.sh common/finalize.sh common/bin/csf-firstboot \
	  common/bin/csf-watchdog e2e/smoke-boot.sh e2e/validate-offline.sh e2e/tier2-cloudstack.sh \
	  ci/*.sh gui/install.sh docker/*.sh
	python3 -m py_compile common/bin/cloudcfg-tune.py common/bin/csf-inspect \
	  e2e/mock-vr/beacon-server.py e2e/qga-probe.py e2e/probe-ds-cloudstack.py e2e/tier3-features.py \
	  gui/cs.py gui/app.py
	@for m in distros/*.yaml; do \
	  yq -e '.name and .url and (.packages | length > 0)' "$$m" >/dev/null \
	    || { echo "incomplete manifest: $$m"; exit 1; }; \
	done
# A fleet-style "no automatic updates" apt policy does NOT belong in templates:
# templates serve tenant VMs, and fleet hosts should get their apt policy from
# configuration management. The 99-csf-no-auto-upgrades file must not sneak back
# into the repo.
	@! grep -rInE 'Unattended-Upgrade[[:space:]]+"0"|systemctl[[:space:]]+mask[[:space:]].*apt-daily' common/ build.sh \
	     | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(#|//)' \
	   || { echo "the common layer disables automatic apt updates — tenant templates must keep them enabled"; exit 1; }
	@echo "lint: OK"

test:
	python3 -m unittest ci/test_cve_controller.py

build:
	./build.sh $(DISTRO) $(VERSION)

validate:
	@test -n "$(IMG)" || { echo "no build/*.env — run make build first"; exit 1; }
	e2e/validate-offline.sh "$(IMG)"

smoke:
	@test -n "$(IMG)" || { echo "no build/*.env — run make build first"; exit 1; }
	e2e/smoke-boot.sh "$(IMG)"

# Artifact publication (only after PASS — see `release`). A missing directory is
# not an error (build on a laptop/WSL) — just a notice.
publish:
	@test -n "$(IMG)" || { echo "no build/*.env — run make build first"; exit 1; }
	@if [ -w "$(ARTIFACTS_DIR)" ]; then \
	  install -m0644 "$(IMG)" "$(ARTIFACTS_DIR)/" && \
	  install -m0644 $$(ls -t build/*.env | head -1) "$(ARTIFACTS_DIR)/" && \
	  echo "published: $(ARTIFACTS_DIR)/$$(basename $(IMG))"; \
	else \
	  echo "skipping publication — $(ARTIFACTS_DIR) is not writable"; \
	fi

# Full local/CI cycle: build + gate + BOOT + artifact publication.
#
# `smoke` is part of the gate for a reason: several templates were once UNBOOTABLE
# ("error: no such partition / grub rescue>") and still passed `validate`, because
# `validate` checks the image CONTENT — datasource, services, QGA, watchdog — and
# never BOOTS it. The boot test (`smoke-boot.sh`, boot under QEMU) existed from the
# start but was run by hand, and only on the one family the problem did not affect.
# Cost: ~3 min per distribution. Shipping an unbootable template to tenants costs
# far more.
release: build validate smoke publish

clean:
	rm -rf build/

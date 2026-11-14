# CloudStack Template Factory - container image (GUI + build toolchain).
#
# One image runs the operator GUI and everything a build needs: libguestfs
# (virt-customize, offline customisation), QEMU/KVM (boot test), the offline
# validation gate and the tier-3 live test. Templates are built INSIDE this
# container, so it needs /dev/kvm from the host (see docker-compose.yml).
#
# The process runs as the unprivileged user `factory` (uid/gid 10001); the code
# under /opt/cs-factory is owned by root and read-only for it. Everything the
# factory writes lives under /srv/cs-factory (volumes).

ARG DEBIAN_IMAGE=debian:trixie-20261027-slim
FROM ${DEBIAN_IMAGE}

ARG CSF_RELEASE=dev
ARG CSF_COMMIT=""

LABEL org.opencontainers.image.title="CloudStack Template Factory" \
      org.opencontainers.image.description="Offline builder of hardened CloudStack/KVM templates from upstream cloud images, with an operator GUI" \
      org.opencontainers.image.source="https://github.com/wd-ppisz/cs-factory" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${CSF_RELEASE}" \
      org.opencontainers.image.revision="${CSF_COMMIT}"

# --no-install-recommends keeps out what the factory never uses (desktop QEMU
# front-ends, UEFI firmware - builds and boot tests use BIOS).
# linux-image-amd64: libguestfs builds its appliance (supermin) from the kernel
# INSIDE the container; the host kernel is not readable from here.
# libguestfs-xfs: Rocky/RHEL images use XFS.
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libguestfs-tools guestfs-tools libguestfs-xfs supermin linux-image-amd64 \
      qemu-system-x86 qemu-utils \
      python3 python3-flask python3-authlib python3-requests gunicorn \
      yq jq curl wget ca-certificates make file parted genisoimage openssh-client \
      xz-utils zstd bzip2 procps; \
    apt-get clean; rm -rf /var/lib/apt/lists/*; \
    # supermin reads the kernel image; Debian ships it 0600
    chmod 0644 /boot/vmlinuz-*; \
    groupadd -g 10001 factory; \
    useradd -u 10001 -g factory -d /srv/cs-factory/state -s /usr/sbin/nologin -M factory; \
    install -d -o factory -g factory -m 0755 /srv/cs-factory \
      /srv/cs-factory/artifacts /srv/cs-factory/work

COPY --chown=root:root . /opt/cs-factory
RUN set -eux; \
    rm -rf /opt/cs-factory/.git /opt/cs-factory/build; \
    # build output (images, logs, descriptors) goes to the work volume
    ln -s /srv/cs-factory/work/build /opt/cs-factory/build; \
    chmod -R a+rX,go-w /opt/cs-factory; \
    # scripts are executed directly (./build.sh, e2e/*.sh): never rely on the
    # checkout keeping the exec bit (a Windows checkout drops it)
    find /opt/cs-factory -type f \( -name '*.sh' -o -name '*.py' -o -path '*/common/bin/*' \) \
      -exec chmod 0755 {} +; \
    install -m 0755 /opt/cs-factory/docker/entrypoint.sh /usr/local/bin/cs-factory-entrypoint

ENV CSF_RELEASE=${CSF_RELEASE} \
    CSF_COMMIT=${CSF_COMMIT} \
    FACTORY_REPO=/opt/cs-factory \
    FACTORY_ARTIFACTS=/srv/cs-factory/artifacts \
    CSF_LOCAL_DISTROS=/srv/cs-factory/work/distros \
    CSF_IMAGE_CACHE=/srv/cs-factory/work/cache \
    CS_CREDS_FILE=/srv/cs-factory/work/state/cs-creds.json \
    LIBGUESTFS_BACKEND=direct \
    LIBGUESTFS_CACHEDIR=/srv/cs-factory/work/cache/guestfs \
    TMPDIR=/srv/cs-factory/work/tmp \
    HOME=/srv/cs-factory/work/state \
    FACTORY_GIT_PULL=0 \
    FACTORY_CONFIG_HINT=".env (next to docker-compose.yml)" \
    FACTORY_RESTART_HINT="run: docker compose up -d" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER factory:factory
WORKDIR /opt/cs-factory/gui
EXPOSE 8500

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8500/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/cs-factory-entrypoint"]
# One worker: the build queue lives in the process. Threads serve the GUI while
# a build runs; --timeout 0 because log/CI views may hold a request open.
CMD ["gunicorn", "--workers", "1", "--threads", "16", "--worker-class", "gthread", \
     "--timeout", "0", "--bind", "0.0.0.0:8500", "--access-logfile", "-", "app:app"]

#!/usr/bin/env bash
# Registers a built template in CloudStack via cmk (CloudMonkey).
# Name follows the same convention as build.sh.
#
# Requires a configured cmk and the variables: CS_OSTYPEID, CS_ZONEID.
# Usage: ./register.sh https://images.example.com/template-debian-13-v1_1.qcow2 debian-13 1.1
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

IMG_URL="${1:?usage: register.sh <https-url-to-qcow2> <distro> [version]}"
DISTRO="${2:?}"
# default release number from the VERSION file — same source as CI and the Makefile
VERSION="${3:-$(tr -d '[:space:]' < "$HERE/VERSION")}"
M="$HERE/distros/${DISTRO}.yaml"
if [ ! -f "$M" ] && [ -n "${CSF_LOCAL_DISTROS:-}" ]; then M="$CSF_LOCAL_DISTROS/${DISTRO}.yaml"; fi
NAME="$(yq -r '.name' "$M")"
PREFIX="${CSF_TEMPLATE_PREFIX-Template}"
TEMPLATE_NAME="${PREFIX:+$PREFIX }${NAME} v${VERSION}"

: "${CS_OSTYPEID:?set CS_OSTYPEID (OS type id in CloudStack)}"
: "${CS_ZONEID:?set CS_ZONEID}"

# --- virtio-serial channel for csf-inspect ---------------------------------------
# extraconfig-1 in the TEMPLATE DETAILS is copied into the details of every VM at
# deploy time and appended to the domain configuration on every start.
#
# The XML is passed RAW, NOT url-encoded: the API parameter `extraconfig` is DECODED
# by CloudStack on write, but a template detail value is copied VERBATIM — encoded
# XML reached the VM as the text `%3Cdevices%3E…`, libvirt ignored it and the channel
# was NOT created (the VM started normally, so the symptom was silent). The HTTP
# transport encodes it once by itself.
#
# REQUIRED on the CloudStack side (Account scope, root admin):
#      enable.additional.vm.configuration = true
#      allow.additional.vm.configuration.list.kvm = devices,channel,source,target,address
#    (EVERY nested tag). Without this CloudStack silently drops the configuration.
# To disable: CSF_INSPECT_CHANNEL=off ./register.sh ...
CSF_INSPECT_CHANNEL="${CSF_INSPECT_CHANNEL:-on}"
EXTRA_ARGS=()
if [ "$CSF_INSPECT_CHANNEL" = "on" ]; then
  CHANNEL_XML='<devices><channel type="unix"><target type="virtio" name="org.csfactory.support.0"/></channel></devices>'
  EXTRA_ARGS+=( "details[0].extraconfig-1=$CHANNEL_XML" )
fi

cmk register template \
  name="$TEMPLATE_NAME" \
  displaytext="$TEMPLATE_NAME" \
  url="$IMG_URL" \
  hypervisor=KVM \
  format=QCOW2 \
  ostypeid="$CS_OSTYPEID" \
  zoneid="$CS_ZONEID" \
  passwordenabled=true \
  isdynamicallyscalable=true \
  requireshvm=true \
  details[0].rootDiskController=virtio \
  ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}

echo ">> registered: $TEMPLATE_NAME (csf-inspect channel: $CSF_INSPECT_CHANNEL)"

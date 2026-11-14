#!/usr/bin/env bash
# Tier-2: acceptance on a REAL CloudStack (staging). Validates what cannot be
# checked locally: the CloudStack datasource (VR) + password reset + user-data via the VR.
#
# Requires a configured cmk and the environment variables below.
# Usage: CS_ZONEID=.. CS_TEMPLATEID=.. CS_OFFERINGID=.. CS_NETWORKID=.. ./tier2-cloudstack.sh
set -euo pipefail
: "${CS_ZONEID:?}"
: "${CS_TEMPLATEID:?id of the registered template (register.sh)}"
: "${CS_OFFERINGID:?service offering id}"
: "${CS_NETWORKID:?}"

UD="$(printf '#cloud-config\nruncmd:\n  - [ touch, /run/e2e-userdata-ok ]\n' | base64 -w0)"

echo ">> deploying test VM"
VMID="$(cmk deploy virtualmachine \
  zoneid="$CS_ZONEID" templateid="$CS_TEMPLATEID" \
  serviceofferingid="$CS_OFFERINGID" networkids="$CS_NETWORKID" \
  userdata="$UD" --output json | yq -r '.virtualmachine.id')"
echo "   VMID=$VMID"

echo ">> password reset (CloudStack mechanism -> VR password server)"
# cloudmonkey addresses the API as: verb + rest-of-the-name-as-one-token
# (resetPasswordForVirtualMachine -> reset passwordforvirtualmachine)
NEWPASS="$(cmk reset passwordforvirtualmachine id="$VMID" --output json \
  | yq -r '.virtualmachine.password')"
if [ -n "$NEWPASS" ] && [ "$NEWPASS" != "null" ]; then
  echo "   OK: CloudStack returned a new password"
else
  echo "   FAIL: no password in the response"; exit 1
fi

echo ">> reboot so the password and user-data take effect"
cmk reboot virtualmachine id="$VMID" >/dev/null

cat <<'EOF'
>> MANUAL in-guest verification (requires access to the staging VM: console/SSH):
   1) cloud-id                      -> expected: cloudstack
   2) test -f /run/e2e-userdata-ok  -> user-data via the VR worked
   3) log in with the new password  -> password reset works
   4) reboot; host key fingerprint unchanged -> ssh != always OK
   Cleanup: cmk destroy virtualmachine id=<VMID> expunge=true
EOF

#!/bin/bash
# Virtual SR-IOV switchdev tier for the tc flower backend.
#
# Boots a throw-away KVM guest with an emulated Intel 82576 (igb) SR-IOV NIC,
# turns it into a switchdev NIC with VF representors using the out-of-tree
# switchdev-mock-driver, and runs guest.sh in it (see there for the checks).
# Nothing is installed or changed on the host besides files under WORKDIR.
#
# Needs Linux with /dev/kvm, qemu-system-x86_64 >= 8.1 (igb SR-IOV),
# qemu-img, cloud-localds (cloud-image-utils), curl, git, tar and Go.
#
#   make test-sriov-switchdev-vm
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORKDIR=${WORKDIR:-$REPO/.cache/sriov-switchdev-vm}

# Pinned inputs. The driver is GPL-2.0 and only ever built and loaded inside
# the guest; nothing of it is part of this repository or its binaries.
MOCK_DRIVER_REPO=https://github.com/SchSeba/switchdev-mock-driver.git
MOCK_DRIVER_SHA=da72a741c756c705fb44a38065d0410b51b99085
IMAGE_URL=https://cloud-images.ubuntu.com/releases/24.04/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img
IMAGE_SHA256=04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94
GUEST_TIMEOUT=${GUEST_TIMEOUT:-1200} # seconds

[ "$(uname -s)" = Linux ] || { echo "needs Linux with KVM" >&2; exit 1; }
[ -w /dev/kvm ] || { echo "needs write access to /dev/kvm" >&2; exit 1; }
for tool in qemu-system-x86_64 qemu-img cloud-localds curl git tar go sha256sum; do
	command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
qemu-system-x86_64 --version | head -n1

mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Guest image, verified against the pinned checksum.
if ! echo "$IMAGE_SHA256  base.img" | sha256sum -c --quiet 2>/dev/null; then
	curl -fsSL --retry 3 -o base.img "$IMAGE_URL"
	echo "$IMAGE_SHA256  base.img" | sha256sum -c --quiet
fi

# Payload: the driver source at the pinned commit, the test binary, guest.sh.
rm -rf payload && mkdir -p payload/switchdev-mock-driver
git -C payload/switchdev-mock-driver init -q
git -C payload/switchdev-mock-driver fetch -q --depth 1 "$MOCK_DRIVER_REPO" "$MOCK_DRIVER_SHA"
git -C payload/switchdev-mock-driver checkout -q FETCH_HEAD
[ "$(git -C payload/switchdev-mock-driver rev-parse HEAD)" = "$MOCK_DRIVER_SHA" ]
rm -rf payload/switchdev-mock-driver/.git
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$WORKDIR/payload/tcflower.test" ./pkg/tcflower/)
cp "$HERE/guest.sh" payload/guest.sh
tar -C payload -cf payload.tar .

# The guest script writes to /dev/console, not /dev/ttyS0: opening the tty
# itself would make it the script's controlling terminal, and the serial
# getty's hangup would kill the script.
cat >user-data <<'EOF'
#cloud-config
runcmd:
  - [bash, -c, "mkdir -p /opt/payload && tar -xf /dev/vdb -C /opt/payload && bash /opt/payload/guest.sh >/dev/console 2>&1; poweroff"]
EOF
cloud-localds seed.img user-data
rm -f disk.qcow2
qemu-img create -q -f qcow2 -b base.img -F qcow2 disk.qcow2 20G

# q35 with the igb PF behind a PCIe root port; management NIC is virtio.
echo "== booting guest (log: $WORKDIR/guest.log)"
timeout "$GUEST_TIMEOUT" qemu-system-x86_64 \
	-machine q35,accel=kvm -cpu host -smp 4 -m 4096 \
	-display none -serial stdio -no-reboot \
	-drive file=disk.qcow2,if=virtio,format=qcow2 \
	-drive file=payload.tar,if=virtio,format=raw,readonly=on \
	-drive file=seed.img,if=virtio,format=raw,readonly=on \
	-netdev user,id=mgmt -device virtio-net-pci,netdev=mgmt \
	-device pcie-root-port,id=rp1,bus=pcie.0,chassis=1 \
	-netdev user,id=sriov0,restrict=on \
	-device igb,bus=rp1,netdev=sriov0,mac=52:54:00:5e:10:01 \
	</dev/null | tee guest.log || true

echo "== summary"
grep -E "^(== guest kernel|CHECK |PROBE |GUEST_DONE)" guest.log || true
rm -f disk.qcow2 payload.tar seed.img
grep -q "^GUEST_DONE failed=0" guest.log || { echo "virtual switchdev tier FAILED (full log: $WORKDIR/guest.log)" >&2; exit 1; }
echo "virtual switchdev tier passed"

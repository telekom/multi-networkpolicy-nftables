#!/bin/bash
# Runs inside the VM started by run.sh, as root. Turns the emulated igb NIC
# into a switchdev NIC with the switchdev-mock-driver, checks what that gives
# us step by step, and runs the tc flower backend's TestVirtualSwitchdev
# against it.
#
# Output protocol, read by run.sh and by people:
#   CHECK <name>: PASS|FAIL   something the tier needs; a FAIL fails the run
#   PROBE <name>: yes|no      what this kernel/driver combination supports;
#                             informational
#   GUEST_DONE failed=<n>     last line
set -u
cd "$(dirname "$0")" || exit 1

NS_POD=mnp-e2e-a   # names and addresses TestVirtualSwitchdev expects
NS_PEER=mnp-e2e-b
IP_POD=10.244.0.1
IP_PEER=10.244.0.2
failed=0

run() { # run <label> <command...>: run, print the tail of the output indented
	local out rc
	out=$("${@:2}" 2>&1)
	rc=$?
	[ -z "$out" ] || printf '%s\n' "$out" | tail -n "${TAIL:-20}" | sed 's/^/    /'
	return $rc
}
check() {
	if run "$@"; then echo "CHECK $1: PASS"; else
		echo "CHECK $1: FAIL"
		failed=$((failed + 1))
	fi
}
probe() { if run "$@"; then echo "PROBE $1: yes"; else echo "PROBE $1: no"; fi; }

echo "== guest kernel: $(uname -r)"

export DEBIAN_FRONTEND=noninteractive
check packages bash -c "apt-get update -qq && apt-get install -y -qq build-essential \
	linux-headers-$(uname -r) linux-modules-extra-$(uname -r) \
	iproute2 netcat-openbsd iputils-ping ethtool pciutils kmod >/dev/null"

# --- the emulated igb PF ---
PF=$(lspci -Dn -d 8086:10c9 | awk 'NR==1 {print $1}')
P=/sys/bus/pci/devices/$PF
check igb-pf-present test -n "$PF" -a -e "$P/sriov_totalvfs"
echo "    PF $PF driver=$(basename "$(readlink -f "$P/driver" 2>/dev/null)") totalvfs=$(cat "$P/sriov_totalvfs" 2>/dev/null)"

# --- build and bind the mock driver (same steps as its scripts/guest.sh) ---
TAIL=40 check mock-driver-build make -C "/lib/modules/$(uname -r)/build" M="$PWD/switchdev-mock-driver/driver" modules
MODULE=$PWD/switchdev-mock-driver/driver/mock_smartnic.ko
bind_pf() {
	modprobe -r igbvf 2>/dev/null
	modprobe sch_ingress && modprobe cls_flower && modprobe act_mirred && modprobe act_gact || return 1
	insmod "$MODULE" target_pf="$PF" allow_igb_emulation=1 || return 1
	echo mock_smartnic_pf >"$P/driver_override" || return 1
	[ ! -L "$P/driver" ] || echo "$PF" >"$P/driver/unbind" || return 1
	echo "$PF" >/sys/bus/pci/drivers/mock_smartnic_pf/bind
}
check mock-driver-bind bind_pf
# udev renames the new netdevs; every name is read only after it has settled.
settle() { udevadm settle --timeout=20 2>/dev/null; }
pf_netdev() { settle; ls "$P/net" 2>/dev/null | head -n1; }
PFDEV=$(pf_netdev)
[ -z "$PFDEV" ] || ip link set "$PFDEV" up

create_vfs() {
	echo 2 >"$P/sriov_numvfs" || return 1
	local vf bdf
	for vf in "$P"/virtfn*; do
		bdf=$(basename "$(readlink -f "$vf")")
		[ -L "$vf/driver" ] && continue
		echo mock_smartnic_vf >"$vf/driver_override" || return 1
		echo "$bdf" >/sys/bus/pci/drivers/mock_smartnic_vf/bind || return 1
	done
}
check sriov-create-vfs create_vfs
VF0=$(basename "$(readlink -f "$P/virtfn0" 2>/dev/null)")
VF1=$(basename "$(readlink -f "$P/virtfn1" 2>/dev/null)")

check devlink-eswitch-switchdev bash -c "devlink dev eswitch set pci/$PF mode switchdev && devlink dev eswitch show pci/$PF"
PFDEV=$(pf_netdev)
ip link set "$PFDEV" up

# --- what the backend's discovery needs from sysfs ---
representor() { # representor <vf index>: netdev with the PF's switch id and port name pf*vf<index>
	local d sw
	sw=$(cat "/sys/class/net/$PFDEV/phys_switch_id" 2>/dev/null)
	[ -n "$sw" ] || return 1
	for d in /sys/class/net/*; do
		[ "$(cat "$d/phys_switch_id" 2>/dev/null)" = "$sw" ] || continue
		case "$(cat "$d/phys_port_name" 2>/dev/null)" in *vf"$1") basename "$d"; return 0 ;; esac
	done
	return 1
}
R0=$(representor 0)
R1=$(representor 1)
check representors-phys-switch-id-and-port-name bash -c "test -n '$R0' -a -n '$R1' && for d in $PFDEV $R0 $R1; do echo \"\$d switch_id=\$(cat /sys/class/net/\$d/phys_switch_id) port_name=\$(cat /sys/class/net/\$d/phys_port_name 2>/dev/null)\"; done"
check pci-physfn-virtfn-links bash -c "test \"\$(basename \$(readlink -f /sys/bus/pci/devices/$VF0/physfn))\" = $PF && test \"\$(basename \$(readlink -f $P/virtfn1))\" = $VF1 && echo '$VF0 and $VF1 -> physfn $PF'"

# --- two VFs as net1 in two netns, representors bridged ---
settle
V0=$(ls "/sys/bus/pci/devices/$VF0/net" 2>/dev/null | head -n1)
V1=$(ls "/sys/bus/pci/devices/$VF1/net" 2>/dev/null | head -n1)
to_netns() { # to_netns <netdev> <netns> <address>
	ip netns add "$2" && ip link set "$1" netns "$2" && ip -n "$2" link set "$1" name net1 &&
		ip -n "$2" addr add "$3/24" dev net1 && ip -n "$2" link set net1 up && ip -n "$2" link set lo up
}
check vf-netdevs-into-netns bash -c "$(declare -f to_netns); test -n '$V0' -a -n '$V1' && to_netns $V0 $NS_POD $IP_POD && to_netns $V1 $NS_PEER $IP_PEER"
probe vf-bus-info-is-pci-address bash -c "ip netns exec $NS_POD ethtool -i net1 | tee /dev/stderr | grep -q 'bus-info: $VF0'"

ip link add br-mock type bridge && ip link set br-mock up
for r in $R0 $R1; do ip link set "$r" master br-mock && ip link set "$r" up; done
sleep 2
ping_peer() { ip netns exec $NS_POD ping -c 2 -W 2 $IP_PEER; }
check vf-to-vf-traffic-via-bridged-representors ping_peer

# --- tc flower on a representor: what works where ---
tc qdisc add dev "$R0" clsact
flt() { tc filter add dev "$R0" "$@"; }
unflt() { tc filter del dev "$R0" ingress 2>/dev/null; tc filter del dev "$R0" egress 2>/dev/null; }

flt ingress protocol ip pref 10 flower skip_hw ip_proto icmp action drop
probe sw-ingress-drop-blocks-vf-traffic bash -c "! ip netns exec $NS_POD ping -c 2 -W 1 $IP_PEER"
unflt
flt egress protocol ip pref 10 flower skip_hw ip_proto icmp action drop
probe sw-egress-drop-blocks-traffic-to-vf bash -c "! ip netns exec $NS_POD ping -c 2 -W 1 $IP_PEER"
unflt
probe sw-goto-chain flt ingress protocol all pref 1 flower skip_hw action goto chain 2
unflt
modprobe act_ct 2>/dev/null
probe sw-act-ct flt ingress protocol ip pref 10 flower skip_hw ct_state -trk action ct zone 7 pipe action goto chain 3
unflt

probe hw-ingress-drop-accepted flt ingress protocol ip pref 10 flower skip_sw ip_proto icmp action drop
probe hw-ingress-drop-blocks-vf-traffic bash -c "! ip netns exec $NS_POD ping -c 2 -W 1 $IP_PEER"
tc -s filter show dev "$R0" ingress 2>&1 | grep -E "in_hw|not_in_hw|Sent" | sed 's/^/    /'
unflt
probe hw-ingress-pass-accepted flt ingress protocol ip pref 10 flower skip_sw ip_proto icmp action pass
unflt
probe hw-goto-chain-accepted flt ingress protocol all pref 1 flower skip_sw action goto chain 2
unflt
probe hw-nonzero-chain-accepted flt ingress protocol ip pref 10 chain 2 flower skip_sw ip_proto icmp action drop
unflt
probe hw-egress-drop-accepted flt egress protocol ip pref 10 flower skip_sw ip_proto icmp action drop
unflt
probe hw-ipv6-match-accepted flt ingress protocol ipv6 pref 10 flower skip_sw ip_proto icmpv6 action drop
unflt
tc qdisc del dev "$R0" clsact
check traffic-restored-after-probes ping_peer

# --- the backend itself ---
chmod +x ./tcflower.test
TAIL=80 check go-TestVirtualSwitchdev env TCFLOWER_SWITCHDEV_VFS="$VF0,$VF1" ./tcflower.test \
	-test.v -test.count=1 -test.timeout 5m -test.run '^TestVirtualSwitchdev$'

echo "== kernel log (tail)"
dmesg | grep -v audit | tail -n 30 | sed 's/^/    /'
echo "GUEST_DONE failed=$failed"

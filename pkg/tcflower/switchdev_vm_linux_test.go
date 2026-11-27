//go:build linux

/*
Copyright 2026 Deutsche Telekom AG.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tcflower

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TestVirtualSwitchdev runs the backend against real PCI VFs with real VF
// representors: an emulated igb NIC in a VM, driven by the out-of-tree
// switchdev-mock-driver (see hack/sriov-switchdev-vm). The harness prepares
// two VFs, each as "net1" in its own netns (mnp-e2e-a is the "pod",
// mnp-e2e-b its peer, with the addresses of the veth tests), and bridges
// their representors. It names the VFs in TCFLOWER_SWITCHDEV_VFS as
// "<pod VF PCI address>,<peer VF PCI address>".
//
// Unlike netdevsim this has real PCI sysfs links, real VF netdevs and traffic
// that passes the representors. The mock driver's own offload engine only
// takes redirect/drop rules in chain 0, so filters are installed in software
// mode (skip_hw); what the kernel says to a skip_sw install is logged.
func TestVirtualSwitchdev(t *testing.T) {
	vfs := strings.Split(os.Getenv("TCFLOWER_SWITCHDEV_VFS"), ",")
	if len(vfs) != 2 {
		t.Skip("set TCFLOWER_SWITCHDEV_VFS=<pod VF>,<peer VF> to run (see make test-sriov-switchdev-vm)")
	}
	podNetns := "/run/netns/" + e2eNSA
	podVF := controllers.InterfaceInfo{NetattachName: testNet, InterfaceName: "net1", PCIAddress: vfs[0]}
	peerVF := controllers.InterfaceInfo{NetattachName: testNet, InterfaceName: "net1", PCIAddress: vfs[1]}
	software := controllers.CommonRuleConfig{TCOffloadMode: "software", CTMode: "off"}

	// Discovery over the real PCI and net sysfs.
	rep, err := ResolveRepresentor("", podVF)
	if err != nil || rep.IfIndex == 0 {
		t.Fatalf("ResolveRepresentor(%s) = %+v, %v", podVF.PCIAddress, rep, err)
	}
	peerRep, err := ResolveRepresentor("", peerVF)
	if err != nil || peerRep.Name == rep.Name {
		t.Fatalf("ResolveRepresentor(%s) = %+v, %v; want a representor other than %s", peerVF.PCIAddress, peerRep, err, rep.Name)
	}
	t.Logf("pod VF %s -> representor %s (ifindex %d); peer VF %s -> %s", podVF.PCIAddress, rep.Name, rep.IfIndex, peerVF.PCIAddress, peerRep.Name)

	// VF-to-pod binding with the real bus info of a VF netdev in a netns.
	if err := CheckEnforceable("", software, podNetns, podVF); err != nil {
		t.Fatalf("CheckEnforceable(pod VF in its own netns): %v", err)
	}
	if err := CheckEnforceable("", software, podNetns, peerVF); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("CheckEnforceable(peer's VF claimed by the pod) = %v, want ErrNotOwned", err)
	}

	t.Cleanup(func() { _ = FlushStale("", nil) })
	tcp := corev1.ProtocolTCP
	allow := func(port int) *multiv1beta1.MultiNetworkPolicy {
		p := intstr.FromInt32(int32(port)) //nolint:gosec // test port
		return makePolicy("vm-egress", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress}, nil,
			[]multiv1beta1.MultiNetworkPolicyEgressRule{{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{{Protocol: &tcp, Port: &p}},
				To:    []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: e2eIPB + "/32"}}},
			}})
	}
	apply := func(cfg controllers.CommonRuleConfig, policies ...*multiv1beta1.MultiNetworkPolicy) error {
		t.Helper()
		podInfo := &controllers.PodInfo{Name: "target", Namespace: testNS, NetNSPath: podNetns, Interfaces: []controllers.InterfaceInfo{podVF}}
		return Apply(context.Background(), newFakeDeps(), cfg, policyMapOf(policies...), targetPod(nil), podInfo, "")
	}
	mustApply := func(what string, cfg controllers.CommonRuleConfig, policies ...*multiv1beta1.MultiNetworkPolicy) {
		t.Helper()
		if err := apply(cfg, policies...); err != nil {
			t.Fatalf("Apply(%s): %v", what, err)
		}
	}

	// Real packets from the pod VF through both representors to the peer VF.
	assertTCPConnect(t, e2eAllowPT, true)
	assertTCPConnect(t, e2eDenyPT, true)

	mustApply("egress policy", software, allow(e2eAllowPT))
	assertTCPConnect(t, e2eAllowPT, true)
	assertTCPConnect(t, e2eDenyPT, false)

	// Policy change through the generation switch.
	mustApply("changed egress policy", software, allow(e2eDenyPT))
	assertTCPConnect(t, e2eDenyPT, true)
	assertTCPConnect(t, e2eAllowPT, false)

	// --tc-default-deny without any policy, and off again.
	deny := software
	deny.TCDefaultDenyEgress = true
	mustApply("default deny egress", deny)
	assertTCPConnect(t, e2eAllowPT, false)
	mustApply("no policy, no default deny", software)
	assertTCPConnect(t, e2eAllowPT, true)

	// Conntrack in the software datapath: ingress denied by default, replies
	// to the allowed outgoing connection still pass.
	ct := controllers.CommonRuleConfig{TCOffloadMode: "software", CTMode: "auto", TCDefaultDenyIngress: true}
	if err := apply(ct, allow(e2eAllowPT)); err != nil {
		t.Errorf("Apply(conntrack, default deny ingress): %v", err)
	} else {
		assertTCPConnect(t, e2eAllowPT, true)
		assertTCPConnect(t, e2eDenyPT, false)
	}
	mustApply("cleanup before the hardware attempt", software)

	// What does this "NIC" say to hardware-only filters?
	hardware := controllers.CommonRuleConfig{TCOffloadMode: "hardware", CTMode: "off"}
	if err := apply(hardware, allow(e2eAllowPT)); err != nil {
		t.Logf("skip_sw install refused: %v", err)
	} else {
		t.Log("skip_sw install accepted")
		assertTCPConnect(t, e2eAllowPT, true)
		assertTCPConnect(t, e2eDenyPT, false)
	}

	if err := FlushStale("", nil); err != nil {
		t.Fatalf("FlushStale: %v", err)
	}
	assertTCPConnect(t, e2eDenyPT, true)
}

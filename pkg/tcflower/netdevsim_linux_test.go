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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	tc "github.com/florianl/go-tc"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

// kernelTestSkip skips a test that needs root or a kernel feature. With
// TCFLOWER_REQUIRE_KERNEL_TESTS set, as in CI, it fails the test instead, so a
// test that silently stopped running cannot go unnoticed.
func kernelTestSkip(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("TCFLOWER_REQUIRE_KERNEL_TESTS") != "" {
		t.Fatalf("TCFLOWER_REQUIRE_KERNEL_TESTS is set but the test cannot run: "+format, args...)
	}
	t.Skipf(format, args...)
}

const (
	nsimID   = "4217"
	nsimBus  = "/sys/bus/netdevsim"
	nsimPF   = "0000:af:00.0" // PCI addresses of the sysfs fixture, see below
	nsimVF0  = "0000:af:00.2"
	nsimVF1  = "0000:af:00.3"
	nsimNet  = testNet
	nsimWait = 5 * time.Second
)

// TestNetdevsimSwitchdev runs the backend against a simulated switchdev NIC:
// a netdevsim device with two VFs in eswitch mode switchdev. Its VF
// representors are real netdevs with a real phys_switch_id and phys_port_name,
// so this covers, against a real kernel:
//
//   - representor discovery from sysfs,
//   - Apply with the real netlink driver on a representor: the direction
//     mapping, the dispatch filter and generation chains, an atomic policy
//     change, --tc-default-deny coming and going,
//   - what happens when the NIC refuses to offload a skip_sw filter,
//   - FlushStale, as used after each pass, on shutdown and by
//     --tc-cleanup-on-start.
//
// What netdevsim cannot do, and this test therefore does not show:
//
//   - netdevsim is not a PCI device, so the PCI links from a VF to its PF
//     (physfn, virtfnN) do not exist. They are the only faked part: a fixture
//     root whose sys/bus/pci tree is made of symlinks, with sys/class/net
//     pointing at the real one.
//   - There are no VF netdevs and no traffic through the representors, so
//     enforcement itself is tested on a veth pair (TestSoftwareEnforcementE2E,
//     TestSoftwareConntrackE2E) and the VF-to-pod check against a fake.
//   - netdevsim does not offload flower, so skip_sw filters are refused.
func TestNetdevsimSwitchdev(t *testing.T) {
	// Opt-in: it creates a netdevsim device on the host. make test-tc-kernel
	// sets this.
	if os.Getenv("TCFLOWER_NETDEVSIM") == "" {
		t.Skip("set TCFLOWER_NETDEVSIM=1 to run the netdevsim test (see make test-tc-kernel)")
	}
	if os.Geteuid() != 0 {
		kernelTestSkip(t, "needs root")
	}
	if _, err := os.Stat(filepath.Join(nsimBus, "new_device")); err != nil {
		kernelTestSkip(t, "the netdevsim module is not loaded: %v", err)
	}
	if _, err := exec.LookPath("devlink"); err != nil {
		kernelTestSkip(t, "devlink (iproute2) not found")
	}

	// One port, two VFs, eswitch in switchdev mode. Teardown goes back the
	// same way (legacy mode, no VFs, delete), as the kernel selftests do, and
	// never waits forever on the kernel.
	handle := "netdevsim/netdevsim" + nsimID
	dev := filepath.Join(nsimBus, "devices", "netdevsim"+nsimID)
	teardown := func() {
		if os.Getenv("TCFLOWER_NETDEVSIM_KEEP") != "" {
			t.Logf("netdevsim teardown: TCFLOWER_NETDEVSIM_KEEP is set, leaving netdevsim%s in place", nsimID)
			return
		}
		// Each step runs under timeout(1) so a step the kernel does not
		// return from cannot hold up the test run.
		for _, step := range []string{
			"devlink dev eswitch set " + handle + " mode legacy",
			"echo 0 > " + filepath.Join(dev, "sriov_numvfs"),
			"echo " + nsimID + " > " + filepath.Join(nsimBus, "del_device"),
		} {
			t.Logf("netdevsim teardown: %s", step)
			if out, err := exec.Command("timeout", "-s", "KILL", "20", "sh", "-c", step).CombinedOutput(); err != nil {
				t.Errorf("netdevsim teardown: %s: %v: %s", step, err, out)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(nsimBus, "new_device"), []byte(nsimID+" 1"), 0o200); err != nil {
		kernelTestSkip(t, "cannot create a netdevsim device: %v", err)
	}
	t.Cleanup(teardown)
	if err := os.WriteFile(filepath.Join(dev, "sriov_numvfs"), []byte("2"), 0o200); err != nil {
		kernelTestSkip(t, "netdevsim cannot create VFs: %v", err)
	}
	if out, err := exec.Command("devlink", "dev", "eswitch", "set", handle, "mode", "switchdev").CombinedOutput(); err != nil {
		kernelTestSkip(t, "netdevsim cannot switch to switchdev mode: %v: %s", err, out)
	}
	// udev renames the new netdevs; wait for it so the names below are final.
	_ = exec.Command("udevadm", "settle", "--timeout=15").Run()

	// The PF port and the two VF representors, straight from the real sysfs.
	// Netdevs are identified by ifindex, which a rename does not change.
	var pfNetdev string
	reps := map[string]int{} // phys_port_name -> ifindex
	deadline := time.Now().Add(nsimWait)
	for (len(reps) < 2 || pfNetdev == "") && time.Now().Before(deadline) {
		entries, _ := os.ReadDir(filepath.Join(dev, "net"))
		for _, e := range entries {
			port := readTrimmedFile(filepath.Join("/sys/class/net", e.Name(), "phys_port_name"))
			if _, isVF := parseVFIndexFromPortName(port); isVF {
				if idx := readIfIndex("", e.Name()); idx != 0 {
					reps[port] = idx
				}
			} else if port != "" {
				pfNetdev = e.Name()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(reps) < 2 || pfNetdev == "" {
		kernelTestSkip(t, "netdevsim created no VF representors (pf=%q representors=%v)", pfNetdev, reps)
	}
	t.Logf("netdevsim%s: pf=%s representor ifindexes=%v switch id=%s", nsimID, pfNetdev, reps,
		readTrimmedFile(filepath.Join("/sys/class/net", pfNetdev, "phys_switch_id")))

	// Sysfs fixture: only the PCI links are made up.
	root := t.TempDir()
	mustSymlink := func(target, link string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	pci := filepath.Join(root, "sys", "bus", "pci", "devices")
	mustSymlink("/sys/class/net", filepath.Join(root, "sys", "class", "net"))
	mustSymlink(filepath.Join("/sys/class/net", pfNetdev), filepath.Join(pci, nsimPF, "net", pfNetdev))
	for i, vf := range []string{nsimVF0, nsimVF1} {
		mustSymlink(filepath.Join("..", nsimPF), filepath.Join(pci, vf, "physfn"))
		mustSymlink(filepath.Join("..", vf), filepath.Join(pci, nsimPF, "virtfn"+string(rune('0'+i))))
	}

	// --- discovery ---
	vf0 := controllers.InterfaceInfo{NetattachName: nsimNet, InterfaceName: "net1", PCIAddress: nsimVF0}
	vf1 := controllers.InterfaceInfo{NetattachName: nsimNet, InterfaceName: "net1", PCIAddress: nsimVF1}
	rep0, err := ResolveRepresentor(root, vf0)
	if err != nil || rep0.IfIndex != reps["pf0vf0"] {
		t.Fatalf("ResolveRepresentor(vf0) = %+v, %v; want the netdev with ifindex %d", rep0, err, reps["pf0vf0"])
	}
	rep1, err := ResolveRepresentor(root, vf1)
	if err != nil || rep1.IfIndex != reps["pf0vf1"] {
		t.Fatalf("ResolveRepresentor(vf1) = %+v, %v; want the netdev with ifindex %d", rep1, err, reps["pf0vf1"])
	}
	if got := listVFRepresentors(root); len(got) < 2 {
		t.Fatalf("listVFRepresentors = %+v, want both netdevsim representors", got)
	}
	// The uplink is not a representor, whatever an annotation says.
	wrong := vf0
	wrong.RepresentorDevice = pfNetdev
	if _, err := ResolveRepresentor(root, wrong); err == nil {
		t.Fatal("ResolveRepresentor accepted the PF port as the VF's representor")
	}
	// The kernel does name the device behind a netdev (the VF-to-pod check
	// reads the same field inside the pod netns).
	if bus, err := netdevBusInfo("/proc/self/ns/net", pfNetdev); err != nil {
		t.Errorf("netdevBusInfo(%s): %v", pfNetdev, err)
	} else {
		t.Logf("bus info of %s: %q", pfNetdev, bus)
	}

	// --- Apply on a representor ---
	drv, err := NewDriver()
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	defer func() { _ = drv.Close() }()
	type filters struct {
		dispatch int // generation the dispatch filter points at, 0 = none
		rules    []tc.Object
	}
	list := func(rep RepresentorInfo, dir Direction) filters {
		t.Helper()
		objs, err := drv.ListFilters(rep.IfIndex, int(dir.parentHandle()))
		if err != nil {
			return filters{} // no clsact qdisc yet
		}
		var f filters
		for _, obj := range objs {
			switch {
			case !isManagedFilter(obj):
			case filterChain(obj) == 0:
				gen, err := dispatchTarget(obj)
				if err != nil {
					t.Fatalf("dispatch filter on %s: %v", rep.Name, err)
				}
				f.dispatch = int(gen)
			default:
				f.rules = append(f.rules, obj)
			}
		}
		return f
	}
	apply := func(iface controllers.InterfaceInfo, cfg controllers.CommonRuleConfig, policies ...*multiv1beta1.MultiNetworkPolicy) error {
		t.Helper()
		podInfo := &controllers.PodInfo{Name: "target", Namespace: testNS, Interfaces: []controllers.InterfaceInfo{iface}}
		return Apply(context.Background(), newFakeDeps(), cfg, policyMapOf(policies...), targetPod(nil), podInfo, root)
	}
	software := controllers.CommonRuleConfig{TCOffloadMode: "software", CTMode: "off"}
	allowFrom := func(cidr string) *multiv1beta1.MultiNetworkPolicy {
		return makePolicy("p1", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
			[]multiv1beta1.MultiNetworkPolicyIngressRule{{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: cidr}}}}}, nil)
	}

	// An ingress policy: its filters go on the representor's EGRESS hook
	// (packets to the VF), in generation 2, behind a dispatch filter.
	if err := apply(vf0, software, allowFrom("10.0.0.0/24")); err != nil {
		t.Fatalf("Apply(ingress policy): %v", err)
	}
	in := list(rep0, DirIngress)
	if in.dispatch != int(generationChains[0]) || len(in.rules) == 0 {
		t.Fatalf("policy-ingress filters on %s = %+v, want a rule set in generation %d", rep0.Name, in, generationChains[0])
	}
	if in.rules[0].Parent&0xffff != tc.HandleMinEgress {
		t.Errorf("policy ingress landed on parent %#x, want the representor's clsact egress hook", in.rules[0].Parent)
	}
	if out := list(rep0, DirEgress); out.dispatch != 0 || len(out.rules) != 0 {
		t.Errorf("ingress-only policy put filters on the other direction: %+v", out)
	}

	// A changed policy ends up in the other generation and nothing is left of
	// the first one.
	if err := apply(vf0, software, allowFrom("192.168.0.0/16")); err != nil {
		t.Fatalf("Apply(changed policy): %v", err)
	}
	in = list(rep0, DirIngress)
	if in.dispatch != int(generationChains[1]) {
		t.Fatalf("after a policy change the dispatch filter points at generation %d, want %d", in.dispatch, generationChains[1])
	}
	for _, obj := range in.rules {
		if !inGeneration(obj, generationChains[1]) {
			t.Errorf("filter left outside the current generation: chain %d", filterChain(obj))
		}
	}

	// Policy gone: no filters. Default deny: the drops are there without any
	// policy, in the denied direction only, and go again with the flag.
	if err := apply(vf0, software); err != nil {
		t.Fatalf("Apply(no policy): %v", err)
	}
	if in := list(rep0, DirIngress); in.dispatch != 0 || len(in.rules) != 0 {
		t.Fatalf("filters left after the policy was removed: %+v", in)
	}
	deny := software
	deny.TCDefaultDenyIngress = true
	if err := apply(vf0, deny); err != nil {
		t.Fatalf("Apply(default deny ingress): %v", err)
	}
	if in, out := list(rep0, DirIngress), list(rep0, DirEgress); in.dispatch == 0 || len(in.rules) == 0 || out.dispatch != 0 {
		t.Fatalf("default deny ingress: ingress %+v egress %+v, want filters in the ingress direction only", in, out)
	}
	if err := apply(vf0, software); err != nil {
		t.Fatalf("Apply(default deny off): %v", err)
	}
	if in := list(rep0, DirIngress); in.dispatch != 0 || len(in.rules) != 0 {
		t.Fatalf("default-deny filters left after the flag was removed: %+v", in)
	}

	// Hardware mode: netdevsim does not offload flower, so the kernel refuses
	// the skip_sw filters. The apply has to fail and must not leave a
	// dispatch filter pointing at a partial rule set.
	hardware := controllers.CommonRuleConfig{TCOffloadMode: "hardware", CTMode: "off"}
	if err := apply(vf0, hardware, allowFrom("10.0.0.0/24")); err == nil {
		t.Log("this kernel's netdevsim accepted skip_sw flower filters")
	} else {
		t.Logf("skip_sw refused as expected: %v", err)
		if in := list(rep0, DirIngress); in.dispatch != 0 {
			t.Errorf("a refused apply left a dispatch filter behind: %+v", in)
		}
	}

	// --- FlushStale ---
	for _, iface := range []controllers.InterfaceInfo{vf0, vf1} {
		if err := apply(iface, software, allowFrom("10.0.0.0/24")); err != nil {
			t.Fatalf("Apply(%s): %v", iface.PCIAddress, err)
		}
	}
	if err := FlushStale(root, []controllers.InterfaceInfo{vf1}); err != nil {
		t.Fatalf("FlushStale(keep vf1): %v", err)
	}
	if a, b := list(rep0, DirIngress), list(rep1, DirIngress); a.dispatch != 0 || len(a.rules) != 0 || b.dispatch == 0 {
		t.Fatalf("FlushStale(keep vf1): rep0 %+v rep1 %+v, want rep0 empty and rep1 untouched", a, b)
	}
	if err := FlushStale(root, nil); err != nil {
		t.Fatalf("FlushStale(nil): %v", err)
	}
	if b := list(rep1, DirIngress); b.dispatch != 0 || len(b.rules) != 0 {
		t.Fatalf("FlushStale(nil) left filters on rep1: %+v", b)
	}
}

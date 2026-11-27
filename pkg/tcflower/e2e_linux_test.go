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

// Software-datapath end-to-end test: REAL translation + REAL kernel enforcement,
// NO hardware.
//
// This drives the FULL engine path — BuildFlowerRules -> toObject -> the real
// netlinkDriver (go-tc over rtnetlink) -> EnsureClsact + reconcile -> the real
// in-kernel tc flower dataplane — and then asserts ACTUAL packet enforcement
// across a veth pair: traffic matching an allow rule passes, traffic hitting a
// non-matching port and the default-deny catch-all is dropped.
//
// It runs in SOFTWARE offload mode (skip_hw). veth and netdevsim have no
// hardware offload, so a skip_sw (hardware-only) filter would be rejected by
// the kernel; skip_hw makes the identical match/verdict enforced in the kernel
// software datapath. That is exactly what the OffloadSoftware mode exists for
// (graceful degradation + CI testability). Hardware offload (skip_sw enforced
// inside the switchdev eSwitch) is a distinct code path that remains gated to
// real ConnectX (CX5+) hardware and cannot be exercised here.
//
// It proves the enforcement is produced by the engine's own translation of a
// MultiNetworkPolicy, not by a hand-written tc filter.
//
// Self-skips (never fails CI) under: -short, non-root (need CAP_NET_ADMIN), or
// when the `ip` tool / veth support / a working baseline is unavailable.

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	tc "github.com/florianl/go-tc"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"github.com/vishvananda/netns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// e2e topology: two netns joined by a veth pair. The "pod side" (nsA) has the
// client; the "representor side" (nsB) holds the enforcement netdev vethB, on
// which we install the engine-produced flower filters. Traffic nsA -> nsB
// enters vethB on its clsact INGRESS parent, which is where DirEgress filters
// live (representor ingress == traffic FROM the pod == policy egress). We
// therefore enforce an EGRESS policy so the filters land on vethB ingress and
// see the client's packets.
const (
	e2eNSA      = "mnp-e2e-a"
	e2eNSB      = "mnp-e2e-b"
	e2eVethA    = "e2e-veth-a"
	e2eVethB    = "e2e-veth-b"
	e2eIPA      = "10.244.0.1"
	e2eIPB      = "10.244.0.2"
	e2ePrefix   = 24
	e2eAllowPT  = 8080 // allowed destination port (policy permits this)
	e2eDenyPT   = 9090 // not permitted -> hits default-deny -> dropped
	e2eProbeTMO = 2 * time.Second
)

func TestSoftwareEnforcementE2E(t *testing.T) {
	requireE2ETools(t)

	// --- build the veth topology across two netns (full cleanup on exit) ---
	setupE2ETopology(t)

	// vethB (the "representor") ifindex is resolved INSIDE nsB.
	ifindex := ifindexInNS(t, e2eNSB, e2eVethB)

	// --- drive the REAL engine: translate a MultiNetworkPolicy into filters ---
	//
	// Egress policy: allow TCP to e2eAllowPT toward the peer CIDR; everything
	// else (including TCP e2eDenyPT) falls to the default-deny catch-all. Built
	// in SOFTWARE mode so the filters carry skip_hw and enforce in-kernel.
	allowPort := intstr.FromInt(e2eAllowPT)
	tcpProto := corev1.ProtocolTCP
	policy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   testNS,
			Name:        "e2e-egress",
			Annotations: map[string]string{policyNetworkAnnotation: testNetName},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{Protocol: &tcpProto, Port: &allowPort},
					},
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{IPBlock: &multiv1beta1.IPBlock{CIDR: e2eIPB + "/32"}},
					},
				},
			},
		},
	}
	policyMap := controllers.PolicyMap{
		types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}: policy,
	}

	// Target pod on the policy network, whose representor is vethB.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "e2e-target"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	podInfo := &controllers.PodInfo{
		Name:      "e2e-target",
		Namespace: testNS,
		Interfaces: []controllers.InterfaceInfo{
			{
				NetattachName:     testNet,
				InterfaceName:     "net1",
				IPs:               []netip.Addr{netip.MustParseAddr(e2eIPA)},
				RepresentorDevice: e2eVethB,
			},
		},
	}

	desired, err := BuildFlowerRules(context.Background(), newFakeDeps(),
		controllers.CommonRuleConfig{TCOffloadMode: "software"},
		policyMap, pod, podInfo, podInfo.Interfaces[0])
	if err != nil {
		t.Fatalf("BuildFlowerRules(software): %v", err)
	}
	if len(desired) == 0 {
		t.Fatalf("engine produced no filters for the e2e egress policy")
	}
	// Every emitted filter must be software (skip_hw); a stray skip_sw would be
	// rejected by the veth kernel path and defeat the test's premise.
	for _, r := range desired {
		if r.Offload != OffloadSoftware {
			t.Fatalf("rule %+v not built in software mode (Offload=%v)", r, r.Offload)
		}
	}

	// --- install the filters on vethB using the REAL netlink driver, inside
	// nsB (this exercises EnsureClsact + reconcile + toObject + the real
	// kernel flower dataplane, exactly as Apply's reconcile does). ---
	withNetns(t, e2eNSB, func() {
		drv, err := NewDriver()
		if err != nil {
			t.Fatalf("NewDriver: %v", err)
		}
		defer func() { _ = drv.Close() }()

		if err := drv.EnsureClsact(ifindex); err != nil {
			t.Fatalf("EnsureClsact on vethB ifindex %d: %v", ifindex, err)
		}
		if err := reconcile(drv, e2eVethB, ifindex, desired); err != nil {
			t.Fatalf("reconcile e2e filters: %v", err)
		}

		// Assert the installed filters carry SkipHw (software mode) on the
		// representor-ingress parent (DirEgress) and NOT skip_sw.
		assertInstalledSoftware(t, drv, ifindex)
	})

	// --- ACTUALLY TEST ENFORCEMENT across the veth ---
	//
	// The egress policy allows TCP to e2eAllowPT and default-denies the rest.
	// Filters live on vethB ingress, so they inspect packets from nsA -> nsB.

	// 1) A matching connection (dst port allowed) must PASS. We start a
	//    listener in nsB and connect from nsA; success proves the SYN was not
	//    dropped by the flower pipeline.
	assertTCPConnect(t, e2eAllowPT, true /* expectPass */)

	// 2) A non-matching connection (dst port not permitted) must be DROPPED by
	//    the default-deny catch-all.
	assertTCPConnect(t, e2eDenyPT, false /* expectPass */)

	// 3) Change the policy: the allowed and the denied port swap. The new rule
	//    set is switched to atomically (see reconcile), and applying it again
	//    must not touch the kernel.
	swapped := intstr.FromInt32(int32(e2eDenyPT))
	policy.Spec.Egress[0].Ports[0].Port = &swapped
	desired, err = BuildFlowerRules(context.Background(), newFakeDeps(),
		controllers.CommonRuleConfig{TCOffloadMode: "software"},
		policyMap, pod, podInfo, podInfo.Interfaces[0])
	if err != nil {
		t.Fatalf("BuildFlowerRules(swapped): %v", err)
	}
	withNetns(t, e2eNSB, func() {
		drv, err := NewDriver()
		if err != nil {
			t.Fatalf("NewDriver: %v", err)
		}
		defer func() { _ = drv.Close() }()
		if err := reconcile(drv, e2eVethB, ifindex, desired); err != nil {
			t.Fatalf("reconcile swapped policy: %v", err)
		}
		counting := &countingDriver{Driver: drv}
		if err := reconcile(counting, e2eVethB, ifindex, desired); err != nil {
			t.Fatalf("reconcile unchanged policy: %v", err)
		}
		if counting.changes != 0 {
			t.Errorf("re-applying an unchanged rule set made %d kernel changes, want 0", counting.changes)
		}
	})
	assertTCPConnect(t, e2eDenyPT, true /* expectPass */)
	assertTCPConnect(t, e2eAllowPT, false /* expectPass */)

	// The VF-to-pod check asks the kernel, inside a netns, which device is
	// behind a netdev. A veth has no bus device, but the ioctl has to work in
	// the netns and has to fail for a netdev the netns does not have.
	if bus, err := netdevBusInfo("/run/netns/"+e2eNSB, e2eVethB); err != nil || bus != "" {
		t.Errorf("netdevBusInfo(veth in netns) = %q, %v; want an empty bus address and no error", bus, err)
	}
	if _, err := netdevBusInfo("/run/netns/"+e2eNSB, "nosuchdev0"); err == nil {
		t.Error("netdevBusInfo found a netdev the netns does not have")
	}

	// 4) Flushing must find the filters again from what the kernel dumps (the
	//    action cookie marks them as ours): afterwards the denied port passes.
	withNetns(t, e2eNSB, func() {
		drv, err := NewDriver()
		if err != nil {
			t.Fatalf("NewDriver: %v", err)
		}
		defer func() { _ = drv.Close() }()
		if err := flushRepresentor(drv, ifindex); err != nil {
			t.Fatalf("flushRepresentor: %v", err)
		}
	})
	assertTCPConnect(t, e2eAllowPT, true /* expectPass */)
}

// requireE2ETools skips (or, in CI, fails) a test that needs root, iproute2
// and nc to pass real packets across a veth pair.
func requireE2ETools(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping kernel e2e test in -short mode")
	}
	if os.Geteuid() != 0 {
		kernelTestSkip(t, "needs root (CAP_NET_ADMIN)")
	}
	for _, tool := range []string{"ip", "tc", "nc"} {
		if !haveTool(tool) {
			kernelTestSkip(t, "%s not found", tool)
		}
	}
}

// TestSoftwareConntrackE2E passes real packets through the conntrack pipeline
// in the kernel's software datapath (act_ct), with the pod's interface denied
// by default in the ingress direction:
//
//   - the pod may open a connection its egress policy allows, and the replies
//     come back although nothing allows ingress: they are established;
//   - without conntrack the same rule set drops those replies, which is why
//     default deny wants the conntrack pipeline.
//
// The "pod" is nsA; vethB in nsB stands in for its VF representor.
func TestSoftwareConntrackE2E(t *testing.T) {
	requireE2ETools(t)
	setupE2ETopology(t)
	ifindex := ifindexInNS(t, e2eNSB, e2eVethB)

	// act_ct is a module of its own; without it the pipeline cannot be loaded.
	probe := ipNetnsExec(e2eNSB, "sh", "-c", "tc qdisc add dev "+e2eVethB+" clsact && "+
		"tc filter add dev "+e2eVethB+" ingress prio 60000 protocol ip flower ct_state -trk action ct zone 9 pipe action pass && "+
		"tc filter del dev "+e2eVethB+" ingress prio 60000")
	if out, err := probe.CombinedOutput(); err != nil {
		kernelTestSkip(t, "the kernel cannot load a flower ct filter (act_ct missing?): %v: %s", err, out)
	}

	tcp := corev1.ProtocolTCP
	allowed := intstr.FromInt32(int32(e2eAllowPT))
	policy := makePolicy("ct-egress", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress}, nil,
		[]multiv1beta1.MultiNetworkPolicyEgressRule{{
			Ports: []multiv1beta1.MultiNetworkPolicyPort{{Protocol: &tcp, Port: &allowed}},
			To:    []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: e2eIPB + "/32"}}},
		}})
	podInfo := &controllers.PodInfo{Name: "target", Namespace: testNS, Interfaces: []controllers.InterfaceInfo{
		{NetattachName: testNet, InterfaceName: "net1", IPs: []netip.Addr{netip.MustParseAddr(e2eIPA)}, RepresentorDevice: e2eVethB},
	}}
	install := func(ct bool) {
		t.Helper()
		cfg := controllers.CommonRuleConfig{TCOffloadMode: "software", CTEnabled: ct, TCDefaultDenyIngress: true}
		desired, err := BuildFlowerRules(context.Background(), newFakeDeps(), cfg, policyMapOf(policy), targetPod(nil), podInfo, podInfo.Interfaces[0])
		if err != nil {
			t.Fatalf("BuildFlowerRules(ct=%v): %v", ct, err)
		}
		withNetns(t, e2eNSB, func() {
			drv, err := NewDriver()
			if err != nil {
				t.Fatalf("NewDriver: %v", err)
			}
			defer func() { _ = drv.Close() }()
			if err := drv.EnsureClsact(ifindex); err != nil {
				t.Fatalf("EnsureClsact: %v", err)
			}
			if err := reconcile(drv, e2eVethB, ifindex, desired); err != nil {
				t.Fatalf("reconcile(ct=%v): %v", ct, err)
			}
		})
	}

	install(true)
	assertTCPConnect(t, e2eAllowPT, true /* allowed out, replies established */)
	assertTCPConnect(t, e2eDenyPT, false /* not allowed out */)

	install(false)
	assertTCPConnect(t, e2eAllowPT, false /* replies hit the ingress default deny */)
}

// countingDriver counts the filter changes made through it.
type countingDriver struct {
	Driver
	changes int
}

func (d *countingDriver) AddFilter(obj tc.Object) error {
	d.changes++
	return d.Driver.AddFilter(obj)
}

func (d *countingDriver) DelFilter(obj tc.Object) error {
	d.changes++
	return d.Driver.DelFilter(obj)
}

// assertInstalledSoftware verifies every managed filter on vethB's egress
// (representor-ingress) parent carries SkipHw and not SkipSw.
func assertInstalledSoftware(t *testing.T, drv Driver, ifindex int) {
	t.Helper()
	parent := int(DirEgress.parentHandle())
	objs, err := drv.ListFilters(ifindex, parent)
	if err != nil {
		t.Fatalf("ListFilters(ifindex=%d parent=%#x): %v", ifindex, parent, err)
	}
	managed := 0
	for i := range objs {
		obj := objs[i]
		if !isManagedFilter(obj) {
			continue
		}
		managed++
		if obj.Flower == nil || obj.Flower.Flags == nil {
			t.Errorf("managed filter handle %#x has no flower flags", obj.Handle)
			continue
		}
		flags := *obj.Flower.Flags
		if flags&tc.SkipHw == 0 {
			t.Errorf("managed filter handle %#x missing SkipHw (software mode): flags=%#x", obj.Handle, flags)
		}
		if flags&tc.SkipSw != 0 {
			t.Errorf("managed filter handle %#x unexpectedly carries SkipSw in software mode: flags=%#x", obj.Handle, flags)
		}
	}
	if managed == 0 {
		t.Errorf("no managed software filters found on vethB egress parent; installation did not take effect")
	}
}

// assertTCPConnect starts a listener in nsB on port and connects from nsA,
// asserting the connection succeeds (expectPass) or is blocked.
func assertTCPConnect(t *testing.T, port int, expectPass bool) {
	t.Helper()
	// Listener in nsB; ignore errors (a stale listener from a prior probe is
	// fine — the point is the SYN either reaches it or is dropped).
	lis := ipNetnsExec(e2eNSB, "sh", "-c",
		"nc -l -p "+strconv.Itoa(port)+" >/dev/null 2>&1")
	if err := lis.Start(); err != nil {
		t.Skipf("could not start nc listener in %s: %v", e2eNSB, err)
	}
	t.Cleanup(func() { _ = lis.Process.Kill(); _, _ = lis.Process.Wait() })
	time.Sleep(300 * time.Millisecond)

	// Connect from nsA with a bounded timeout.
	conn := ipNetnsExec(e2eNSA, "nc", "-w2", "-z", e2eIPB, strconv.Itoa(port))
	done := make(chan error, 1)
	if err := conn.Start(); err != nil {
		t.Skipf("could not start nc client in %s: %v", e2eNSA, err)
	}
	go func() { done <- conn.Wait() }()

	var connErr error
	select {
	case connErr = <-done:
	case <-time.After(e2eProbeTMO + time.Second):
		_ = conn.Process.Kill()
		connErr = <-done
	}

	passed := connErr == nil
	switch {
	case expectPass && !passed:
		t.Errorf("TCP connect to %s:%d should PASS (matches allow rule) but was blocked: %v", e2eIPB, port, connErr)
	case !expectPass && passed:
		t.Errorf("TCP connect to %s:%d should be DROPPED (default-deny) but SUCCEEDED", e2eIPB, port)
	default:
		t.Logf("TCP connect to %s:%d behaved as expected (pass=%v)", e2eIPB, port, expectPass)
	}
}

// --- netns / veth plumbing (shell out to iproute2; simplest reliable path,
// netlink is not vendored) ---

// setupE2ETopology builds two netns joined by a veth pair, assigns addresses,
// brings links up, and asserts a working baseline (else skips). Registers full
// teardown via t.Cleanup.
func setupE2ETopology(t *testing.T) {
	t.Helper()

	// Clean any stale leftovers from an aborted prior run.
	teardownE2ETopology()
	t.Cleanup(teardownE2ETopology)

	steps := [][]string{
		{"netns", "add", e2eNSA},
		{"netns", "add", e2eNSB},
		{"link", "add", e2eVethA, "netns", e2eNSA, "type", "veth", "peer", "name", e2eVethB, "netns", e2eNSB},
		{"-n", e2eNSA, "addr", "add", e2eIPA + "/" + strconv.Itoa(e2ePrefix), "dev", e2eVethA},
		{"-n", e2eNSB, "addr", "add", e2eIPB + "/" + strconv.Itoa(e2ePrefix), "dev", e2eVethB},
		{"-n", e2eNSA, "link", "set", e2eVethA, "up"},
		{"-n", e2eNSB, "link", "set", e2eVethB, "up"},
		{"-n", e2eNSA, "link", "set", "lo", "up"},
		{"-n", e2eNSB, "link", "set", "lo", "up"},
	}
	for _, args := range steps {
		if out, err := ipCmd(args...).CombinedOutput(); err != nil {
			t.Skipf("veth/netns setup step `ip %v` failed (kernel lacks veth/netns?): %v: %s", args, err, out)
		}
	}

	// Baseline connectivity check (before any filter): if the veth pair does
	// not even pass ICMP, the runner cannot support this test.
	if out, err := ipNetnsExec(e2eNSA, "ping", "-c1", "-W2", e2eIPB).CombinedOutput(); err != nil {
		t.Skipf("baseline ping %s->%s failed; veth/netns not functional here: %v: %s", e2eIPA, e2eIPB, err, out)
	}
}

// teardownE2ETopology best-effort removes both netns (which also destroys the
// veth pair).
func teardownE2ETopology() {
	_ = ipCmd("netns", "del", e2eNSA).Run()
	_ = ipCmd("netns", "del", e2eNSB).Run()
}

// ifindexInNS resolves a netdev's ifindex inside a named netns by reading
// /sys/class/net/<dev>/ifindex from within the namespace.
func ifindexInNS(t *testing.T, ns, dev string) int {
	t.Helper()
	// `ip -n <ns> -o link show <dev>` prints "<ifindex>: <dev>@...".
	out, err := ipCmd("-n", ns, "-o", "link", "show", dev).Output()
	if err != nil {
		t.Skipf("resolving ifindex of %s in %s: %v", dev, ns, err)
	}
	// Parse the leading integer before the first ':'.
	s := string(out)
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		t.Skipf("could not parse ifindex from `ip link show` output: %q", s)
	}
	idx, err := strconv.Atoi(s[:i])
	if err != nil {
		t.Skipf("bad ifindex %q: %v", s[:i], err)
	}
	return idx
}

// withNetns runs fn with the calling goroutine's OS thread switched into the
// named netns, restoring the original namespace afterward. The OS thread is
// locked for the whole duration (and, defensively, never unlocked on the error
// path so the Go runtime retires the possibly-misconfigured thread rather than
// reusing it) so the netlink socket opened inside fn binds to the target
// namespace. Uses the vendored vishvananda/netns package (no netlink dep).
func withNetns(t *testing.T, ns string, fn func()) {
	t.Helper()

	runtime.LockOSThread()

	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("netns.Get (current namespace): %v", err)
	}
	defer func() { _ = orig.Close() }()

	target, err := netns.GetFromName(ns)
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("netns.GetFromName(%q): %v", ns, err)
	}
	defer func() { _ = target.Close() }()

	if err := netns.Set(target); err != nil {
		runtime.UnlockOSThread()
		t.Skipf("netns.Set(%q): %v", ns, err)
	}

	restored := false
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
		// If restore failed we intentionally leave the thread locked so the
		// runtime discards it.
	}()

	fn()

	if err := netns.Set(orig); err != nil {
		t.Errorf("restoring original netns: %v", err)
		return
	}
	restored = true
}

// haveTool reports whether a binary is on PATH.
func haveTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ipCmd builds an `ip <args...>` command.
func ipCmd(args ...string) *exec.Cmd { return exec.Command("ip", args...) }

// ipNetnsExec builds an `ip netns exec <ns> <cmd> <args...>` command.
func ipNetnsExec(ns, cmd string, args ...string) *exec.Cmd {
	full := append([]string{"netns", "exec", ns, cmd}, args...)
	return exec.Command("ip", full...)
}

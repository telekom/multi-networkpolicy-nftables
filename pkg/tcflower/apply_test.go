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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	tc "github.com/florianl/go-tc"
)

// fakeDriver records filter add/delete calls for reconcile tests. It does NOT
// touch netlink, so this test runs without root; the real netlink round-trip is
// exercised only by integration tests on Linux+root hardware.
type fakeDriver struct {
	installed []tc.Object
	added     []tc.Object
	deleted   []tc.Object
}

func (d *fakeDriver) EnsureClsact(_ int) error { return nil }

func (d *fakeDriver) ListFilters(ifindex, parent int) ([]tc.Object, error) {
	var out []tc.Object
	for _, o := range d.installed {
		if o.Parent == uint32(parent) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (d *fakeDriver) AddFilter(obj tc.Object) error {
	d.added = append(d.added, obj)
	return nil
}

func (d *fakeDriver) DelFilter(obj tc.Object) error {
	d.deleted = append(d.deleted, obj)
	return nil
}

func (d *fakeDriver) Close() error { return nil }

var _ Driver = (*fakeDriver)(nil)

// TestIsManagedFilterRecognizesBothModes asserts that isManagedFilter treats
// both a hardware (skip_sw) and a software (skip_hw) flower filter of ours as
// managed, while leaving foreign filters untouched: non-flower, flag-less
// flower, and a skip_sw flower without our cookie (e.g. installed by OVS).
func TestIsManagedFilterRecognizesBothModes(t *testing.T) {
	hw := FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 1, Verdict: VerdictDrop}
	sw := hw
	sw.Offload = OffloadSoftware

	if !isManagedFilter(hw.toObject(1)) {
		t.Errorf("hardware-mode (skip_sw) filter must be managed")
	}
	if !isManagedFilter(sw.toObject(1)) {
		t.Errorf("software-mode (skip_hw) filter must be managed")
	}

	// A foreign non-flower filter is not managed.
	foreign := tc.Object{Attribute: tc.Attribute{Kind: "u32"}}
	if isManagedFilter(foreign) {
		t.Errorf("non-flower filter must not be managed")
	}

	// A flower filter with no offload flags (e.g. a plain software filter added
	// out-of-band) is not ours.
	noFlags := tc.Object{Attribute: tc.Attribute{Kind: "flower", Flower: &tc.Flower{}}}
	if isManagedFilter(noFlags) {
		t.Errorf("flag-less flower filter must not be managed")
	}

	noCookie := hw.toObject(1)
	noCookie.Flower.Actions = &[]*tc.Action{{Kind: "gact"}}
	if isManagedFilter(noCookie) {
		t.Errorf("skip_sw flower filter without the daemon's cookie must not be managed")
	}
}

// memDriver keeps the installed filters like the kernel would and logs every
// change, so a test can check both the end state and the order of operations.
type memDriver struct {
	installed []tc.Object
	ops       []string // "add <chain>", "dispatch <generation>", "del <chain>"
	failAdd   func(tc.Object) error
}

var _ Driver = (*memDriver)(nil)

func (d *memDriver) EnsureClsact(int) error { return nil }
func (d *memDriver) Close() error           { return nil }

func (d *memDriver) ListFilters(_, parent int) ([]tc.Object, error) {
	var out []tc.Object
	for _, o := range d.installed {
		if o.Parent == uint32(parent) { //nolint:gosec // test value
			out = append(out, o)
		}
	}
	return out, nil
}

func sameFilter(a, b tc.Object) bool {
	return a.Parent == b.Parent && filterChain(a) == filterChain(b) && a.Info == b.Info && a.Handle == b.Handle
}

func (d *memDriver) AddFilter(obj tc.Object) error {
	if d.failAdd != nil {
		if err := d.failAdd(obj); err != nil {
			return err
		}
	}
	op := fmt.Sprintf("add %d", filterChain(obj))
	if filterChain(obj) == 0 {
		target, _ := dispatchTarget(obj)
		op = fmt.Sprintf("dispatch %d", target)
	}
	d.ops = append(d.ops, op)
	d.installed = slices.DeleteFunc(d.installed, func(o tc.Object) bool { return sameFilter(o, obj) })
	d.installed = append(d.installed, obj)
	return nil
}

func (d *memDriver) DelFilter(obj tc.Object) error {
	d.ops = append(d.ops, fmt.Sprintf("del %d", filterChain(obj)))
	d.installed = slices.DeleteFunc(d.installed, func(o tc.Object) bool { return sameFilter(o, obj) })
	return nil
}

// TestReconcileSwitchesGenerationsAtomically: a changed rule set is built
// completely next to the current one, switched to with a single replace of
// the dispatch filter, and only then is the old one removed.
func TestReconcileSwitchesGenerationsAtomically(t *testing.T) {
	const ifindex = 10
	allow := func(cidr string) []FlowerRule {
		return []FlowerRule{
			{Rep: testRep, Direction: DirIngress, Priority: 1, Src: netip.MustParsePrefix(cidr), Verdict: VerdictAccept},
			{Rep: testRep, Direction: DirIngress, Priority: 2, Verdict: VerdictDrop},
		}
	}
	foreign := tc.Object{
		Msg:       tc.Msg{Ifindex: ifindex, Parent: DirIngress.parentHandle(), Handle: 0xdead},
		Attribute: tc.Attribute{Kind: "u32"},
	}
	drv := &memDriver{installed: []tc.Object{foreign}}
	run := func(desired []FlowerRule) []string {
		t.Helper()
		drv.ops = nil
		if err := reconcile(drv, testRep, ifindex, desired); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		return drv.ops
	}

	if got, want := run(allow("10.0.0.0/8")), []string{"add 2", "add 2", "dispatch 2"}; !slices.Equal(got, want) {
		t.Fatalf("first apply ops = %v, want %v", got, want)
	}
	if got := run(allow("10.0.0.0/8")); len(got) != 0 {
		t.Fatalf("unchanged rule set caused ops %v, want none", got)
	}
	// A change goes into the other generation; the old one is only removed
	// after the dispatch filter points at the new one.
	if got, want := run(allow("192.168.0.0/16")), []string{"add 4", "add 4", "dispatch 4", "del 2", "del 2"}; !slices.Equal(got, want) {
		t.Fatalf("change ops = %v, want %v", got, want)
	}
	if got, want := run(allow("172.16.0.0/12")), []string{"add 2", "add 2", "dispatch 2", "del 4", "del 4"}; !slices.Equal(got, want) {
		t.Fatalf("second change ops = %v, want %v", got, want)
	}

	// A failure while building the new generation leaves the current one in
	// force; the next run cleans up the half-built one and completes.
	adds := 0
	drv.failAdd = func(tc.Object) error {
		if adds++; adds == 2 {
			return errors.New("table full")
		}
		return nil
	}
	drv.ops = nil
	if err := reconcile(drv, testRep, ifindex, allow("10.1.0.0/16")); err == nil {
		t.Fatal("reconcile succeeded despite a failing add")
	}
	if got, want := drv.ops, []string{"add 4"}; !slices.Equal(got, want) {
		t.Fatalf("failed change ops = %v, want %v (no dispatch change, nothing deleted)", got, want)
	}
	drv.failAdd = nil
	if got, want := run(allow("10.1.0.0/16")), []string{"del 4", "add 4", "add 4", "dispatch 4", "del 2", "del 2"}; !slices.Equal(got, want) {
		t.Fatalf("retry ops = %v, want %v", got, want)
	}

	// No policy any more: dispatching stops before the rules go.
	if got, want := run(nil), []string{"del 0", "del 4", "del 4"}; !slices.Equal(got, want) {
		t.Fatalf("removal ops = %v, want %v", got, want)
	}
	if len(drv.installed) != 1 || drv.installed[0].Kind != "u32" {
		t.Fatalf("installed = %+v, want only the foreign filter left", drv.installed)
	}
}

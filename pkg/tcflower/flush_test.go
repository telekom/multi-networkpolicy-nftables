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
	"net/netip"
	"testing"

	tc "github.com/florianl/go-tc"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

// listErrDriver wraps fakeDriver but returns an error from ListFilters, to model
// a representor with no clsact qdisc (flushRepresentor must treat that as
// already-clean, not an error).
type listErrDriver struct {
	fakeDriver
	err error
}

func (d *listErrDriver) ListFilters(int, int) ([]tc.Object, error) {
	return nil, d.err
}

func TestFlushRepresentorDeletesOnlyManaged(t *testing.T) {
	const ifindex = 7

	managedIngress := FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 1, Src: netip.MustParsePrefix("10.0.0.0/8"), Verdict: VerdictAccept}.toObject(ifindex)
	managedEgress := FlowerRule{Rep: testRep, Direction: DirEgress, Priority: 1, Dst: netip.MustParsePrefix("10.0.0.0/8"), Verdict: VerdictAccept}.toObject(ifindex)
	foreign := tc.Object{
		Msg:       tc.Msg{Ifindex: ifindex, Parent: DirIngress.parentHandle(), Handle: 0xbeef},
		Attribute: tc.Attribute{Kind: "u32"}, // not flower => not managed
	}

	drv := &fakeDriver{installed: []tc.Object{managedIngress, managedEgress, foreign}}

	if err := flushRepresentor(drv, ifindex); err != nil {
		t.Fatalf("flushRepresentor: %v", err)
	}

	if len(drv.deleted) != 2 {
		t.Fatalf("expected 2 managed filters deleted (ingress+egress), got %d: %+v", len(drv.deleted), drv.deleted)
	}
	for _, d := range drv.deleted {
		if d.Kind == "u32" {
			t.Errorf("foreign (non-managed) filter must not be deleted")
		}
	}
}

func TestFlushRepresentorToleratesMissingQdisc(t *testing.T) {
	// A representor whose clsact qdisc is gone surfaces as a ListFilters error;
	// flushRepresentor must treat it as already-clean and return nil.
	drv := &listErrDriver{err: errNoQdisc{}}
	if err := flushRepresentor(drv, 3); err != nil {
		t.Fatalf("flushRepresentor should tolerate a missing qdisc, got: %v", err)
	}
	if len(drv.deleted) != 0 {
		t.Fatalf("expected no deletes, got %d", len(drv.deleted))
	}
}

// errNoQdisc is a stand-in error for "no clsact qdisc / no such object".
type errNoQdisc struct{}

func (errNoQdisc) Error() string { return "no such file or directory" }

// TestFlushStaleKeepsEnforcedRepresentors: filters go from every VF
// representor except the ones still enforced, and only our own filters go.
func TestFlushStaleKeepsEnforcedRepresentors(t *testing.T) {
	fs := newFakeSysfs(t)
	fs.vf("0000:03:00.2", "0000:03:00.0", 0)
	fs.vf("0000:03:00.3", "0000:03:00.0", 1)
	fs.pfNet("0000:03:00.0", "enp3s0f0", "sw1")
	fs.netdev("enp3s0f0", "sw1", "p0", "2") // uplink: never flushed
	fs.netdev("rep0", "sw1", "pf0vf0", "10")
	fs.netdev("rep1", "sw1", "pf0vf1", "11")

	ours := func(ifindex int) tc.Object {
		return FlowerRule{Direction: DirIngress, Priority: 1, Verdict: VerdictDrop}.toObject(ifindex)
	}
	// Same shape as ours (flower, skip_sw) but without the cookie.
	foreign := ours(11)
	foreign.Flower.Actions = &[]*tc.Action{{Kind: "gact"}}
	foreign.Handle = 0xbeef
	uplink := ours(2)

	drv := &ifindexDriver{installed: []tc.Object{ours(10), ours(11), foreign, uplink}}
	keep := []controllers.InterfaceInfo{{InterfaceName: "net1", PCIAddress: "0000:03:00.2"}}
	if err := flushStale(drv, fs.root, keep); err != nil {
		t.Fatalf("flushStale: %v", err)
	}
	if len(drv.deleted) != 1 || drv.deleted[0].Ifindex != 11 || drv.deleted[0].Handle == 0xbeef {
		t.Fatalf("deleted = %+v, want only the daemon's filter on rep1 (ifindex 11)", drv.deleted)
	}

	// A kept interface that no longer resolves must not cause a flush.
	drv.deleted = nil
	keep = append(keep, controllers.InterfaceInfo{InterfaceName: "net2", PCIAddress: "0000:03:00.9"})
	if err := flushStale(drv, fs.root, keep); err == nil || len(drv.deleted) != 0 {
		t.Fatalf("flushStale with an unresolvable keep: err = %v, deleted = %+v; want an error and no deletes", err, drv.deleted)
	}

	// Shutdown: keep nothing.
	if err := flushStale(drv, fs.root, nil); err != nil {
		t.Fatalf("flushStale(nil): %v", err)
	}
	if len(drv.deleted) != 2 {
		t.Fatalf("deleted %d filters on shutdown, want the daemon's 2 representor filters", len(drv.deleted))
	}
}

// ifindexDriver is a fakeDriver whose ListFilters also honors the ifindex.
type ifindexDriver struct {
	fakeDriver
	installed []tc.Object
}

func (d *ifindexDriver) ListFilters(ifindex, parent int) ([]tc.Object, error) {
	var out []tc.Object
	for _, o := range d.installed {
		if o.Ifindex == uint32(ifindex) && o.Parent == uint32(parent) { //nolint:gosec // test values
			out = append(out, o)
		}
	}
	return out, nil
}

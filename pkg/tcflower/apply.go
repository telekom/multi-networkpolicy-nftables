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
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"syscall"
	"time"

	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// Apply enforces the MultiNetworkPolicies that select pod on each of the pod's
// SR-IOV interfaces, using tc flower filters on the VF representors.
//
// For every SR-IOV interface it:
//  1. resolves the VF representor,
//  2. decides whether to emit the conntrack pipeline (see resolveCTForRep),
//  3. builds the desired FlowerRules (pure translation),
//  4. ensures a clsact qdisc exists,
//  5. declaratively reconciles installed vs desired filters (add missing,
//     delete stale) — mirroring the nft engine's build-desired-then-diff.
//
// Reconcile keys filters by (parent, priority, handle). SkipSw insertion errors
// are surfaced (fail-closed): a filter that cannot be offloaded to hardware is
// a policy-enforcement failure, not something to swallow.
func Apply(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig,
	policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo, hostPrefix string) error {
	if podInfo == nil {
		return fmt.Errorf("nil podInfo")
	}

	drv, err := NewDriver()
	if err != nil {
		return fmt.Errorf("open tc driver: %w", err)
	}
	defer func() {
		if cerr := drv.Close(); cerr != nil {
			klog.Errorf("failed to close tc driver: %v", cerr)
		}
	}()

	var errs []error
	for _, iface := range podInfo.Interfaces {
		if !iface.IsSRIOV() {
			continue
		}

		rep, err := ResolveRepresentor(hostPrefix, iface)
		if err != nil {
			// Fail closed: leaving an SR-IOV interface unenforced is a security
			// failure.
			incRepresentorResolutionError(resolutionErrorReason(err))
			errs = append(errs, fmt.Errorf("resolve representor for interface %q: %w", iface.InterfaceName, err))
			continue
		}

		// Decide, per representor, whether to emit the stateful conntrack (CT)
		// pipeline from --tc-ct-mode and the PF's steering mode. The result is
		// a cfg copy with CTEnabled set; see resolveCTForRep.
		repCfg := resolveCTForRep(cfg, hostPrefix, rep.Name, pfPCIAddress(hostPrefix, iface))
		if rep.IfIndex == 0 {
			incRepresentorResolutionError(resolveReasonNoIfindex)
			errs = append(errs, fmt.Errorf("representor %q has no resolvable ifindex", rep.Name))
			continue
		}

		// Ensure BuildFlowerRules stamps the resolved representor name onto the
		// rules regardless of whether the CNI populated iface.RepresentorDevice.
		ifaceForBuild := iface
		ifaceForBuild.RepresentorDevice = rep.Name

		desired, err := BuildFlowerRules(ctx, deps, repCfg, policyMap, pod, podInfo, ifaceForBuild)
		if err != nil {
			errs = append(errs, fmt.Errorf("build flower rules for representor %q: %w", rep.Name, err))
			continue
		}

		// Observe the per-representor enforcement latency (build+ensure+reconcile)
		// regardless of outcome. Timing starts here — after resolution/preflight,
		// which are gated separately — so the histogram reflects dataplane work.
		start := time.Now()

		if err := drv.EnsureClsact(rep.IfIndex); err != nil {
			observeReconcileDuration(rep.Name, start)
			errs = append(errs, err)
			continue
		}

		if err := reconcile(drv, rep.Name, rep.IfIndex, desired); err != nil {
			observeReconcileDuration(rep.Name, start)
			errs = append(errs, fmt.Errorf("reconcile filters on representor %q: %w", rep.Name, err))
			continue
		}
		observeReconcileDuration(rep.Name, start)
	}

	return errors.Join(errs...)
}

// FlushStale removes the daemon's tc flower filters from every VF representor
// on the host except the representors of keep. The reconciler calls it after
// each pass with the interfaces it enforces via tc, so filters do not outlive
// their pod (a freed VF is handed to the next pod with its representor
// unchanged) or an interface that fell back to nftables. On shutdown keep is
// nil and everything is removed.
//
// Only filters carrying filterCookie are touched; the clsact qdisc is left in
// place. If a keep interface no longer resolves, nothing is removed: its
// representor cannot be told apart from an unused one.
//
// ponytail: dumps both clsact parents of every VF representor on each pass
// (two netlink dumps per VF). Track the representors the daemon programmed if
// that shows up on hosts with many VFs.
func FlushStale(hostPrefix string, keep []controllers.InterfaceInfo) error {
	drv, err := NewDriver()
	if err != nil {
		return fmt.Errorf("open tc driver: %w", err)
	}
	defer func() {
		if cerr := drv.Close(); cerr != nil {
			klog.Errorf("failed to close tc driver: %v", cerr)
		}
	}()
	return flushStale(drv, hostPrefix, keep)
}

func flushStale(drv Driver, hostPrefix string, keep []controllers.InterfaceInfo) error {
	kept := make(map[string]struct{}, len(keep))
	for _, iface := range keep {
		rep, err := ResolveRepresentor(hostPrefix, iface)
		if err != nil {
			return fmt.Errorf("resolve representor for interface %q: %w", iface.InterfaceName, err)
		}
		kept[rep.Name] = struct{}{}
	}

	var errs []error
	for _, rep := range listVFRepresentors(hostPrefix) {
		if _, ok := kept[rep.Name]; ok || rep.IfIndex == 0 {
			continue
		}
		if err := flushRepresentor(drv, rep.IfIndex); err != nil {
			errs = append(errs, fmt.Errorf("flush filters on representor %q: %w", rep.Name, err))
		}
	}
	return errors.Join(errs...)
}

// flushRepresentor deletes every managed filter on both clsact parents of the
// representor. A representor with no clsact qdisc (ListFilters errors) is
// treated as already-clean.
func flushRepresentor(drv Driver, ifindex int) error {
	var errs []error
	for _, parent := range []uint32{DirIngress.parentHandle(), DirEgress.parentHandle()} {
		objs, err := drv.ListFilters(ifindex, int(parent))
		if err != nil {
			// No clsact qdisc / no filters: nothing to clean on this parent.
			klog.V(4).Infof("tc flush: list filters on ifindex %d parent %#x: %v", ifindex, parent, err)
			continue
		}
		objs = slices.DeleteFunc(objs, func(obj tc.Object) bool { return !isManagedFilter(obj) })
		// Chain 0 first: it only holds the dispatch filter, so traffic stops
		// reaching the rule set before the rule set is taken apart.
		slices.SortStableFunc(objs, func(a, b tc.Object) int { return cmp.Compare(filterChain(a), filterChain(b)) })
		for _, obj := range objs {
			if err := drv.DelFilter(obj); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// filterKey identifies a managed filter within one clsact parent. The handle
// is a hash of the filter's whole content, chain included (see
// FlowerRule.handle), so two filters with the same key are the same filter.
type filterKey struct {
	chain  uint32
	prio   uint16
	handle uint32
}

// filterChain returns the tc chain of an installed filter, treating an absent
// Chain attribute as chain 0 (the kernel omits it for the default chain).
func filterChain(obj tc.Object) uint32 {
	if obj.Chain != nil {
		return *obj.Chain
	}
	return 0
}

// A rule set is never changed in place. Each direction of a representor has
// one dispatch filter in chain 0 that matches every packet and jumps to the
// chains holding the current rule set (a "generation"). A changed rule set is
// built completely in the other generation's chains, then the dispatch filter
// is replaced to point at it, and only then the old generation is removed.
// Replacing one filter is atomic, so every packet is judged by one complete
// rule set, the old or the new one, never by a mix of both.
const (
	dispatchPrio   uint16 = 1
	dispatchHandle uint32 = 1
	ethPAll        uint16 = 0x0003 // ETH_P_ALL: the dispatch filter matches every protocol

	tcActExtValMask uint32 = 0x0fffffff // TC_ACT_EXT_VAL_MASK: the chain of a goto action
)

// generationChains are the chain bases of the two generations. A rule's own
// chain (ctEntryChain or ctPolicyChain) is added to the base.
var generationChains = [2]uint32{2, 4}

// inGeneration reports whether a filter lives in the chains of generation base.
func inGeneration(obj tc.Object, base uint32) bool {
	chain := filterChain(obj)
	return chain == base+ctEntryChain || chain == base+ctPolicyChain
}

// inGenerationRules returns rules moved into the chains of generation base.
func inGenerationRules(rules []FlowerRule, base uint32) []FlowerRule {
	out := make([]FlowerRule, len(rules))
	for i, r := range rules {
		r.Chain += base
		if r.CTDispatch {
			r.GotoChain += base
		}
		out[i] = r
	}
	return out
}

// dispatchObject builds the chain-0 filter that sends every packet of one
// direction to generation base.
func dispatchObject(ifindex int, parent, base uint32, mode OffloadMode) tc.Object {
	flags := offloadFlags(mode)
	cookie := []byte(filterCookie)
	return tc.Object{
		Msg: tc.Msg{
			Ifindex: uint32(ifindex), //nolint:gosec // ifindex is a small positive netdev index
			Handle:  dispatchHandle,
			Parent:  parent,
			Info:    core.FilterInfo(dispatchPrio, ethPAll),
		},
		Attribute: tc.Attribute{Kind: "flower", Flower: &tc.Flower{
			Flags: &flags,
			Actions: &[]*tc.Action{{
				Kind:   "gact",
				Gact:   &tc.Gact{Parms: &tc.GactParms{Action: tcActGotoChain | (base + ctEntryChain)}},
				Cookie: &cookie,
			}},
		}},
	}
}

// dispatchTarget returns the generation an installed dispatch filter points at.
func dispatchTarget(obj tc.Object) (uint32, error) {
	for _, act := range *obj.Flower.Actions {
		if act == nil || act.Gact == nil || act.Gact.Parms == nil {
			continue
		}
		if a := act.Gact.Parms.Action; a&^tcActExtValMask == tcActGotoChain {
			return a&tcActExtValMask - ctEntryChain, nil
		}
	}
	return 0, fmt.Errorf("dispatch filter (handle %#x parent %#x) has no goto chain action", obj.Handle, obj.Parent)
}

// reconcile makes the representor's filters match desired, per direction. rep
// is the representor netdev name, used only for metric labels.
func reconcile(drv Driver, rep string, ifindex int, desired []FlowerRule) error {
	byDir := make(map[Direction][]FlowerRule)
	for _, r := range desired {
		byDir[r.Direction] = append(byDir[r.Direction], r)
	}
	for _, dir := range []Direction{DirIngress, DirEgress} {
		// Both directions are set (0 when a direction carries no rules) so
		// removing all policies for a direction shows as a drop to zero.
		setFiltersInstalled(rep, dir.String(), len(byDir[dir]))
		if err := reconcileDirection(drv, rep, ifindex, dir, byDir[dir]); err != nil {
			return err
		}
	}

	// Read back the HARDWARE-OFFLOAD state of the now-installed filters and
	// publish in_hw / not_in_hw gauges per direction. This is the truth signal
	// for eSwitch offload: a filter can install without error yet not be
	// offloaded (not_in_hw), which on a switchdev NIC means it is not actually
	// enforcing in hardware. Best-effort: a ListFilters error here does not fail
	// the (already successful) reconcile.
	publishHWState(drv, rep, ifindex)
	return nil
}

func reconcileDirection(drv Driver, rep string, ifindex int, dir Direction, desired []FlowerRule) error {
	parent := dir.parentHandle()
	objs, err := drv.ListFilters(ifindex, int(parent))
	if err != nil {
		return err
	}
	var dispatch *tc.Object
	var rules []tc.Object // our filters other than the dispatch filter
	for i := range objs {
		switch {
		case !isManagedFilter(objs[i]):
		case filterChain(objs[i]) == 0 && objs[i].Handle == dispatchHandle:
			dispatch = &objs[i]
		default:
			rules = append(rules, objs[i])
		}
	}
	// del removes the filters of ours that keep does not want.
	del := func(keep func(tc.Object) bool) error {
		for _, obj := range rules {
			if keep(obj) {
				continue
			}
			if err := drv.DelFilter(obj); err != nil {
				incFilterApplyError(rep, reasonDelete)
				return err
			}
		}
		return nil
	}

	if len(desired) == 0 {
		// No policy: stop dispatching first, so the rule set is out of the
		// path before it is taken apart.
		if dispatch != nil {
			if err := drv.DelFilter(*dispatch); err != nil {
				incFilterApplyError(rep, reasonDelete)
				return err
			}
		}
		return del(func(tc.Object) bool { return false })
	}

	current, haveCurrent := uint32(0), false
	if dispatch != nil {
		if current, err = dispatchTarget(*dispatch); err != nil {
			return err
		}
		haveCurrent = true
		// Nothing to do when the current generation already is the desired
		// rule set; only leftovers of an interrupted switch are removed.
		want := make(map[filterKey]struct{}, len(desired))
		for _, r := range inGenerationRules(desired, current) {
			want[filterKey{chain: r.Chain, prio: r.Priority, handle: r.handle()}] = struct{}{}
		}
		have := 0
		for _, obj := range rules {
			if !inGeneration(obj, current) {
				continue
			}
			if _, ok := want[filterKey{chain: filterChain(obj), prio: filterPriority(obj.Info), handle: obj.Handle}]; !ok {
				have = -1
				break
			}
			have++
		}
		if have == len(want) {
			return del(func(obj tc.Object) bool { return inGeneration(obj, current) })
		}
	}

	next := generationChains[0]
	if haveCurrent && current == next {
		next = generationChains[1]
	}
	// Build the new generation next to the current one. Leftovers of an
	// interrupted switch go first; a failure leaves the current one in force.
	if err := del(func(obj tc.Object) bool { return !inGeneration(obj, next) }); err != nil {
		return err
	}
	add := func(obj tc.Object) error {
		if err := drv.AddFilter(obj); err != nil {
			// A hardware offload rejection (skip_sw insertion refused) is the
			// security-critical case and is labeled distinctly from other add
			// failures.
			incFilterApplyError(rep, addErrorReason(obj, err))
			return err
		}
		return nil
	}
	for _, r := range inGenerationRules(desired, next) {
		if err := add(r.toObject(ifindex)); err != nil {
			return err
		}
	}
	// The switch: one replace of the dispatch filter.
	if err := add(dispatchObject(ifindex, parent, next, desired[0].Offload)); err != nil {
		return err
	}
	return del(func(obj tc.Object) bool { return inGeneration(obj, next) })
}

// publishHWState re-lists managed filters per representor parent and records how
// many are offloaded (in_hw) vs. present-but-not-offloaded (not_in_hw). The
// kernel reports this via the TCA_CLS_FLAGS_IN_HW / NOT_IN_HW bits carried in the
// flower Flags word (go-tc: tc.InHw / tc.NotInHw).
func publishHWState(drv Driver, rep string, ifindex int) {
	for dir, parent := range map[Direction]uint32{
		DirIngress: DirIngress.parentHandle(),
		DirEgress:  DirEgress.parentHandle(),
	} {
		objs, err := drv.ListFilters(ifindex, int(parent))
		if err != nil {
			klog.V(4).Infof("tcflower hw-state: list filters on %q parent %#x: %v", rep, parent, err)
			continue
		}
		inHW, notInHW := 0, 0
		for _, obj := range objs {
			if !isManagedFilter(obj) || obj.Flower == nil || obj.Flower.Flags == nil {
				continue
			}
			flags := *obj.Flower.Flags
			switch {
			case flags&tc.InHw != 0:
				inHW++
			case flags&tc.NotInHw != 0:
				notInHW++
			}
		}
		setFiltersHWState(rep, dir.String(), inHW, notInHW)
	}
}

// addErrorReason classifies an AddFilter failure for the apply-error counter.
// A hardware-only (skip_sw) filter that the NIC cannot offload is rejected by
// the kernel rather than falling back to software; that rejection surfaces as
// EOPNOTSUPP/ENOTSUPP and is labeled skip_sw (the fail-closed offload-insertion
// signal). A software (skip_hw) filter never triggers an offload rejection, so
// any failure installing one is a generic add failure — as is any non-offload
// error on a hardware filter.
func addErrorReason(obj tc.Object, err error) string {
	offloadReject := errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP)
	if offloadReject && isSkipSw(obj) {
		return reasonSkipSw
	}
	return reasonAdd
}

// isSkipSw reports whether a flower object carries the SkipSw (hardware-only)
// flag, i.e. was built in the default OffloadHardware mode.
func isSkipSw(obj tc.Object) bool {
	return obj.Flower != nil && obj.Flower.Flags != nil && (*obj.Flower.Flags&tc.SkipSw) != 0
}

// isManagedFilter reports whether an installed filter is one this backend owns:
// a flower filter whose first action carries filterCookie.
func isManagedFilter(obj tc.Object) bool {
	if obj.Kind != "flower" || obj.Flower == nil || obj.Flower.Actions == nil {
		return false
	}
	actions := *obj.Flower.Actions
	return len(actions) > 0 && actions[0] != nil && actions[0].Cookie != nil && string(*actions[0].Cookie) == filterCookie
}

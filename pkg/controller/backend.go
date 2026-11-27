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

package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/tcflower"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	klog "k8s.io/klog/v2"
)

// backendKind identifies which dataplane enforces an interface.
type backendKind int

const (
	backendNFT backendKind = iota
	backendTC
)

// String returns a short label used in logs and wrapped errors.
func (k backendKind) String() string {
	switch k {
	case backendTC:
		return "tc"
	default:
		return "nftables"
	}
}

// selectBackend chooses the dataplane for a single interface.
//
// The tc backend is opt-in (--enable-tc-backend). While it is disabled every
// interface uses nftables and nothing in pkg/tcflower is called. When it is
// enabled, an SR-IOV VF (an interface carrying PCI/representor device info
// from the Multus network-status annotation) is enforced with tc flower on its
// host representor if tcflower.CheckEnforceable passes. Otherwise it stays on
// nftables in the pod netns: legacy (non-switchdev) eSwitch, no representor,
// not a VF, not confirmed to be in the pod (whose network namespace is
// netnsPath), or --tc-ct-mode=require without confirmed CT offload. Each such
// fallback is counted in multinetworkpolicy_tc_backend_fallback_total and
// logged once per VF and reason.
func (r *NodeReconciler) selectBackend(netnsPath string, iface controllers.InterfaceInfo) backendKind {
	if !r.TCBackendEnabled || !iface.IsSRIOV() {
		return backendNFT
	}
	check := tcflower.CheckEnforceable
	if r.TCCheckEnforceableFunc != nil {
		check = r.TCCheckEnforceableFunc
	}
	if err := check(r.HostPrefix, r.CommonCfg, netnsPath, iface); err != nil {
		reason := tcflower.FallbackReason(err)
		tcflower.IncBackendFallback(reason)
		logFallbackOnce(iface, reason, err.Error())
		return backendNFT
	}
	return backendTC
}

// fallbackLogged dedupes fallback logs by VF + reason. Keyed by node-local
// hardware identity (PCI / representor), so it is bounded by the VF count.
var fallbackLogged sync.Map

func logFallbackOnce(iface controllers.InterfaceInfo, reason, detail string) {
	key := iface.PCIAddress + "\x00" + iface.RepresentorDevice + "\x00" + reason
	if _, loaded := fallbackLogged.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	klog.Warningf("SR-IOV interface %q (pci=%q representor=%q) enforced by the nftables backend in the pod netns "+
		"instead of tc flower (reason=%s): %s", iface.InterfaceName, iface.PCIAddress, iface.RepresentorDevice, reason, detail)
}

// tcPass is the per-Reconcile state of the tc backend. It only exists when the
// backend is enabled; podInfoFailed is nil-safe so the disabled path stays a
// no-op.
type tcPass struct {
	// incomplete is set when a pod's interfaces could not be determined.
	incomplete bool
}

func (p *tcPass) podInfoFailed() {
	if p != nil {
		p.incomplete = true
	}
}

// applyPod enforces policy for one pod. With the tc backend disabled (pass ==
// nil) it is exactly the nftables apply. Otherwise the pod's interfaces are
// split by backend and each backend is applied independently, so a failure in
// one does not leave the other unenforced.
func (r *NodeReconciler) applyPod(ctx context.Context, pass *tcPass, deps controllers.PolicyDeps, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo) error {
	if pass == nil {
		return r.applyRulesForPod(ctx, deps, r.CommonCfg, policyMap, pod, podInfo, r.HostPrefix)
	}
	if r.tcEnforced == nil {
		r.tcEnforced = map[types.UID][]controllers.InterfaceInfo{}
		r.nftFlushed = map[types.UID]struct{}{}
	}

	byBackend := partitionByBackend(podInfo, func(iface controllers.InterfaceInfo) backendKind {
		return r.selectBackend(podInfo.NetNSPath, iface)
	})
	var errs []error
	if nft, ok := byBackend[backendNFT]; ok {
		delete(r.nftFlushed, pod.UID)
		if err := r.applyRulesForPod(ctx, deps, r.CommonCfg, policyMap, pod, nft, r.HostPrefix); err != nil {
			errs = append(errs, fmt.Errorf("nftables: %w", err))
		}
	} else if _, done := r.nftFlushed[pod.UID]; !done {
		// Every interface is on tc. Drop nftables rules an earlier apply may
		// have left in the pod netns (the interface was on nftables before, or
		// the daemon was restarted with the tc backend newly enabled); nothing
		// would update them any more.
		if err := r.flushRulesForPod(pod.Namespace, pod.Name, podInfo.NetNSPath, r.HostPrefix); err != nil {
			errs = append(errs, fmt.Errorf("flush nftables rules superseded by tc: %w", err))
		} else {
			r.nftFlushed[pod.UID] = struct{}{}
		}
	}
	if tc, ok := byBackend[backendTC]; ok {
		r.tcEnforced[pod.UID] = tc.Interfaces
		if err := r.applyTCRulesForPod(ctx, deps, r.CommonCfg, policyMap, pod, tc, r.HostPrefix); err != nil {
			errs = append(errs, fmt.Errorf("tc: %w", err))
		}
	} else {
		delete(r.tcEnforced, pod.UID)
	}
	return errors.Join(errs...)
}

// finishTCPass removes tc filters from VF representors that no pod is enforced
// on any more: the pod is gone (its VF may already serve another pod), or the
// interface fell back to nftables.
//
// It errs on the side of leaving filters in place. A pod that is still there
// but reported no interfaces in this pass keeps what it had (network-status
// can be transiently incomplete), and nothing is removed in a pass where a
// pod could not be inspected at all.
func (r *NodeReconciler) finishTCPass(pass *tcPass, pods []corev1.Pod) error {
	live := make(map[types.UID]struct{}, len(pods))
	for i := range pods {
		if controllers.IsMultiNetworkpolicyTarget(&pods[i]) {
			live[pods[i].UID] = struct{}{}
		}
	}
	for uid := range r.nftFlushed {
		if _, ok := live[uid]; !ok {
			delete(r.nftFlushed, uid)
		}
	}
	var keep []controllers.InterfaceInfo
	for uid, ifaces := range r.tcEnforced {
		if _, ok := live[uid]; !ok {
			delete(r.tcEnforced, uid)
			continue
		}
		keep = append(keep, ifaces...)
	}
	if pass.incomplete {
		return nil
	}
	return r.flushStaleTC(keep)
}

func (r *NodeReconciler) applyTCRulesForPod(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo, hostPrefix string) error {
	if r.ApplyTCRulesForPodFunc != nil {
		return r.ApplyTCRulesForPodFunc(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
	}
	return tcflower.Apply(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
}

func (r *NodeReconciler) flushRulesForPod(podNamespace, podName, netnsPath, hostPrefix string) error {
	if r.FlushRulesForPodFunc != nil {
		return r.FlushRulesForPodFunc(podNamespace, podName, netnsPath, hostPrefix)
	}
	return flushRulesForPod(podNamespace, podName, netnsPath, hostPrefix)
}

func (r *NodeReconciler) flushStaleTC(keep []controllers.InterfaceInfo) error {
	if r.FlushStaleTCFunc != nil {
		return r.FlushStaleTCFunc(r.HostPrefix, keep)
	}
	return tcflower.FlushStale(r.HostPrefix, keep)
}

// partitionByBackend groups a pod's interfaces by the dataplane that must
// enforce them (as chosen by selectBackend), returning one narrowed PodInfo per
// backend that has at least one interface. The returned PodInfos share the
// scalar PodInfo fields (name, namespace, netns, node) and carry only their own
// subset of Interfaces. The map is empty when podInfo has no interfaces.
func partitionByBackend(podInfo *controllers.PodInfo, selectBackend func(controllers.InterfaceInfo) backendKind) map[backendKind]*controllers.PodInfo {
	if podInfo == nil || len(podInfo.Interfaces) == 0 {
		return nil
	}

	grouped := map[backendKind][]controllers.InterfaceInfo{}
	for _, iface := range podInfo.Interfaces {
		kind := selectBackend(iface)
		grouped[kind] = append(grouped[kind], iface)
	}

	out := make(map[backendKind]*controllers.PodInfo, len(grouped))
	for kind, ifaces := range grouped {
		narrowed := *podInfo
		narrowed.Interfaces = ifaces
		out[kind] = &narrowed
	}
	return out
}

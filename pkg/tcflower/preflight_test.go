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
	"testing"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

func TestParseDevlinkParamValue(t *testing.T) {
	out := "pci/0000:03:00.0:\n  name flow_steering_mode type driver-specific\n    values:\n      cmode runtime value smfs\n"
	if v, ok := parseDevlinkParamValue(out); !ok || v != "smfs" {
		t.Fatalf("parseDevlinkParamValue = %q, %v; want smfs", v, ok)
	}
	if _, ok := parseDevlinkParamValue("kernel answers: Operation not supported"); ok {
		t.Fatal("parsed a value out of an error message")
	}
}

// TestPFPCIAddress: steering mode is read from the PF's devlink instance.
func TestPFPCIAddress(t *testing.T) {
	fs := newFakeSysfs(t)
	fs.vf("0000:03:00.2", "0000:03:00.0", 0)
	if got := pfPCIAddress(fs.root, controllers.InterfaceInfo{PCIAddress: "0000:03:00.2"}); got != "0000:03:00.0" {
		t.Fatalf("pfPCIAddress from sysfs = %q, want the PF 0000:03:00.0", got)
	}
	if got := pfPCIAddress(fs.root, controllers.InterfaceInfo{PCIAddress: "0000:03:00.2", PFPCIAddress: "0000:05:00.0"}); got != "0000:05:00.0" {
		t.Fatalf("pfPCIAddress = %q, want the CNI-reported PF", got)
	}
	if got := pfPCIAddress(fs.root, controllers.InterfaceInfo{RepresentorDevice: "rep0"}); got != "" {
		t.Fatalf("pfPCIAddress without a PCI address = %q, want empty", got)
	}
}

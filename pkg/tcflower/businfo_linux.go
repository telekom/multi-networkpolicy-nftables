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
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

// netdevBusInfo asks the kernel, inside the network namespace at netnsPath,
// which device is behind the netdev ifName (ETHTOOL_GDRVINFO bus_info).
func netdevBusInfo(netnsPath, ifName string) (string, error) {
	netNS, err := ns.GetNS(netnsPath)
	if err != nil {
		return "", fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	defer func() { _ = netNS.Close() }()

	var bus string
	err = netNS.Do(func(ns.NetNS) error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open socket: %w", err)
		}
		defer func() { _ = unix.Close(fd) }()
		info, err := unix.IoctlGetEthtoolDrvinfo(fd, ifName)
		if err != nil {
			return fmt.Errorf("ethtool drvinfo of %q: %w", ifName, err)
		}
		bus = unix.ByteSliceToString(info.Bus_info[:])
		return nil
	})
	return bus, err
}

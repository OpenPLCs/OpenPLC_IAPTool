//go:build linux

package netiface

import (
	"net"
	"os"
)

// On Linux, a network interface backed by real hardware has a "device"
// symlink under /sys/class/net/<name>/ pointing at its PCI/USB device node.
// Purely virtual interfaces (veth, bridges, tun/tap, docker0, wg-*, a bond
// with no backing NIC, ...) never have one. This is a plain filesystem
// check, so unlike the macOS/Windows classifiers it never fails.
func classifyHardware(ifaces []net.Interface) map[string]bool {
	result := make(map[string]bool, len(ifaces))
	for _, ifc := range ifaces {
		_, err := os.Lstat("/sys/class/net/" + ifc.Name + "/device")
		result[ifc.Name] = err == nil
	}
	return result
}

//go:build darwin

package netiface

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
)

// On macOS, `networksetup -listallhardwareports` is Apple's own authoritative
// enumeration of real hardware network ports (Wi-Fi, Ethernet, Thunderbolt
// Ethernet, ...). Virtual interfaces (utun*, bridge100, awdl0, llw0, feth*,
// vmnet*, ...) never show up in it. Output looks like:
//
//	Hardware Port: Wi-Fi
//	Device: en0
//	Ethernet Address: aa:bb:cc:dd:ee:ff
//
//	Hardware Port: Thunderbolt Ethernet
//	Device: en5
//	...
func classifyHardware(ifaces []net.Interface) map[string]bool {
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil
	}

	hardwarePortDevices := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if dev, ok := strings.CutPrefix(line, "Device:"); ok {
			hardwarePortDevices[strings.TrimSpace(dev)] = true
		}
	}

	result := make(map[string]bool, len(ifaces))
	for _, ifc := range ifaces {
		result[ifc.Name] = hardwarePortDevices[ifc.Name]
	}
	return result
}

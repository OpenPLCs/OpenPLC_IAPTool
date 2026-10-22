//go:build windows

package netiface

import (
	"encoding/json"
	"net"
	"os/exec"
)

// On Windows, Go's net.Interface.Name is the user-renamable "friendly name"
// (Windows renumbers even virtual adapters into generic names like
// "Ethernet 5", so it can't distinguish a VirtualBox/Hyper-V/VMware adapter
// from a real NIC). MSFT_NetAdapter's "Virtual" property is the OS's own
// authoritative flag for this - it's exactly what `Get-NetAdapter` surfaces,
// derived from the adapter's real driver/registry characteristics rather
// than its display name.
type netAdapterInfo struct {
	InterfaceIndex int  `json:"InterfaceIndex"`
	Virtual        bool `json:"Virtual"`
}

func classifyHardware(ifaces []net.Interface) map[string]bool {
	// @(...) forces ConvertTo-Json to always emit a JSON array, even for
	// zero or one adapters (Windows PowerShell 5.1 has no -AsArray switch).
	script := `@(Get-CimInstance -ClassName MSFT_NetAdapter -Namespace root/StandardCimv2 |
		Select-Object InterfaceIndex, Virtual) | ConvertTo-Json -Compress`

	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil
	}

	var adapters []netAdapterInfo
	if err := json.Unmarshal(out, &adapters); err != nil {
		return nil
	}

	virtualByIndex := make(map[int]bool, len(adapters))
	for _, a := range adapters {
		virtualByIndex[a.InterfaceIndex] = a.Virtual
	}

	result := make(map[string]bool, len(ifaces))
	for _, ifc := range ifaces {
		if virtual, ok := virtualByIndex[ifc.Index]; ok {
			result[ifc.Name] = !virtual
		}
		// Unknown to PowerShell's view: leave unset so isRealHardwareInterface
		// fails open instead of assuming virtual.
	}
	return result
}

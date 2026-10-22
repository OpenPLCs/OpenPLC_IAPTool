//go:build windows || linux

package serialx

import (
	"runtime"
	"strings"

	"go.bug.st/serial/enumerator"
)

// On Windows and Linux the detailed enumeration is pure Go, so a cross-compile
// gets the USB descriptors: which adapter a COM number belongs to is exactly
// what nobody can tell from the number, and on a bench with four adapters
// plugged in that is the whole question.
func listPorts() ([]PortInfo, error) {
	details, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return nil, err
	}
	out := make([]PortInfo, 0, len(details))
	for _, d := range details {
		if d == nil {
			continue
		}
		p := PortInfo{
			Name:    d.Name,
			Product: strings.TrimSpace(d.Product),
			VID:     d.VID,
			PID:     d.PID,
			Serial:  d.SerialNumber,
			IsUSB:   d.IsUSB,
		}
		if runtime.GOOS == "linux" {
			describeFromSysfs(&p)
		}
		out = append(out, p)
	}
	return out, nil
}

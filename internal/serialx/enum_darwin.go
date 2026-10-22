//go:build darwin

package serialx

import (
	"os/exec"

	"go.bug.st/serial"
)

// The detailed enumerator needs cgo on macOS, which would cost the one-command
// cross-compile. ioreg ships with every macOS and gives the same USB ids.
// See $PROD/maps/porttool-on-linux-and-macos/issues/XPT-01-macos-serial-port-without-description-or-vid.md
func listPorts() ([]PortInfo, error) {
	names, err := serial.GetPortsList()
	if err != nil {
		return nil, err
	}
	// No ioreg or unreadable output leaves names only: a port list must not
	// fail because descriptions are missing.
	var usb map[string]PortInfo
	if b, err := exec.Command("ioreg", "-r", "-c", "IOUSBHostDevice", "-l", "-w", "0").Output(); err == nil {
		usb = parseIoreg(string(b))
	}
	out := make([]PortInfo, 0, len(names))
	for _, n := range names {
		if p, ok := usb[n]; ok {
			out = append(out, p)
		} else {
			out = append(out, PortInfo{Name: n})
		}
	}
	return out, nil
}

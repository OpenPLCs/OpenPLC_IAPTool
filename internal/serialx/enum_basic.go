//go:build !windows && !linux && !darwin

package serialx

import "go.bug.st/serial"

// Any other platform: names only. None of them is shipped.
func listPorts() ([]PortInfo, error) {
	names, err := serial.GetPortsList()
	if err != nil {
		return nil, err
	}
	out := make([]PortInfo, 0, len(names))
	for _, n := range names {
		out = append(out, PortInfo{Name: n})
	}
	return out, nil
}

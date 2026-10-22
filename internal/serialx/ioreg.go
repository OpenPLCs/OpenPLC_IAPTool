package serialx

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Untagged so its test runs on the machines this repo is built on; only
// enum_darwin.go calls it.

var (
	ioregNode = regexp.MustCompile(`\+-o .*<class (IOUSBHostDevice|IOUSBDevice)[,>]`)
	ioregProp = regexp.MustCompile(`"([^"]+)" = (.*)$`)
)

// parseIoreg maps each serial device path found in `ioreg -r -c IOUSBHostDevice
// -l -w 0` output to the USB device it sits under. A port appears under the
// nearest USB device node printed above it.
func parseIoreg(text string) map[string]PortInfo {
	out := map[string]PortInfo{}
	var cur PortInfo
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if ioregNode.MatchString(line) {
			cur = PortInfo{IsUSB: true}
			continue
		}
		m := ioregProp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		switch key {
		case "idVendor":
			cur.VID = ioregHex(val)
		case "idProduct":
			cur.PID = ioregHex(val)
		case "USB Product Name":
			cur.Product = strings.Trim(val, `"`)
		case "USB Serial Number":
			cur.Serial = strings.Trim(val, `"`)
		case "IOCalloutDevice", "IODialinDevice":
			p := cur
			p.Name = strings.Trim(val, `"`)
			out[p.Name] = p
		}
	}
	return out
}

// ioreg prints the ids in decimal; the other platforms report four hex digits.
func ioregHex(v string) string {
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%04X", n)
}

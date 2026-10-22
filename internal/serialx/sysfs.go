package serialx

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// On Linux go.bug.st/serial leaves Product empty, so a port shows up as a bare
// ttyUSB0. sysfs has the adapter's own strings and the kernel driver, and the
// driver names the chip (ch341-uart, pl2303, ftdi_sio, cdc_acm).
// See DECISIONS.md 73 in $PROD.
func describeFromSysfs(p *PortInfo) {
	dev, err := filepath.EvalSymlinks("/sys/class/tty/" + path.Base(p.Name) + "/device")
	if err != nil {
		return
	}
	describeSysfsDevice(p, filepath.ToSlash(dev), func(f string) (string, error) {
		b, err := os.ReadFile(f)
		return string(b), err
	})
}

// describeSysfsDevice fills in what p is missing from dev, the resolved sysfs
// directory behind a tty. The driver is on dev itself; the strings are on the
// USB device above it, one level up for cdc_acm and two for usb-serial.
func describeSysfsDevice(p *PortInfo, dev string, read func(string) (string, error)) {
	if ue, err := read(dev + "/uevent"); err == nil {
		for _, line := range strings.Split(ue, "\n") {
			if v, ok := strings.CutPrefix(line, "DRIVER="); ok {
				p.Driver = strings.TrimSpace(v)
			}
		}
	}
	for d := dev; d != "/" && d != "." && d != ""; d = path.Dir(d) {
		if _, err := read(d + "/idVendor"); err != nil {
			continue
		}
		if p.Product == "" {
			var words []string
			for _, f := range []string{"manufacturer", "product"} {
				if s, err := read(d + "/" + f); err == nil && strings.TrimSpace(s) != "" {
					words = append(words, strings.TrimSpace(s))
				}
			}
			p.Product = strings.Join(words, " ")
		}
		return
	}
}

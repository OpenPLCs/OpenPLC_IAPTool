package serialx

import (
	"os"
	"testing"
)

// Recorded 2026-09-30 in WSL (Debian 13, kernel 6.18) with the adapters passed
// through by usbipd-win.
var sysfsSample = map[string]string{
	// CH340 behind usb-serial: tty -> interface -> USB device.
	"/sys/devices/platform/vhci_hcd.0/usb1/1-2/1-2:1.0/ttyUSB0/uevent": "DRIVER=ch341-uart\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-2/idVendor":               "1a86\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-2/product":                "USB Serial\n",

	// PL2303: manufacturer and product both padded with a trailing space.
	"/sys/devices/platform/vhci_hcd.0/usb1/1-3/1-3:1.0/ttyUSB1/uevent": "DRIVER=pl2303\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-3/idVendor":               "067b\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-3/manufacturer":           "Prolific Technology Inc. \n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-3/product":                "USB-Serial Controller \n",

	// CANable under cdc_acm: tty -> interface, which is the device's child.
	"/sys/devices/platform/vhci_hcd.0/usb1/1-4/1-4:1.0/uevent": "DEVTYPE=usb_interface\nDRIVER=cdc_acm\nPRODUCT=16d0/117e/200\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-4/idVendor":       "16d0\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-4/manufacturer":   "Openlight Labs\n",
	"/sys/devices/platform/vhci_hcd.0/usb1/1-4/product":        "CANable2 b158aa7 github.com/normaldotcom/canable2.git\n",
}

func readSample(f string) (string, error) {
	if s, ok := sysfsSample[f]; ok {
		return s, nil
	}
	return "", os.ErrNotExist
}

func TestSysfsNamesTheChip(t *testing.T) {
	cases := []struct {
		dev, want string
	}{
		{"/sys/devices/platform/vhci_hcd.0/usb1/1-2/1-2:1.0/ttyUSB0",
			"/dev/ttyUSB0 - USB Serial (ch341-uart) [1a86:7523]"},
		{"/sys/devices/platform/vhci_hcd.0/usb1/1-3/1-3:1.0/ttyUSB1",
			"/dev/ttyUSB0 - Prolific Technology Inc. USB-Serial Controller (pl2303) [1a86:7523]"},
		{"/sys/devices/platform/vhci_hcd.0/usb1/1-4/1-4:1.0",
			"/dev/ttyUSB0 - Openlight Labs CANable2 b158aa7 github.com/normaldotcom/canable2.git (cdc_acm) [1a86:7523]"},
	}
	for _, c := range cases {
		p := PortInfo{Name: "/dev/ttyUSB0", VID: "1a86", PID: "7523"}
		describeSysfsDevice(&p, c.dev, readSample)
		if got := p.Label(); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.dev, got, c.want)
		}
	}
}

// A description the enumerator already had wins; sysfs only fills gaps.
func TestSysfsKeepsExistingProduct(t *testing.T) {
	p := PortInfo{Name: "/dev/ttyUSB0", Product: "given"}
	describeSysfsDevice(&p, "/sys/devices/platform/vhci_hcd.0/usb1/1-2/1-2:1.0/ttyUSB0", readSample)
	if p.Product != "given" || p.Driver != "ch341-uart" {
		t.Errorf("got Product=%q Driver=%q", p.Product, p.Driver)
	}
}

// A tty with no USB device above it (a built-in UART) still lists.
func TestSysfsNothingAbove(t *testing.T) {
	p := PortInfo{Name: "/dev/ttyS0"}
	describeSysfsDevice(&p, "/sys/devices/platform/serial8250/tty/ttyS0", readSample)
	if p.Label() != "/dev/ttyS0" {
		t.Errorf("got %q", p.Label())
	}
}

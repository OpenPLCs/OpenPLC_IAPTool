package serialx

import "testing"

// Hand-written from ioreg's documented layout, NOT recorded on a real Mac.
// Replace it with a recording once one exists - see XPT-03 in
// $PROD/maps/porttool-on-linux-and-macos/.
//
// A hub with an ST-Link under it (its own VCP is 0483:3754), then the board's
// CDC port (0483:5740), then a device with no serial port at all.
const ioregSample = `+-o USB2.0 Hub@01100000  <class IOUSBHostDevice, id 0x100000a01, registered, matched, active, busy 0 (3 ms), retain 20>
  | {
  |   "idProduct" = 2082
  |   "idVendor" = 1507
  |   "USB Product Name" = "USB2.0 Hub"
  | }
  |
  +-o STM32 STLink@01110000  <class IOUSBHostDevice, id 0x100000a02, registered, matched, active, busy 0 (5 ms), retain 25>
    | {
    |   "idProduct" = 14164
    |   "idVendor" = 1155
    |   "USB Product Name" = "STM32 STLink"
    |   "USB Serial Number" = "066DFF485550755187162538"
    | }
    |
    +-o IOUSBHostInterface@2  <class IOUSBHostInterface, id 0x100000a05, registered, matched, active, busy 0 (1 ms), retain 7>
      +-o AppleUSBACMData  <class AppleUSBACMData, id 0x100000a09, registered, matched, active, busy 0 (0 ms), retain 6>
        +-o IOSerialBSDClient  <class IOSerialBSDClient, id 0x100000a0c, registered, matched, active, busy 0 (0 ms), retain 5>
            {
              "IOCalloutDevice" = "/dev/cu.usbmodem11103"
              "IODialinDevice" = "/dev/tty.usbmodem11103"
            }
+-o STM32 Virtual ComPort@01200000  <class IOUSBHostDevice, id 0x100000b01, registered, matched, active, busy 0 (4 ms), retain 22>
  | {
  |   "idProduct" = 22336
  |   "idVendor" = 1155
  |   "USB Product Name" = "STM32 Virtual ComPort"
  |   "USB Serial Number" = "207A33A45741"
  | }
  |
  +-o IOUSBHostInterface@1  <class IOUSBHostInterface, id 0x100000b04, registered, matched, active, busy 0 (1 ms), retain 7>
    +-o AppleUSBACMData  <class AppleUSBACMData, id 0x100000b08, registered, matched, active, busy 0 (0 ms), retain 6>
      +-o IOSerialBSDClient  <class IOSerialBSDClient, id 0x100000b0b, registered, matched, active, busy 0 (0 ms), retain 5>
          {
            "IOCalloutDevice" = "/dev/cu.usbmodem207A33A457411"
            "IODialinDevice" = "/dev/tty.usbmodem207A33A457411"
          }
+-o USB Receiver@01300000  <class IOUSBHostDevice, id 0x100000c01, registered, matched, active, busy 0 (2 ms), retain 18>
    {
      "idProduct" = 50475
      "idVendor" = 1133
    }
`

func TestParseIoregSeparatesBoardFromSTLink(t *testing.T) {
	got := parseIoreg(ioregSample)

	want := map[string]PortInfo{
		"/dev/cu.usbmodem11103":          {Name: "/dev/cu.usbmodem11103", Product: "STM32 STLink", VID: "0483", PID: "3754", Serial: "066DFF485550755187162538", IsUSB: true},
		"/dev/tty.usbmodem11103":         {Name: "/dev/tty.usbmodem11103", Product: "STM32 STLink", VID: "0483", PID: "3754", Serial: "066DFF485550755187162538", IsUSB: true},
		"/dev/cu.usbmodem207A33A457411":  {Name: "/dev/cu.usbmodem207A33A457411", Product: "STM32 Virtual ComPort", VID: "0483", PID: "5740", Serial: "207A33A45741", IsUSB: true},
		"/dev/tty.usbmodem207A33A457411": {Name: "/dev/tty.usbmodem207A33A457411", Product: "STM32 Virtual ComPort", VID: "0483", PID: "5740", Serial: "207A33A45741", IsUSB: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d ports, want %d: %+v", len(got), len(want), got)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s:\n got  %+v\n want %+v", name, got[name], w)
		}
	}
}

func TestParseIoregUnreadableGivesNothing(t *testing.T) {
	if got := parseIoreg("ioreg: command not understood\n"); len(got) != 0 {
		t.Fatalf("got %+v, want no ports", got)
	}
}

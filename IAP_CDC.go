package main

import (
	"fmt"
	"strings"
	"time"

	"go.bug.st/serial"

	"IAPTool/internal/serialx"
)

// Helper function to open a serial port with specified baud rate.
func openPort(comName string, baudRate int) (serial.Port, error) {
	return serialx.Open(comName, baudRate)
}

// openIAPPort opens the port at MagicBaud so that the board sees the rate
// change: Linux reopens a port at its last rate and then sends no
// SET_LINE_CODING, so a plain open at 1200 after an earlier one leaves the
// application out of IAP mode ($PROD/docs/modules/M1/IAP-PROTOCOL.md
// "USB 上的 IAP 模式").
func openIAPPort(comName string) (serial.Port, error) {
	port, err := serialx.Open(comName, iapLeadInBaud)
	if err != nil {
		return nil, err
	}
	if err := port.SetMode(&serial.Mode{BaudRate: MagicBaud}); err != nil {
		port.Close()
		return nil, fmt.Errorf("cannot set %s to %d baud: %v", comName, MagicBaud, err)
	}
	return port, nil
}

// iapLeadInBaud is any rate other than MagicBaud.
const iapLeadInBaud = 9600

func RunCDC(portName, filePath string) {
	runUpload(cdcLink{port: portName}, filePath, CM_Flash)
}

// cdcLink reaches a board over its USB port. Everything asked of a running
// application goes at MagicBaud, which puts it in IAP mode; the bootloader
// ignores the rate. So the sketch's Serial never sees an IAP command
// (decision 176, $PROD/docs/modules/M1/IAP-PROTOCOL.md "USB 上的 IAP 模式").
type cdcLink struct{ port string }

func (l cdcLink) target() string { return l.port }

func (l cdcLink) identify() (boardInfo, error) {
	if board, err := cdcIdentify(l.port); err == nil {
		return board, nil
	}
	// An older board package reboots the moment the port is set to 1200, so
	// nothing answers: that reboot was the request. The bootloader it lands in
	// reports no app version, so the version gate does not apply this time.
	logv("No answer at %d baud on %s: older board package, it reboots on that rate", MagicBaud, l.port)
	logv("Waiting %.1f seconds for the bootloader...", getRebootWaitDuration().Seconds())
	time.Sleep(getRebootWaitDuration())
	for attempt := 1; attempt <= bootloaderDiscoveryRetries; attempt++ {
		board, err := cdcIdentify(l.port)
		if err == nil {
			return board, nil
		}
		logv("Identify attempt %d/%d on %s found nothing (%v)", attempt, bootloaderDiscoveryRetries, l.port, err)
		time.Sleep(identifyRetryDelay)
	}
	return boardInfo{}, fmt.Errorf("No board answers on %s. If it runs this board package, its program did not "+
		"answer in IAP mode: a loop() that runs long without delay() answers late.", l.port)
}

func (l cdcLink) requestReboot(id uploadIdentity) error {
	port, err := openIAPPort(l.port)
	if err != nil {
		return err
	}
	defer port.Close()
	s := serialSession{port}
	err = authenticatedReboot(id,
		func() (string, error) { return cdcAsk(s, CM_RebootChallenge, isNonceHex) },
		func(cmd string) error { return s.write([]byte(cmd + "\n")) })
	if err != nil {
		return err
	}
	// Keep the port open until the board has gone: closing drops DTR, which
	// ends IAP mode before a busy sketch has read the command.
	if err := waitPortGone(l.port, getRebootWaitDuration()); err != nil {
		logv("%v", err)
	}
	return nil
}

func (l cdcLink) finder(uid string) *boardFinder {
	return &boardFinder{
		ip: l.port, uid: uid,
		identify: func() (string, error) {
			board, err := cdcIdentify(l.port)
			return board.Raw, err
		},
		now:   time.Now,
		sleep: time.Sleep,
	}
}

func (l cdcLink) openSession(boardInfo) (session, error) {
	port, err := openPort(l.port, l_config.BaudRate)
	if err != nil {
		return nil, err
	}
	return serialSession{port}, nil
}

func (l cdcLink) resetSeen(boardInfo) (func(bool) bool, time.Duration) {
	return usbResetSeen(func() bool { return serialPortPresent(l.port) }), cdcPresencePoll
}

// serialSession is a session over a serial port.
type serialSession struct{ port serial.Port }

func (s serialSession) write(b []byte) error {
	_, err := s.port.Write(b)
	return err
}

func (s serialSession) readSome(p []byte, wait time.Duration) (int, error) {
	if err := s.port.SetReadTimeout(wait); err != nil {
		return 0, err
	}
	return s.port.Read(p)
}

func (s serialSession) Close() error { return s.port.Close() }

// cdcIdentify opens the port at MagicBaud and asks who is there: the
// bootloader, or the application in IAP mode.
func cdcIdentify(portName string) (boardInfo, error) {
	port, err := openIAPPort(portName)
	if err != nil {
		return boardInfo{}, err
	}
	defer port.Close()
	reply, err := cdcAsk(serialSession{port}, CM_PullIP, func(s string) bool {
		_, ok := parseCDCIdentity(s, portName)
		return ok
	})
	if err != nil {
		return boardInfo{}, err
	}
	board, _ := parseCDCIdentity(reply, portName)
	return board, nil
}

// cdcAsk sends one command and returns the first reply line accept takes.
// Lines it does not take are skipped: what the sketch printed before IAP mode
// is still in the board's send queue, and a slow loop() answers late enough
// that "quiet for a while" is no end-of-reply signal. The bootloader ends a
// reply without a newline, so a pending partial line counts once the port
// has been quiet for replyIdleGap.
func cdcAsk(s session, cmd string, accept func(string) bool) (string, error) {
	if err := s.write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("failed to send command %q: %v", cmd, err)
	}
	logv("Send command: %s", cmd)

	chunk := make([]byte, 256)
	pending := ""
	for start := time.Now(); time.Since(start) < CommandTimeout; {
		n, err := s.readSome(chunk, replyIdleGap)
		if err != nil {
			return "", fmt.Errorf("error reading from serial port: %v", err)
		}
		pending += string(chunk[:n])
		for {
			i := strings.IndexByte(pending, '\n')
			if i < 0 {
				break
			}
			line := strings.TrimSpace(pending[:i])
			pending = pending[i+1:]
			if accept(line) {
				return line, nil
			}
		}
		if n == 0 && accept(strings.TrimSpace(pending)) {
			return strings.TrimSpace(pending), nil
		}
	}
	return "", fmt.Errorf("no answer to %q", cmd)
}

// parseCDCIdentity parses the identity string in s, skipping whatever the
// port carried before it.
func parseCDCIdentity(s, portName string) (boardInfo, bool) {
	if i := strings.LastIndex(s, deviceReplyPrefix+"_"); i > 0 {
		s = s[i:]
	}
	return parseBoardInfoFromReply(s, portName)
}

// waitPortGone returns once portName has left the system's port list.
func waitPortGone(portName string, timeout time.Duration) error {
	for start := time.Now(); time.Since(start) < timeout; time.Sleep(cdcPresencePoll) {
		if !serialPortPresent(portName) {
			return nil
		}
	}
	return fmt.Errorf("%s is still there %.0f s after the reboot request: the board did not accept it",
		portName, timeout.Seconds())
}

// serialPortPresent reports whether the OS still lists the port. An
// enumeration that fails says nothing, so it counts as present.
func serialPortPresent(name string) bool {
	ports, err := serialx.List()
	if err != nil {
		return true
	}
	for _, p := range ports {
		if strings.EqualFold(p.Name, name) {
			return true
		}
	}
	return false
}

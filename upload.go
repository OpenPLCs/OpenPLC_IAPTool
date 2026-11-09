package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"IAPTool/iapcert"
)

// One upload flow for both channels (decision 132): USB and ethernet differ
// only in how bytes reach the board. Behaviour:
// $PROD/docs/modules/M1-firmware-upgrade.md "IAPTool 怎么判上传结论、打什么日志".

// boardLink is one way to reach a board: a serial port or an IP address.
type boardLink interface {
	target() string // what the user named: COM17, /dev/ttyACM0, 192.168.0.4
	// identify asks who answers at target now.
	identify() (boardInfo, error)
	// requestReboot asks a running application to reboot into its bootloader.
	requestReboot(id uploadIdentity) error
	// finder looks for uid where the board was last seen.
	finder(uid string) *boardFinder
	// openSession opens the bootloader's command and data stream.
	openSession(board boardInfo) (session, error)
	// resetSeen reports, every poll, whether the board reset after the last
	// block -- the only way an accepted image is confirmed.
	resetSeen(board boardInfo) (seen func(readFailed bool) bool, poll time.Duration)
}

// session is a byte stream to the board.
type session interface {
	write(b []byte) error
	// readSome waits up to wait for bytes. Nothing within wait is (0, nil);
	// an error means the stream is gone.
	readSome(p []byte, wait time.Duration) (int, error)
	Close() error
}

// A reply is complete once the stream has been quiet this long.
const replyIdleGap = 100 * time.Millisecond

// runUpload sends an application (CM_Flash) or bootloader (CM_FlashBoot)
// image to the board at link.
func runUpload(link boardLink, filePath, verb string) {
	logf("[PATH] start %s upload, target=%s", verb, link.target())

	board, err := link.identify()
	if err != nil {
		logf(true, "%v", err)
	}
	// The target name is not an identity: a COM port re-enumerates and an IP
	// can be handed to another board. Refuse rather than flash a stranger.
	if want := strings.TrimSpace(l_config.UID); want != "" && !strings.EqualFold(want, board.UID) {
		logf(true, "Device at %s reports uid=%s, not the configured target uid=%s. Refusing to flash.",
			link.target(), board.UID, want)
	}
	targetUID := board.UID
	logf("[PATH] target device UID=%s", targetUID)

	// Before anything asks the board to leave its application: in the
	// bootloader the app-version field is "-". Not for flashboot: a bootloader
	// image carries no sketch version.
	if verb == CM_Flash {
		checkVersionGate(filePath, board, true, g_forceFlash)
	}

	var id *uploadIdentity
	switch role := strings.ToUpper(board.Role); role {
	case "BOOTLD-INVALID":
		logf("[PATH] %s is bootloader with NO valid signed app installed (previous update failed, was rejected, or flash was tampered with) -> proceeding to flash a new image", link.target())
	case "BOOTLD":
		logv("[PATH] %s is bootloader -> transfer", link.target())
	case "CUSAPP":
		// Resolved once and reused for the reboot and the flash: issuing a
		// self-signed certificate for each would burn two serial numbers.
		resolved, err := resolveUploadIdentity()
		logf(err, "Cannot authenticate to this board")
		id = &resolved
		logf("Asking the application to reboot into the bootloader...")
		res := rebootIntoBootloader(func() error { return link.requestReboot(resolved) }, link.finder(targetUID))
		if res.state != rebootInBootloader {
			logf(true, "%s", rebootFailureText(res, link.target(), targetUID, resolved.keyPath))
		}
		board = res.board
		logf("[PATH] bootloader found at %s (uid=%s) -> transfer", board.IP, board.UID)
	default:
		logf(true, "Unexpected role %q from %s, exiting.", board.Role, link.target())
	}

	transfer(link, board, filePath, verb, id)
}

// transfer runs one bootloader session: claim, key check, flash command,
// blocks, verdict. id is the identity the reboot already used, or nil.
func transfer(link boardLink, board boardInfo, filePath, verb string, id *uploadIdentity) {
	s, err := link.openSession(board)
	logf(err, "Cannot open an upload session with %s", board.IP)
	defer s.Close()

	if err := ping(s); err != nil {
		logf(true, "Ping failed: %v", err)
	}

	// A board with no root is always in its bootloader. Only an application
	// upload claims it; the board refuses flashboot without a root.
	if verb == CM_Flash {
		err := claimIfUnclaimed(func(cmd string) (string, error) { return ask(s, cmd, CommandTimeout) })
		logf(err, "Cannot claim this board")
	}

	if id == nil {
		resolved, err := resolveUploadIdentity()
		logf(err, "Cannot authenticate to this board")
		id = &resolved
	}

	sigHex, err := signImageInMemory(filePath, id.key)
	logf(err, "Failed to prepare signature for %s", filePath)

	err = verifyIdentityMatchesDevice(*id, func() (string, error) { return ask(s, CM_GetPubKey, CommandTimeout) })
	logf(err, "Signing key check failed")

	checksum, fileSize, file := CalculateCRC32(filePath)
	defer file.(io.Closer).Close()
	logv("CRC Checksum: %x", checksum)

	flashCmd, err := flashCommand(*id, verb, fileSize, checksum, sigHex, func() (string, error) {
		return ask(s, CM_AuthChallenge, CommandTimeout)
	})
	logf(err, "Flash authorisation failed")
	logv("Send command: %s", flashCmd)
	if _, err := awaitOK(s, []byte(flashCmd+"\n"), FlashAckTimeout); err != nil {
		logf(true, "the board refused the flash command: %v", err)
	}

	// Raw image bytes from here on: no "\n" framing, the board is now in its
	// receive state and takes every byte as image data.
	buf := make([]byte, Buf_b)
	bar := newProgress(fileSize)
	rest := ""
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			if rest, err = awaitOK(s, buf[:n], Timeout); err != nil {
				bar.end()
				logf(true, "The board did not take the data after %d of %d bytes: %v", bar.sent, fileSize, err)
			}
			bar.add(n)
			logv("Sent %d bytes of total %d bytes", bar.sent, fileSize)
		}
		if readErr == io.EOF {
			break
		}
		logf(readErr, "File read error")
	}
	bar.end()

	seen, poll := link.resetSeen(board)
	err = readVerdict(s, rest, seen, poll, verdictTimeout)
	logf(err, "Upload failed")
	logf("File transfer complete.")
	// Only after the board accepted: a failed forced flash can be retried.
	noteFlashSucceeded()
}

// ping sends "ping" until the board answers "OK", up to MaxRetries times.
func ping(s session) error {
	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		logv("Sending ping...")
		if _, lastErr = awaitOK(s, []byte(CM_Ping+"\n"), Timeout); lastErr == nil {
			logv("Ping successful.")
			return nil
		}
		logv("ping failed: %v", lastErr)
		time.Sleep(time.Second)
	}
	return fmt.Errorf("no OK after %d tries: %w", MaxRetries, lastErr)
}

// ask sends one text command and returns the whole reply, trimmed. A reply
// can arrive in several reads, so it is complete once the stream goes quiet.
func ask(s session, cmd string, timeout time.Duration) (string, error) {
	if err := s.write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("failed to send %q: %w", cmd, err)
	}
	logv("Send command: %s", cmd)

	chunk := make([]byte, 256)
	var buf []byte
	var lastByteAt time.Time
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		n, err := s.readSome(chunk, replyIdleGap)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			lastByteAt = time.Now()
			continue
		}
		if len(buf) > 0 && (err != nil || time.Since(lastByteAt) >= replyIdleGap) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("no answer to %q: %w", cmd, err)
		}
	}
	if len(buf) == 0 {
		return "", fmt.Errorf("no answer to %q within %s", cmd, timeout)
	}
	return strings.TrimSpace(string(buf)), nil
}

// awaitOK sends data and waits for a reply that starts with "OK". It returns
// what followed the OK in the same reads: after the last block the board's
// verdict can arrive stuck to it. Any other reply is returned as the error.
func awaitOK(s session, data []byte, timeout time.Duration) (string, error) {
	if err := s.write(data); err != nil {
		return "", fmt.Errorf("send error: %w", err)
	}
	chunk := make([]byte, 256)
	buf := ""
	var lastByteAt time.Time
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		n, err := s.readSome(chunk, replyIdleGap)
		if n > 0 {
			buf += string(chunk[:n])
			lastByteAt = time.Now()
			if said := strings.TrimLeft(buf, " \t\r\n"); strings.HasPrefix(said, Rsp_OK) {
				return said[len(Rsp_OK):], nil
			}
			continue
		}
		said := strings.TrimSpace(buf)
		if said != "" && (err != nil || time.Since(lastByteAt) >= replyIdleGap) {
			return "", fmt.Errorf("%q", said)
		}
		if err != nil {
			return "", fmt.Errorf("connection lost: %w", err)
		}
	}
	if said := strings.TrimSpace(buf); said != "" {
		return "", fmt.Errorf("%q", said)
	}
	return "", fmt.Errorf("no answer within %s", timeout)
}

// After the last block the board verifies the image and only then decides.
// It answers only to refuse ("Signature Failed", "Checksum Failed",
// "Flash Failed"); acceptance is a reset, which takes the MAC or the USB
// device down before any reply could leave.
const (
	// Long because "Flash Failed" comes only after the region was erased and written.
	verdictTimeout = 90 * time.Second
	// Ethernet: how often to look for the board on the network.
	etherResetPoll = 2 * time.Second
	// USB: how often to look whether the port is still enumerated.
	cdcPresencePoll = 500 * time.Millisecond
)

// readVerdict decides whether the board took the image. rest is what followed
// the last block's "OK". Text is a refusal; seen() -- asked every poll, and
// at once when the stream fails -- is the only evidence of acceptance.
func readVerdict(s session, rest string, seen func(readFailed bool) bool, poll, timeout time.Duration) error {
	buf := []byte(rest)
	var lastByteAt time.Time
	if len(buf) > 0 {
		lastByteAt = time.Now()
	}
	chunk := make([]byte, 256)
	readFailed := false
	nextLook := time.Now().Add(poll)

	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		var n int
		var err error
		if readFailed {
			time.Sleep(replyIdleGap)
		} else if n, err = s.readSome(chunk, replyIdleGap); n > 0 {
			buf = append(buf, chunk[:n]...)
			lastByteAt = time.Now()
			continue
		}
		failedNow := err != nil
		readFailed = readFailed || failedNow
		said := strings.TrimSpace(string(buf))
		if said != "" {
			if readFailed || time.Since(lastByteAt) >= replyIdleGap {
				return verdictFromText(said)
			}
			continue
		}
		if failedNow || time.Now().After(nextLook) {
			if seen(readFailed) {
				return nil
			}
			nextLook = time.Now().Add(poll)
		}
	}
	if said := strings.TrimSpace(string(buf)); said != "" {
		return verdictFromText(said)
	}
	return fmt.Errorf("the board neither refused the image nor reset within %s. "+
		"It was NOT confirmed: check its log before assuming anything was written", timeout)
}

func verdictFromText(said string) error {
	if said == Rsp_OK {
		return nil
	}
	return fmt.Errorf("the board refused the image: %s", said)
}

// usbResetSeen: the bootloader resets only when it accepted, and a reset takes
// the COM port away -- reads fail, or the system stops listing it.
func usbResetSeen(present func() bool) func(bool) bool {
	return func(readFailed bool) bool {
		if readFailed || !present() {
			logf("The board reset (its USB port went away) - the image was accepted.")
			return true
		}
		return false
	}
}

// authenticatedReboot asks for a nonce, signs it with the reboot command and
// sends the certificate and that signature. The application ignores an
// unauthenticated reboot. Format: $PROD/docs/modules/M1/IAP-PROTOCOL.md.
func authenticatedReboot(id uploadIdentity, challenge func() (string, error), send func(cmd string) error) error {
	nonce, err := challenge()
	if err != nil {
		return fmt.Errorf("reboot challenge request failed: %w", err)
	}
	nonce = strings.TrimSpace(nonce)
	if !isNonceHex(nonce) {
		return fmt.Errorf("reboot challenge answered %q, not a nonce", nonce)
	}
	noncesigHex, err := iapcert.NonceSig(id.key, nonce, CM_Reboot)
	if err != nil {
		return err
	}
	if err := send(fmt.Sprintf("%s %s %s", CM_Reboot, id.certHex, noncesigHex)); err != nil {
		return fmt.Errorf("failed to send %s: %w", CM_Reboot, err)
	}
	logv("Send command: %s", CM_Reboot)
	return nil
}

// isNonceHex reports whether s looks like a reboot challenge: 16 bytes in hex.
func isNonceHex(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

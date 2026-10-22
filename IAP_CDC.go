package main

import (
	"io"
	"strings"
	"time"

	"go.bug.st/serial"

	"IAPTool/internal/serialx"
)

// Helper function to open a serial port with specified baud rate.
func openPort(comName string, baudRate int) (serial.Port, error) {
	return serialx.Open(comName, baudRate)
}

func RunCDC(portName, filePath string) {
	logf("[PATH] start cdc upgrade flow, target=%s", portName)

	board, ok := cdcIdentify(portName)
	if ok {
		// Runs, but on this path it can only ever let the upload through: a
		// board that answers cdcIdentify is already in the bootloader, and the
		// bootloader reports "-" for the app version. A board still running the
		// application answers nothing at all (see cdcIdentify below), so there
		// is no moment on the CDC path at which the installed version is
		// readable.
		//
		// => THE VERSION GATE DOES NOT PROTECT CDC UPLOADS. Only the ethernet
		// path can compare. The call is kept so the one-shot force marker is
		// still reset by an upload without --force, and so this stays correct
		// if the CDC path ever learns to reach the application.
		checkVersionGate(filePath, board, true, g_forceFlash)
	}
	if !ok {
		logf("No bootloader answered. Asking the application to reboot into it...")
		triggerPortResetAndWait(portName, getRebootWaitDuration())

		for attempt := 1; attempt <= bootloaderDiscoveryRetries; attempt++ {
			if board, ok = cdcIdentify(portName); ok {
				break
			}
			logv("Bootloader identify attempt %d/%d on %s found nothing", attempt, bootloaderDiscoveryRetries, portName)
			time.Sleep(time.Second)
		}
		if !ok {
			logf(true, "No bootloader on %s after the reboot request, exiting.", portName)
		}
	}

	switch board.Role {
	case "BOOTLD-INVALID":
		logf("[PATH] %s is bootloader with NO valid signed app installed (previous update failed, was rejected, or flash was tampered with) -> proceeding to flash a new image", portName)
	case "BOOTLD":
		logv("[PATH] %s is bootloader -> cdc transfer", portName)
	default:
		logf(true, "Unexpected role %q from %s, exiting.", board.Role, portName)
	}

	/* The COM port name is not an identity: the board re-enumerates after the
	 * reboot request, and on a bench with several boards the name can come back
	 * pointing at a different one. Refuse rather than flash a stranger. */
	if want := strings.TrimSpace(l_config.UID); want != "" && !strings.EqualFold(want, board.UID) {
		logf(true, "Device on %s reports uid=%s, not the configured target uid=%s. Refusing to flash.",
			portName, board.UID, want)
	}
	logf("[PATH] target device UID=%s", board.UID)

	runCDCAttempt(portName, filePath)
}

// cdcIdentify asks the port who it is, using the same identity string the UDP
// discovery reply carries. A board running the user's application never answers:
// the sketch owns the CDC data pipe, so silence -- or anything the sketch echoes
// back -- is what "the application is running" looks like from here.
func cdcIdentify(portName string) (boardInfo, bool) {
	port, err := openPort(portName, l_config.BaudRate)
	if err != nil {
		logv("Failed to open serial port %s with baud rate %d: %v", portName, l_config.BaudRate, err)
		return boardInfo{}, false
	}
	defer port.Close()

	reply, err := SendCommandReadResponse(port, CM_PullIP, CommandTimeout)
	if err != nil {
		return boardInfo{}, false
	}
	return parseBoardInfoFromReply(reply, portName)
}

// The application reboots the moment it sees the port opened at MagicBaud, so
// the open itself usually fails with the port already gone. That is the normal
// outcome, not an error: a board that did not take the reset is reported by the
// ping that follows.
func triggerPortResetAndWait(portName string, wait time.Duration) {
	if port, err := openPort(portName, MagicBaud); err == nil {
		port.Close()
	}
	logv("Reboot requested on %s@%d. Waiting %.1f seconds for the bootloader...",
		portName, MagicBaud, wait.Seconds())
	time.Sleep(wait)
	logv("Reconnecting with default baud now.")
}

func runCDCAttempt(portName, filePath string) {
	port, err := openPort(portName, l_config.BaudRate)
	if err != nil {
		logf(true, "Failed to open serial port %s with baud rate %d: %v", portName, l_config.BaudRate, err)
	}
	defer port.Close()

	if err := claimIfUnclaimed(func(cmd string) (string, error) {
		return SendCommandReadResponse(port, cmd, CommandTimeout)
	}); err != nil {
		logf(err, "Cannot claim this board")
		return
	}

	id, err := resolveUploadIdentity()
	if err != nil {
		logf(err, "Cannot authenticate to this board")
		return
	}

	logv("Proceeding with file transfer.")
	checksum, fileSize, file := CalculateCRC32(filePath)
	defer file.(io.Closer).Close()
	logv("CRC Checksum: %x", checksum)

	sigHex, err := signImageInMemory(filePath, id.key)
	if err != nil {
		logf(err, "Failed to prepare signature for %s", filePath)
		return
	}

	if err := verifyIdentityMatchesDevice(id, func() (string, error) {
		return SendCommandReadResponse(port, CM_GetPubKey, CommandTimeout)
	}); err != nil {
		logf(err, "Signing key check failed")
		return
	}

	flashCmd, err := flashCommand(id, CM_Flash, fileSize, checksum, sigHex, func() (string, error) {
		return SendCommandReadResponse(port, CM_AuthChallenge, CommandTimeout)
	})
	if err != nil {
		logf(err, "Flash authorisation failed")
		return
	}
	if ok, reply := SendCommandWaitForResponse(port, flashCmd, Rsp_OK, FlashAckTimeout); !ok {
		logf(true, "the board refused the flash command: %q", strings.TrimSpace(reply))
	}

	err = SendFile(port, portName, file, fileSize)
	logf(err, "Upload failed")
}

// SendCommandWaitForResponse sends a command through the serial port,
// waits for a specific response string, and returns true if received within
// timeout, else false and whatever the board answered instead.
//
// The trailing "\n" frames the command so the bootloader knows where it
// ends -- without it, a command longer than one USB CDC packet (e.g.
// "flash ... <sig> <hmac>") can arrive split across multiple reads on the
// device side with no way to tell it's still the same command.
func SendCommandWaitForResponse(port serial.Port, command string, expected string, timeout time.Duration) (bool, string) {
	if _, err := port.Write([]byte(command + "\n")); err != nil {
		logf(err, "Failed to send command: %s", command)
		return false, ""
	}
	logv("Send command: %s", command)

	port.SetReadTimeout(timeout)
	return readUntil(port, expected, timeout)
}

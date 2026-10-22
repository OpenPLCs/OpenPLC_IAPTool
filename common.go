package main

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.bug.st/serial"

	"IAPTool/iapproto"
	"IAPTool/internal/serialx"
)

const (
	Buf_b = iapproto.ChunkSize // one flash data frame
	Buf_s = 1024               // smnall buffer

	CM_Flash           = "flash"                           // Flash command
	CM_FlashBoot       = "flashboot"                       // replace the bootloader in place; same frame as CM_Flash
	CM_PullIP          = "openplc_server_where_r_y"        // command to get server IP
	CM_Reboot          = "openplc_server_reboot"           //command to reboot server
	CM_RebootChallenge = "openplc_server_reboot_challenge" // request a nonce before CM_Reboot
	CM_ReadLog         = "openplc_log"                     // UDP, bootloader and app: one piece of the SRAM4 boot log
	CM_Ping            = "ping"                            // Ping command
	CM_AuthChallenge   = "authchallenge"                   // request a nonce before CM_Flash
	CM_GetUID          = "getuid"                          // ask device for its machine ID (STM32 UID hex), used to derive its device key
	CM_GetPubKey       = "getpubkey"                       // ask device which firmware-signing public key it verifies against
	Rsp_OK             = "OK"

	// One command, one reply -- the same budget on both channels.
	CommandTimeout = iapproto.CommandTimeout
	// "flash" ack: the bootloader answers once staging starts (it erases only
	// after verifying), so this budget is not about erase time.
	FlashAckTimeout = 10 * time.Second
	// Broadcast discovery collects replies for the whole window, so this one is
	// deliberately longer than CommandTimeout: it is not a per-reply deadline.
	Timeout    = 5 * time.Second
	MagicBaud  = 1200 // Baud rate to reset PLC
	MaxRetries = 3    // Maximum retry attempts for ping and port opening
)

const configFile = "local_config.json"
const defaultBaudRate = 115200
const defaultServerPort = "56865"
const defaultRebootWaitSeconds = 4

// Mode constants
const (
	ModeCDC       = "cdc"
	ModeEther     = "ether"
	ModeFlashBoot = "flashboot"
)

// exitCleanups run before a fatal logf exits; os.Exit skips deferred calls.
var exitCleanups []func()

func fatalExit(format string, args ...any) {
	for _, f := range exitCleanups {
		f()
	}
	log.Printf(format, args...)
	os.Exit(1)
}

// g_verbose is set by -v: every step is logged, not just the key lines.
// The IDE passes it when "Show verbose output during upload" is ticked.
var g_verbose bool

// logv is logf for the lines only -v shows.
func logv(format string, args ...any) {
	if g_verbose {
		logf(append([]any{format}, args...)...)
	}
}

// progress draws one line of '#' on stderr while blocks go out; under -v the
// callers log each block instead, so it draws nothing.
type progress struct {
	total int64
	sent  int64
	shown int
	open  bool
}

const progressWidth = 40

func newProgress(total int64) *progress {
	p := &progress{total: total}
	if !g_verbose {
		fmt.Fprint(os.Stderr, "Uploading: ")
		p.open = true
	}
	return p
}

func (p *progress) add(n int) {
	p.sent += int64(n)
	if !p.open || p.total <= 0 {
		return
	}
	for want := int(p.sent * progressWidth / p.total); p.shown < want && p.shown < progressWidth; p.shown++ {
		fmt.Fprint(os.Stderr, "#")
	}
}

// end closes the line, so whatever is logged next starts on its own.
func (p *progress) end() {
	if !p.open {
		return
	}
	p.open = false
	if p.sent >= p.total {
		fmt.Fprintln(os.Stderr, " 100%")
	} else {
		fmt.Fprintln(os.Stderr)
	}
}

func logf(args ...any) {
	if len(args) == 0 {
		return
	}

	switch v := args[0].(type) {
	case error:
		if v != nil && len(args) > 1 {
			fatalExit("[FATAL] "+args[1].(string)+": %v\n", append(args[2:], v)...)
		}
	case bool:
		if v && len(args) > 1 {
			fatalExit("[FATAL] "+args[1].(string)+"\n", args[2:]...)
		}
	case string:
		log.Printf("[INFO] "+v+"\n", args[1:]...)
		// default:
		// 	log.Println("[ERROR] logf usage error")
	}
}

// Calculate CRC32 checksum of a file
func CalculateCRC32(filePath string) (uint32, int64, io.ReadSeeker) {
	file, err := os.Open(filePath)
	logf(err, "Failed to open binary file")
	// Calculate checksum
	hasher := crc32.NewIEEE()
	fileSize, err := io.Copy(hasher, file)
	logf(err, "Failed to calculate CRC32 checksum")

	_, err = file.Seek(0, io.SeekStart) // Reset file pointer
	logf(err, "Failed to reset file pointer")

	return hasher.Sum32(), fileSize, file
}

func ReadResponse(port serial.Port, expected string, timeout time.Duration) bool {
	port.SetReadTimeout(timeout)
	ok, _ := readUntil(port, expected, timeout)
	return ok
}

// readUntil reads until expected has arrived and returns what came after it
// in the same reads: the board's verdict can follow the last block's "OK"
// closely enough to share a read with it. On timeout it returns what did arrive.
func readUntil(port io.Reader, expected string, timeout time.Duration) (bool, string) {
	response := make([]byte, 64)
	buffer := ""

	start := time.Now()
	for time.Since(start) < timeout {
		n, err := port.Read(response)
		if err != nil {
			logf(err, "Error reading from serial port")
			return false, ""
		}
		if n > 0 {
			buffer += string(response[:n])
			if i := strings.Index(buffer, expected); i >= 0 {
				logv("Received expected response: %q", expected)
				return true, buffer[i+len(expected):]
			}
		}
	}
	logv("Timeout waiting for response: expected %q, got so far %q", expected, buffer)
	return false, buffer
}

// SendCommandReadResponse sends a command and returns whatever the device
// replies with (trimmed), rather than checking against a specific expected
// string. Used for reading back the nonce from an "authchallenge" request
// and the UID from a "getuid" request.
//
// The device's CDC_Transmit_FS call can hand a short response to the USB
// stack in more than one packet, and Windows' generic USB-CDC driver can in
// turn deliver those packets to a single port.Read() call one at a time --
// so a single Read() is not guaranteed to return the whole response (seen
// in practice: "getuid"'s 24-char reply arriving as a 1-byte first read).
// This accumulates reads until the port goes quiet for idleGap, the same
// way ReadResponse above already accumulates while scanning for a known
// substring; here there's no known substring to scan for, so "quiet for a
// bit after receiving something" is the completion signal instead.
func SendCommandReadResponse(port serial.Port, command string, timeout time.Duration) (string, error) {
	// Trailing "\n" frames the command -- see SendCommandWaitForResponse.
	if _, err := port.Write([]byte(command + "\n")); err != nil {
		return "", fmt.Errorf("failed to send command %q: %v", command, err)
	}
	logv("Send command: %s", command)

	const idleGap = 100 * time.Millisecond
	port.SetReadTimeout(idleGap)
	response := make([]byte, 256)
	var buffer []byte
	var lastByteAt time.Time

	start := time.Now()
	for time.Since(start) < timeout {
		n, err := port.Read(response)
		if err != nil {
			return "", fmt.Errorf("error reading from serial port: %v", err)
		}
		if n > 0 {
			buffer = append(buffer, response[:n]...)
			lastByteAt = time.Now()
			continue
		}
		if len(buffer) > 0 && time.Since(lastByteAt) >= idleGap {
			break
		}
	}
	if len(buffer) == 0 {
		return "", fmt.Errorf("timeout waiting for response to %q", command)
	}
	return strings.TrimSpace(string(buffer)), nil
}

// SendFile sends the image block by block, then waits for the board's
// verdict on it: a transfer the board then refuses is a failed upload.
func SendFile(port serial.Port, portName string, file io.Reader, fileSize int64) error {
	logf("Starting file transfer...")
	buffer := make([]byte, Buf_b)
	bar := newProgress(fileSize)
	defer bar.end()
	rest := ""

	for {
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read file chunk: %v", err)
		}

		if _, err = port.Write(buffer[:n]); err != nil {
			return fmt.Errorf("failed to send data: %v", err)
		}
		bar.add(n)
		logv("Sent %d bytes of total %d bytes", bar.sent, fileSize)

		port.SetReadTimeout(Timeout)
		var ok bool
		if ok, rest = readUntil(port, Rsp_OK, Timeout); !ok {
			return fmt.Errorf("no OK from the board after %d of %d bytes", bar.sent, fileSize)
		}
	}
	bar.end()

	port.SetReadTimeout(cdcVerdictIdleGap)
	if err := readCDCVerdict(port, rest, func() bool { return serialPortPresent(portName) }, verdictTimeout); err != nil {
		return err
	}
	logf("File transfer completed.")
	return nil
}

const (
	// A reply is complete once the port has been quiet this long.
	cdcVerdictIdleGap = 100 * time.Millisecond
	// How often to look whether the board's port is still enumerated.
	cdcPresencePoll = 500 * time.Millisecond
)

// readCDCVerdict decides whether the board took the image on the USB path.
// rest is what followed the last block's "OK" in the same read.
//
// A refusal is text; acceptance is a reset, which takes the USB device and so
// the COM port away -- the bootloader resets on no other path.
// See $PROD/docs/modules/M1/IAP-PROTOCOL.md "一次 flash 的往返".
func readCDCVerdict(port io.Reader, rest string, portPresent func() bool, timeout time.Duration) error {
	buf := []byte(rest)
	var lastByteAt time.Time
	if len(buf) > 0 {
		lastByteAt = time.Now()
	}
	chunk := make([]byte, 256)
	deadline := time.Now().Add(timeout)
	nextLook := time.Now().Add(cdcPresencePoll)

	for time.Now().Before(deadline) {
		n, err := port.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			lastByteAt = time.Now()
			continue
		}
		said := strings.TrimSpace(string(buf))
		if err != nil {
			if said == "" {
				logf("The board reset (its USB port went away) - the image was accepted.")
				return nil
			}
			return verdictFromText(said)
		}
		if said != "" && time.Since(lastByteAt) >= cdcVerdictIdleGap {
			return verdictFromText(said)
		}
		if said == "" && time.Now().After(nextLook) {
			if !portPresent() {
				logf("The board reset (its USB port went away) - the image was accepted.")
				return nil
			}
			nextLook = time.Now().Add(cdcPresencePoll)
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

// Utility: Get the current file path
func GetCurDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exePath)
}

func GetLocalConfigPath() string {
	exeDir := GetCurDir()
	if exeDir == "" {
		logf(true, "Failed to determine executable directory:")
	}
	return filepath.Join(exeDir, configFile)
}

// Load serial port configuration from JSON
func LoadConfig() {
	l_config = LocalConfig{
		BaudRate:          defaultBaudRate,
		UID:               "",
		ServerPort:        defaultServerPort,
		RebootWaitSeconds: defaultRebootWaitSeconds,
		SigningKey:        "",
	}

	jsonFile, err := os.ReadFile(GetLocalConfigPath())
	if err != nil {
		logv("Config not found, using defaults...")
	} else {
		err = json.Unmarshal(jsonFile, &l_config)
		logf(err, "Failed to parse JSON config")
	}
}

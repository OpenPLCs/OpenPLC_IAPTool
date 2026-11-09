package main

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"IAPTool/iapproto"
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

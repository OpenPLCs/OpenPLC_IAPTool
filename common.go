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
)

const (
	Buf_b = 8 * 1024 // big buffer ( KB)
	Buf_s = 1024     // smnall buffer

	CM_Flash           = "flash"                           // Flash command
	CM_PullIP          = "openplc_server_where_r_y"        // command to get server IP
	CM_Reboot          = "openplc_server_reboot"           //command to reboot server
	CM_RebootChallenge = "openplc_server_reboot_challenge" // request a nonce before CM_Reboot
	CM_Ping            = "ping"                            // Ping command
	CM_AuthChallenge   = "authchallenge"                   // request a nonce before CM_Flash
	CM_GetVersion      = "getversion"                      // ask device for its currently-installed firmware version
	Rsp_OK             = "OK"

	PingTimeout = 2 * time.Second // Ping response timeout
	Timeout     = 5 * time.Second // delay
	MagicBaud   = 1200            // Baud rate to reset PLC
	MaxRetries  = 3               // Maximum retry attempts for ping and port opening
)

const configFile = "local_config.json"
const defaultMAC = "00:80:e1:00:43:21"
const defaultBaudRate = 115200
const defaultParity = 0
const defaultDataBits = 8
const defaultStopBits = 0
const defaultServerPort = "56865"
const defaultRebootWaitSeconds = 4

// Mode constants
const (
	ModeCDC   = "cdc"
	ModeEther = "ether"
)

func logf(args ...any) {
	if len(args) == 0 {
		return
	}

	switch v := args[0].(type) {
	case error:
		if v != nil && len(args) > 1 {
			log.Fatalf("[FATAL] "+args[1].(string)+": %v\n", append(args[2:], v)...)
			os.Exit(1)
		}
	case bool:
		if v && len(args) > 1 {
			log.Fatalf("[FATAL] "+args[1].(string)+"\n", args[2:]...)
			os.Exit(1)
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
	response := make([]byte, 64)
	buffer := ""

	start := time.Now()
	for time.Since(start) < timeout {
		n, err := port.Read(response)
		if err != nil {
			logf(err, "Error reading from serial port")
			return false
		}
		if n > 0 {
			buffer += string(response[:n])
			if strings.Contains(buffer, expected) {
				logf("Received expected response: %q", expected)
				return true
			}
		}
	}
	logf("Timeout waiting for response: expected %q", expected)
	return false
}

// SendCommandReadResponse sends a command and returns whatever the device
// replies with (trimmed), rather than checking against a specific expected
// string. Used for reading back the nonce from an "authchallenge" request.
func SendCommandReadResponse(port serial.Port, command string, timeout time.Duration) (string, error) {
	if _, err := port.Write([]byte(command)); err != nil {
		return "", fmt.Errorf("failed to send command %q: %v", command, err)
	}
	logf("Send command: %s", command)

	port.SetReadTimeout(timeout)
	response := make([]byte, 256)
	start := time.Now()
	for time.Since(start) < timeout {
		n, err := port.Read(response)
		if err != nil {
			return "", fmt.Errorf("error reading from serial port: %v", err)
		}
		if n > 0 {
			return strings.TrimSpace(string(response[:n])), nil
		}
	}
	return "", fmt.Errorf("timeout waiting for response to %q", command)
}

func SendFile(port serial.Port, file io.Reader, fileSize int64) error {
	logf("Starting file transfer...")
	buffer := make([]byte, Buf_b) //
	var totalSent int64

	for {
		// 读取文件数据块
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read file chunk: %v", err)
		}

		// 发送数据块
		_, err = port.Write(buffer[:n])
		if err != nil {
			return fmt.Errorf("failed to send data: %v", err)
		}

		totalSent += int64(n)
		logf("Sent %d bytes of total %d bytes", totalSent, fileSize)

		// 等待服务器响应
		if !ReadResponse(port, Rsp_OK, Timeout) {
			return fmt.Errorf("failed to get response: %v", err)
		}
	}

	logf("File transfer completed.")
	return nil
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
		Parity:            defaultParity,
		DataBits:          defaultDataBits,
		StopBits:          defaultStopBits,
		UID:               "",
		BootIP:            "",
		AppIP:             "",
		MAC:               defaultMAC,
		ServerPort:        defaultServerPort,
		RebootWaitSeconds: defaultRebootWaitSeconds,
	}

	jsonFile, err := os.ReadFile(GetLocalConfigPath())
	if err != nil {
		logf("Config not found, using default MAC...")
	} else {
		var raw struct {
			LocalConfig
			LegacyIP string `json:"ip"`
		}
		raw.LocalConfig = l_config
		err = json.Unmarshal(jsonFile, &raw)
		logf(err, "Failed to parse JSON config")
		l_config = raw.LocalConfig
		if l_config.BootIP == "" && l_config.AppIP == "" && strings.TrimSpace(raw.LegacyIP) != "" {
			l_config.AppIP = strings.TrimSpace(raw.LegacyIP)
		}
	}
}

func SaveConfig() error {
	data, err := json.MarshalIndent(&l_config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(GetLocalConfigPath(), data, 0644)
}

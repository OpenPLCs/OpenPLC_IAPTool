package main

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.bug.st/serial"
)

const (
	Buf_b         = 8 * 1024 // big buffer ( KB)
	Buf_s         = 1024     // smnall buffer
	local_ip_file = "server_ip.txt"
	//ConfigFile    = "sp_setting_default.json" // Default config file

	CM_Flash  = "flash"                    // Flash command
	CM_PullIP = "openplc_server_where_r_y" // command to get server IP
	CM_Reboot = "openplc_server_reboot"    //command to reboot server
	CM_Ping   = "ping"                     // Ping command
	Rsp_Pong  = "pong"                     // Pong response
	Rsp_OK    = "OK"

	PingTimeout = 2 * time.Second // Ping response timeout
	Timeout     = 5 * time.Second // delay
	MagicBaud   = 1200            // Baud rate to reset PLC
	MaxRetries  = 3               // Maximum retry attempts for ping and port opening
	s_tcp_port  = "8247"
	s_udp_port  = "12345"
)

const configFile = "local_config.json"
const defaultMAC = "00:80:e1:00:43:21"
const defaultBaudRate = 115200
const defaultParity = 0
const defaultDataBits = 8
const defaultStopBits = 0
const defaultUDPPort = "16861"
const defaultTCPPort = "8247"
const defaultRebootWaitSeconds = 4

// Mode constants
const (
	ModeCDC   = "cdc"
	ModeEther = "ether"
)

// Command line arguments
type Args struct {
	Mode     string
	Port     string // For CDC mode
	FilePath string
}

// Parse command line arguments
func ParseArgs() Args {
	if len(os.Args) < 3 {
		logf(true, "Usage: program <mode> <file_path> [port/ip]")
	}

	args := Args{
		Mode:     strings.ToLower(os.Args[1]),
		FilePath: os.Args[2],
	}

	if args.Mode == ModeCDC {
		if len(os.Args) < 4 {
			logf(true, "CDC mode requires port name (e.g. COM1)")
		}
		args.Port = os.Args[3]
	}

	return args
}

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
		BaudRate: defaultBaudRate,
		Parity:   defaultParity,
		DataBits: defaultDataBits,
		StopBits: defaultStopBits,
		UID:      "",
		IP:       "",
		MAC:      defaultMAC,
		UDPPort:          defaultUDPPort,
		TCPPort:          defaultTCPPort,
		RebootWaitSeconds: defaultRebootWaitSeconds,
	}

	jsonFile, err := os.ReadFile(GetLocalConfigPath())
	if err != nil {
		logf("Config not found, using default MAC...")
	} else {
		err = json.Unmarshal(jsonFile, &l_config)
		logf(err, "Failed to parse JSON config")
	}
}

func SaveConfig() error {
	data, err := json.MarshalIndent(&l_config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(GetLocalConfigPath(), data, 0644)
}

func GetLocalCIDRs() ([]string, error) {
	var cidrs []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Filter only WiFi or Ethernet interfaces
		if !isWiFiOrEthernet(iface.Name) {
			continue
		}
		if !isPhysicalDeviceLinux(iface.Name) {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				//Assume net mask of phiysical ethernet interface is less than or equal to 24
				ones, _ := ipNet.Mask.Size()
				if ones <= 24 {
					cidrs = append(cidrs, ipNet.String())
				}
			}
		}
	}
	return cidrs, nil
}

// get the broadcast address of the local network
func getBroadcastAddress() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Filter only WiFi or Ethernet interfaces
		if !isWiFiOrEthernet(iface.Name) {
			continue
		}
		if !isPhysicalDeviceLinux(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.To4() == nil {
				continue
			}

			ip := ipNet.IP.To4()
			mask := ipNet.Mask

			broadcast := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = ip[i] | ^mask[i]
			}

			return broadcast.String(), nil
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

// Check if the interface name indicates WiFi or Ethernet
func isWiFiOrEthernet(name string) bool {
	name = strings.ToLower(name)
	//
	virtualKeywords := []string{"vmnet", "vmware", "vbox", "docker", "br-", "veth", "virbr", "tap", "tun", "zt", "tailscale", "ts", "wsl", "utun", "nat", "loopback"}
	for _, keyword := range virtualKeywords {
		if strings.Contains(name, keyword) {
			return false
		}
	}
	// Match common keywords for WiFi or Ethernet
	return strings.Contains(name, "eth") || // Linux Ethernet: eth0
		strings.HasPrefix(name, "en") || // macOS Ethernet: en0
		strings.Contains(name, "wlan") || // Linux WiFi: wlan0
		strings.Contains(name, "wi-fi") || // Windows WiFi: Wi-Fi
		strings.Contains(name, "wifi") // Alternative spellings
}

// Check for physical network device on Linux
func isPhysicalDeviceLinux(name string) bool {
	if runtime.GOOS != "linux" {
		return true // For non-Linux, assume true
	}
	_, err := os.Stat("/sys/class/net/" + name + "/device")
	return err == nil
}

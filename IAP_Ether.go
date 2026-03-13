package main

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

// UDP

const (
	deviceReplyPrefix = "STM32H743"
)

type boardInfo struct {
	IP  string
	MAC string
}

func RunEtherUpgrade(filePath string) {
	logf("[PATH] start ether upgrade flow")

	if strings.TrimSpace(l_config.IP) == "" {
		logf("[PATH] cache miss -> discover")
		boards, err := discoverBoardsViaDirectedBroadcast()
		logf(err, "No board reply from UDP broadcast discovery")

		selected, err := selectBoardAfterDiscovery(boards)
		logf(err, "Discovery returned multiple devices. Please configure local_config.json and retry")
		cacheBoardSelection(selected)
	} else {
		logf("[PATH] cache hit -> use ip=%s mac=%s", l_config.IP, l_config.MAC)
	}

	for attempt := 1; attempt <= MaxRetries+2; attempt++ {
		status, err := udpPingAndGetStatus(l_config.IP)
		if err != nil {
			logf(true, "UDP ping/status check failed for ip=%s: %v. Please reboot the board and retry.", l_config.IP, err)
		}
		logf("UDP status response: %s", status.Raw)

		switch {
		case strings.Contains(strings.ToLower(status.Mode), "boot"):
			logf("[PATH] boot -> direct tcp")
			RunEther_TCP(filePath)
			return
		case strings.Contains(strings.ToLower(status.Mode), "app"):
			logf("[PATH] app -> reboot -> ping retry")
			err = sendUDPNoResponseOnPort(l_config.IP, getUDPPort(), CM_Reboot)
			logf(err, "Failed to send reboot command to %s", l_config.IP)
			wait := getRebootWaitDuration()
			logf("Waiting %.1f seconds for reboot...", wait.Seconds())
			time.Sleep(wait)
		default:
			logf(true, "Unexpected ping status response mode=%q raw=%q", status.Mode, status.Raw)
		}
	}

	logf(true, "Unable to switch board to BOOT mode after retries")
}

func cacheBoardSelection(selected boardInfo) {
	l_config.IP = selected.IP
	l_config.MAC = selected.MAC
	err := SaveConfig()
	logf(err, "Failed to save board cache")
	logf("Cached selected board: ip=%s mac=%s", selected.IP, selected.MAC)
}

func discoverBoardsViaDirectedBroadcast() ([]boardInfo, error) {
	broadcastAddrs, err := getDirectedBroadcastAddrs()
	if err != nil {
		return nil, err
	}
	if len(broadcastAddrs) == 0 {
		return nil, fmt.Errorf("no broadcast address found from local interfaces")
	}

	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, fmt.Errorf("UDP listen failed: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(Timeout)
	conn.SetDeadline(deadline)

	for _, bcast := range broadcastAddrs {
		remoteAddr, rerr := net.ResolveUDPAddr("udp4", bcast+":"+getUDPPort())
		if rerr != nil {
			logf("Skip invalid broadcast addr %s: %v", bcast, rerr)
			continue
		}
		if _, werr := conn.WriteToUDP([]byte(CM_PullIP), remoteAddr); werr != nil {
			logf("Broadcast send failed to %s: %v", remoteAddr.String(), werr)
			continue
		}
		logf("UDP broadcast sent to %s", remoteAddr.String())
	}

	seen := make(map[string]struct{})
	var boards []boardInfo
	buffer := make([]byte, Buf_s)
	for {
		n, addr, rerr := conn.ReadFromUDP(buffer)
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				break
			}
			logf("UDP receive error: %v", rerr)
			continue
		}

		info, ok := parseBoardInfoFromReply(string(buffer[:n]), addr.IP.String())
		if !ok {
			logf("Ignore invalid discovery response from %s: %q", addr.IP.String(), strings.TrimSpace(string(buffer[:n])))
			continue
		}

		key := info.IP + "|" + info.MAC
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		boards = append(boards, info)
	}

	if len(boards) == 0 {
		return nil, fmt.Errorf("no valid discovery response")
	}

	sort.Slice(boards, func(i, j int) bool {
		return boards[i].IP < boards[j].IP
	})
	return boards, nil
}

func parseBoardInfoFromReply(reply, fallbackIP string) (boardInfo, bool) {
	parts := strings.Split(strings.TrimSpace(reply), ",")
	if len(parts) < 3 {
		return boardInfo{}, false
	}
	if strings.TrimSpace(parts[0]) != deviceReplyPrefix {
		return boardInfo{}, false
	}

	ip := strings.TrimSpace(parts[2])
	mac := ""
	if len(parts) >= 4 {
		mac = strings.TrimSpace(parts[3])
	}
	if ip == "" {
		ip = fallbackIP
	}
	if ip == "" {
		return boardInfo{}, false
	}

	return boardInfo{
		IP:  ip,
		MAC: mac,
	}, true
}

func printDiscoveredBoards(boards []boardInfo) {
	logf("Discovered %d board(s):", len(boards))
	for i, b := range boards {
		fmt.Printf("  [%d] IP=%s MAC=%s\n", i+1, b.IP, b.MAC)
	}
}

func selectBoardAfterDiscovery(boards []boardInfo) (boardInfo, error) {
	if len(boards) == 0 {
		return boardInfo{}, fmt.Errorf("empty board list")
	}
	if len(boards) == 1 {
		logf("Single board found, auto-selecting ip=%s mac=%s", boards[0].IP, boards[0].MAC)
		return boards[0], nil
	}

	printDiscoveredBoards(boards)
	fmt.Printf("Found %d machines from UDP broadcast.\n", len(boards))
	fmt.Printf("Please edit %s and set the target 'ip' and 'mac', then retry.\n", GetLocalConfigPath())
	return boardInfo{}, fmt.Errorf("multiple UDP responses")
}

type pingStatus struct {
	Raw     string
	Chip    string
	Mode    string
	Version string
}

func udpPingAndGetStatus(ip string) (pingStatus, error) {
	buffer, _, err := sendUDPWithResponseOnPort(ip, getUDPPort(), CM_Ping, Timeout)
	if err != nil {
		return pingStatus{}, err
	}

	resp := strings.TrimSpace(string(buffer))
	status, err := parsePingStatus(resp)
	if err != nil {
		return pingStatus{}, err
	}
	return status, nil
}

func parsePingStatus(resp string) (pingStatus, error) {
	raw := strings.TrimSpace(resp)
	parts := strings.Split(raw, "_")
	if len(parts) < 3 {
		return pingStatus{}, fmt.Errorf("invalid ping response, expected chip_mode_version: %q", raw)
	}

	chip := strings.TrimSpace(parts[0])
	mode := strings.TrimSpace(parts[1])
	version := strings.TrimSpace(parts[2])
	if chip == "" || mode == "" || version == "" {
		return pingStatus{}, fmt.Errorf("invalid ping response fields: %q", raw)
	}

	return pingStatus{Raw: raw, Chip: chip, Mode: mode, Version: version}, nil
}

// ----------------------
// func GetServerIP() string {
// 	serverIP, _ := loadServerIP()

// 	if serverIP == "" || !tryPing(serverIP) {
// 		log.Println("Server unreachable or unknown, starting discovery...")

// 		serverIP = discoverServer()
// 		if serverIP == "" {
// 			log.Println("No server found. Aborting.")
// 			return ""
// 		}

// 		saveServerIP(serverIP)
// 	}

// 	sendUDPNoResponse(serverIP, CM_Reboot)
// 	log.Println("Sent reboot command to ", serverIP, " and Waiting for OpenPLC restart...")
// 	time.Sleep(3 * time.Second)
// 	return serverIP
// }
// func getServerIPFilePath() string {
// 	return filepath.Join(GetCurDir(), local_ip_file)
// }
// func deleteServerIPFile() error {
// 	path := getServerIPFilePath()
// 	return os.Remove(path)
// }
// func loadServerIP() (string, error) {
// 	path := getServerIPFilePath()
// 	data, err := os.ReadFile(path)
// 	if err != nil {
// 		return "", err
// 	}
// 	ip := strings.TrimSpace(string(data))
// 	log.Println("Found IP in file:", ip)
// 	return ip, nil
// }

// func saveServerIP(ip string) error {
// 	path := getServerIPFilePath()
// 	return os.WriteFile(path, []byte(ip), 0644)
// }

// func tryPing(serverAddr string) bool {
// 	buffer, _, err := sendUDPWithResponse(serverAddr, CM_Ping)
// 	if err != nil {
// 		logf("tryPing receive failed:", err)
// 		return false
// 	}
//
// 	resp := string(buffer)
// 	if resp == Rsp_Pong {
// 		logf("Ping success.")
// 		return true
// 	}
//
// 	logf("Ping failed, response:", resp)
// 	//deleteServerIPFile()
// 	return false
// }

// func discoverServer() string {
// 	broadcastAddr, err := getBroadcastAddress()
// 	if err != nil {
// 		logf("Broadcast address resolve failed:", err)
// 		return ""
// 	}
//
// 	for attempt := 1; attempt <= MaxRetries; attempt++ {
// 		logf("Broadcasting (", attempt, ")...")
// 		_, addr, err := sendUDPWithResponse(broadcastAddr, CM_PullIP)
// 		if err != nil {
// 			logf("Broadcast receive failed:", err)
// 			logf("Waiting for 2 seconds...", err)
// 			time.Sleep(2 * time.Second)
// 			continue
// 		}
// 		logf("Received from ", addr.IP.String())
// 		return addr.IP.String()
// 	}
//
// 	return ""
// }

// Send UDP message and wait for a response within Timeout duration.
// Returns response bytes and error (nil if success).
// func sendUDPWithResponse(serverAddr, msg string) ([]byte, *net.UDPAddr, error) {
// 	return sendUDPWithResponseOnPort(serverAddr, s_udp_port, msg, Timeout)
// }

func sendUDPWithResponseOnPort(serverAddr, port, msg string, timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	// listen up from UDP port
	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("UDP listen failed: %w", err)
	}
	defer conn.Close()

	// set read timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// prepare broadcast address
	remoteAddr, err := net.ResolveUDPAddr("udp4", serverAddr+":"+port)
	if err != nil {
		return nil, nil, fmt.Errorf("UDP ResolveUDPAddr failed: %w", err)
	}

	// broadcast send request
	_, err = conn.WriteToUDP([]byte(msg), remoteAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("UDP WriteToUDP failed: %w", err)
	}
	logf("UDP sent:", msg)

	// receive reply
	buffer := make([]byte, Buf_s)
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("UDP ReadFromUDP Timeout: %w", err)
	}

	return buffer[:n], addr, nil
}

// Send UDP message without waiting for a response.
// func sendUDPNoResponse(serverAddr, msg string) error {
// 	return sendUDPNoResponseOnPort(serverAddr, s_udp_port, msg)
// }

func sendUDPNoResponseOnPort(serverAddr, port, msg string) error {
	conn, err := net.Dial("udp", serverAddr+":"+port)
	if err != nil {
		return fmt.Errorf("UDP connection failed: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("UDP send failed: %w", err)
	}

	return nil
}

func getDirectedBroadcastAddrs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var addrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifaceAddrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || len(ipNet.Mask) != net.IPv4len {
				continue
			}

			bcast := net.IPv4(
				ip4[0]|^ipNet.Mask[0],
				ip4[1]|^ipNet.Mask[1],
				ip4[2]|^ipNet.Mask[2],
				ip4[3]|^ipNet.Mask[3],
			).String()
			if _, ok := seen[bcast]; ok {
				continue
			}
			seen[bcast] = struct{}{}
			addrs = append(addrs, bcast)
		}
	}
	sort.Strings(addrs)
	return addrs, nil
}

// TCP
func RunEther_TCP(filePath string) {
	logf("Trying to connect to TCP server...")

	conn, err := net.DialTimeout("tcp", l_config.IP+":"+getTCPPort(), Timeout)
	if err != nil {
		logf(true, "Failed to connect to server: %v", err)
	}
	defer conn.Close()

	if err := ping(conn); err != nil {
		logf(true, "Ping failed: %v", err)
	}

	if err := sendFile(conn, filePath); err != nil {
		logf(err, "File send failed: %v", err)
	}
}

func getUDPPort() string {
	if strings.TrimSpace(l_config.UDPPort) != "" {
		return strings.TrimSpace(l_config.UDPPort)
	}
	return defaultUDPPort
}

func getTCPPort() string {
	if strings.TrimSpace(l_config.TCPPort) != "" {
		return strings.TrimSpace(l_config.TCPPort)
	}
	return defaultTCPPort
}

func getRebootWaitDuration() time.Duration {
	if l_config.RebootWaitSeconds >= 5 {
		return time.Duration(l_config.RebootWaitSeconds) * time.Second
	}
	return 5 * time.Second
}

// 发送 ping 并等待 ok
func ping(conn net.Conn) error {
	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		logf("Sending ping...")
		if err := sendAndWaitOK(conn, []byte(CM_Ping)); err != nil {
			logf("ping failed: %v", err)
			lastErr = err
		} else {
			logf("Ping successful.")
			return nil
		}

		time.Sleep(1 * time.Second)
	}
	if lastErr != nil {
		return fmt.Errorf("ping failed after %d retries: %w", MaxRetries, lastErr)
	}
	return fmt.Errorf("ping failed after %d retries", MaxRetries)
}

// 文件发送函数（按 buffer 分块发送，每块等 ok）
func sendFile(conn net.Conn, filePath string) error {
	// Calculate checksum and file size
	checksum, fileSize, file := CalculateCRC32(filePath)
	defer file.(io.Closer).Close()
	logf("CRC Checksum: %x", checksum)

	// Send flash command

	flashCmd := fmt.Sprintf("%s %d %x", CM_Flash, fileSize, checksum)
	if err := sendAndWaitOK(conn, []byte(flashCmd)); err != nil {
		return fmt.Errorf("failed to send FLASH: %v", err)
	}
	//
	buf := make([]byte, Buf_b)
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			if err := sendAndWaitOK(conn, buf[:n]); err != nil {
				return fmt.Errorf("failed to send chunk: %v", err)
			}
		}
		if readErr == io.EOF {
			logf("File transfer complete.")
			break
		}
		if readErr != nil {
			return fmt.Errorf("file read error: %v", readErr)
		}
	}
	return nil
}

// 通用函数：发送数据，等待 server 回复 "ok"
func sendAndWaitOK(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(Timeout))
	dataLen, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("send error: %v", err)
	}

	logf("Sent %d bytes", dataLen)

	conn.SetReadDeadline(time.Now().Add(Timeout))
	ack := make([]byte, 4)
	n, err := conn.Read(ack)
	if err != nil {
		return fmt.Errorf("read ack error: %v", err)
	}
	if string(ack[:n]) != Rsp_OK {
		return fmt.Errorf("unexpected ack: %s", string(ack[:n]))
	}
	return nil
}

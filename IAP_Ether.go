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
	UID     string
	IP      string
	Role    string
	Version string
	Raw     string
}

const bootloaderDiscoveryRetries = 3

func RunEtherUpgrade(filePath, ip string) {
	logf("[PATH] start ether upgrade flow, target=%s", ip)

	resp, err := udpPingAndGetStatus(ip)
	if err != nil {
		logf(true, "No response from %s, exiting.", ip)
		return
	}

	board, ok := parseBoardInfoFromReply(resp, ip)
	if !ok {
		logf(true, "Unrecognized reply from %s: %q, exiting.", ip, resp)
		return
	}

	targetUID := board.UID
	logf("[PATH] target device UID=%s cached for this upgrade", targetUID)

	switch strings.ToUpper(board.Role) {
	case "BOOTLD-INVALID":
		logf("[PATH] %s is bootloader with NO valid signed app installed (previous update failed, was rejected, or flash was tampered with) -> proceeding to flash a new image", ip)
		RunEther_TCP(filePath, ip)

	case "BOOTLD":
		logf("[PATH] %s is bootloader -> tcp transfer", ip)
		RunEther_TCP(filePath, ip)

	case "CUSAPP":
		logf("[PATH] %s is app -> reboot to bootloader", ip)
		if err := authenticatedUDPReboot(ip); err != nil {
			logf(err, "Failed to send authenticated reboot command to %s", ip)
		}

		wait := getRebootWaitDuration()
		logf("Waiting %.1f seconds for reboot...", wait.Seconds())
		time.Sleep(wait)

		bootBoard, ok := discoverBootloader(bootloaderDiscoveryRetries, targetUID)
		if !ok {
			logf(true, "No bootloader with UID=%s found after %d attempts, exiting.", targetUID, bootloaderDiscoveryRetries)
			return
		}
		logf("[PATH] bootloader found at %s (uid=%s) -> tcp transfer", bootBoard.IP, bootBoard.UID)
		RunEther_TCP(filePath, bootBoard.IP)

	default:
		logf(true, "Unexpected role %q from %s, exiting.", board.Role, ip)
	}
}

// discoverBootloader repeats the broadcast discovery until a bootloader reply
// carrying targetUID is seen, since multiple devices on the LAN may answer the
// broadcast and only the one that was just rebooted should be flashed.
func discoverBootloader(maxAttempts int, targetUID string) (boardInfo, bool) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		boards, err := discoverBoardsViaDirectedBroadcast("BOOTLD")
		if err != nil {
			logf("Bootloader discovery attempt %d/%d: %v", attempt, maxAttempts, err)
			continue
		}
		if board, ok := selectDiscoveredBoard(boards, targetUID); ok {
			return board, true
		}
		logf("Bootloader discovery attempt %d/%d: target UID=%s not among %d discovered device(s)", attempt, maxAttempts, targetUID, len(boards))
	}
	return boardInfo{}, false
}

func discoverBoardsViaDirectedBroadcast(expectedRole string) ([]boardInfo, error) {
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
		remoteAddr, rerr := net.ResolveUDPAddr("udp4", bcast+":"+getPort())
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
		if !strings.EqualFold(info.Role, expectedRole) {
			logf("Ignore %s response from %s while waiting for %s: %s", info.Role, info.IP, expectedRole, info.Raw)
			continue
		}
		boards = append(boards, info)
	}

	if len(boards) == 0 {
		return nil, fmt.Errorf("no valid %s discovery response within %.1f seconds", expectedRole, Timeout.Seconds())
	}
	printDiscoveredBoards(boards, expectedRole)
	return boards, nil
}

func parseBoardInfoFromReply(reply, fallbackIP string) (boardInfo, bool) {
	raw := strings.TrimSpace(reply)
	parts := strings.Split(raw, "_")
	if len(parts) < 4 {
		return boardInfo{}, false
	}
	if strings.TrimSpace(parts[0]) != deviceReplyPrefix {
		return boardInfo{}, false
	}

	uid := strings.TrimSpace(parts[1])
	role := strings.ToUpper(strings.TrimSpace(parts[2]))
	ip := strings.TrimSpace(fallbackIP)
	if uid == "" || ip == "" || role == "" {
		return boardInfo{}, false
	}

	return boardInfo{
		UID:     uid,
		IP:      ip,
		Role:    role,
		Version: strings.Join(parts[3:], "_"),
		Raw:     raw,
	}, true
}

func printDiscoveredBoards(boards []boardInfo, expectedRole string) {
	logf("Discovered %d %s device(s) in %.1f seconds:", len(boards), expectedRole, Timeout.Seconds())
	for i, b := range boards {
		fmt.Printf("  [%d] UID=%s IP=%s Role=%s Reply=%s\n", i+1, b.UID, b.IP, b.Role, b.Raw)
	}
	fmt.Printf("Default selection: [1]")
	if expectedRole == "CUSAPP" {
		fmt.Printf(" (you can modify local_config.json appIP if you want a different device)")
	}
	fmt.Printf("\n")
}

func selectDiscoveredBoard(boards []boardInfo, targetUID string) (boardInfo, bool) {
	for _, b := range boards {
		if strings.EqualFold(b.UID, targetUID) {
			logf("Matched cached target device: uid=%s ip=%s", b.UID, b.IP)
			return b, true
		}
	}
	return boardInfo{}, false
}

func udpPingAndGetStatus(ip string) (string, error) {
	buffer, _, err := sendUDPWithResponseOnPort(ip, getPort(), CM_Ping, Timeout)
	if err != nil {
		return "", err
	}

	resp := strings.TrimSpace(string(buffer))
	if !strings.HasPrefix(resp, deviceReplyPrefix) {
		return "", fmt.Errorf("unexpected UDP ping response: %q", resp)
	}
	return resp, nil
}

// Send UDP message and wait for a response within timeout.
// Returns response bytes and error (nil if success).
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
	logf("UDP sent: %s", msg)

	// receive reply
	buffer := make([]byte, Buf_s)
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("UDP ReadFromUDP Timeout: %w", err)
	}

	return buffer[:n], addr, nil
}

// authenticatedUDPReboot performs the challenge-response handshake before
// sending CM_Reboot: request a nonce, prove possession of iapAuthKey by
// HMAC-signing the exact reboot command, then send the authenticated form.
// An unauthenticated "openplc_server_reboot" (no hmac) is now ignored by
// the device.
func authenticatedUDPReboot(ip string) error {
	nonceResp, _, err := sendUDPWithResponseOnPort(ip, getPort(), CM_RebootChallenge, Timeout)
	if err != nil {
		return fmt.Errorf("reboot challenge request failed: %w", err)
	}
	hmacHex, err := computeAuthHMAC(string(nonceResp), CM_Reboot)
	if err != nil {
		return err
	}
	return sendUDPNoResponseOnPort(ip, getPort(), fmt.Sprintf("%s %s", CM_Reboot, hmacHex))
}

// Send UDP message without waiting for a response.
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
func RunEther_TCP(filePath, serverIP string) {
	logf("Trying to connect to TCP server at %s...", serverIP)

	conn, err := net.DialTimeout("tcp", serverIP+":"+getPort(), Timeout)
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

// getPort returns the configured server port (shared by the TCP flash
// channel and the UDP discovery/reboot channel), falling back to the default.
func getPort() string {
	if strings.TrimSpace(l_config.ServerPort) != "" {
		return strings.TrimSpace(l_config.ServerPort)
	}
	return defaultServerPort
}

func getRebootWaitDuration() time.Duration {
	if l_config.RebootWaitSeconds > 0 {
		return time.Duration(l_config.RebootWaitSeconds) * time.Second
	}
	return time.Duration(defaultRebootWaitSeconds) * time.Second
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

	sigHex, err := loadSignature(filePath)
	if err != nil {
		return err
	}

	localVersion, haveVersion, err := loadVersion(filePath)
	if err != nil {
		return err
	}
	if haveVersion {
		remoteVer, verErr := sendAndReadResponse(conn, []byte(CM_GetVersion))
		if verErr != nil {
			logf("Could not query installed version (older bootloader?): %v -- skipping downgrade check", verErr)
		} else if !confirmDowngradeIfNeeded(localVersion, remoteVer) {
			return fmt.Errorf("downgrade declined by operator")
		}
	}

	base := fmt.Sprintf("%s %d %x %s", CM_Flash, fileSize, checksum, sigHex)
	authMsg := base
	if haveVersion {
		authMsg = fmt.Sprintf("%s %d", base, localVersion)
	}

	nonceResp, err := sendAndReadResponse(conn, []byte(CM_AuthChallenge))
	if err != nil {
		return fmt.Errorf("auth challenge failed: %v", err)
	}
	hmacHex, err := computeAuthHMAC(nonceResp, authMsg)
	if err != nil {
		return err
	}

	// Send flash command
	flashCmd := fmt.Sprintf("%s %s", base, hmacHex)
	if haveVersion {
		flashCmd = fmt.Sprintf("%s %s %d", base, hmacHex, localVersion)
	}
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

// sendAndReadResponse sends data and returns whatever the device replies
// with (trimmed), rather than checking against a fixed "OK". Used to read
// back the nonce from an "authchallenge" request.
func sendAndReadResponse(conn net.Conn, data []byte) (string, error) {
	conn.SetWriteDeadline(time.Now().Add(Timeout))
	if _, err := conn.Write(data); err != nil {
		return "", fmt.Errorf("send error: %v", err)
	}
	logf("Sent %d bytes", len(data))

	conn.SetReadDeadline(time.Now().Add(Timeout))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		return "", fmt.Errorf("read response error: %v", err)
	}
	return strings.TrimSpace(string(resp[:n])), nil
}

package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"IAPTool/iapproto"
	"IAPTool/netiface"
)

// UDP

const (
	deviceReplyPrefix = "STM32H743"
)

type boardInfo struct {
	UID  string
	IP   string
	Role string
	// Version is the board package release (identity field 4) -- the same for
	// every sketch built with one package. AppVersion is the sketch's own
	// (field 5), which is what the version gate compares. Firmware older than
	// 2026-09-21 sends four fields and leaves AppVersion empty.
	Version    string
	AppVersion string
	Raw        string
}

const bootloaderDiscoveryRetries = 3

// How many times to ask a running application to reboot into the bootloader.
// The handshake has no acknowledgement of its own, so one lost datagram must
// not end the upload.
const rebootAttempts = 3

// Pause between identify attempts. The board's discovery cap is device-wide,
// not per source (IAPServer/udp_server.c), so this only spaces the retries.
const identifyRetryDelay = 2500 * time.Millisecond

// Waiting for a board to come back: the original IP is asked once a second and
// broadcast joins only after it has been quiet for findQuietBeforeBroadcast, so
// a normal upload sends no broadcast. $PROD/docs/modules/M1-firmware-upgrade.md
// "等板子回来".
const (
	findInterval             = time.Second
	findQuietBeforeBroadcast = 30 * time.Second
	rebootWindow             = 20 * time.Second // per reboot request
)

// RunEtherUpgrade sends an application image. RunEtherFlashBoot sends a
// bootloader image over the same path -- see $PROD/docs/modules/M1/FLASHBOOT.md
// for what the board does differently with it.
func RunEtherUpgrade(filePath, ip string) {
	runUpload(etherLink{ip: ip}, filePath, CM_Flash)
}

// RunEtherFlashBoot replaces the board's bootloader.
//
// The key it signs with has to be the owner root itself: the board checks a
// bootloader image against the root, not against the certificate's leaf. The
// same key also serves as the session identity, so one --key is enough.
func RunEtherFlashBoot(filePath, ip string) {
	logf("** flashboot replaces the bootloader in place. Do not cut power. **")
	runUpload(etherLink{ip: ip}, filePath, CM_FlashBoot)
}

// etherLink reaches a board by IP: UDP for identify and reboot, one TCP
// connection for the bootloader session (decision 54).
type etherLink struct{ ip string }

func (l etherLink) target() string { return l.ip }

func (l etherLink) identify() (boardInfo, error) {
	resp, err := udpIdentifyWithRetry(l.ip)
	if err != nil {
		return boardInfo{}, fmt.Errorf("No response from %s after %d attempts, exiting.", l.ip, bootloaderDiscoveryRetries)
	}
	board, ok := parseBoardInfoFromReply(resp, l.ip)
	if !ok {
		return boardInfo{}, fmt.Errorf("Unrecognized reply from %s: %q, exiting.", l.ip, resp)
	}
	return board, nil
}

func (l etherLink) requestReboot(id uploadIdentity) error {
	return authenticatedReboot(id,
		func() (string, error) {
			resp, _, err := sendUDPWithResponseOnPort(l.ip, getPort(), CM_RebootChallenge, Timeout)
			return string(resp), err
		},
		func(cmd string) error { return sendUDPNoResponseOnPort(l.ip, getPort(), cmd) })
}

func (l etherLink) finder(uid string) *boardFinder { return newBoardFinder(l.ip, uid) }

func (l etherLink) openSession(board boardInfo) (session, error) {
	logv("Trying to connect to TCP server at %s...", board.IP)
	conn, err := iapproto.DialTCP(board.IP, getPort(), Timeout)
	if err != nil {
		return nil, err
	}
	return tcpSession{conn}, nil
}

// An accepted image resets the board; it is confirmed by the board answering
// on the network again.
func (l etherLink) resetSeen(board boardInfo) (func(bool) bool, time.Duration) {
	f := newBoardFinder(board.IP, board.UID)
	return func(bool) bool {
		st := f.look().state
		if st == rebootInBootloader || st == rebootStillApp {
			logf("The board reset and is answering again - the image was accepted.")
			return true
		}
		return false
	}, etherResetPoll
}

// tcpSession is a session over the bootloader's TCP connection.
type tcpSession struct{ conn net.Conn }

func (s tcpSession) write(b []byte) error {
	s.conn.SetWriteDeadline(time.Now().Add(Timeout))
	_, err := s.conn.Write(b)
	return err
}

func (s tcpSession) readSome(p []byte, wait time.Duration) (int, error) {
	s.conn.SetReadDeadline(time.Now().Add(wait))
	n, err := s.conn.Read(p)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return n, nil
	}
	return n, err
}

func (s tcpSession) Close() error { return s.conn.Close() }

type rebootState int

const (
	rebootInBootloader rebootState = iota // the target UID answers as a bootloader
	rebootStillApp                        // the target UID still answers as the application
	rebootNoAnswer                        // nothing usable answered at the original IP
	rebootOtherBoard                      // another board answers at the original IP
)

type rebootResult struct {
	state rebootState
	board boardInfo // the board that answered as the target
	sent  int       // reboot requests that got through
	other string    // the UID that answered, when state is rebootOtherBoard
}

// boardFinder looks for one board, by UID, at the address it was last seen.
type boardFinder struct {
	ip, uid   string
	identify  func() (string, error)      // one unicast identify of ip
	broadcast func() ([]boardInfo, error) // one broadcast discovery round; nil on USB
	now       func() time.Time
	sleep     func(time.Duration)
	quietFrom time.Time // when ip stopped answering; zero while it answers
}

func newBoardFinder(ip, uid string) *boardFinder {
	return &boardFinder{
		ip: ip, uid: uid,
		identify:  func() (string, error) { return udpIdentify(ip, findInterval) },
		broadcast: func() ([]boardInfo, error) { return discoverBoardsViaDirectedBroadcast("") },
		now:       time.Now,
		sleep:     time.Sleep,
	}
}

// look makes one round and says what it saw.
func (f *boardFinder) look() rebootResult {
	if resp, err := f.identify(); err == nil {
		f.quietFrom = time.Time{}
		board, ok := parseBoardInfoFromReply(resp, f.ip)
		if !ok {
			return rebootResult{state: rebootNoAnswer}
		}
		if !strings.EqualFold(board.UID, f.uid) {
			return rebootResult{state: rebootOtherBoard, other: board.UID}
		}
		return roleResult(board)
	}
	if f.broadcast == nil {
		return rebootResult{state: rebootNoAnswer}
	}
	if f.quietFrom.IsZero() {
		f.quietFrom = f.now()
	}
	if f.now().Sub(f.quietFrom) < findQuietBeforeBroadcast {
		return rebootResult{state: rebootNoAnswer}
	}
	logv("%s has been quiet for %s; looking for uid=%s by broadcast", f.ip, findQuietBeforeBroadcast, f.uid)
	boards, err := f.broadcast()
	if err != nil {
		return rebootResult{state: rebootNoAnswer}
	}
	if board, ok := selectDiscoveredBoard(boards, f.uid); ok {
		return roleResult(board)
	}
	return rebootResult{state: rebootNoAnswer}
}

func roleResult(board boardInfo) rebootResult {
	switch role := strings.ToUpper(board.Role); {
	case strings.HasPrefix(role, "BOOTLD"):
		return rebootResult{state: rebootInBootloader, board: board}
	case role == "CUSAPP":
		return rebootResult{state: rebootStillApp, board: board}
	}
	return rebootResult{state: rebootNoAnswer}
}

// awaitBootloader looks once a second until the target answers as a
// bootloader, another board answers at its address, or window passes.
func (f *boardFinder) awaitBootloader(window time.Duration) rebootResult {
	end := f.now().Add(window)
	for {
		start := f.now()
		res := f.look()
		if res.state == rebootInBootloader || res.state == rebootOtherBoard || !f.now().Before(end) {
			return res
		}
		if spent := f.now().Sub(start); spent < findInterval {
			f.sleep(findInterval - spent)
		}
	}
}

// rebootIntoBootloader asks the application to reboot until the target board
// answers as a bootloader. A bootloader does not answer the reboot challenge,
// so a request that fails is followed by one look in case it is already there.
func rebootIntoBootloader(request func() error, f *boardFinder) rebootResult {
	var res rebootResult
	for attempt := 1; attempt <= rebootAttempts; attempt++ {
		var r rebootResult
		if err := request(); err != nil {
			logv("Reboot request %d/%d did not get through: %v", attempt, rebootAttempts, err)
			r = f.look()
		} else {
			res.sent++
			r = f.awaitBootloader(rebootWindow)
		}
		r.sent = res.sent
		if r.state == rebootInBootloader || r.state == rebootOtherBoard {
			return r
		}
		res = r
		if attempt < rebootAttempts {
			logv("Target uid=%s is not in its bootloader yet; asking it to reboot again (%d/%d)",
				f.uid, attempt+1, rebootAttempts)
		}
	}
	return res
}

// rebootFailureText explains a run that did not reach the bootloader. Only a
// board still running its application can mean a key it does not trust, and
// even then the request may simply have been lost: the application answers a
// rejected reboot with silence.
func rebootFailureText(res rebootResult, ip, targetUID, keyPath string) string {
	switch {
	case res.sent == 0 && res.state != rebootOtherBoard:
		return fmt.Sprintf("No reboot request could be sent to %s in %d attempt(s) (reasons above).",
			ip, rebootAttempts)
	case res.state == rebootStillApp:
		return fmt.Sprintf("%s (uid=%s) is still running its application after %d reboot request(s):\n"+
			"  the board did not accept the reboot request. Either the key %s is not one\n"+
			"  this board trusts, or the request was lost on the way.\n"+
			"  To tell which: put the board in its bootloader (hold BOOT0 while it resets),\n"+
			"  then `IAPTool getowner %s` shows which key it trusts.",
			ip, targetUID, res.sent, keyPath, ip)
	case res.state == rebootOtherBoard:
		return fmt.Sprintf("%s now answers as a different board (uid=%s, expected %s); not uploading to it.",
			ip, res.other, targetUID)
	default:
		return fmt.Sprintf("%s (uid=%s) did not come back after %d reboot request(s): it answers neither\n"+
			"  discovery nor a direct identify. Check its power and cable, then run the upload again.",
			ip, targetUID, res.sent)
	}
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
			logv("Skip invalid broadcast addr %s: %v", bcast, rerr)
			continue
		}
		if _, werr := conn.WriteToUDP([]byte(CM_PullIP), remoteAddr); werr != nil {
			logv("Broadcast send failed to %s: %v", remoteAddr.String(), werr)
			continue
		}
		logv("UDP broadcast sent to %s", remoteAddr.String())
	}

	var boards []boardInfo
	buffer := make([]byte, Buf_s)
	for {
		n, addr, rerr := conn.ReadFromUDP(buffer)
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				break
			}
			logv("UDP receive error: %v", rerr)
			continue
		}

		info, ok := parseBoardInfoFromReply(string(buffer[:n]), addr.IP.String())
		if !ok {
			logv("Ignore invalid discovery response from %s: %q", addr.IP.String(), strings.TrimSpace(string(buffer[:n])))
			continue
		}
		// An empty expectedRole means "whatever it is now": used to confirm a
		// board came back after a write, when which role it lands in is the
		// thing that depends on what was written.
		if expectedRole != "" && !strings.EqualFold(info.Role, expectedRole) {
			logv("Ignore %s response from %s while waiting for %s: %s", info.Role, info.IP, expectedRole, info.Raw)
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

	appVersion := ""
	if len(parts) >= 5 {
		appVersion = strings.TrimSpace(parts[4])
	}

	return boardInfo{
		UID:        uid,
		IP:         ip,
		Role:       role,
		Version:    strings.TrimSpace(parts[3]),
		AppVersion: appVersion,
		Raw:        raw,
	}, true
}

func printDiscoveredBoards(boards []boardInfo, expectedRole string) {
	if !g_verbose {
		return
	}
	logf("Discovered %d %s device(s) in %.1f seconds:", len(boards), expectedRole, Timeout.Seconds())
	for i, b := range boards {
		fmt.Printf("  [%d] UID=%s IP=%s Role=%s Reply=%s\n", i+1, b.UID, b.IP, b.Role, b.Raw)
	}
	fmt.Printf("Default selection: [1]\n")
}

func selectDiscoveredBoard(boards []boardInfo, targetUID string) (boardInfo, bool) {
	for _, b := range boards {
		if strings.EqualFold(b.UID, targetUID) {
			logv("Matched cached target device: uid=%s ip=%s", b.UID, b.IP)
			return b, true
		}
	}
	return boardInfo{}, false
}

// udpIdentifyWithRetry asks a known address who it is, retrying like the
// broadcast discovery already does. A single lost datagram must not end the
// upgrade: UDP has no delivery guarantee, and the operator only ever sees
// "no response", which reads as a dead board rather than a dropped packet.
func udpIdentifyWithRetry(ip string) (string, error) {
	var lastErr error

	for attempt := 1; attempt <= bootloaderDiscoveryRetries; attempt++ {
		resp, err := udpIdentify(ip, CommandTimeout)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt < bootloaderDiscoveryRetries {
			logv("Identify attempt %d/%d on %s got no usable reply (%v), retrying in %.1fs...",
				attempt, bootloaderDiscoveryRetries, ip, err, identifyRetryDelay.Seconds())
			time.Sleep(identifyRetryDelay)
		}
	}
	return "", lastErr
}

func udpIdentify(ip string, timeout time.Duration) (string, error) {
	// CM_PullIP, not CM_Ping: "ping" answers with the identity string over UDP but
	// with "OK" over CDC/TCP, and one command must not mean two things.
	buffer, _, err := sendUDPWithResponseOnPort(ip, getPort(), CM_PullIP, timeout)
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
	conn, err := iapproto.DialUDP(serverAddr, port)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte(msg)); err != nil {
		return nil, nil, fmt.Errorf("UDP Write failed: %w", err)
	}
	logv("UDP sent: %s", msg)

	// A connected socket only accepts datagrams from the address it dialed, so
	// this can no longer be answered by some other device on the network.
	buffer := make([]byte, Buf_s)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("UDP Read Timeout: %w", err)
	}

	return buffer[:n], conn.RemoteAddr().(*net.UDPAddr), nil
}

// Boot log read over UDP. Wire format: $PROD/docs/modules/M1/IAP-PROTOCOL.md
// "openplc_log". The whole 4 KB buffer is about five pieces; the cap only stops
// a board whose log grows faster than we read it.
const (
	logReadMaxPieces = 64
	logReadAttempts  = 3
	// The board drops requests over 20 replies/s; wait out its window before retrying.
	logReadRetryDelay = time.Second
)

// RunReadLog prints every line of the board's SRAM4 boot log, oldest first,
// as "<seq> <text>". The bootloader and the application both answer.
func RunReadLog(ip string) {
	var from uint64
	printed := 0
	defer func() {
		if printed == 0 {
			logf("The boot log on %s is empty.", ip)
		}
	}()
	for piece := 0; piece < logReadMaxPieces; piece++ {
		reply, err := readLogPieceWithRetry(ip, from)
		if err != nil {
			logf(true, "No boot log from %s (%v): no answer (old firmware?).", ip, err)
		}
		next, more, lines, err := parseLogPiece(reply)
		logf(err, "Unexpected boot log reply from %s", ip)
		for _, line := range lines {
			fmt.Println(line)
		}
		printed += len(lines)
		if !more || next <= from {
			return
		}
		from = next
	}
}

func readLogPieceWithRetry(ip string, from uint64) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= logReadAttempts; attempt++ {
		reply, _, err := sendUDPWithResponseOnPort(ip, getPort(), fmt.Sprintf("%s %d", CM_ReadLog, from), CommandTimeout)
		if err == nil {
			return reply, nil
		}
		lastErr = err
		if attempt < logReadAttempts {
			logv("Boot log piece from seq %d: no reply (%v), retrying", from, err)
			time.Sleep(logReadRetryDelay)
		}
	}
	return nil, lastErr
}

// parseLogPiece splits "log <next> <more>\n<seq> <text>\n...".
func parseLogPiece(reply []byte) (next uint64, more bool, lines []string, err error) {
	text := strings.TrimRight(string(reply), "\n")
	header, body, _ := strings.Cut(text, "\n")
	var moreFlag int
	if n, serr := fmt.Sscanf(header, "log %d %d", &next, &moreFlag); serr != nil || n != 2 {
		return 0, false, nil, fmt.Errorf("bad header %q", header)
	}
	if body != "" {
		lines = strings.Split(body, "\n")
	}
	return next, moreFlag == 1, lines, nil
}

// Send UDP message without waiting for a response.
func sendUDPNoResponseOnPort(serverAddr, port, msg string) error {
	conn, err := iapproto.DialUDP(serverAddr, port)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("UDP send failed: %w", err)
	}

	return nil
}

// Only physical interfaces are broadcast to. A VPN tunnel or a Docker switch
// answers nothing and its broadcast address merely costs a timeout, while its
// default route can pull the probe off the real NIC entirely. See
// $PROD/docs/tables/DECISIONS.md decision 51.
func getDirectedBroadcastAddrs() ([]string, error) {
	ifaces, err := netiface.Physical()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var addrs []string
	for _, iface := range ifaces {
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

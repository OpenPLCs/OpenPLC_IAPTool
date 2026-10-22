package main

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"IAPTool/iapcert"
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
// not end the upload (OWN-08).
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
	runEtherFlow(filePath, ip, CM_Flash)
}

// RunEtherFlashBoot replaces the board's bootloader.
//
// The key it signs with has to be the owner root itself: the board checks a
// bootloader image against the root, not against the certificate's leaf. The
// same key also serves as the session identity, so one --key is enough.
func RunEtherFlashBoot(filePath, ip string) {
	logf("** flashboot replaces the bootloader in place. Do not cut power. **")
	runEtherFlow(filePath, ip, CM_FlashBoot)
}

func runEtherFlow(filePath, ip, verb string) {
	logf("[PATH] start ether %s flow, target=%s", verb, ip)

	resp, err := udpIdentifyWithRetry(ip)
	if err != nil {
		logf(true, "No response from %s after %d attempts, exiting.", ip, bootloaderDiscoveryRetries)
		return
	}

	board, ok := parseBoardInfoFromReply(resp, ip)
	if !ok {
		logf(true, "Unrecognized reply from %s: %q, exiting.", ip, resp)
		return
	}

	targetUID := board.UID
	logv("[PATH] target device UID=%s cached for this upgrade", targetUID)

	// Has to run here, before anything asks the board to leave the
	// application: in the bootloader the app-version field is "-" and what is
	// currently installed can no longer be read. A board that never answered
	// has already exited above, so reaching this line means discovery worked.
	// Skipped for flashboot: a bootloader image carries no sketch version,
	// and the field the gate reads describes the application.
	if verb == CM_Flash {
		checkVersionGate(filePath, board, true, g_forceFlash)
	}

	// A board with no root is always in its bootloader: nothing it could run
	// has been verified. Only an application upload claims it; flashboot on
	// such a board is refused by the board.
	if verb == CM_Flash && strings.HasPrefix(strings.ToUpper(board.Role), "BOOTLD") {
		if err := claimIfUnclaimed(func(cmd string) (string, error) {
			return ownerCommand(ip, cmd)
		}); err != nil {
			logf(err, "Cannot claim this board")
			return
		}
	}

	// Resolved once and reused: a run that starts from the application state
	// authenticates twice (the reboot, then the flash), and issuing a fresh
	// self-signed certificate for each would burn two serial numbers on one
	// upload.
	id, err := resolveUploadIdentity()
	if err != nil {
		logf(err, "Cannot authenticate to this board")
		return
	}

	switch strings.ToUpper(board.Role) {
	case "BOOTLD-INVALID":
		logf("[PATH] %s is bootloader with NO valid signed app installed (previous update failed, was rejected, or flash was tampered with) -> proceeding to flash a new image", ip)
		RunEther_TCP(filePath, ip, id, verb, targetUID)

	case "BOOTLD":
		logf("[PATH] %s is bootloader (uid=%s) -> tcp transfer", ip, targetUID)
		RunEther_TCP(filePath, ip, id, verb, targetUID)

	case "CUSAPP":
		logf("[PATH] %s is app -> reboot to bootloader", ip)
		res := rebootIntoBootloader(func() error { return authenticatedUDPReboot(ip, id) },
			newBoardFinder(ip, targetUID))
		if res.state != rebootInBootloader {
			logf(true, "%s", rebootFailureText(res, ip, targetUID, id.keyPath))
			return
		}
		logf("[PATH] bootloader found at %s (uid=%s) -> tcp transfer", res.board.IP, res.board.UID)
		RunEther_TCP(filePath, res.board.IP, id, verb, targetUID)

	default:
		logf(true, "Unexpected role %q from %s, exiting.", board.Role, ip)
	}
}

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
	broadcast func() ([]boardInfo, error) // one broadcast discovery round
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

// authenticatedUDPReboot performs the challenge-response handshake before
// sending CM_Reboot: request a nonce, sign the exact reboot command, then send
// the certificate and that signature. An unauthenticated
// "openplc_server_reboot" is ignored by the device.
func authenticatedUDPReboot(ip string, id uploadIdentity) error {
	nonceResp, _, err := sendUDPWithResponseOnPort(ip, getPort(), CM_RebootChallenge, Timeout)
	if err != nil {
		return fmt.Errorf("reboot challenge request failed: %w", err)
	}
	noncesigHex, err := iapcert.NonceSig(id.key, string(nonceResp), CM_Reboot)
	if err != nil {
		return err
	}
	return sendUDPNoResponseOnPort(ip, getPort(), fmt.Sprintf("%s %s %s", CM_Reboot, id.certHex, noncesigHex))
}

// Boot log read over UDP. Wire format: $PROD/docs/modules/M1/IAP-PROTOCOL.md
// "openplc_log". The whole 4 KB buffer is about five pieces; the cap only stops
// a board whose log grows faster than we read it.
const (
	logReadMaxPieces  = 64
	logReadAttempts   = 3
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

// TCP
//
// One connection for the whole upload: dial, ping, confirm the board accepts
// this identity, then send the file.
func RunEther_TCP(filePath, serverIP string, id uploadIdentity, verb, targetUID string) {
	sigHex, err := signImageInMemory(filePath, id.key)
	logf(err, "Failed to prepare signature for %s", filePath)

	logv("Trying to connect to TCP server at %s...", serverIP)

	conn, err := iapproto.DialTCP(serverIP, getPort(), Timeout)
	if err != nil {
		logf(true, "Failed to connect to server: %v", err)
	}
	defer conn.Close()

	if err := ping(conn); err != nil {
		logf(true, "Ping failed: %v", err)
	}

	if err := verifyIdentityMatchesDevice(id, func() (string, error) {
		return sendAndReadResponse(conn, []byte(CM_GetPubKey+"\n"))
	}); err != nil {
		logf(true, "Signing key check failed: %v", err)
	}

	f := newBoardFinder(serverIP, targetUID)
	cameBack := func() bool {
		st := f.look().state
		return st == rebootInBootloader || st == rebootStillApp
	}
	if err := sendFile(conn, filePath, id, sigHex, verb, cameBack); err != nil {
		logf(err, "File send failed")
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

// ping sends "ping" and waits for "OK", retrying up to MaxRetries times.
func ping(conn net.Conn) error {
	var lastErr error
	for attempt := 1; attempt <= MaxRetries; attempt++ {
		logv("Sending ping...")
		if err := sendAndWaitOK(conn, []byte(CM_Ping+"\n")); err != nil {
			logv("ping failed: %v", err)
			lastErr = err
		} else {
			logv("Ping successful.")
			return nil
		}

		time.Sleep(1 * time.Second)
	}
	if lastErr != nil {
		return fmt.Errorf("ping failed after %d retries: %w", MaxRetries, lastErr)
	}
	return fmt.Errorf("ping failed after %d retries", MaxRetries)
}

// sendFile carries no interactive step: the identity check already ran on
// this same connection, in RunEther_TCP, before this is called.
func sendFile(conn net.Conn, filePath string, id uploadIdentity, sigHex, verb string, cameBack func() bool) error {
	// Calculate checksum and file size
	checksum, fileSize, file := CalculateCRC32(filePath)
	defer file.(io.Closer).Close()
	logv("CRC Checksum: %x", checksum)

	flashCmd, err := flashCommand(id, verb, fileSize, checksum, sigHex, func() (string, error) {
		return sendAndReadResponse(conn, []byte(CM_AuthChallenge+"\n"))
	})
	if err != nil {
		return err
	}

	// Send flash command
	if err := sendAndWaitOK(conn, []byte(flashCmd+"\n")); err != nil {
		return fmt.Errorf("failed to send FLASH: %v", err)
	}
	// Raw binary chunks below -- do NOT append "\n" framing to these, only
	// to the text commands above; the device switches to FLASH_RECEIVE
	// state after the "OK" ack and treats every subsequent byte as image
	// data, not text to scan for a newline.
	buf := make([]byte, Buf_b)
	bar := newProgress(fileSize)
	defer bar.end()
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			if err := sendAndWaitOK(conn, buf[:n]); err != nil {
				return fmt.Errorf("failed to send chunk: %v", err)
			}
			bar.add(n)
		}
		if readErr == io.EOF {
			bar.end()
			// The board has every byte now, but it has not judged them yet:
			// it verifies the staged image and only then says whether it
			// took it. Reading that verdict is the difference between
			// "uploaded" and "accepted" -- without it a refused image was
			// reported as a successful transfer.
			if err := readFinalVerdict(conn, verb, cameBack); err != nil {
				return err
			}
			logf("File transfer complete.")
			// Only now is the one-shot force marker written: a transfer that
			// failed above never reaches this line, so retrying a failed
			// forced flash is not blocked.
			noteFlashSucceeded()
			break
		}
		if readErr != nil {
			return fmt.Errorf("file read error: %v", readErr)
		}
	}
	return nil
}

// After the last chunk the board verifies the image, and only then decides.
// It answers ONLY to refuse -- "Signature Failed", "No Signature",
// "Flash Failed". Both success paths reset the board instead, and a reset
// takes the MAC down before anything queued for the peer leaves it, so there
// is no "OK" to wait for.
//
// So success is confirmed the only way it can be: the board comes back and
// answers discovery again.
const (
	// The whole window. Long because a refusal from the flash write itself
	// arrives only after the application region has been erased and written.
	verdictTimeout = 90 * time.Second
	// One slice of TCP listening before looking for the board on the network
	// instead. Short: a refusal that is coming is already on its way.
	verdictPoll = 2 * time.Second
)

// readFinalVerdict decides whether the board took the image.
//
// Returns nil only on evidence: either the board said OK (no path does today,
// but a refusal-shaped silence must not be read as one), or it came back on
// the network, which only happens after it reset, which only happens when it
// accepted. Anything the board says other than OK is a refusal.
func readFinalVerdict(conn net.Conn, verb string, cameBack func() bool) error {
	deadline := time.Now().Add(verdictTimeout)

	for time.Now().Before(deadline) {
		// Errors here are not failures: a reset board yields a timeout or a
		// dropped connection, and that is one of the expected outcomes.
		resp, _ := readWithIdleGap(conn, verdictPoll)
		if said := strings.TrimSpace(string(resp)); said != "" {
			if said == Rsp_OK {
				return nil
			}
			return fmt.Errorf("the board refused the image: %s", said)
		}
		if cameBack() {
			logf("The board reset and is answering again - the image was accepted.")
			return nil
		}
	}
	return fmt.Errorf("the board neither refused the image nor came back within %s. "+
		"It was NOT confirmed: check its log before assuming anything was written", verdictTimeout)
}

// readWithIdleGap accumulates reads from conn until it goes quiet for
// idleGap, instead of trusting a single Read() to return a complete reply.
// Mirrors the CDC-side fix in SendCommandReadResponse: a short TCP write on
// the device side can still reach the caller split across more than one
// Read() (Go's net.Conn makes no promise that one Write() on the far end
// arrives as one Read() on this end), so treating the first Read() as "the
// whole response" is not safe here either.
func readWithIdleGap(conn net.Conn, overallTimeout time.Duration) ([]byte, error) {
	const idleGap = 100 * time.Millisecond
	buf := make([]byte, 256)
	var accumulated []byte
	deadline := time.Now().Add(overallTimeout)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(idleGap))
		n, err := conn.Read(buf)
		if n > 0 {
			accumulated = append(accumulated, buf[:n]...)
			continue
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if len(accumulated) > 0 {
					return accumulated, nil
				}
				continue
			}
			return accumulated, err
		}
	}
	if len(accumulated) == 0 {
		return nil, fmt.Errorf("timeout waiting for response")
	}
	return accumulated, nil
}

// sendAndWaitOK sends data and waits for the board to answer "OK".
func sendAndWaitOK(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(Timeout))
	dataLen, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("send error: %v", err)
	}

	logv("Sent %d bytes", dataLen)

	resp, err := readWithIdleGap(conn, Timeout)
	if err != nil {
		return fmt.Errorf("read ack error: %v", err)
	}
	if strings.TrimSpace(string(resp)) != Rsp_OK {
		return fmt.Errorf("unexpected ack: %s", string(resp))
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
	logv("Sent %d bytes", len(data))

	resp, err := readWithIdleGap(conn, Timeout)
	if err != nil {
		return "", fmt.Errorf("read response error: %v", err)
	}
	return strings.TrimSpace(string(resp)), nil
}

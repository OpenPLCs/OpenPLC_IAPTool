package main

// Board ownership: claim a board for a customer's own signing key, hand it
// over to another key, and ask which key it currently trusts.
//
// The bootloader answers these commands on the upload channels -- the TCP
// port, or the USB CDC port -- one exchange per connection because it serves a
// single client at a time:
//
//   getpubkey                          the 64-byte root public key, hex; "none" = no root
//   getowner                           generation of the record in force
//   takeown  <pubkey>                  claim; accepted only while the board has no root
//   setowner <gen> <pubkey> <sig>      hand over; refused unless the CURRENT owner signed
//   revoke   <leafhex> <sig>           revoke one leaf; refused unless the CURRENT owner signed
//   getapprevoked                      "yes" / "no" / "none" - was the installed image's signer revoked
//
// The read-only ones (getpubkey, getowner, getapprevoked, getuid) a running
// application also answers, over UDP only, with the same text (decision 148);
// ownerQuery asks it there instead of rebooting the board. The others stay
// bootloader-only. Protocol: $PROD/docs/modules/M1/IAP-PROTOCOL.md.
//
// See $PROD/docs/modules/M2-ownership.md for why the first claim has no
// gate and every later one needs a signature. Revocation names a
// leaf by the first 16 bytes of its public key, not a tool-assigned number --
// see $PROD/maps/owner-revoke-and-boot-upgrade/issues/OWN-01-revoke-by-serial-or-by-pubkey.md.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"IAPTool/iapproto"
)

// Mirrors the owner area in OpenPLC_BootLoader/IAPServer/owner_slot.h: an 'O'
// segment of 160-byte ownership records and an 'R' segment of 32-byte
// revocation records, sharing one format_ver. Only the bytes the board signs
// over are built here -- the first 88 of an 'O' record
// (type/reserved0/format_ver/generation/flags/root_pubkey/uid), the whole 32
// of an 'R' record. Layout: $PROD/docs/modules/M2-ownership.md.
const (
	ownerRecordType       = 'O'
	ownerRecordTypeRevoke = 'R'
	ownerRecordReserved0  = 0
	ownerRecordFormatVer  = 4
	ownerUIDLen           = 12
	ownerSignedPrefixLen  = 88
	ownerRevokePrefixLen  = 16
	ownerRevokeRecordLen  = 32
)

var pubKeyPattern = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)

// isSerialTarget says whether target names a serial port (COM3, /dev/ttyACM0)
// rather than a board on the network.
func isSerialTarget(target string) bool {
	if net.ParseIP(target) != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToUpper(target), "COM")
	}
	return strings.HasPrefix(target, "/dev/")
}

// ownerCommand runs one command on the board at target -- a serial port or an
// IP -- and returns the device's reply.
func ownerCommand(target, cmd string) (string, error) {
	if isSerialTarget(target) {
		port, err := openPort(target, l_config.BaudRate)
		if err != nil {
			return "", fmt.Errorf("cannot open %s: %v", target, err)
		}
		defer port.Close()
		reply, err := SendCommandReadResponse(port, cmd, CommandTimeout)
		if err != nil {
			// A running sketch owns the USB port and answers nothing yet.
			return "", fmt.Errorf("%v (is the board in its bootloader? a running sketch answers these only over the network for now)", err)
		}
		return reply, nil
	}
	// Pinned to the physical NIC like every other dial to the board (decision 51).
	conn, err := iapproto.DialTCP(target, getPort(), Timeout)
	if err != nil {
		// A running sketch never answers TCP; ownerQuery already sent the read-only commands over UDP.
		return "", fmt.Errorf("cannot reach %s: %v (is the board in its bootloader? a running sketch does not take this command)", target, err)
	}
	defer conn.Close()
	return sendAndReadResponse(conn, []byte(cmd+"\n"))
}

// ownerQueryAttempts covers a lost datagram; the board's 20 replies/s cap is
// far above what one command sends.
const ownerQueryAttempts = 3

// appRole caches, per network target, whether it answered discovery as a
// running application, so a command reading several values identifies once.
var appRole = map[string]bool{}

// boardRunsApp says whether the board at ip answers discovery as a running
// application. No answer counts as "no": the TCP path then reports it.
func boardRunsApp(ip string) bool {
	if v, ok := appRole[ip]; ok {
		return v
	}
	isApp := false
	if resp, err := udpIdentifyWithRetry(ip); err == nil {
		if board, ok := parseBoardInfoFromReply(resp, ip); ok {
			isApp = strings.EqualFold(board.Role, "CUSAPP")
		}
	}
	appRole[ip] = isApp
	return isApp
}

// ownerQuery runs a read-only query (getpubkey, getowner, getapprevoked,
// getuid). A board running its application is asked over UDP and keeps
// running; anything else goes through ownerCommand as before.
func ownerQuery(target, cmd string) (string, error) {
	if isSerialTarget(target) || !boardRunsApp(target) {
		return ownerCommand(target, cmd)
	}
	var lastErr error
	for attempt := 1; attempt <= ownerQueryAttempts; attempt++ {
		reply, _, err := sendUDPWithResponseOnPort(target, getPort(), cmd, CommandTimeout)
		if err == nil {
			return string(reply), nil
		}
		lastErr = err
		if attempt < ownerQueryAttempts {
			logv("%s on %s: no UDP reply (%v), retrying", cmd, target, err)
			time.Sleep(time.Second)
		}
	}
	return "", fmt.Errorf("%s runs its application and did not answer %s over UDP: %v "+
		"(application built with an older board package?)", target, cmd, lastErr)
}

// ownerPublicKeyHex reads a PEM private key and returns its public half in the
// form the device speaks.
func ownerPublicKeyHex(keyPath string) (string, error) {
	key, err := loadSigningKey(keyPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %v", keyPath, err)
	}
	return publicKeyHex(&key.PublicKey), nil
}

// ownerReadState returns the generation in force and the trusted key; the key
// is "" on a board with no root.
func ownerReadState(ip string) (uint32, string, error) {
	genReply, err := ownerQuery(ip, "getowner")
	if err != nil {
		return 0, "", err
	}
	key, err := ownerQuery(ip, "getpubkey")
	if err != nil {
		return 0, "", err
	}
	key = strings.TrimSpace(key)
	if key == noRootReply {
		key = ""
	} else if !pubKeyPattern.MatchString(key) {
		return 0, "", fmt.Errorf("the board answered getpubkey with %q", key)
	}
	gen, err := strconv.ParseUint(strings.TrimSpace(genReply), 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("the board answered getowner with %q", genReply)
	}
	return uint32(gen), strings.ToLower(key), nil
}

// ownerSignedPrefix builds the 88 bytes the next owner record is signed
// over: type, slots, format_ver, generation, flags, the incoming public key,
// and (v2) the target board's own uid -- the board fills uid into the record
// itself from its own hardware UID when it writes it, so the signature has
// to cover the exact bytes the board will end up with, or verification fails
// the moment the board recomputes sha256 over its own copy.
func ownerSignedPrefix(generation uint32, pubKeyHex string, uidHex string) ([]byte, error) {
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pub) != 64 {
		return nil, fmt.Errorf("the new key must be 128 hex characters")
	}
	uid, err := hex.DecodeString(strings.TrimSpace(uidHex))
	if err != nil || len(uid) != ownerUIDLen {
		return nil, fmt.Errorf("the board's uid must be %d hex characters, got %q", ownerUIDLen*2, uidHex)
	}
	var b bytes.Buffer
	b.WriteByte(ownerRecordType)
	b.WriteByte(ownerRecordReserved0)
	binary.Write(&b, binary.LittleEndian, uint16(ownerRecordFormatVer))
	binary.Write(&b, binary.LittleEndian, generation)
	binary.Write(&b, binary.LittleEndian, uint32(0)) // flags
	b.Write(pub)
	b.Write(uid)
	if b.Len() != ownerSignedPrefixLen {
		return nil, fmt.Errorf("built a %d byte prefix, expected %d", b.Len(), ownerSignedPrefixLen)
	}
	return b.Bytes(), nil
}

// ownerRevokeSignedPrefix builds the whole 32-byte 'R' record: type,
// reserved0, format_ver, the board's own uid, the revoked leaf's 16-byte
// prefix. The board verifies the signature at write time and then discards it,
// so the signed bytes are exactly the bytes it writes, reserved0 included.
// Layout: $PROD/docs/modules/M2-ownership.md.
func ownerRevokeSignedPrefix(leafPrefixHex string, uidHex string) ([]byte, error) {
	prefix, err := hex.DecodeString(leafPrefixHex)
	if err != nil || len(prefix) != ownerRevokePrefixLen {
		return nil, fmt.Errorf("the leaf prefix must be %d hex characters", ownerRevokePrefixLen*2)
	}
	uid, err := hex.DecodeString(strings.TrimSpace(uidHex))
	if err != nil || len(uid) != ownerUIDLen {
		return nil, fmt.Errorf("the board's uid must be %d hex characters, got %q", ownerUIDLen*2, uidHex)
	}

	var b bytes.Buffer
	b.WriteByte(ownerRecordTypeRevoke)
	b.WriteByte(ownerRecordReserved0)
	binary.Write(&b, binary.LittleEndian, uint16(ownerRecordFormatVer))
	b.Write(uid)
	b.Write(prefix)
	if b.Len() != ownerRevokeRecordLen {
		return nil, fmt.Errorf("built a %d byte record, expected %d", b.Len(), ownerRevokeRecordLen)
	}
	return b.Bytes(), nil
}

// ownerGetUID asks the board for its own hardware UID ("getuid"), the same
// value it will fill into a new owner record's uid field itself.
func ownerGetUID(ip string) (string, error) {
	reply, err := ownerQuery(ip, "getuid")
	if err != nil {
		return "", err
	}
	uidHex := strings.ToLower(strings.TrimSpace(reply))
	if _, err := hex.DecodeString(uidHex); err != nil || len(uidHex) != ownerUIDLen*2 {
		return "", fmt.Errorf("the board answered getuid with %q, expected %d hex characters", reply, ownerUIDLen*2)
	}
	return uidHex, nil
}

// RunGetOwner prints which key the board trusts and how to change that.
func RunGetOwner(ip string) {
	gen, key, err := ownerReadState(ip)
	logf(err, "cannot read this board's ownership state")

	if key == "" {
		fmt.Println("No root. This board trusts no key yet (new, or factory-reset).")
		fmt.Println("The next upload claims it for the uploading computer's key.")
		return
	}
	fmt.Printf("Claimed at generation %d.\n", gen)
	fmt.Printf("Trusted key: %s\n", key)
	fmt.Println("Only firmware signed by that key, or by a key it certified, will start.")
	fmt.Println()
	fmt.Println("To hand this board to a different key:")
	fmt.Println("  setowner      - signed by the current owner's key, no button needed")
	fmt.Println("  factory reset - hold BOOT0 for 10 s; the next upload then claims it")
}

// RunGetAppRevoked reports whether the image installed on this board was
// signed by a leaf that has since been revoked.
//
// A revoked leaf's image keeps booting (decision 60), so this is the only way
// to find the boards that want a re-upload after revoking somebody. One board
// per call, by design: scanning a subnet is the caller's job, from discovery.
func RunGetAppRevoked(ip string) {
	reply, err := ownerQuery(ip, "getapprevoked")
	logf(err, "cannot ask this board about its installed firmware")

	switch strings.TrimSpace(reply) {
	case "yes":
		fmt.Println("REVOKED. This board is running firmware signed by a leaf that has been revoked.")
		fmt.Println("It keeps running, and it keeps working. But that signer is no longer trusted,")
		fmt.Println("so re-upload this board with a current key when you get the chance.")
	case "no":
		fmt.Println("OK. The firmware on this board was signed by a leaf that is still trusted.")
	case "none":
		fmt.Println("No signed firmware installed - nothing to re-upload.")
	default:
		logf(true, fmt.Sprintf("the board answered getapprevoked with %q", reply))
	}
}

// RunTakeOwn claims a board that has no root for the key in keyPath. An upload
// does this by itself; the command is for claiming without uploading.
func RunTakeOwn(ip, keyPath string) {
	if strings.TrimSpace(keyPath) == "" {
		logf(true, "takeown needs --key=<owner.pem>, the key this board should trust from now on.\n"+
			"Generate one first:  IAPTool genkey owner\n"+
			"There is deliberately no default: claiming a board with the wrong key takes a factory reset to undo.")
	}
	pub, err := ownerPublicKeyHex(keyPath)
	logf(err, "cannot use that key")

	_, was, err := ownerReadState(ip)
	logf(err, "cannot read this board's ownership state")
	if was != "" {
		logf(true, "This board already trusts %s...\n"+
			"Hand it over with setowner and the current owner's key, or factory-reset it\n"+
			"(hold BOOT0 for 10 s) and claim it again.", was[:32])
	}

	fmt.Println("Claiming this board for:")
	fmt.Printf("  %s\n", pub)
	fmt.Println("From then on it runs only firmware signed by that key. The way back is a")
	fmt.Println("factory reset: hold BOOT0 for 10 s.")
	fmt.Println()

	reply, err := ownerCommand(ip, "takeown "+pub)
	logf(err, "the takeown command did not get through")
	reply = strings.TrimSpace(reply)
	if !strings.Contains(reply, Rsp_OK) {
		logf(true, "The board refused: %s", reply)
	}

	gen, now, err := ownerReadState(ip)
	logf(err, "claimed, but reading the state back failed")
	if now != strings.ToLower(pub) {
		logf(true, "The board answered OK but reports a different key:\n  claimed  %s\n  reports  %s", pub, now)
	}
	fmt.Printf("Claimed at generation %d. Keep %s safe - it is now the only key\n", gen, keyPath)
	fmt.Println("that can produce firmware this board will run.")
}

// RunSetOwner hands a claimed board to newKeyPath, signed by currentKeyPath.
//
// With wipe, the board also empties its revocation records, the only way to
// get those slots back; it rewrites its state sector to do so and resets. The
// board never decides to do this on its own -- the operator asks for it
// (OWN-07).
func RunSetOwner(ip, currentKeyPath, newKeyPath string, wipe bool) {
	if strings.TrimSpace(currentKeyPath) == "" || strings.TrimSpace(newKeyPath) == "" {
		logf(true, "setowner needs both keys:\n"+
			"  --current-key=<owner.pem>  the key the board trusts today, to sign the handover\n"+
			"  --new-key=<next.pem>       the key it should trust from now on")
	}
	newPub, err := ownerPublicKeyHex(newKeyPath)
	logf(err, "cannot use the new key")
	currentPub, err := ownerPublicKeyHex(currentKeyPath)
	logf(err, "cannot use the current owner key")

	gen, trusted, err := ownerReadState(ip)
	logf(err, "cannot read this board's ownership state")
	if trusted == "" {
		logf(true, "This board has no root - there is no owner to sign a handover.\n"+
			"The next upload claims it, or use takeown.")
	}
	if trusted != strings.ToLower(currentPub) {
		logf(true, "The board does not trust the key in %s:\n  board trusts  %s\n  you offered   %s\n"+
			"Only the current owner can hand the board over.", currentKeyPath, trusted, currentPub)
	}

	uidHex, err := ownerGetUID(ip)
	logf(err, "cannot read this board's UID")

	next := gen + 1
	prefix, err := ownerSignedPrefix(next, newPub, uidHex)
	logf(err, "cannot build the owner record")

	sig, err := signRawHex(hex.EncodeToString(prefix), currentKeyPath)
	logf(err, "cannot sign the handover")

	fmt.Printf("Handing over at generation %d -> %d\n", gen, next)
	fmt.Printf("  new key: %s\n", newPub)

	verb := "setowner"
	if wipe {
		verb = "setownerwipe"
		fmt.Println("  --wipe: the board will rewrite its state sector and reset.")
	}

	reply, err := ownerCommand(ip, fmt.Sprintf("%s %d %s %s", verb, next, newPub, strings.TrimSpace(sig)))
	if wipe {
		// A successful wipe never answers: the board resets as soon as the
		// new sector is written. An answer therefore means it refused, and a
		// dropped connection is the expected outcome.
		if err == nil && strings.Contains(strings.TrimSpace(reply), "Refused") {
			logf(true, "The board refused the wipe and erased nothing: %s", strings.TrimSpace(reply))
		}
		fmt.Println("The board is rewriting its flash and will reset. Give it a few seconds,")
		fmt.Printf("then check with: IAPTool getowner %s\n", ip)
		return
	}
	logf(err, "the setowner command did not get through")
	reply = strings.TrimSpace(reply)
	if !strings.Contains(reply, Rsp_OK) {
		logf(true, "The board refused: %s", reply)
	}

	gotGen, now, err := ownerReadState(ip)
	logf(err, "handed over, but reading the state back failed")
	if gotGen != next || now != strings.ToLower(newPub) {
		logf(true, "The board answered OK but reports generation %d and key %s", gotGen, now)
	}
	fmt.Printf("Done. Generation %d, and the board now runs only firmware signed by %s.\n", gotGen, newKeyPath)
}

// RunRevoke revokes one leaf, named by its public key, signed by the current
// owner. currentKeyPath is the private half of the root the board trusts
// today -- the same role --current-key plays in RunSetOwner.
func RunRevoke(ip, currentKeyPath, leafPubHex string) {
	if strings.TrimSpace(currentKeyPath) == "" || strings.TrimSpace(leafPubHex) == "" {
		logf(true, "revoke needs both:\n"+
			"  --key=<owner.pem>   the current owner's key, to sign the revocation\n"+
			"  --leaf=<pubkey hex> the leaf to revoke, 128 hex characters")
	}
	leafPub, err := hex.DecodeString(strings.TrimSpace(leafPubHex))
	if err != nil || len(leafPub) != 64 {
		logf(true, "--leaf must be 128 hex characters (a raw secp256r1 public key), got %q", leafPubHex)
	}
	leafPrefixHex := hex.EncodeToString(leafPub[:ownerRevokePrefixLen])

	currentPub, err := ownerPublicKeyHex(currentKeyPath)
	logf(err, "cannot use the current owner key")

	gen, trusted, err := ownerReadState(ip)
	logf(err, "cannot read this board's ownership state")
	if trusted == "" {
		logf(true, "This board has no root - there is no owner to sign a revocation.")
	}
	if trusted != strings.ToLower(currentPub) {
		logf(true, "The board does not trust the key in %s:\n  board trusts  %s\n  you offered   %s\n"+
			"Only the current owner can revoke a leaf.", currentKeyPath, trusted, currentPub)
	}

	uidHex, err := ownerGetUID(ip)
	logf(err, "cannot read this board's UID")

	prefix, err := ownerRevokeSignedPrefix(leafPrefixHex, uidHex)
	logf(err, "cannot build the revocation record")

	sig, err := signRawHex(hex.EncodeToString(prefix), currentKeyPath)
	logf(err, "cannot sign the revocation")

	fmt.Printf("Revoking one leaf. The board stays at owner generation %d - a revocation does not take one.\n", gen)
	fmt.Printf("  leaf (first %d bytes): %s\n", ownerRevokePrefixLen, leafPrefixHex)

	reply, err := ownerCommand(ip, fmt.Sprintf("revoke %s %s", leafPrefixHex, strings.TrimSpace(sig)))
	logf(err, "the revoke command did not get through")
	reply = strings.TrimSpace(reply)
	if !strings.Contains(reply, Rsp_OK) {
		logf(true, "The board refused: %s", reply)
	}

	// The board's OK already means it wrote the record, re-scanned the owner
	// area and confirmed every name just written now reads back as revoked
	// (owner_slot_revoke, IAPServer/owner_slot.c). Do NOT re-check the
	// generation here: a revoke record never becomes the effective owner
	// record, so the effective generation deliberately does not move, and
	// requiring it to advance reports a successful revocation as a failure.
	// What is worth reading back is that the root did not change -- a
	// revocation must never hand the board to somebody else.
	_, now, err := ownerReadState(ip)
	logf(err, "revoked, but reading the state back failed")
	if now != strings.ToLower(currentPub) {
		logf(true, "The board answered OK but now trusts %s, not %s -\n"+
			"a revocation must not change the root.", now, strings.ToLower(currentPub))
	}
	if strings.Contains(reply, "already revoked") {
		fmt.Println("That leaf was already revoked; nothing was written.")
	}
	fmt.Printf("Done. The board still trusts %s;\n", now)
	fmt.Println("any firmware certified by the revoked leaf is refused from the next reset on.")
}

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// *** PLACEHOLDER TEST-ONLY KEY ***
// Must match iap_auth_key in open_plc_cube_ide/IAPServer/iap_auth.c and its
// copy in the Arduino core's libraries/OpenPLC_Net/src/iap_auth.c. This lets
// the whole challenge-response protocol be built and tested end to end
// before a real per-device key provisioning process exists. Every device
// built from this source tree shares this exact key until it is replaced.
// See IAPServer/keys/README.md.
var iapAuthKey = []byte("IAP-TEST-KEY-DO-NOT-USE-IN-PROD!")

// computeAuthHMAC returns hex(HMAC-SHA256(iapAuthKey, nonce || msg)), where
// nonce is decoded from nonceHex (as returned by "authchallenge" /
// "openplc_server_reboot_challenge"). msg must be the exact command string
// being authorized -- the device recomputes the same construction.
func computeAuthHMAC(nonceHex string, msg string) (string, error) {
	nonce, err := hex.DecodeString(strings.TrimSpace(nonceHex))
	if err != nil {
		return "", fmt.Errorf("invalid nonce hex %q: %w", nonceHex, err)
	}
	mac := hmac.New(sha256.New, iapAuthKey)
	mac.Write(nonce)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// loadSignature reads the raw 64-byte ECDSA signature produced by
// keys/sign_firmware.sh for the given .bin (expects a sibling <name>.sig
// file) and returns it hex-encoded, ready to embed in a "flash" command.
func loadSignature(binPath string) (string, error) {
	sigPath := strings.TrimSuffix(binPath, ".bin") + ".sig"
	data, err := os.ReadFile(sigPath)
	if err != nil {
		return "", fmt.Errorf("failed to read signature file %s (run keys/sign_firmware.sh on this .bin first): %w", sigPath, err)
	}
	if len(data) != 64 {
		return "", fmt.Errorf("signature file %s has %d bytes, expected 64", sigPath, len(data))
	}
	return hex.EncodeToString(data), nil
}

// loadVersion reads an optional sibling <name>.version file (decimal ASCII,
// written by keys/sign_firmware.sh --version=N) next to the .bin. Returns
// ok=false with no error if the file simply doesn't exist -- version
// tracking is opt-in; an image signed without one still flashes exactly as
// before this feature existed, just with no downgrade comparison possible.
func loadVersion(binPath string) (version uint32, ok bool, err error) {
	verPath := strings.TrimSuffix(binPath, ".bin") + ".version"
	data, readErr := os.ReadFile(verPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("failed to read version file %s: %w", verPath, readErr)
	}
	v, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if parseErr != nil {
		return 0, false, fmt.Errorf("invalid version in %s: %w", verPath, parseErr)
	}
	return uint32(v), true, nil
}

// confirmDowngradeIfNeeded compares the version about to be flashed against
// what the device reports installed (via "getversion"), and if it's a
// downgrade, warns and requires an explicit "yes" in this console before
// proceeding. The device itself never blocks a downgrade -- this operator
// confirmation is the only gate, and it's skipped entirely (proceeds) if
// either side has no version to compare: no local .version file, or a
// device reply that doesn't parse as a number (older bootloader without
// "getversion" support replies "Unknown command", for example).
func confirmDowngradeIfNeeded(localVersion uint32, remoteVerStr string) bool {
	remoteVersion, err := strconv.ParseUint(strings.TrimSpace(remoteVerStr), 10, 32)
	if err != nil {
		logf("Could not parse device-reported version %q, skipping downgrade check", remoteVerStr)
		return true
	}
	if localVersion >= uint32(remoteVersion) {
		return true
	}

	fmt.Printf("WARNING: device currently has version %d installed; this image is version %d (older).\n",
		remoteVersion, localVersion)
	fmt.Print("Proceed with this downgrade? [y/N]: ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

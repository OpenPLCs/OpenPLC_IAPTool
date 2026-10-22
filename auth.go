package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"IAPTool/iapcert"
)

// uploadIdentity is what this machine presents to a board: the private key it
// signs with, and the certificate saying a root the board trusts authorised
// that key.
//
// Two ways to come by one, and the board cannot tell them apart -- which is
// the point (see $PROD/docs/modules/M2-ownership.md, "客户自己建根之后，他的密钥怎么和根挂上"):
//
//   - No certificate file: the key certifies itself. One person, one key, the
//     key is the root. This is what a fresh install does.
//   - A certificate file: an administrator holding the root issued it for this
//     key. The root private key never has to be on this machine.
type uploadIdentity struct {
	key       *ecdsa.PrivateKey
	cert      *iapcert.Cert
	certHex   string
	delegated bool   // the certificate came from a file rather than self-signing
	keyPath   string // where key was loaded from, for error messages
}

// resolveUploadIdentity loads the signing key and the certificate that goes
// with it. Session authentication signs a fresh challenge, so the private key
// itself is required -- there is no offline-signature path for this step.
func resolveUploadIdentity() (uploadIdentity, error) {
	var id uploadIdentity

	keyPath := findSigningKey()
	if keyPath == "" {
		return id, fmt.Errorf("no signing key found.\n"+
			"  Authenticating an upload means signing a challenge, which needs the private key.\n"+
			"  Put it at %s, or pass --key=<key.pem>", defaultKeyLocation())
	}
	fmt.Printf("Signing key: %s\n", keyPath)
	key, err := loadSigningKey(keyPath)
	if err != nil {
		return id, err
	}
	id.key = key
	id.keyPath = keyPath

	certPath := findCert(keyPath)
	if certPath == "" {
		certHex, issueErr := issueLeafCert(keyPath, "")
		if issueErr != nil {
			return id, fmt.Errorf("cannot issue a certificate for %s: %w", keyPath, issueErr)
		}
		id.certHex = certHex
	} else {
		data, readErr := os.ReadFile(certPath)
		if readErr != nil {
			return id, fmt.Errorf("failed to read certificate %s: %w", certPath, readErr)
		}
		id.certHex = strings.TrimSpace(string(data))
		id.delegated = true
	}

	id.cert, err = iapcert.ParseHex(id.certHex)
	if err != nil {
		return id, fmt.Errorf("%s: %w", certPath, err)
	}

	// A certificate issued for somebody else's key is useless here: the board
	// verifies the image and the challenge against the leaf key the
	// certificate names, and this machine can only sign with its own.
	localPub := iapcert.RawPublicKey(&key.PublicKey)
	if !bytes.Equal(id.cert.LeafPub, localPub) {
		return id, fmt.Errorf("the certificate %s was issued for a different key.\n"+
			"  certificate names: %s...\n"+
			"  %s is:             %s...\n"+
			"  Ask for a certificate covering this key, or point --key at the one it covers",
			certPath, hex.EncodeToString(id.cert.LeafPub)[:16],
			filepath.Base(keyPath), hex.EncodeToString(localPub)[:16])
	}

	if id.delegated {
		logv("Using certificate %s for %s", certPath, keyPath)
	}
	return id, nil
}

// signImageInMemory signs the image at binPath and returns the raw r||s
// signature, hex-encoded. Nothing is written to disk.
func signImageInMemory(binPath string, key *ecdsa.PrivateKey) (string, error) {
	image, err := os.ReadFile(binPath)
	if err != nil {
		return "", fmt.Errorf("failed to read image %s: %w", binPath, err)
	}
	_, sig, err := signImage(image, key)
	if err != nil {
		return "", err
	}
	logv("Signed %s in memory", filepath.Base(binPath))
	return hex.EncodeToString(sig), nil
}

// pubKeyQuery asks the device which root it verifies against. Each transport
// supplies its own (CDC serial, or the ethernet TCP connection).
type pubKeyQuery func() (string, error)

// boardExchange sends one text command to the bootloader and returns its
// reply. Each transport supplies its own.
type boardExchange func(cmd string) (string, error)

// noRootReply is what getpubkey answers on a board that trusts no key yet:
// fresh from the factory, or factory-reset. See
// $PROD/docs/modules/M1/IAP-PROTOCOL.md.
const noRootReply = "none"

// claimIfUnclaimed makes a board with no root trust this machine's key before
// an upload: the first upload is what claims a factory board (decision 72).
// Uses the key the upload would sign with, generating one at the default
// location when there is none. A board that already has a root is left alone.
func claimIfUnclaimed(exchange boardExchange) error {
	reply, err := exchange(CM_GetPubKey)
	if err != nil || strings.TrimSpace(reply) != noRootReply {
		// Either it has a root, or it cannot say; the key check that follows
		// reports both.
		return nil
	}

	fmt.Println("This board has no root yet: claiming it for this computer's key.")
	keyPath := findSigningKey()
	if keyPath == "" {
		keyPath = userKeyLocation()
		if keyPath == "" {
			return fmt.Errorf("no user config directory to create a signing key in; pass --key=<key.pem>")
		}
		if _, err := generateSigningKey(keyPath); err != nil {
			return err
		}
	}
	pub, err := ownerPublicKeyHex(keyPath)
	if err != nil {
		return err
	}

	reply, err = exchange("takeown " + pub)
	if err != nil {
		return fmt.Errorf("the claim did not get through: %v", err)
	}
	if !strings.Contains(reply, Rsp_OK) {
		return fmt.Errorf("the board refused the claim: %s", strings.TrimSpace(reply))
	}
	fmt.Printf("Claimed. From now on this board runs only firmware signed by %s\n", keyPath)
	fmt.Println("  Losing that file means a factory reset (hold BOOT0 for 10 s) to reclaim the board.")
	return nil
}

// otherOwnerHint tells someone whose key a board does not trust the two ways
// to get one it does. keyPath is where this machine looked for its key.
func otherOwnerHint(keyPath string) string {
	return fmt.Sprintf("  This board belongs to another key. Either:\n"+
		"    - copy that root private key from the computer that claimed the board to\n"+
		"      %s, or\n"+
		"    - ask whoever holds that root for a certificate: send them the output of\n"+
		"      `IAPTool pubkey`, they run `IAPTool cert <that pubkey>`, and you save the\n"+
		"      result as %s%s",
		keyPath, keyPath, certSuffix)
}

// verifyIdentityMatchesDevice confirms up front that this board will accept
// what we are about to send, so a mismatch is reported before spending time on
// the transfer instead of after it.
//
// The question is the same one the board asks: does the root this board trusts
// vouch for our certificate. For a self-signed certificate that reduces to
// "is our key the board's root", which is why both cases are one check.
//
// A board that cannot be reached only produces a warning: the flash that
// follows fails on its own. A reply that is not a root is refused: every
// bootloader since getpubkey answers it, and older ones are not supported
// (decision 79).
func verifyIdentityMatchesDevice(id uploadIdentity, askDevice pubKeyQuery) error {
	reply, err := askDevice()
	if err != nil {
		logf("Could not read the device public key (%v) -- skipping key match check", err)
		return nil
	}

	devicePubHex := strings.ToLower(strings.TrimSpace(reply))
	if devicePubHex == noRootReply {
		return fmt.Errorf("this board has no root and was not claimed; it accepts nothing until it is")
	}
	devicePub, decodeErr := hex.DecodeString(devicePubHex)
	if decodeErr != nil || len(devicePub) != sigLen {
		return fmt.Errorf("the board did not answer %q with a root (replied %q); "+
			"its bootloader is too old for this IAPTool -- update it with ST-Link",
			CM_GetPubKey, strings.TrimSpace(reply))
	}

	if id.cert.VerifiedBy(devicePub) {
		if id.delegated {
			logf("Certificate was issued by this board's root (%s...)", devicePubHex[:16])
		} else {
			logf("Signing key matches this board (%s...)", devicePubHex[:16])
		}
		return nil
	}

	if id.delegated {
		return fmt.Errorf("this certificate was not issued by this board's root.\n"+
			"  board trusts: %s...\n%s",
			devicePubHex[:16], otherOwnerHint(id.keyPath))
	}
	return fmt.Errorf("this board's bootloader verifies against a different signing key.\n"+
		"  board: %s...\n"+
		"  local: %s...\n%s",
		devicePubHex[:16], hex.EncodeToString(id.cert.LeafPub)[:16], otherOwnerHint(id.keyPath))
}

// flashCommand builds the authenticated flash (or flashboot) command, the same
// on both channels: "<verb> <size> <crc> <imagesig> <cert> <noncesig>", where
// noncesig covers the board's fresh nonce and the text before the cert.
// challenge asks the board for that nonce over whichever channel is open.
func flashCommand(id uploadIdentity, verb string, size int64, crc uint32, sigHex string,
	challenge func() (string, error)) (string, error) {
	authMsg := fmt.Sprintf("%s %d %x %s", verb, size, crc, sigHex)
	nonce, err := challenge()
	if err != nil {
		return "", fmt.Errorf("auth challenge failed: %v", err)
	}
	nonceSig, err := iapcert.NonceSig(id.key, nonce, authMsg)
	if err != nil {
		return "", fmt.Errorf("failed to sign auth challenge: %v", err)
	}
	return fmt.Sprintf("%s %s %s", authMsg, id.certHex, nonceSig), nil
}

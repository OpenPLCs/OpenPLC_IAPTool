package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"IAPTool/iapcert"
)

// Raw r||s signature length for P-256, as stored by the bootloader and fed
// to uECC_verify in IAPServer/fw_verify.c. Also the length of the raw
// X||Y public key the bootloader reports for "getpubkey".
const sigLen = 64

// Where the tool looks for a signing key when none was given explicitly. The
// Arduino IDE passes no options (see platform.txt), so the key has to be
// findable by convention. Order and rationale: RELEASE-NOTES.md in
// OpenPLC_BootLoader, "Where IAPTool finds the upload key".
const keysDirName = "keys"
const defaultKeyName = "fw_signing_key.pem"

// A certificate lives at "<the key it covers>.cert": state derived from a key
// belongs beside that key, where it cannot be paired with the wrong one.
const certSuffix = ".cert"

// userKeyLocation is <user config dir>/openplc/keys/fw_signing_key.pem, the
// same parent as the force-flash marker. It is outside the versioned tool
// directory, so it survives tool package upgrades. "" if there is no user
// config directory.
func userKeyLocation() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "openplc", keysDirName, defaultKeyName)
}

// keyExeDir is the directory IAPTool ships in; a variable so tests can point
// it somewhere else.
var keyExeDir = GetCurDir

// exeKeyLocation is <exe dir>/keys/fw_signing_key.pem, kept for machines set
// up before the user directory was introduced.
func exeKeyLocation() string {
	exeDir := keyExeDir()
	if exeDir == "" {
		return ""
	}
	return filepath.Join(exeDir, keysDirName, defaultKeyName)
}

func isFile(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// findSigningKey returns the signing key to use: --key, then local_config.json
// "signing_key" (both already in g_signing.keyPath), then the user directory,
// then <exe dir>/keys. Returns "" when there is no key available.
func findSigningKey() string {
	if g_signing.keyPath != "" {
		return g_signing.keyPath
	}
	for _, candidate := range []string{userKeyLocation(), exeKeyLocation()} {
		if isFile(candidate) {
			return candidate
		}
	}
	return ""
}

// defaultKeyLocation is where an operator should put a key, used in error
// messages.
func defaultKeyLocation() string {
	if p := userKeyLocation(); p != "" {
		return p
	}
	return exeKeyLocation()
}

// findCert returns the certificate to present alongside keyPath, or "" when
// there is none and the key should certify itself. An explicit --cert wins,
// otherwise "<keyPath>.cert" if it exists.
//
// Absence is the normal case, not an error: one person with one key needs no
// certificate from anybody.
func findCert(keyPath string) string {
	if g_signing.certPath != "" {
		return g_signing.certPath
	}
	if keyPath == "" {
		return ""
	}
	candidate := keyPath + certSuffix
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	return ""
}

// loadSigningKey reads a PEM-encoded ECDSA P-256 private key, accepting both
// the SEC1 "EC PRIVATE KEY" form written by `openssl ecparam -genkey` and the
// PKCS#8 "PRIVATE KEY" form.
func loadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	return iapcert.LoadKey(path)
}

// signImage returns SHA-256(image) and the raw 64-byte r||s signature over
// that hash, each half left-padded to 32 bytes.
func signImage(image []byte, key *ecdsa.PrivateKey) (hash [32]byte, sig []byte, err error) {
	hash = sha256.Sum256(image)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return hash, nil, fmt.Errorf("failed to sign image: %w", err)
	}

	sig = make([]byte, sigLen)
	r.FillBytes(sig[:sigLen/2])
	s.FillBytes(sig[sigLen/2:])
	return hash, sig, nil
}

// signRawHex signs an arbitrary blob given as hex, returning the raw 64-byte
// r||s signature over SHA-256 of those bytes, hex-encoded.
//
// Used for the owner-record prefix in the bootloader's ownership chain, where
// what gets signed is 76 bytes of record rather than a firmware image. Kept
// here beside signImage so both go through the same key loading and the same
// r||s encoding -- a second implementation of that encoding is exactly the kind
// of thing cases T1-19 / T1-20 exist to catch, and not having one is better.
func signRawHex(dataHex, keyPath string) (string, error) {
	data, err := hex.DecodeString(strings.TrimSpace(dataHex))
	if err != nil {
		return "", fmt.Errorf("data is not hex: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("nothing to sign")
	}
	key, err := loadSigningKey(keyPath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	sig := make([]byte, sigLen)
	r.FillBytes(sig[:sigLen/2])
	s.FillBytes(sig[sigLen/2:])
	return hex.EncodeToString(sig), nil
}

// signBinFile writes the sibling .sha256, .size and .sig files next to the
// image, the same set that an earlier "IAPTool sign" run produces.
func signBinFile(binPath, keyPath, outPrefix string) error {
	key, err := loadSigningKey(keyPath)
	if err != nil {
		return err
	}

	image, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("failed to read image %s: %w", binPath, err)
	}

	hash, sig, err := signImage(image, key)
	if err != nil {
		return err
	}

	if outPrefix == "" {
		outPrefix = strings.TrimSuffix(binPath, ".bin")
	}

	written := []string{outPrefix + ".sha256", outPrefix + ".size", outPrefix + ".sig"}
	if err := os.WriteFile(outPrefix+".sha256", []byte(hex.EncodeToString(hash[:])+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write %s.sha256: %w", outPrefix, err)
	}
	if err := os.WriteFile(outPrefix+".size", []byte(strconv.Itoa(len(image))+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write %s.size: %w", outPrefix, err)
	}
	if err := os.WriteFile(outPrefix+".sig", sig, 0644); err != nil {
		return fmt.Errorf("failed to write %s.sig: %w", outPrefix, err)
	}

	logf("Wrote %s for %s", strings.Join(written, " "), binPath)
	logf("sha256=%s size=%d", hex.EncodeToString(hash[:]), len(image))
	return nil
}

// generateSigningKey writes a new P-256 private key to path, creating its
// directory, and prints where it went and its public half on stdout. It never
// overwrites: an existing key may be the only one a board trusts.
func generateSigningKey(path string) (*ecdsa.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing %s", path)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", path, err)
	}

	fmt.Printf("Private key written to: %s\n", path)
	fmt.Println("  Keep it safe and do not commit it. To upload from another computer, copy")
	fmt.Println("  this file to the same place there.")
	fmt.Printf("Public key: %s\n", publicKeyHex(&key.PublicKey))
	return key, nil
}

// rawPublicKey returns the uncompressed point as X||Y, the form the
// bootloader stores in an owner record.
func rawPublicKey(pub *ecdsa.PublicKey) []byte {
	return iapcert.RawPublicKey(pub)
}

// publicKeyHex is rawPublicKey hex-encoded, directly comparable with what
// the device answers to "getpubkey".
func publicKeyHex(pub *ecdsa.PublicKey) string {
	return hex.EncodeToString(rawPublicKey(pub))
}

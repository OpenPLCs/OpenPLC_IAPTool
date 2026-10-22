// Package iapcert holds the certificate and challenge-signing primitives the
// IAP protocol runs on. It is a package rather than part of IAPTool's main so
// that the test cases can import it: a case that reimplements the crypto
// proves only that the reimplementation agrees with itself.
//
// The wire format mirrors iap_cert_t in
// OpenPLC_BootLoader/IAPServer/iap_cert.h byte-for-byte:
//
//	leaf_pubkey[64] || root_sig[64]   (128 bytes)
//
// No serial number: revocation names leaves by public key
// ($PROD/docs/modules/M2-ownership.md, "定下来的取舍").
//
// Simple mode (LeafPubHex == "") self-signs: the certificate says "this
// root's own key is authorised", and the board's iap_cert_verify() has no
// branch for that -- it is a certificate like any other, just one whose leaf
// happens to equal its root. See $PROD/docs/modules/M2-ownership.md for why having no
// special case is the whole point.
package iapcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const (
	// SigLen is a raw secp256r1 signature, r||s.
	SigLen = 64
	// Size is one whole certificate on the wire.
	Size = 128
	// SignedLen is the prefix the root signature covers: leaf_pubkey.
	SignedLen = 64
)

// Cert is a parsed certificate. Two fields at fixed offsets and nothing else,
// the same shape iap_cert.h parses -- Raw is kept because the root signature
// covers the bytes, not the fields.
type Cert struct {
	LeafPub []byte // 64, secp256r1 X||Y
	RootSig []byte // 64, over sha256(Raw[:SignedLen])
	Raw     []byte // Size bytes
}

// ParseHex decodes the 256-hex-character form that goes on the wire.
func ParseHex(certHex string) (*Cert, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(certHex))
	if err != nil {
		return nil, fmt.Errorf("certificate is not hex: %w", err)
	}
	if len(raw) != Size {
		return nil, fmt.Errorf("certificate is %d bytes, expected %d", len(raw), Size)
	}
	return &Cert{
		LeafPub: raw[:64],
		RootSig: raw[64:Size],
		Raw:     raw,
	}, nil
}

// VerifiedBy answers the one question the board asks of a certificate: did
// this root sign it. Mirrors iap_cert_verify() in
// OpenPLC_BootLoader/IAPServer/iap_cert.c, so the tool can refuse a
// certificate the board would refuse -- before spending a transfer on it.
//
// Says nothing about the image or the challenge that certificate will go on
// to authorise, nor about revocation; those are separate checks, on the board.
func (c *Cert) VerifiedBy(rootPub []byte) bool {
	if len(rootPub) != SigLen {
		return false
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(rootPub[:32]),
		Y:     new(big.Int).SetBytes(rootPub[32:]),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return false
	}
	digest := sha256.Sum256(c.Raw[:SignedLen])
	r := new(big.Int).SetBytes(c.RootSig[:32])
	s := new(big.Int).SetBytes(c.RootSig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// LoadKey reads a PEM-encoded ECDSA P-256 private key, accepting both the
// SEC1 "EC PRIVATE KEY" form written by `openssl ecparam -genkey` and the
// PKCS#8 "PRIVATE KEY" form.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing key %s is not PEM-encoded", path)
	}

	key, sec1Err := x509.ParseECPrivateKey(block.Bytes)
	if sec1Err != nil {
		parsed, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("failed to parse EC private key %s: %w", path, sec1Err)
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s holds a %T, not an EC private key", path, parsed)
		}
		key = ecKey
	}
	return key, nil
}

// RawPublicKey is the uncompressed point X||Y, with no 0x04 prefix -- the
// form the board stores and compares.
func RawPublicKey(pub *ecdsa.PublicKey) []byte {
	raw := make([]byte, SigLen)
	pub.X.FillBytes(raw[:SigLen/2])
	pub.Y.FillBytes(raw[SigLen/2:])
	return raw
}

// PublicKeyHex is RawPublicKey hex-encoded, directly comparable with what the
// device answers to "getpubkey".
func PublicKeyHex(pub *ecdsa.PublicKey) string {
	return hex.EncodeToString(RawPublicKey(pub))
}

// SignDigest signs a 32-byte SHA-256 digest, returning raw r||s.
func SignDigest(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SigLen)
	r.FillBytes(sig[:SigLen/2])
	s.FillBytes(sig[SigLen/2:])
	return sig, nil
}

// Issue builds and signs a certificate with the root key at rootKeyPath.
// leafPubHex == "" means self-signed (leaf_pubkey = the root's own public
// key); otherwise it must be a 128-hex-char raw X||Y public key belonging to
// a leaf whose private half the caller holds separately. Issuing never
// touches that private half, only its public point.
//
// Returns the certificate hex-encoded (256 hex chars) -- exactly what goes on
// the wire in a "flash" or "openplc_server_reboot" command.
func Issue(rootKeyPath string, leafPubHex string) (string, error) {
	root, err := LoadKey(rootKeyPath)
	if err != nil {
		return "", fmt.Errorf("cannot load root key %s: %w", rootKeyPath, err)
	}

	var leafPub []byte
	if strings.TrimSpace(leafPubHex) == "" {
		leafPub = RawPublicKey(&root.PublicKey)
	} else {
		leafPub, err = hex.DecodeString(strings.TrimSpace(leafPubHex))
		if err != nil || len(leafPub) != SigLen {
			return "", fmt.Errorf("leaf public key must be %d hex characters", SigLen*2)
		}
	}

	signed := make([]byte, SignedLen)
	copy(signed, leafPub)

	digest := sha256.Sum256(signed)
	rootSig, err := SignDigest(root, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert := make([]byte, Size)
	copy(cert, signed)
	copy(cert[64:], rootSig)
	return hex.EncodeToString(cert), nil
}

// NonceSig returns hex(ECDSA-sign(key, sha256(nonce || msg))). The device
// verifies it against the leaf public key named by whatever certificate
// accompanies the same command. nonceHex is what "authchallenge" /
// "openplc_server_reboot_challenge" returned; msg must be the exact command
// string being authorized.
func NonceSig(key *ecdsa.PrivateKey, nonceHex string, msg string) (string, error) {
	nonce, err := hex.DecodeString(strings.TrimSpace(nonceHex))
	if err != nil {
		return "", fmt.Errorf("invalid nonce hex %q: %w", nonceHex, err)
	}
	digest := sha256.Sum256(append(append([]byte{}, nonce...), []byte(msg)...))
	sig, err := SignDigest(key, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign challenge: %w", err)
	}
	return hex.EncodeToString(sig), nil
}

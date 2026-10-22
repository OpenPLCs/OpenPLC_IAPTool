// Package testcase holds standalone Go tests for the certificate primitives
// the IAP protocol runs on (see IAPTranfer_Tool/iapcert).
//
// What these pin down is the part the board cannot tell us about: the exact
// bytes the root signature covers. The board's half of the same format is
// checked by H2, against certificates this code produced.
//
// Run with: go test ./tests/...
package testcase

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"IAPTool/iapcert"
)

// writeKey puts a fresh P-256 key in a temp dir and returns its path along
// with the key itself, so a test can check what was signed.
func writeKey(t *testing.T, dir, name string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("could not encode the key: %v", err)
	}
	path := filepath.Join(dir, name+".pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0600); err != nil {
		t.Fatalf("could not write %s: %v", path, err)
	}
	return path, key
}

// TestIssue_LayoutAndSignedBytes locks in what the board parses: two fields
// at fixed offsets, and a root signature over exactly the first 64 of them. If
// the signature ever covered a different span, every check on the board would
// still "work" -- over the wrong bytes.
func TestIssue_LayoutAndSignedBytes(t *testing.T) {
	dir := t.TempDir()
	rootPath, root := writeKey(t, dir, "root")

	certHex, err := iapcert.Issue(rootPath, "")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	cert, err := hex.DecodeString(certHex)
	if err != nil {
		t.Fatalf("Issue returned non-hex: %v", err)
	}
	if len(cert) != iapcert.Size {
		t.Fatalf("certificate is %d bytes, want %d", len(cert), iapcert.Size)
	}

	wantLeaf := iapcert.RawPublicKey(&root.PublicKey)
	if got := cert[:64]; string(got) != string(wantLeaf) {
		t.Errorf("self-signed leaf_pubkey is not the root's own key:\n got %x\nwant %x", got, wantLeaf)
	}

	digest := sha256.Sum256(cert[:iapcert.SignedLen])
	r := new(big.Int).SetBytes(cert[64:96])
	s := new(big.Int).SetBytes(cert[96:128])
	if !ecdsa.Verify(&root.PublicKey, digest[:], r, s) {
		t.Error("root_sig does not verify over sha256(cert[0:64]) -- the signed span moved")
	}

	// A signature over the whole certificate would pass the check above by
	// accident if the span were wrong. Verify it fails over a deliberately
	// wrong span.
	otherDigest := sha256.Sum256(cert)
	if ecdsa.Verify(&root.PublicKey, otherDigest[:], r, s) {
		t.Error("root_sig also verifies over the whole certificate -- SignedLen is not pinned")
	}
}

// TestIssue_Delegated is the other half of "no self-signed branch": a
// delegated certificate differs from a self-signed one only in whose public
// key sits at offset 0.
func TestIssue_Delegated(t *testing.T) {
	dir := t.TempDir()
	rootPath, _ := writeKey(t, dir, "root")
	_, leaf := writeKey(t, dir, "leaf")

	leafPubHex := iapcert.PublicKeyHex(&leaf.PublicKey)
	certHex, err := iapcert.Issue(rootPath, leafPubHex)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	cert, _ := hex.DecodeString(certHex)

	if got := hex.EncodeToString(cert[:64]); got != leafPubHex {
		t.Errorf("delegated leaf_pubkey is %s, want %s", got, leafPubHex)
	}
}

func TestIssue_RejectsMalformedLeafKey(t *testing.T) {
	dir := t.TempDir()
	rootPath, _ := writeKey(t, dir, "root")

	for _, bad := range []string{"abcd", "zz" + hex.EncodeToString(make([]byte, 63))} {
		if _, err := iapcert.Issue(rootPath, bad); err == nil {
			t.Errorf("Issue accepted %q as a leaf public key", bad)
		}
	}
}

// TestNonceSig_SignsNonceThenMessage pins the challenge construction: the
// board hashes nonce||msg and verifies over that. Swapping the two, or
// hashing only one of them, is the kind of mistake that leaves authentication
// looking like it works while accepting a replayed answer.
func TestNonceSig_SignsNonceThenMessage(t *testing.T) {
	dir := t.TempDir()
	_, key := writeKey(t, dir, "leaf")

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("could not make a nonce: %v", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	const msg = "flash 1024 deadbeef abcd1234"

	sigHex, err := iapcert.NonceSig(key, nonceHex, msg)
	if err != nil {
		t.Fatalf("NonceSig failed: %v", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != iapcert.SigLen {
		t.Fatalf("NonceSig returned %q, want %d hex characters", sigHex, iapcert.SigLen*2)
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	want := sha256.Sum256(append(append([]byte{}, nonce...), []byte(msg)...))
	if !ecdsa.Verify(&key.PublicKey, want[:], r, s) {
		t.Error("the signature does not cover sha256(nonce || msg)")
	}

	swapped := sha256.Sum256(append([]byte(msg), nonce...))
	if ecdsa.Verify(&key.PublicKey, swapped[:], r, s) {
		t.Error("the signature also covers sha256(msg || nonce) -- the order is not pinned")
	}
}

func TestNonceSig_RejectsMalformedNonce(t *testing.T) {
	dir := t.TempDir()
	_, key := writeKey(t, dir, "leaf")

	if _, err := iapcert.NonceSig(key, "not hex", "msg"); err == nil {
		t.Error("NonceSig accepted a non-hex nonce")
	}
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// keyEnv points os.UserConfigDir and the exe directory at fresh temp dirs and
// clears any explicit key. Returns (user config dir, exe dir).
func keyEnv(t *testing.T) (string, string) {
	t.Helper()
	userDir := t.TempDir()
	exeDir := t.TempDir()
	t.Setenv("APPDATA", userDir)         // windows
	t.Setenv("XDG_CONFIG_HOME", userDir) // linux
	t.Setenv("HOME", userDir)            // darwin: $HOME/Library/Application Support
	got, err := os.UserConfigDir()
	if err != nil || !strings.HasPrefix(got, userDir) {
		t.Fatalf("UserConfigDir = %q, %v; want under %q", got, err, userDir)
	}

	oldExe, oldSigning := keyExeDir, g_signing
	keyExeDir = func() string { return exeDir }
	g_signing = signingOptions{}
	t.Cleanup(func() { keyExeDir, g_signing = oldExe, oldSigning })
	return got, exeDir
}

// writeKey generates a real P-256 key at path.
func writeKey(t *testing.T, path string) {
	t.Helper()
	if _, err := generateSigningKey(path); err != nil {
		t.Fatal(err)
	}
}

func TestKeyLookupOrder(t *testing.T) {
	cfgDir, exeDir := keyEnv(t)
	userKey := filepath.Join(cfgDir, "openplc", "keys", "fw_signing_key.pem")
	exeKey := filepath.Join(exeDir, "keys", "fw_signing_key.pem")

	// Nothing anywhere.
	if p := findSigningKey(); p != "" {
		t.Fatalf("no keys: got %q", p)
	}
	if got := defaultKeyLocation(); got != userKey {
		t.Fatalf("defaultKeyLocation = %q, want %q", got, userKey)
	}

	// A key left in the old published-key place is never picked up.
	writeKey(t, filepath.Join(exeDir, "keys", "published_root.TEST_ONLY.pem"))
	if p := findSigningKey(); p != "" {
		t.Fatalf("published key must not be used, got %q", p)
	}

	writeKey(t, exeKey)
	if p := findSigningKey(); p != exeKey {
		t.Fatalf("exe dir: got %q", p)
	}

	// User dir beats the exe dir.
	writeKey(t, userKey)
	if p := findSigningKey(); p != userKey {
		t.Fatalf("user dir: got %q", p)
	}

	// --key / local_config.json beats everything.
	g_signing.keyPath = filepath.Join(t.TempDir(), "explicit.pem")
	if p := findSigningKey(); p != g_signing.keyPath {
		t.Fatalf("explicit: got %q", p)
	}
}

func TestUploadIdentityNoKeyNamesUserDir(t *testing.T) {
	cfgDir, _ := keyEnv(t)
	_, err := resolveUploadIdentity()
	want := filepath.Join(cfgDir, "openplc", "keys", "fw_signing_key.pem")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v does not name %s", err, want)
	}
}

func TestGenkeyRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.pem")
	writeKey(t, path)
	if _, err := generateSigningKey(path); err == nil {
		t.Fatal("second generateSigningKey on the same path succeeded")
	}
}

// fakeBoard answers the bootloader's text commands for claimIfUnclaimed.
type fakeBoard struct {
	root    string // "" = no root
	refuse  bool
	claimed string
	sent    []string
}

func (b *fakeBoard) exchange(cmd string) (string, error) {
	b.sent = append(b.sent, cmd)
	switch {
	case cmd == CM_GetPubKey:
		if b.root == "" {
			return noRootReply, nil
		}
		return b.root, nil
	case strings.HasPrefix(cmd, "takeown "):
		if b.refuse || b.root != "" {
			return "Refused", nil
		}
		b.claimed = strings.TrimPrefix(cmd, "takeown ")
		b.root = b.claimed
		return "OK", nil
	}
	return "Unknown command", nil
}

func TestClaimNoRootNoKeyGeneratesAtDefault(t *testing.T) {
	cfgDir, _ := keyEnv(t)
	board := &fakeBoard{}
	if err := claimIfUnclaimed(board.exchange); err != nil {
		t.Fatal(err)
	}
	userKey := filepath.Join(cfgDir, "openplc", "keys", "fw_signing_key.pem")
	pub, err := ownerPublicKeyHex(userKey)
	if err != nil {
		t.Fatalf("no key generated at %s: %v", userKey, err)
	}
	if board.claimed != pub {
		t.Fatalf("claimed %q, want the generated key %q", board.claimed, pub)
	}
}

func TestClaimNoRootReusesExistingKey(t *testing.T) {
	cfgDir, _ := keyEnv(t)
	userKey := filepath.Join(cfgDir, "openplc", "keys", "fw_signing_key.pem")
	writeKey(t, userKey)
	before, _ := os.ReadFile(userKey)
	pub, _ := ownerPublicKeyHex(userKey)

	board := &fakeBoard{}
	if err := claimIfUnclaimed(board.exchange); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(userKey)
	if string(before) != string(after) {
		t.Fatal("the existing key was replaced")
	}
	if board.claimed != pub {
		t.Fatalf("claimed %q, want the existing key %q", board.claimed, pub)
	}
}

func TestClaimSkippedWhenBoardHasRoot(t *testing.T) {
	keyEnv(t)
	board := &fakeBoard{root: strings.Repeat("ab", 64)}
	if err := claimIfUnclaimed(board.exchange); err != nil {
		t.Fatal(err)
	}
	for _, c := range board.sent {
		if strings.HasPrefix(c, "takeown") {
			t.Fatal("takeown sent to a board that already has a root")
		}
	}
}

func TestClaimRefusedIsAnError(t *testing.T) {
	keyEnv(t)
	board := &fakeBoard{refuse: true}
	err := claimIfUnclaimed(board.exchange)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("got %v, want a refusal error", err)
	}
}

func TestMismatchNamesBothWaysOut(t *testing.T) {
	cfgDir, _ := keyEnv(t)
	userKey := filepath.Join(cfgDir, "openplc", "keys", "fw_signing_key.pem")
	writeKey(t, userKey)
	id, err := resolveUploadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.pem")
	writeKey(t, other)
	otherPub, _ := ownerPublicKeyHex(other)

	err = verifyIdentityMatchesDevice(id, func() (string, error) { return otherPub, nil })
	if err == nil {
		t.Fatal("a board with another root was accepted")
	}
	for _, want := range []string{userKey, "IAPTool pubkey", "IAPTool cert", userKey + certSuffix} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("mismatch message lacks %q:\n%v", want, err)
		}
	}
}

// A bootloader that cannot answer getpubkey used to be waved through; it is
// refused now (decision 79), so nothing uploads without the key check.
func TestNonRootReplyIsRefused(t *testing.T) {
	cfgDir, _ := keyEnv(t)
	writeKey(t, filepath.Join(cfgDir, "openplc", "keys", "fw_signing_key.pem"))
	id, err := resolveUploadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	err = verifyIdentityMatchesDevice(id, func() (string, error) { return "Unknown command", nil })
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("a board without getpubkey was not refused: %v", err)
	}
}

func TestIsSerialTarget(t *testing.T) {
	if isSerialTarget("192.168.0.3") || isSerialTarget("127.0.0.1") {
		t.Fatal("an IP was taken for a serial port")
	}
	port := "/dev/ttyACM0"
	if runtime.GOOS == "windows" {
		port = "COM11"
	}
	if !isSerialTarget(port) {
		t.Fatalf("%s not taken for a serial port", port)
	}
}

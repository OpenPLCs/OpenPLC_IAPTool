package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// scriptedPort returns one scripted read per call, then (0, nil) -- a quiet
// port -- or err once the script runs out and err is set.
type scriptedPort struct {
	reads []string
	err   error
}

func (s *scriptedPort) Read(p []byte) (int, error) {
	if len(s.reads) > 0 {
		n := copy(p, s.reads[0])
		s.reads = s.reads[1:]
		return n, nil
	}
	time.Sleep(5 * time.Millisecond)
	if s.err != nil {
		return 0, s.err
	}
	return 0, nil
}

func alwaysPresent() bool { return true }

func TestCDCVerdictRefusalIsAnError(t *testing.T) {
	err := readCDCVerdict(&scriptedPort{reads: []string{"Signature ", "Failed"}}, "", alwaysPresent, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refused the image: Signature Failed") {
		t.Fatalf("want a refusal naming Signature Failed, got %v", err)
	}
}

func TestCDCVerdictRefusalStuckToTheLastOK(t *testing.T) {
	ok, rest := readUntil(&scriptedPort{reads: []string{"OKChecksum Failed"}}, Rsp_OK, time.Second)
	if !ok {
		t.Fatal("the last block's OK was not seen")
	}
	err := readCDCVerdict(&scriptedPort{}, rest, alwaysPresent, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "Checksum Failed") {
		t.Fatalf("want the refusal that shared a read with OK, got %v", err)
	}
}

func TestCDCVerdictPortErrorMeansAccepted(t *testing.T) {
	if err := readCDCVerdict(&scriptedPort{err: errors.New("device removed")}, "", alwaysPresent, 2*time.Second); err != nil {
		t.Fatalf("a port that went away after the last block is a reset, got %v", err)
	}
}

func TestCDCVerdictPortGoneFromListMeansAccepted(t *testing.T) {
	err := readCDCVerdict(&scriptedPort{}, "", func() bool { return false }, 3*time.Second)
	if err != nil {
		t.Fatalf("a port missing from the list is a reset, got %v", err)
	}
}

func TestCDCVerdictSilenceIsNotConfirmed(t *testing.T) {
	err := readCDCVerdict(&scriptedPort{}, "", alwaysPresent, 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "NOT confirmed") {
		t.Fatalf("silence with the port still there must not pass, got %v", err)
	}
}

func TestVerboseFlag(t *testing.T) {
	for _, flag := range []string{"-v", "--verbose"} {
		g_verbose = false
		args, err := parseSigningFlags([]string{"cdc", "a.bin", flag, "COM3"})
		if err != nil || !g_verbose || strings.Join(args, " ") != "cdc a.bin COM3" {
			t.Fatalf("%s: verbose=%v args=%v err=%v", flag, g_verbose, args, err)
		}
	}
	g_verbose = false
}

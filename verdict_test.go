package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// scriptedSession returns one scripted read per call, then (0, nil) -- a
// quiet stream -- or err once the script runs out and err is set.
type scriptedSession struct {
	reads []string
	err   error
	sent  []string
}

func (s *scriptedSession) write(b []byte) error { s.sent = append(s.sent, string(b)); return nil }

func (s *scriptedSession) readSome(p []byte, wait time.Duration) (int, error) {
	if len(s.reads) > 0 {
		n := copy(p, s.reads[0])
		s.reads = s.reads[1:]
		return n, nil
	}
	time.Sleep(5 * time.Millisecond)
	return 0, s.err
}

func (s *scriptedSession) Close() error { return nil }

func usbPresent(present bool) func(bool) bool { return usbResetSeen(func() bool { return present }) }

func TestVerdictRefusalIsAnError(t *testing.T) {
	err := readVerdict(&scriptedSession{reads: []string{"Signature ", "Failed"}}, "", usbPresent(true), cdcPresencePoll, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refused the image: Signature Failed") {
		t.Fatalf("want a refusal naming Signature Failed, got %v", err)
	}
}

func TestVerdictRefusalStuckToTheLastOK(t *testing.T) {
	rest, err := awaitOK(&scriptedSession{reads: []string{"OKChecksum Failed"}}, []byte("block"), time.Second)
	if err != nil {
		t.Fatalf("the last block's OK was not seen: %v", err)
	}
	err = readVerdict(&scriptedSession{}, rest, usbPresent(true), cdcPresencePoll, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "Checksum Failed") {
		t.Fatalf("want the refusal that shared a read with OK, got %v", err)
	}
}

func TestVerdictUSBPortErrorMeansAccepted(t *testing.T) {
	if err := readVerdict(&scriptedSession{err: errors.New("device removed")}, "", usbPresent(true), cdcPresencePoll, 2*time.Second); err != nil {
		t.Fatalf("a port that went away after the last block is a reset, got %v", err)
	}
}

func TestVerdictUSBPortGoneFromListMeansAccepted(t *testing.T) {
	if err := readVerdict(&scriptedSession{}, "", usbPresent(false), cdcPresencePoll, 3*time.Second); err != nil {
		t.Fatalf("a port missing from the list is a reset, got %v", err)
	}
}

// Ethernet: a dropped connection alone proves nothing; the board answering
// again does.
func TestVerdictDroppedConnectionWaitsForTheBoard(t *testing.T) {
	looks := 0
	seen := func(bool) bool { looks++; return looks >= 2 }
	if err := readVerdict(&scriptedSession{err: errors.New("reset by peer")}, "", seen, 50*time.Millisecond, 2*time.Second); err != nil || looks != 2 {
		t.Fatalf("want acceptance on the second look, got err=%v looks=%d", err, looks)
	}
}

func TestVerdictSilenceIsNotConfirmed(t *testing.T) {
	err := readVerdict(&scriptedSession{}, "", usbPresent(true), cdcPresencePoll, 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "NOT confirmed") {
		t.Fatalf("silence with the port still there must not pass, got %v", err)
	}
}

// A reply counts as OK only when it starts with OK; anything else is the error.
func TestAwaitOKNeedsOKFirst(t *testing.T) {
	if _, err := awaitOK(&scriptedSession{reads: []string{"Fail", "ed"}}, []byte("x"), time.Second); err == nil || !strings.Contains(err.Error(), "Failed") {
		t.Fatalf("want the refusal text, got %v", err)
	}
	if _, err := awaitOK(&scriptedSession{reads: []string{"ERR OK"}}, []byte("x"), time.Second); err == nil {
		t.Fatal("a reply that only contains OK passed")
	}
	if rest, err := awaitOK(&scriptedSession{reads: []string{"O", "K"}}, []byte("x"), time.Second); err != nil || rest != "" {
		t.Fatalf("an OK split over two reads: rest=%q err=%v", rest, err)
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

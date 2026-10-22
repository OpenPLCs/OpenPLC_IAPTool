package serialx

import (
	"bufio"
	"errors"
	"io"
	"testing"
)

// idleThenSpeak answers with nothing `quiet` times, then with one line, the way
// a serial port that has no data yet does.
type idleThenSpeak struct {
	quiet int
	line  []byte
	sent  bool
	reads int
}

func (r *idleThenSpeak) Read(p []byte) (int, error) {
	r.reads++
	if r.quiet > 0 {
		r.quiet--
		return 0, nil // nothing to say, and nothing wrong
	}
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(p, r.line), nil
}

// *** The failure this exists to prevent. *** bufio gives up after a hundred
// empty reads with ErrNoProgress, and a quiet port produces exactly those - so
// a healthy board that happened to be between replies read as a board that had
// stopped answering, and a working RS485 adapter read as one receiving nothing.
func TestBufioGivesUpOnAQuietPort(t *testing.T) {
	raw := &idleThenSpeak{quiet: 200, line: []byte("OK hello\n")}
	sc := bufio.NewScanner(raw)

	if sc.Scan() {
		t.Fatalf("scanned %q straight off a port that was quiet first", sc.Text())
	}
	if !errors.Is(sc.Err(), io.ErrNoProgress) {
		t.Fatalf("err = %v, want ErrNoProgress - if this changed, the wrapper "+
			"below may no longer be needed", sc.Err())
	}
}

func TestSteadyReaderWaitsThroughTheQuiet(t *testing.T) {
	raw := &idleThenSpeak{quiet: 200, line: []byte("OK hello\n")}
	sc := bufio.NewScanner(SteadyReader{R: raw})

	if !sc.Scan() {
		t.Fatalf("gave up on a quiet port: %v", sc.Err())
	}
	if got := sc.Text(); got != "OK hello" {
		t.Errorf("read %q, want the line the port eventually sent", got)
	}
	if raw.reads <= 200 {
		t.Errorf("only %d reads - the quiet period was not actually waited out",
			raw.reads)
	}
}

// A real error still has to come straight back. Waiting through a closed port
// would hang the reader instead of letting it report what happened.
func TestSteadyReaderPassesErrorsOn(t *testing.T) {
	want := errors.New("port closed")
	n, err := SteadyReader{R: &errReader{err: want}}.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, want) {
		t.Errorf("got (%d, %v), want (0, %v)", n, err, want)
	}
}

// Bytes delivered alongside an error must not be dropped: a port can hand over
// its last line and close in the same call.
func TestSteadyReaderKeepsBytesThatCameWithAnError(t *testing.T) {
	raw := errReader{data: []byte("tail"), err: io.EOF}
	buf := make([]byte, 8)
	n, err := SteadyReader{R: &raw}.Read(buf)
	if n != 4 || string(buf[:n]) != "tail" {
		t.Errorf("got %q (%d bytes), want \"tail\"", buf[:n], n)
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want EOF", err)
	}
}

type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) { return copy(p, r.data), r.err }

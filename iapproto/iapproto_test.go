package iapproto

import (
	"net"
	"testing"
	"time"
)

// Loopback has no physical interface, so both dials take the plain path and
// must still reach a listener.
func TestDialTCPReachesListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	conn, err := DialTCP("127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	conn.Close()
}

func TestDialUDPConnects(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	conn, err := DialUDP("127.0.0.1", port)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 8)
	pc.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("listener got %q, %v", buf[:n], err)
	}
}

func TestDialTCPRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	if _, err := DialTCP("127.0.0.1", port, time.Second); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
}

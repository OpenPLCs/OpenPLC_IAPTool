// Package iapproto holds what IAPTool and OpenPLC_Test's TestCase tool must agree on to
// talk to the bootloader: the protocol constants and how the board is dialed.
//
// It is public so TestCase imports these instead of copying them; IAPTool itself
// is package main and cannot be imported. See $PROD/docs/tables/DECISIONS.md 77.
package iapproto

import (
	"fmt"
	"net"
	"time"

	"IAPTool/netiface"
)

const (
	// ChunkSize is the payload of one flash data frame.
	ChunkSize = 8 * 1024
	// CommandTimeout is one command, one reply - the same budget on both
	// channels. A discovery reply later than this is dropped by IAPTool.
	CommandTimeout = 2 * time.Second
)

// DialUDP opens a UDP socket to the board with the source address pinned to
// the physical interface on the board's subnet.
//
// Without the pin the routing table decides, and a VPN tunnel or a Docker
// switch holding a better default route takes the datagram instead (seen on
// 2026-09-18). A connected socket only accepts replies from the address it
// dialed. When no physical interface shares the board's subnet the board is
// reached through a router, so the plain dial is correct.
// See $PROD/docs/tables/DECISIONS.md decision 51.
func DialUDP(host, port string) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("UDP ResolveUDPAddr failed: %w", err)
	}
	var laddr *net.UDPAddr
	if local := netiface.LocalIPFor(raddr.IP); local != nil {
		laddr = &net.UDPAddr{IP: local}
	}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("UDP connection failed: %w", err)
	}
	return conn, nil
}

// DialTCP is DialUDP's sibling for the command and flash channel. An unpinned
// TCP dial to a specific IP let a VPN endpoint complete the handshake for the
// board on 2026-09-18 (connect in 0.03s, then reset, from a host never on the
// board's subnet).
func DialTCP(host, port string, timeout time.Duration) (net.Conn, error) {
	target := net.JoinHostPort(host, port)
	if raddr, err := net.ResolveTCPAddr("tcp", target); err == nil {
		if local := netiface.LocalIPFor(raddr.IP); local != nil {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: local}, Timeout: timeout}
			return d.Dial("tcp", target)
		}
	}
	return net.DialTimeout("tcp", target, timeout)
}

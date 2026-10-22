// Package netiface decides which of this host's network interfaces may be
// used to reach a board.
//
// Only physical interfaces count. A VPN tunnel, a Docker or Hyper-V switch or
// any other virtual adapter can hold a default route with a better metric than
// the real NIC, and then every probe leaves through it and times out -- which
// reads as "the board is not answering". Decision 51 in
// $PROD/docs/tables/DECISIONS.md.
//
// MIRRORED CODE. The source is the Arduino core's
// tools/discovery/network_discovery.go (isPhysicalInterface) together with its
// three iface_*.go classifiers. Item 10 of the cross-repo mirror table in
// $PROD/docs/repo/ARCHITECTURE.md; case P2 compares the two. Change the core
// first, then bring the change here.
package netiface

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// IsPhysical reports whether an interface is backed by real hardware and can
// therefore be used to look for a board.
func IsPhysical(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if iface.Flags&net.FlagPointToPoint != 0 {
		return false
	}
	if len(iface.HardwareAddr) == 0 {
		return false
	}
	return isRealHardwareInterface(iface)
}

// Physical returns the subset of the host's interfaces that IsPhysical accepts.
func Physical() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	refreshHardwareCacheIfNeeded(ifaces)

	var out []net.Interface
	for _, ifc := range ifaces {
		if IsPhysical(ifc) {
			out = append(out, ifc)
		}
	}
	return out, nil
}

// LocalIPFor returns the address of the physical interface whose subnet
// contains target, or nil when no physical interface is on that subnet.
//
// Binding the source address is what keeps a probe off a virtual adapter: the
// routing table alone will hand the socket to whichever interface holds the
// best default route, and that is frequently the VPN.
func LocalIPFor(target net.IP) net.IP {
	target = target.To4()
	if target == nil {
		return nil
	}

	ifaces, err := Physical()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			if ipNet.Contains(target) {
				return ipNet.IP.To4()
			}
		}
	}
	return nil
}

// hwCache maps interface name -> "is this backed by real hardware", as
// classified by the OS-specific classifyHardware. It's refreshed only when the
// set of interfaces changes, or at most every hwCacheMaxAge, since the
// classifiers can shell out to an external command (PowerShell, networksetup).
var (
	hwCacheMu  sync.Mutex
	hwCache    map[string]bool
	hwCacheKey string
	hwCacheAt  time.Time
)

const hwCacheMaxAge = 60 * time.Second

func refreshHardwareCacheIfNeeded(ifaces []net.Interface) {
	names := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		names = append(names, ifc.Name)
	}
	sort.Strings(names)
	key := strings.Join(names, ",")

	hwCacheMu.Lock()
	stale := hwCache == nil || key != hwCacheKey || time.Since(hwCacheAt) > hwCacheMaxAge
	hwCacheMu.Unlock()
	if !stale {
		return
	}

	fresh := classifyHardware(ifaces) // OS-specific; nil means "unavailable"

	hwCacheMu.Lock()
	defer hwCacheMu.Unlock()
	if fresh != nil {
		hwCache = fresh
	} else if hwCache == nil {
		hwCache = map[string]bool{}
	}
	hwCacheKey = key
	hwCacheAt = time.Now()
}

// isRealHardwareInterface fails open (treats an interface as real) whenever the
// OS-specific classifier is unavailable or doesn't know about a given
// interface, so a classifier bug never silently hides every NIC.
func isRealHardwareInterface(iface net.Interface) bool {
	hwCacheMu.Lock()
	defer hwCacheMu.Unlock()
	if hwCache == nil {
		return true
	}
	v, ok := hwCache[iface.Name]
	if !ok {
		return true
	}
	return v
}

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// pingSweep pings devices in the subnet and returns the ARP table.
func pingSweep(subnet string) string {
	start := time.Now()
	var cmds []*exec.Cmd

	switch runtime.GOOS {
	case "windows":
		script := fmt.Sprintf(`for /L %%i in (1,1,254) do @ping -n 1 -w 50 %s.%%i >nul`, subnet)
		cmds = []*exec.Cmd{
			exec.Command("cmd", "/C", script),
			exec.Command("cmd", "/C", "arp -a"),
		}
	case "linux", "darwin":
		// Ping all hosts in the subnet in parallel, then get ARP table
		pingScript := fmt.Sprintf("for ip in $(seq 1 254); do ping -c 1 -W 1 %s.$ip > /dev/null & done; wait", subnet)
		cmds = []*exec.Cmd{
			exec.Command("bash", "-c", pingScript),
			exec.Command("ip", "neigh", "show"),
		}
	default:
		logf(true, "Unsupported OS: %s", runtime.GOOS)
	}

	var arpOutput bytes.Buffer
	for _, cmd := range cmds {
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Ignore failed commands like ping timeout
			continue
		}
		arpOutput.Write(out)
	}
	elapsed := time.Since(start)
	logf("Subnet scan completed in %.2f seconds.", elapsed.Seconds())
	return arpOutput.String()
}

// findIPByMAC parses the ARP table output to find the IP address for a given MAC address.
func findIPByMAC(arpTable, targetMAC string) string {
	lines := strings.Split(arpTable, "\n")

	for _, line := range lines {
		if strings.Contains(strings.ToLower(strings.ReplaceAll(line, "-", ":")), targetMAC) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[0] // First field is usually the IP
			}
		}
	}
	return ""
}

func GetServerIP() {
	if l_config.MAC == "" {
		logf(true, "MAC field is required in config, but it's empty. Exiting.")
	}

	if l_config.IP != "" {
		// make sure the IP is reachable
		if err := pingOnce(l_config.IP); err == nil {
			logf("Using cached IP (verified): %s", l_config.IP)
		} else {
			logf("Cached IP %s is not reachable. Re-discovering... That may take a while. Please wait.", l_config.IP)
			l_config.IP = ""
		}
	}

	if l_config.IP == "" {
		cidrs, err := GetLocalCIDRs()
		if err != nil || len(cidrs) == 0 {
			logf(true, "Failed to get local subnets: %s", err)
		}

		// Extract base subnet
		ip := strings.Split(cidrs[0], "/")[0]
		base := ip[:strings.LastIndex(ip, ".")]

		logf("Scanning subnet: %s.0/24 ...", base)
		arpTable := pingSweep(base)
		l_config.IP = findIPByMAC(arpTable, l_config.MAC)
		if l_config.IP == "" {
			logf(true, "Could not find IP for MAC: %s", l_config.MAC)
		} else {
			err = SaveConfig()
			logf(err, "Failed to save config: %s", err)
			logf("Discovered IP: %s for MAC: %s", l_config.IP, l_config.MAC)
		}
	}
}

func pingOnce(ip string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	default: // linux/mac
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run()
}

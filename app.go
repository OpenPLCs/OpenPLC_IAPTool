package main

import (
	"fmt"
)

// json file struct
type LocalConfig struct {
	BaudRate          int    `json:"BaudRate"`
	Parity            int    `json:"Parity"`
	DataBits          int    `json:"DataBits"`
	StopBits          int    `json:"StopBits"`
	ReadTimeout       int    `json:"ReadTimeout"`
	IP                string `json:"ip"`
	MAC               string `json:"mac"`
	UDPPort           string `json:"udp_port"`
	TCPPort           string `json:"tcp_port"`
	RebootWaitSeconds int    `json:"reboot_wait_seconds"`
}

var l_config LocalConfig

func main() {
	LoadConfig()
	args := ParseArgs()

	switch args.Mode {
	case ModeCDC:
		RunCDC(args.Port, args.FilePath)
	case ModeEther:
		RunEtherUpgrade(args.FilePath)
	default:
		logf(true, "Invalid mode: %s. Use '%s' or '%s'", args.Mode, ModeCDC, ModeEther)
	}

	fmt.Println("Upgrade process completed.")
}

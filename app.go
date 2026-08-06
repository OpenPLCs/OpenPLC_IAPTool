package main

import (
	"os"
	"strings"
)

// json file struct
type LocalConfig struct {
	BaudRate          int    `json:"BaudRate"`
	Parity            int    `json:"Parity"`
	DataBits          int    `json:"DataBits"`
	StopBits          int    `json:"StopBits"`
	ReadTimeout       int    `json:"ReadTimeout"`
	UID               string `json:"uid"`
	BootIP            string `json:"bootIP"`
	AppIP             string `json:"appIP"`
	MAC               string `json:"mac"`
	ServerPort        string `json:"server_port"`
	RebootWaitSeconds int    `json:"reboot_wait_seconds"`
}

var l_config LocalConfig

func main() {
	// Load config from JSON file
	LoadConfig()

	if len(os.Args) < 3 {
		logf(true, "Usage: program <mode> <file_path>")
	}

	mode := strings.ToLower(os.Args[1])
	filePath := os.Args[2]

	switch mode {
	case "cdc":
		if len(os.Args) < 4 {
			logf(true, "Usage: program <mode> <file_path> [port]")
		}

		port := os.Args[3]
		RunCDC(port, filePath)
	case "ether":
		if len(os.Args) < 4 {
			logf(true, "Usage: program <mode> <file_path> <ip>")
		}

		ip := os.Args[3]
		RunEtherUpgrade(filePath, ip)
	default:
		logf(true, "Invalid mode: %s. Use 'cdc' or 'ether'", mode)
	}
}

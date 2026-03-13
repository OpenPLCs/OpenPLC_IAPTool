package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.bug.st/serial"
)

// Helper function to open a serial port with specified baud rate
func openPort(comName string, baudRate int) (serial.Port, error) {
	mode := &serial.Mode{BaudRate: baudRate}
	port, err := serial.Open(comName, mode)
	if err != nil {
		return nil, err
	}
	if port == nil {
		return nil, errors.New("serial.Open returned nil port")
	}
	return port, nil
}

// Retry logic for opening serial port
// func retryOpenPort(comName string, baudRate int, maxRetries int) serial.Port {
// 	var port serial.Port
// 	var err error
// 	for attempt := 1; attempt <= maxRetries; attempt++ {
// 		time.Sleep(2 * time.Second)
// 		port, err = openPort(comName, baudRate)
// 		if err == nil {
// 			logf("Successfully opened port on attempt %d", attempt)
// 			return port
// 		}
// 		logf("Failed to open port %s on attempt %d of %d. Retrying in 2 seconds...", comName, attempt, maxRetries)
//
// 	}
// 	logf(true, "Failed to open serial port %s after %d attempts", comName, maxRetries)
// 	return nil
// }

func RunCDC(portName, filePath string) {
	logf("Trying to switch to Upload Mod in CDC...")
	if runCDCAttempt(portName, filePath) {
		return
	}

	logf("First ping failed. Reconnecting port with MagicBaud...")
	triggerPortResetAndWait(portName, 4*time.Second)

	if runCDCAttempt(portName, filePath) {
		return
	}

	logf("Second ping failed. Exit program.")
	os.Exit(1)
}

func triggerPortResetAndWait(portName string, wait time.Duration) {
	port, err := openPort(portName, MagicBaud)
	if err != nil {
		logf("MagicBaud reset skipped: failed to open %s@%d: %v", portName, MagicBaud, err)
	} else {
		port.Close()
	}
	logf("MagicBaud reset done. Waiting %.1f seconds...", wait.Seconds())
	time.Sleep(wait)
	logf("Wait finished. Reconnecting with default baud now.")
}

func runCDCAttempt(portName, filePath string) bool {
	port, err := openPort(portName, l_config.BaudRate)
	if err != nil {
		logf("Failed to open serial port %s with baud rate %d: %v", portName, l_config.BaudRate, err)
		return false
	}
	defer port.Close()

	if !SendCommandWaitForResponse(port, CM_Ping, Rsp_OK, PingTimeout) {
		return false
	}

	logf("Proceeding with file transfer.")
	checksum, fileSize, file := CalculateCRC32(filePath)
	defer file.(io.Closer).Close()
	logf("CRC Checksum: %x", checksum)

	flashCmd := fmt.Sprintf("%s %d %x", CM_Flash, fileSize, checksum)
	if !SendCommandWaitForResponse(port, flashCmd, Rsp_OK, PingTimeout) {
		return true
	}

	err = SendFile(port, file, fileSize)
	logf(err, "File transfer failed: %v", err)
	return true
}

// SendCommandWaitForResponse sends a command through the serial port,
// waits for a specific response string, and returns true if received within timeout.
func SendCommandWaitForResponse(port serial.Port, command string, expected string, timeout time.Duration) bool {
	if _, err := port.Write([]byte(command)); err != nil {
		logf(err, "Failed to send command: %s", command)
		return false
	}
	logf("Send command: %s", command)

	return ReadResponse(port, expected, timeout)
}

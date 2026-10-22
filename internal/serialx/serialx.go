// Package serialx is the one place IAPTool opens a serial port.
//
// The retry and timeout behaviour here was arrived at by watching real USB
// adapters fail.
package serialx

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.bug.st/serial"
)

// DefaultBaud is what every port on these boards runs at: the RS232 log and
// command line, the RS485 terminal, and the USB CDC channel alike.
const DefaultBaud = 115200

// ReadTimeout bounds one Read on an idle port.
//
// Without it a UART driver answers an idle port immediately with zero bytes,
// and whoever is reading spins. With it the spin becomes one wake-up every
// tenth of a second, which is far below anything a person or a frame notices.
const ReadTimeout = 100 * time.Millisecond

// Open opens a port at 8N1.
func Open(name string, baud int) (serial.Port, error) {
	port, err := serial.Open(name, &serial.Mode{BaudRate: baud})
	if err != nil {
		return nil, err
	}
	// Ignoring the error: a port that will not take a read timeout still reads,
	// and SteadyReader below is what actually makes an idle port safe. Failing
	// the open over this would turn a working bench into a broken one.
	_ = port.SetReadTimeout(ReadTimeout)
	if port == nil {
		// Not observed, but a nil port with a nil error would surface much
		// later as a nil dereference in whoever writes to it first.
		return nil, errors.New("serial.Open returned nil port")
	}
	return port, nil
}

// RetryOpen keeps trying for `attempts`, waiting `gap` between tries, and
// reports each failure through `log` if one is given.
//
// The wait comes first on purpose: the usual reason a port will not open is
// that the board is still enumerating after a reset, so trying instantly only
// spends an attempt on a port the OS has not created yet.
func RetryOpen(name string, baud, attempts int, gap time.Duration, log func(string, ...any)) (serial.Port, error) {
	var lastErr error
	for i := 1; i <= attempts; i++ {
		time.Sleep(gap)
		port, err := Open(name, baud)
		if err == nil {
			if log != nil && i > 1 {
				log("opened %s on attempt %d", name, i)
			}
			return port, nil
		}
		lastErr = err
		if log != nil {
			log("could not open %s, attempt %d of %d: %v", name, i, attempts, err)
		}
	}
	return nil, fmt.Errorf("could not open %s after %d attempts: %w", name, attempts, lastErr)
}

// PortInfo is one serial port as the operating system describes it.
type PortInfo struct {
	Name    string // "COM7", "/dev/ttyUSB0"
	Product string // what the adapter calls itself, empty if it says nothing
	Driver  string // Linux kernel driver, which names the chip (ch341-uart, pl2303)
	VID     string
	PID     string
	Serial  string
	IsUSB   bool
}

// Label is what to show a person choosing a port. Which physical adapter a
// COM number belongs to is exactly the thing nobody can tell from the number,
// and on a bench with four adapters plugged in that is the whole question.
func (p PortInfo) Label() string {
	var b strings.Builder
	b.WriteString(p.Name)
	if p.Product != "" {
		fmt.Fprintf(&b, " - %s", p.Product)
	}
	if p.Driver != "" {
		fmt.Fprintf(&b, " (%s)", p.Driver)
	}
	if p.VID != "" && p.PID != "" {
		fmt.Fprintf(&b, " [%s:%s]", p.VID, p.PID)
	}
	if p.Serial != "" {
		fmt.Fprintf(&b, " #%s", p.Serial)
	}
	return b.String()
}

// List reports every serial port the OS knows about, USB adapters described as
// fully as the platform allows - see enum_detailed.go and enum_darwin.go.
//
// Ports with no USB details are still listed: a built-in port or one behind a
// driver that reports nothing is still a port somebody may need to pick.
func List() ([]PortInfo, error) {
	return listPorts()
}

// SteadyReader hides empty reads from whoever is above it.
//
// *** bufio.Scanner gives up after a hundred of them. *** Its error is
// "multiple Read calls return no data or error" (bufio.ErrNoProgress), and an
// idle serial port produces exactly that: the driver has nothing, so Read
// returns (0, nil) as fast as it is asked. The scanner then stops - on a port
// that is perfectly healthy and merely quiet.
//
// *** Both scanners in this program read serial ports. *** The control port
// showed it as the board "stopping answering" partway through a reply, and the
// RS485 far end showed it as an adapter that never received a byte while a
// bare read of the same port at the same baud returned clean data. One cause,
// two failures that look nothing alike, and both of them intermittent because
// they depend on how long the port happened to be quiet.
//
// Reading again rather than returning is the whole fix: a quiet port is not
// the end of the stream, and only the port itself can say when it is.
type SteadyReader struct {
	R io.Reader
}

func (s SteadyReader) Read(p []byte) (int, error) {
	for {
		n, err := s.R.Read(p)
		if n > 0 || err != nil {
			return n, err
		}
		// Nothing yet and nothing wrong. The read timeout above is what keeps
		// this from becoming a busy loop.
	}
}

package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const testUID = "0123456789ABCDEF01234567"

// fakeNet scripts the network side of a boardFinder on a fake clock.
type fakeNet struct {
	requestErr []error  // per reboot request; missing entries succeed
	answers    []string // per identify; "" means no answer
	rest       string   // the answer after the script runs out
	bcast      []boardInfo
	requests   int
	identifies int
	broadcasts int
	clock      time.Time
}

func (n *fakeNet) request() error {
	n.requests++
	if n.requests <= len(n.requestErr) {
		return n.requestErr[n.requests-1]
	}
	return nil
}

func (n *fakeNet) finder() *boardFinder {
	return &boardFinder{
		ip: "10.0.0.9", uid: testUID,
		identify: func() (string, error) {
			n.identifies++
			n.clock = n.clock.Add(findInterval)
			a := n.rest
			if n.identifies <= len(n.answers) {
				a = n.answers[n.identifies-1]
			}
			if a == "" {
				return "", errors.New("timeout")
			}
			return a, nil
		},
		broadcast: func() ([]boardInfo, error) { n.broadcasts++; return n.bcast, nil },
		now:       func() time.Time { return n.clock },
		sleep:     func(d time.Duration) { n.clock = n.clock.Add(d) },
	}
}

func reply(uid, role string) string { return "STM32H743_" + uid + "_" + role + "_0.1.3_-" }

// The normal upload: the original IP answers, so nothing is broadcast.
func TestRebootFoundAtOriginalIP(t *testing.T) {
	n := &fakeNet{answers: []string{reply(testUID, "CUSAPP"), "", ""}, rest: reply(testUID, "BOOTLD")}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootInBootloader || n.requests != 1 || n.broadcasts != 0 {
		t.Fatalf("state=%v requests=%d broadcasts=%d", res.state, n.requests, n.broadcasts)
	}
}

// IDE-16: a bootloader that cannot answer for up to 19 s is still caught by
// the once-a-second identify, without another reboot request.
func TestRebootSlowBootloaderNeedsNoSecondRequest(t *testing.T) {
	quiet := make([]string, 19)
	n := &fakeNet{answers: quiet, rest: reply(testUID, "BOOTLD")}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootInBootloader || n.requests != 1 || n.broadcasts != 0 {
		t.Fatalf("state=%v requests=%d broadcasts=%d", res.state, n.requests, n.broadcasts)
	}
}

// A board DHCP moved is found by broadcast once the original IP stays quiet.
func TestRebootMovedBoardFoundByBroadcast(t *testing.T) {
	n := &fakeNet{bcast: []boardInfo{{UID: testUID, IP: "10.0.0.20", Role: "BOOTLD"}}}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootInBootloader || res.board.IP != "10.0.0.20" || n.broadcasts == 0 {
		t.Fatalf("state=%v ip=%s broadcasts=%d", res.state, res.board.IP, n.broadcasts)
	}
}

// A failed request (no challenge from a bootloader) must not hide a board that
// is already in its bootloader.
func TestRebootLookAfterFailedRequest(t *testing.T) {
	app := reply(testUID, "CUSAPP")
	window := int(rebootWindow / findInterval)
	answers := make([]string, 0, window+2)
	for i := 0; i < window; i++ {
		answers = append(answers, app)
	}
	n := &fakeNet{requestErr: []error{nil, errors.New("no challenge")}, answers: answers,
		rest: reply(testUID, "BOOTLD-INVALID")}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootInBootloader || n.requests != 2 {
		t.Fatalf("state=%v requests=%d", res.state, n.requests)
	}
}

func TestRebootStillApp(t *testing.T) {
	n := &fakeNet{rest: reply(testUID, "CUSAPP")}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootStillApp || res.sent != rebootAttempts {
		t.Fatalf("state=%v sent=%d", res.state, res.sent)
	}
	msg := rebootFailureText(res, "10.0.0.9", testUID, "key.pem")
	for _, want := range []string{"did not accept the reboot request", "lost", "getowner"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "belongs to another key") {
		t.Errorf("message asserts another owner:\n%s", msg)
	}
}

func TestRebootNoAnswerDoesNotBlameTheKey(t *testing.T) {
	n := &fakeNet{}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootNoAnswer {
		t.Fatalf("state=%v", res.state)
	}
	msg := rebootFailureText(res, "10.0.0.9", testUID, "key.pem")
	if strings.Contains(msg, "key") {
		t.Errorf("no-answer message mentions the key:\n%s", msg)
	}
}

// Another board at the original IP gets no further reboot request.
func TestRebootOtherBoardAtSameIP(t *testing.T) {
	n := &fakeNet{rest: reply("FFFFFFFFFFFFFFFFFFFFFFFF", "BOOTLD")}
	res := rebootIntoBootloader(n.request, n.finder())
	if res.state != rebootOtherBoard || n.requests != 1 {
		t.Fatalf("state=%v requests=%d", res.state, n.requests)
	}
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The IDE's network_discovery and this tool both send the same discovery query
// from the same host; while this file exists, discovery stands aside so its
// poll never competes with an upload's own query for the board's reply budget.
//
// It is advisory in both directions: a lock that cannot be written never stops
// a flash, and a discovery that cannot read it just carries on broadcasting.
const uploadLockName = "openplc-iap-upload.lock"

// A fatal logf removes the lock before exiting (exitCleanups). The age bound
// covers a process killed outright: just past the worst realistic upload --
// identify with retries (~14s) + reboot wait (4s) + bootloader discovery
// (~15s) + transfer (~10s) -- so a crash costs at most one stale window rather
// than minutes of an empty port menu.
const UploadLockMaxAge = 90 * time.Second

func UploadLockPath() string {
	return filepath.Join(os.TempDir(), uploadLockName)
}

// AcquireUploadLock announces that an upload is in progress and returns the
// function that takes the announcement back.
func AcquireUploadLock() func() {
	path := UploadLockPath()

	// Whatever is there belongs to a run that is already over: this process is
	// the one uploading now.
	_ = os.Remove(path)

	body := fmt.Sprintf("pid=%d\nstarted=%d\n", os.Getpid(), time.Now().UnixMilli())
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		logf("Could not write %s (%v). The upload continues; the IDE's discovery "+
			"may collide with it and cost a retry.", path, err)
		return func() {}
	}

	release := func() { _ = os.Remove(path) }
	exitCleanups = append(exitCleanups, release)
	return release
}

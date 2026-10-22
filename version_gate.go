package main

// The version gate: refuse to flash an image older than what the board is
// already running.
//
// This is a guard against pushing a stale build by mistake -- it is not a
// security control. Anyone with an ST-Link bypasses it completely, and that is
// accepted: the only way to stop that is RDP Level 2, which is irreversible and
// would take BOOT0 factory reset and ST-Link recovery with it. See
// $PROD/docs/tables/DECISIONS.md #62.
//
// The version being compared is the sketch's own, declared with
// OPENPLC_APP_VERSION() and reported as the fifth field of the identity string.
// It is not the board package release version, which is the fourth field and is
// the same for every sketch built with one package.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// appVersion is a three-field version, each field 0..255. The core rejects
// anything else at compile time.
type appVersion struct {
	major, minor, patch int
}

func (v appVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

// olderThan is a field-by-field numeric comparison. A string compare would put
// 10.0.0 before 9.0.0.
func (v appVersion) olderThan(o appVersion) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	return v.patch < o.patch
}

func parseAppVersion(s string) (appVersion, bool) {
	fields := strings.Split(strings.TrimSpace(s), ".")
	if len(fields) != 3 {
		return appVersion{}, false
	}
	out := make([]int, 3)
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || n > 255 {
			return appVersion{}, false
		}
		out[i] = n
	}
	return appVersion{out[0], out[1], out[2]}, true
}

// imageVersionPath is where postbuild.sh leaves the version it pulled out of
// the ELF: the same name as the binary, with .version instead of .bin.
func imageVersionPath(binPath string) string {
	return strings.TrimSuffix(binPath, filepath.Ext(binPath)) + ".version"
}

// readImageVersion reports the version of the image about to be flashed.
// A missing file is not an error: images built before this feature, and images
// built by hand, simply have no version and are let through.
func readImageVersion(binPath string) (appVersion, bool) {
	raw, err := os.ReadFile(imageVersionPath(binPath))
	if err != nil {
		return appVersion{}, false
	}
	// objcopy copies the NUL terminator along with the string.
	return parseAppVersionTrimmed(string(raw))
}

func parseAppVersionTrimmed(s string) (appVersion, bool) {
	return parseAppVersion(strings.Trim(strings.TrimSpace(s), "\x00"))
}

// forceMarkerPath is where the one-shot marker lives. The Arduino IDE keeps a
// board menu selection until the user changes it back, and nothing can reach in
// and reset it, so "force once" has to be enforced on this side instead.
func forceMarkerPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "openplc", "force_flash_used")
}

func forceMarkerExists() bool {
	_, err := os.Stat(forceMarkerPath())
	return err == nil
}

// markForceUsed is called only after a forced flash has actually succeeded.
// A failed attempt leaves no marker, so retrying it is not blocked.
func markForceUsed(from, to string) {
	p := forceMarkerPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(p, []byte(fmt.Sprintf("forced flash: board had %s, wrote %s\n", from, to)), 0o644)
}

// clearForceUsed runs on every upload that did not pass --force. Switching the
// IDE menu back to "No" is what produces such an upload, so that switch is the
// reset.
func clearForceUsed() {
	_ = os.Remove(forceMarkerPath())
}

// checkVersionGate decides whether this upload may proceed. It must run while
// the board is still in the application: once it is in the bootloader the fifth
// identity field is "-" and the installed version is no longer knowable.
//
// found reports whether discovery actually reached a board.
func checkVersionGate(binPath string, board boardInfo, found bool, force bool) {
	if !force {
		// The menu is back to "No" (or was never "Yes"): reset the one-shot.
		clearForceUsed()
	} else if forceMarkerExists() {
		logf(true, "force flash has already been used once.\n"+
			"  Set  Tools > Force flash (allow older version)  back to \"No\",\n"+
			"  then upload again. It resets the one-shot.")
	}

	imgVer, haveImg := readImageVersion(binPath)
	if !haveImg {
		// Built before this feature, or built by hand. Nothing to compare.
		return
	}

	if !found {
		if force {
			logf("** FORCE FLASH -- could not read the board's version, check skipped **")
			return
		}
		logf(true, "cannot read the board's current version (it did not answer discovery).\n"+
			"  Not knowing is not the same as there being nothing there, so this upload is refused.\n"+
			"  Check power and cabling, or use  Tools > Force flash (allow older version).")
	}

	// Only a running application can say which sketch version is installed.
	// In the bootloader the field is "-", and a board with no valid app has no
	// current version at all -- both are let through.
	if !strings.HasPrefix(board.Role, "CUSAPP") {
		return
	}

	boardVer, haveBoard := parseAppVersion(board.AppVersion)
	if !haveBoard {
		// Older firmware: four-field identity, no app version to compare.
		return
	}

	if !imgVer.olderThan(boardVer) {
		return // newer or equal -- equal is allowed, re-flashing one build is routine
	}

	if force {
		logf("** FORCE FLASH -- board has %s, writing older %s. Version check skipped. **",
			boardVer, imgVer)
		logf("** This is one-shot: the next forced flash is refused until the menu goes back to \"No\". **")
		g_forcedDowngrade = [2]string{boardVer.String(), imgVer.String()}
		return
	}

	logf(true, "this board already runs %s; the image you are uploading is %s, which is older.\n"+
		"  To flash it anyway, set  Tools > Force flash (allow older version)  to \"Yes\".\n"+
		"  That is one-shot: it is refused again until the menu goes back to \"No\".",
		boardVer, imgVer)
}

// g_forceFlash is set by --force on the command line.
var g_forceFlash bool

// g_forcedDowngrade remembers that this run is a forced downgrade, so the
// marker can be written after the flash succeeds rather than before.
var g_forcedDowngrade [2]string

// noteFlashSucceeded writes the one-shot marker, but only for a forced
// downgrade that actually landed.
func noteFlashSucceeded() {
	if g_forcedDowngrade[0] != "" {
		markForceUsed(g_forcedDowngrade[0], g_forcedDowngrade[1])
	}
}

package main

import (
	"fmt"
	"os"
	"strings"
)

// json file struct
type LocalConfig struct {
	BaudRate          int    `json:"BaudRate"`
	UID               string `json:"uid"`
	ServerPort        string `json:"server_port"`
	RebootWaitSeconds int    `json:"reboot_wait_seconds"`
	SigningKey        string `json:"signing_key"`
}

var l_config LocalConfig

// signingOptions holds the command-line signing overrides for this run.
type signingOptions struct {
	keyPath    string
	certPath   string
	outPrefix  string
	currentKey string
	newKey     string
	leaf       string
	// wipeOwner says --wipe was typed: setowner should erase and rewrite the
	// owner area rather than append to it.
	wipeOwner bool
	// keyExplicit says --key was actually typed. A manual takeown names its key
	// explicitly: claiming with the wrong one takes a factory reset to undo.
	keyExplicit bool
}

var g_signing signingOptions

const usageText = `Usage:
  IAPTool cdc    <file.bin> <port>       [--key=<key.pem>] [--cert=<cert.txt>]
  IAPTool ether  <file.bin> <ip>         [--key=<key.pem>] [--cert=<cert.txt>]
                   uploads an application. A board with no root (new, or
                   factory-reset) is first claimed for the signing key; with no
                   key anywhere, one is generated at the default location below.
  IAPTool flashboot <boot.bin> <ip> --key=<owner.pem>
                   replaces the board's bootloader in place. --key must be the
                   owner root: a leaf certificate cannot authorise this. A board
                   with no root refuses it. Do not cut power during it.
  IAPTool sign   <file.bin> [<key.pem>]  [--key=<key.pem>] [--out=<prefix>]
  IAPTool genkey [<name>]    writes <name>.pem, or the default key location when no
                   name is given; prints the path and the public key
  IAPTool pubkey [<key.pem>] the key's public half as 128 hex characters, the form
                   "cert" and "getpubkey" speak. Send this to whoever holds the
                   root when you need a certificate issued for your key.
  IAPTool cert   [<leafPubHex>]
                   issues a 128-byte leaf certificate signed by the signing key,
                   hex on stdout. No argument = self-signed (simple mode: the key
                   authorises itself); a 128-hex-char public key = delegated leaf.
  IAPTool signraw <hex> [<key.pem>]  raw r||s signature over SHA-256 of those
                   bytes, hex on stdout. For the bootloader's owner-record
                   chain (setowner), not for firmware images.

  IAPTool log    <ip>        prints the board's boot log (bootloader and system
                   lines kept across resets, lost on power-off), oldest first,
                   as "<seq> <text>". The bootloader and the application both answer.

  The commands below take <board>: a serial port (the board's USB port, answered
  only while it is in its bootloader) or an IP.
  IAPTool getowner <board>   which key this board trusts, and at which generation
  IAPTool getapprevoked <board> was this board's firmware signed by a leaf that has
                   since been revoked? Such firmware keeps running, so this is the
                   only way to find the boards worth re-uploading after a revoke.
  IAPTool takeown  <board> --key=<owner.pem>
                   claims a board with no root for that key, without uploading.
                   The first upload does the same by itself.
  IAPTool setowner <board> --current-key=<owner.pem> --new-key=<next.pem> [--wipe]
                   hands a claimed board over to another key. The handover is
                   signed by the current owner, so no button is needed.
  IAPTool revoke   <board> --key=<owner.pem> --leaf=<pubkey>
                   revokes one leaf (128-hex-char public key), signed by the
                   current owner. That leaf's next upload is refused; firmware
                   it already installed keeps running (see getapprevoked).
                   No button is needed. The root itself can never be revoked.

  --key            ECDSA P-256 private key (PEM). When omitted, falls back to
                   "signing_key" in local_config.json, then to
                   <user config dir>/openplc/keys/fw_signing_key.pem (the default
                   location), then to keys/fw_signing_key.pem next to this
                   executable. Uploading needs the private key itself: the image
                   is signed in memory and so is the board's challenge. To upload
                   from another computer, copy the key to the same place there.
  --cert           Certificate presented to the board, as issued by the holder of
                   the root it trusts. When omitted, falls back to "<the signing
                   key>.cert", and with no certificate there the signing key
                   certifies itself - which is what one person with one key wants.
  --out            Output prefix for "sign". Defaults to the .bin path without its extension.
  --wipe           For setowner only: also empty the revocation records, which is
                   the only way to reclaim revocation slots. The board rewrites
                   its state sector to do it and resets.
  --force          Flash even when the image is older than what the board runs.
                   One-shot: refused again until an upload arrives without it.
                   The Arduino IDE passes this from
                   Tools > Force flash (allow older version).
  -v, --verbose    Log every step of an upload: each block, each command, each
                   discovery round. Without it an upload prints the target,
                   a progress bar and the verdict. The Arduino IDE passes it
                   when "Show verbose output during upload" is ticked.

A factory reset (hold BOOT0 for 10 s) makes a board forget its root; the next
upload claims it again.`

func main() {
	args, err := parseSigningFlags(os.Args[1:])
	if err != nil {
		logf(true, "%v", err)
	}
	// After the flags: -v decides whether loading the config is logged.
	LoadConfig()
	if g_signing.keyPath == "" {
		g_signing.keyPath = strings.TrimSpace(l_config.SigningKey)
	}

	if len(args) < 1 {
		logf(true, usageText)
	}
	mode := strings.ToLower(args[0])

	switch mode {
	case "sign":
		if len(args) < 2 {
			logf(true, usageText)
		}
		// A positional key overrides --key/config, keeping the argument
		// order of the shell script it replaces.
		keyPath := findSigningKey()
		if len(args) >= 3 {
			keyPath = args[2]
		}
		if keyPath == "" {
			logf(true, "No signing key found. Pass one as an argument or as --key=<key.pem>, "+
				"put one at %s, or set \"signing_key\" in local_config.json", defaultKeyLocation())
		}
		err := signBinFile(args[1], keyPath, g_signing.outPrefix)
		logf(err, "Failed to sign %s", args[1])

	case "genkey":
		path := userKeyLocation()
		if len(args) >= 2 {
			path = args[1] + ".pem"
		}
		if path == "" {
			logf(true, "No user config directory; name the key: IAPTool genkey <name>")
		}
		_, err := generateSigningKey(path)
		logf(err, "Failed to generate signing key")

	case "pubkey":
		// The one form a root holder can act on: "cert <leafPubHex>" takes
		// exactly these 128 characters, and so does comparing against what a
		// board answers to getpubkey.
		keyPath := findSigningKey()
		if len(args) >= 2 {
			keyPath = args[1]
		}
		if keyPath == "" {
			logf(true, "No signing key found. Pass one as an argument or as --key=<key.pem>, "+
				"or put one at %s", defaultKeyLocation())
		}
		key, err := loadSigningKey(keyPath)
		logf(err, "Failed to read %s", keyPath)
		fmt.Println(publicKeyHex(&key.PublicKey))

	case "cert":
		// cert [<leafPubHex>] -- issue a certificate with the signing key as
		// root. With no argument it self-signs (simple mode: the root
		// authorises its own key); with one it delegates to that leaf public
		// key. Prints the 256-hex-char certificate on stdout, which is
		// exactly what cdc/ether put on the wire.
		keyPath := findSigningKey()
		if keyPath == "" {
			logf(true, "No signing key found. Pass --key=<key.pem>, put one at %s, "+
				"or set \"signing_key\" in local_config.json", defaultKeyLocation())
		}
		leafPubHex := ""
		if len(args) >= 2 {
			leafPubHex = args[1]
		}
		certHex, err := issueLeafCert(keyPath, leafPubHex)
		logf(err, "Failed to issue certificate")
		fmt.Println(certHex)

	case "signraw":
		// signraw <hex> [<key.pem>] -- raw r||s signature over SHA-256(hex).
		// For the bootloader's owner-record chain, where the thing being
		// signed is a record prefix rather than a firmware image.
		if len(args) < 2 {
			logf(true, usageText)
		}
		keyPath := findSigningKey()
		if len(args) >= 3 {
			keyPath = args[2]
		}
		if keyPath == "" {
			logf(true, "No signing key found. Pass one as an argument or as --key=<key.pem>")
		}
		sig, err := signRawHex(args[1], keyPath)
		logf(err, "Failed to sign")
		fmt.Println(sig)

	case "getowner":
		if len(args) < 2 {
			logf(true, usageText)
		}
		RunGetOwner(args[1])

	case "getapprevoked":
		if len(args) < 2 {
			logf(true, usageText)
		}
		RunGetAppRevoked(args[1])

	case "log":
		if len(args) < 2 {
			logf(true, usageText)
		}
		RunReadLog(args[1])

	case "takeown":
		if len(args) < 2 {
			logf(true, usageText)
		}
		takeownKey := ""
		if g_signing.keyExplicit {
			takeownKey = g_signing.keyPath
		}
		RunTakeOwn(args[1], takeownKey)

	case "setowner":
		if len(args) < 2 {
			logf(true, usageText)
		}
		RunSetOwner(args[1], g_signing.currentKey, g_signing.newKey, g_signing.wipeOwner)

	case "revoke":
		if len(args) < 2 {
			logf(true, usageText)
		}
		revokeKey := g_signing.currentKey
		if revokeKey == "" && g_signing.keyExplicit {
			revokeKey = g_signing.keyPath
		}
		RunRevoke(args[1], revokeKey, g_signing.leaf)

	case ModeCDC:
		if len(args) < 3 {
			logf(true, usageText)
		}
		defer AcquireUploadLock()()
		RunCDC(args[2], args[1])

	case ModeEther:
		if len(args) < 3 {
			logf(true, usageText)
		}
		defer AcquireUploadLock()()
		RunEtherUpgrade(args[1], args[2])

	case ModeFlashBoot:
		if len(args) < 3 {
			logf(true, usageText)
		}
		defer AcquireUploadLock()()
		RunEtherFlashBoot(args[1], args[2])

	default:
		logf(true, "Invalid mode: %s. Use 'cdc', 'ether', 'flashboot', 'sign', 'genkey', "+
			"'pubkey', 'cert', 'signraw', 'getowner', 'getapprevoked', 'log', 'takeown', "+
			"'setowner' or 'revoke'", mode)
	}
}

// parseSigningFlags strips the --key / --cert / --out options out of the
// argument list and returns the remaining positional arguments. Both
// "--key=path" and "--key path" are accepted, in any position.
func parseSigningFlags(args []string) ([]string, error) {
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-v" {
			g_verbose = true
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			positional = append(positional, arg)
			continue
		}

		name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")

		// Boolean flag: it takes no value, so it must not swallow the next
		// argument the way the value-taking options below do.
		if name == "force" {
			g_forceFlash = true
			continue
		}
		if name == "verbose" {
			g_verbose = true
			continue
		}
		if name == "wipe" {
			g_signing.wipeOwner = true
			continue
		}

		if !hasValue {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("option --%s needs a value", name)
			}
			i++
			value = args[i]
		}

		switch name {
		case "key":
			g_signing.keyPath = value
			g_signing.keyExplicit = true
		case "cert":
			g_signing.certPath = value
		case "out":
			g_signing.outPrefix = value
		case "current-key":
			g_signing.currentKey = value
		case "new-key":
			g_signing.newKey = value
		case "leaf":
			g_signing.leaf = value
		default:
			return nil, fmt.Errorf("unknown option --%s", name)
		}
	}

	return positional, nil
}

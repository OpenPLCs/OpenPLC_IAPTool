# IAPTranfer_Tool
For OpenPLC transfer bin file

中文：[README.zh-CN.md](README.zh-CN.md)

## Building from source

`IAPTool` signs and uploads firmware. It needs only Go 1.23 or newer; the first
build downloads its modules, so it needs network access. Run from the
repository root:

```
go build -o IAPTool .                     # for this machine
```

On Windows name the output `IAPTool.exe`. To build for another system, set
`GOOS` / `GOARCH` (no C compiler needed), e.g.
`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o IAPTool .`

`build.py` (double-click `build.cmd` on Windows) is the maintainers' release
script: it builds Windows and Linux (amd64) and macOS (amd64 + arm64, behind a launcher
named `IAPTool` that picks by CPU) and copies them into the installed Arduino
board package. It is not needed to build IAPTool.

Tests: `python tests/selfcheck.py` (Go and Python 3 only).

## Usage

```
IAPTool cdc    <file.bin> <port>       [--key=<key.pem>] [--cert=<cert.txt>]
IAPTool ether  <file.bin> <ip>         [--key=<key.pem>] [--cert=<cert.txt>]
IAPTool flashboot <boot.bin> <ip>      --key=<owner.pem>
IAPTool sign   <file.bin> [<key.pem>]  [--key=<key.pem>] [--out=<prefix>]
IAPTool genkey [<name>]
IAPTool pubkey [<key.pem>]
IAPTool cert   [<leafPubHex>]          [--key=<root.pem>]

IAPTool getowner <ip>
IAPTool takeown  <ip> --key=<owner.pem>
IAPTool setowner <ip> --current-key=<owner.pem> --new-key=<next.pem>

IAPTool log      <ip>
```

`log` prints the board's boot log over Ethernet (bootloader and system lines,
kept across resets, lost on power-off), oldest first, as `<seq> <text>`. The
bootloader and the application both answer.

An upload (`cdc`, `ether`, `flashboot`) prints the target, a progress bar and the board's verdict; `-v` logs every step. A refused image exits 1.

## Firmware signing

The bootloader only executes an image whose ECDSA P-256 signature verifies
against the `fw_public_key[64]` baked into it (`IAPServer/fw_pubkey.c`), so
every image has to be signed before it can be flashed. Signing is built in
here -- no `openssl`, no shell scripts, nothing to `chmod +x`.

```sh
# Nothing is written to disk; the image is signed in memory and sent straight
# to the device.
IAPTool cdc app.bin COM5 --key=fw_signing_key.pem
```

`sign` writes `<name>.sha256`, `<name>.size` and `<name>.sig` (raw 64-byte
r||s) for anyone who needs the signature as a file, but uploading does not use
them: the upload also has to sign a fresh challenge from the board, which needs
the private key itself.

The tool does not track firmware versions and does not compare them. An image
that verifies against the key the board trusts is flashed, whatever it
contains -- versioning an application is the author's business.

### Where the key comes from

Resolution order:

1. `--key=<path>` on the command line
2. `"signing_key"` in `local_config.json` (write an absolute path)
3. `<user config dir>/openplc/keys/fw_signing_key.pem` (`os.UserConfigDir()`;
   `%AppData%` on Windows) -- survives tool package upgrades
4. `keys/fw_signing_key.pem` next to the executable

The Arduino IDE passes no key, so steps 3-4 are what it relies on. On a board
with no root (a factory board) an upload claims it first: with no key found,
one is generated at step 3's path, and the path is printed.
`local_config.json` and `keys/` are looked up relative to the **executable**,
not the current directory.

## Uploading without the root key

One person with one key needs nothing below: their key is the root, it
certifies itself, and everything already works.

A team where one administrator holds the root does need it. Each colleague
keeps their own key; the administrator issues a certificate saying that key is
authorised, and the root private key never leaves the administrator's machine.

```sh
# On the colleague's machine
IAPTool genkey fw_signing_key               # their own key; move it to step 3 above
IAPTool pubkey                              # 128 hex characters -- send these

# On the administrator's machine
IAPTool cert <those 128 hex characters> --key=root.pem > colleague.cert

# Back on the colleague's machine: save it beside the key it covers
#   <user config dir>/openplc/keys/fw_signing_key.pem.cert
IAPTool ether app.bin 192.168.1.50           # nothing else changes
```

A certificate lives at `<the key it covers>.cert`, so a key and its
certificate cannot be paired up wrongly, and the Arduino IDE finds it with no
configuration for the same reason it finds the key. `--cert=<file>` overrides.

Revoking one colleague is `IAPTool revoke --leaf=<their pubkey>`: that leaf is
refused from its next upload on, while firmware it already installed keeps
running (`IAPTool getapprevoked` finds those boards). Handing the board to a new
root (`IAPTool setowner`) retires every certificate the old root issued,
including on firmware already installed. See
`OpenPLC_Docs/docs/modules/M2-ownership.md`.

### Mismatch is caught before the transfer

Before sending anything, the tool asks the bootloader (`getpubkey`) which root
it verifies against, and checks that the certificate it is about to present was
issued by that root. For a self-signed certificate this is the same question as
"is my key the board's key", so there is one check rather than two paths.

A mismatch stops the upload immediately with both fingerprints printed,
instead of transferring the whole image and having the board reject it at the
end. A bootloader too old to know `getpubkey` answers `Unknown command`; the
check is then skipped with a warning and the upload proceeds as before.

### Generating keys

```sh
IAPTool genkey                  # the default key, path printed
IAPTool genkey my_release_key   # my_release_key.pem in the current directory
```

`genkey` writes the private key (mode 0600), never overwrites an existing one,
and prints its path and public key. No key is compiled into the firmware:
changing the root is `setowner`, and the bootloader is never rebuilt for it.
Keep the private key offline; it never goes on a device. On a new computer,
copy it into the default location.

Keys are interchangeable with `openssl` in both directions -- `genkey` emits
standard SEC1 PEM, and `sign` accepts SEC1 or PKCS#8.

## Board ownership

A board leaves the factory with no root: it runs nothing and accepts nothing
until it is claimed. The first `cdc` or `ether` upload claims it for this
computer's key (generating one if there is none), then uploads. From then on
nothing else will start. `<board>` below is an IP address or a USB port.

```sh
IAPTool getowner <board>             # which key does this board trust?
IAPTool takeown  <board> --key=owner.pem       # what the first upload does
IAPTool setowner <board> --current-key=owner.pem --new-key=next.pem
```

`getowner` and `getapprevoked` also work on a board running its application,
over Ethernet (UDP), without restarting it. Over USB, and for `takeown`,
`setowner` and `revoke`, the board has to be in its bootloader.

## Replacing the bootloader

`flashboot` writes a new bootloader into sector 0 without an ST-Link. The
owner records live in sector 15, so the board stays claimed.

```sh
IAPTool flashboot boot.bin 192.168.0.30 --key=owner.pem
```

The key has to be the owner root itself: the board checks a bootloader image
against the root, not against a leaf certificate. A board with no root refuses
`flashboot`; claim it first.

**Do not cut power during it.** The board is running out of the sector being
rewritten; an interruption leaves it unable to boot, and only an ST-Link gets
it back.

`takeown` is accepted only while the board has no root, over USB or
Ethernet, no button. Until the first claim, whoever reaches the board first
claims it; a factory reset (hold BOOT0 for ten seconds after reset) puts the
board back to no root.

`setowner` needs no button. It is signed by the key the board trusts today, so
a handover can be done over the network, and a stolen record cannot take a
board over -- the board checks the signature, not the generation number.

## Reclaiming revocation slots

The owner area holds 96 revocations and only ever appends, so the only way to
get slots back is to erase the flash sector they live in. The boot log starts
saying so with 8 left.

```sh
IAPTool setowner 192.168.0.30 --current-key=owner.pem --new-key=next.pem --wipe
```

`--wipe` hands the board over AND leaves the area holding nothing but the new
record. The board rewrites sector 15 to do it (never the bootloader), keeping
a copy in battery-backed SRAM while the sector is erased. The board never
decides to wipe on its own.

Changing the root *without* `--wipe` retires every leaf the old root issued,
so they no longer need revoking one by one -- but it does not free the slots
those revocations already occupy.

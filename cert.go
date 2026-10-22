package main

// Leaf certificate issuance for the command paths. The format and the crypto
// live in iapcert/ so the test cases import the same code the tool ships with.

import (
	"IAPTool/iapcert"
)

// issueLeafCert issues a certificate with the signing key at rootKeyPath as
// root, self-signed when leafPubHex is empty.
func issueLeafCert(rootKeyPath string, leafPubHex string) (string, error) {
	return iapcert.Issue(rootKeyPath, leafPubHex)
}

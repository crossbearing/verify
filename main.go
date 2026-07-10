// Command verify checks a crossbearing Agent Evidence Package (aep/1):
// the findings hash chain always, and the detached ECDSA signature when a
// public key is supplied. Fully offline — no AWS access, no network, no
// dependencies beyond the Go standard library.
//
// Usage:
//
//	verify <package.json> --public-key <key.pem|key.b64>
//	verify <package.json> --chain-only
//
// The public key is the signing key's public half, as PEM or as the raw
// base64 DER printed by:
//
//	aws kms get-public-key --key-id <arn> --query PublicKey --output text
//
// Exit codes: 0 every requested check passed; 1 verification failed or a
// present signature went unchecked without --chain-only; 2 usage error.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"os"

	"github.com/crossbearing/verify/aep"
)

func main() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyPath := fs.String("public-key", "", "signing key public half (PEM, or base64 DER from `aws kms get-public-key`)")
	chainOnly := fs.Bool("chain-only", false, "verify the hash chain only; accept an unchecked signature")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: verify <package.json> [--public-key <pem|b64>] [--chain-only]")
		fs.PrintDefaults()
	}

	args := os.Args[1:]
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	doc, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(2)
	}
	_ = fs.Parse(args[1:])

	var pub *ecdsa.PublicKey
	if *keyPath != "" {
		material, err := os.ReadFile(*keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(2)
		}
		if pub, err = aep.ParsePublicKey(material); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(2)
		}
	}

	res, err := aep.Verify(doc, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("chain      OK — %d findings re-derive from genesis to head\n", res.Links)
	switch {
	case res.SigOK:
		fmt.Printf("signature  OK — ECDSA verified against %s\n", res.KeyRef)
	case res.Signed && *chainOnly:
		fmt.Printf("signature  PRESENT, not checked (--chain-only) — key ref %s\n", res.KeyRef)
	case res.Signed:
		fmt.Fprintf(os.Stderr, "verify: FAILED: package is signed (%s) but no --public-key was given; pass the key or --chain-only\n", res.KeyRef)
		os.Exit(1)
	default:
		fmt.Printf("signature  ABSENT — package is explicitly unsigned\n")
	}
}

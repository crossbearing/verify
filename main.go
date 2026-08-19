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
// Flags may appear before or after the package path.
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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/crossbearing/verify/aep"
)

// maxDocumentBytes bounds what this tool will read into memory. An aep/1
// package is a findings document, not a data set — the sample packages run to
// a few kilobytes and a large real one to a few megabytes — so anything past
// this is a mistake or a hostile input, and refusing it by size beats
// discovering it by exhausting memory. The aep package parses from a byte
// slice, so the whole document is resident during verification; that is what
// makes the ceiling worth having rather than streaming.
const maxDocumentBytes = 64 << 20 // 64 MiB

const (
	exitOK      = 0
	exitFailed  = 1
	exitUsage   = 2
	usageString = "usage: verify <package.json> [--public-key <pem|b64>] [--chain-only]"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run holds the whole command so its decisions — above all the fail-closed
// exit when a signature is present but unchecked — are reachable from tests
// rather than only from a shell.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("public-key", "", "signing key public half (PEM, or base64 DER from `aws kms get-public-key`)")
	chainOnly := fs.Bool("chain-only", false, "verify the hash chain only; accept an unchecked signature")
	fs.Usage = func() {
		fmt.Fprintln(stderr, usageString)
		fs.PrintDefaults()
	}

	docPath, err := parseArgs(fs, args)
	switch {
	case err == nil:
		// fall through to verification
	case errors.Is(err, flag.ErrHelp):
		// -h and --help are a request, not a mistake, and the FlagSet has
		// already printed the usage they asked for.
		return exitOK
	case errors.Is(err, errFlagReported):
		// The FlagSet printed both the complaint and the usage block; saying
		// it again would only make the real message harder to find.
		return exitUsage
	default:
		fmt.Fprintln(stderr, "verify:", err)
		fs.Usage()
		return exitUsage
	}

	doc, err := readBounded(docPath)
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return exitUsage
	}

	var pub *ecdsa.PublicKey
	if *keyPath != "" {
		material, err := readBounded(*keyPath)
		if err != nil {
			fmt.Fprintln(stderr, "verify:", err)
			return exitUsage
		}
		if pub, err = aep.ParsePublicKey(material); err != nil {
			fmt.Fprintln(stderr, "verify:", err)
			return exitUsage
		}
	}

	res, err := aep.Verify(doc, pub)
	if err != nil {
		fmt.Fprintf(stderr, "verify: FAILED: %v\n", err)
		return exitFailed
	}

	fmt.Fprintf(stdout, "chain      OK — %d findings re-derive from genesis to head\n", res.Links)
	switch {
	case res.SigOK:
		fmt.Fprintf(stdout, "signature  OK — ECDSA verified against %s\n", res.KeyRef)
	case res.Signed && *chainOnly:
		fmt.Fprintf(stdout, "signature  PRESENT, not checked (--chain-only) — key ref %s\n", res.KeyRef)
	case res.Signed:
		fmt.Fprintf(stderr, "verify: FAILED: package is signed (%s) but no --public-key was given; pass the key or --chain-only\n", res.KeyRef)
		return exitFailed
	default:
		fmt.Fprintf(stdout, "signature  ABSENT — package is explicitly unsigned\n")
	}
	return exitOK
}

// errFlagReported marks a parse failure the FlagSet has already printed, so
// the caller does not report it twice.
var errFlagReported = errors.New("flag parse error")

// classifyParseError keeps flag.ErrHelp distinguishable from a real failure.
// Both have already been reported by the FlagSet, but one of them is a request
// the user made deliberately and must not be answered with a failing exit code.
func classifyParseError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return errFlagReported
}

// parseArgs accepts the package path before or after the flags.
//
// Go's flag package stops at the first non-flag argument, so a single Parse
// handles `verify --chain-only pkg.json` but silently ignores the flags in
// `verify pkg.json --chain-only` — the documented form. Parsing twice covers
// both: the first pass consumes any leading flags, and if a positional is
// followed by more arguments, they are the trailing flags and get their own
// pass.
func parseArgs(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("no package given")
	}
	if err := fs.Parse(args); err != nil {
		return "", classifyParseError(err)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return "", errors.New("no package given")
	}
	docPath := rest[0]
	if len(rest) > 1 {
		if err := fs.Parse(rest[1:]); err != nil {
			return "", classifyParseError(err)
		}
		if extra := fs.Args(); len(extra) > 0 {
			return "", fmt.Errorf("unexpected extra argument %q (one package at a time)", extra[0])
		}
	}
	return docPath, nil
}

// readBounded reads a file, refusing anything larger than maxDocumentBytes
// instead of taking it into memory unbounded.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// One byte past the ceiling distinguishes "exactly at the limit" from
	// "over it" without reading the remainder of an oversized file.
	b, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDocumentBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes; an aep/1 package is a findings document, not a data set", path, maxDocumentBytes)
	}
	return b, nil
}

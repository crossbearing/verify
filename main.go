// Command verify checks a crossbearing Agent Evidence Package (aep/1):
// the findings hash chain always, and the detached ECDSA signature when a
// public key is supplied. Fully offline — no AWS access, no network, no
// dependencies beyond the Go standard library.
//
// Usage:
//
//	verify <package.json> --public-key <key.pem|key.b64>
//	verify <package.json> --chain-only
//	verify <package.json> --public-key <key> --json
//
// Flags may appear before or after the package path.
//
// Output is prose by default, because a human runs this. --json writes the
// result of schema/verify-result-1.schema.json to stdout instead, and nothing
// else, so it can be piped without filtering; diagnostics stay on stderr in
// both modes. The exit code is identical either way.
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
	"encoding/json"
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
	usageString = "usage: verify <package.json> [--public-key <pem|b64>] [--chain-only] [--json]"
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
	asJSON := fs.Bool("json", false, "write the machine-readable result to stdout instead of prose")
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

	res, verifyErr := aep.Verify(doc, pub)
	out := describe(res, verifyErr, *chainOnly)

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out.report); err != nil {
			fmt.Fprintln(stderr, "verify:", err)
			return exitFailed
		}
	} else {
		for _, line := range out.prose {
			fmt.Fprintln(stdout, line)
		}
	}
	for _, line := range out.diagnostics {
		fmt.Fprintln(stderr, line)
	}
	return out.code
}

// outcome is one verification rendered three ways that must agree: the exit
// code, the machine-readable report, and the prose. They are produced together
// so no output mode can be changed without the others being looked at.
type outcome struct {
	report      aep.Report
	code        int
	prose       []string // stdout, prose mode only
	diagnostics []string // stderr, both modes
}

// describe decides what happened. It is the single place the fail-closed rule
// lives: a package carrying a signature nobody checked is a failure unless the
// caller explicitly accepted that with --chain-only.
func describe(res aep.Result, verifyErr error, acceptUnchecked bool) outcome {
	report := aep.Report{
		Chain:     aep.ChainReport{Verified: res.ChainOK, Links: res.Links},
		Signature: aep.SignatureReport{State: aep.SignatureState(res), KeyRef: res.KeyRef},
	}

	if verifyErr != nil {
		report.Error = verifyErr.Error()
		return outcome{
			report:      report,
			code:        exitFailed,
			diagnostics: []string{fmt.Sprintf("verify: FAILED: %v", verifyErr)},
		}
	}

	prose := []string{fmt.Sprintf("chain      OK — %d findings re-derive from genesis to head", res.Links)}

	switch {
	case res.SigOK:
		prose = append(prose, fmt.Sprintf("signature  OK — ECDSA verified against %s", res.KeyRef))
	case res.Signed && acceptUnchecked:
		prose = append(prose, fmt.Sprintf("signature  PRESENT, not checked (--chain-only) — key ref %s", res.KeyRef))
	case res.Signed:
		report.Error = fmt.Sprintf("package is signed (%s) but no --public-key was given; pass the key or --chain-only", res.KeyRef)
		return outcome{
			report:      report,
			code:        exitFailed,
			prose:       prose,
			diagnostics: []string{"verify: FAILED: " + report.Error},
		}
	default:
		prose = append(prose, "signature  ABSENT — package is explicitly unsigned")
	}

	report.Verified = true
	return outcome{report: report, code: exitOK, prose: prose}
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

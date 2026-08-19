package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crossbearing/verify/aep"
)

const (
	signedFixture   = "aep/testdata/sample-signed.json"
	unsignedFixture = "aep/testdata/sample-unsigned.json"
	keyFixture      = "aep/testdata/public.pem"
)

// exec runs the command exactly as main does, returning what a shell would see.
func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// The fail-closed rule is the security-critical decision this command makes: a
// package that carries a signature nobody checked must not exit 0, because a
// caller scripting on the exit code would read that as verified.
func TestRun_FailsClosedOnUncheckedSignature(t *testing.T) {
	code, stdout, stderr := exec(t, signedFixture)

	if code != exitFailed {
		t.Errorf("exit = %d, want %d — an unchecked signature must not report success", code, exitFailed)
	}
	if !strings.Contains(stderr, "package is signed") || !strings.Contains(stderr, "--chain-only") {
		t.Errorf("stderr = %q, want an explanation naming the remedy", stderr)
	}
	// The chain genuinely did verify, and saying so is not the same as saying
	// the package verified.
	if !strings.Contains(stdout, "chain      OK") {
		t.Errorf("stdout = %q, want the chain result still reported", stdout)
	}
	if strings.Contains(stdout, "signature  OK") {
		t.Error("reported a signature as OK that was never checked")
	}
}

func TestRun_AcceptsUncheckedSignatureOnlyWhenAsked(t *testing.T) {
	code, stdout, stderr := exec(t, signedFixture, "--chain-only")

	if code != exitOK {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "PRESENT, not checked") {
		t.Errorf("stdout = %q, want the signature reported as present but unchecked", stdout)
	}
	if !strings.Contains(stdout, "fixture:local-test-key") {
		t.Errorf("stdout = %q, want the key ref named so the reader knows what went unchecked", stdout)
	}
}

func TestRun_FullVerification(t *testing.T) {
	code, stdout, stderr := exec(t, signedFixture, "--public-key", keyFixture)

	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "chain      OK") || !strings.Contains(stdout, "signature  OK") {
		t.Errorf("stdout = %q, want both checks reported", stdout)
	}
}

func TestRun_UnsignedPackageIsNotAFailure(t *testing.T) {
	code, stdout, _ := exec(t, unsignedFixture)

	if code != exitOK {
		t.Errorf("exit = %d, want %d — an explicitly unsigned package is well-formed", code, exitOK)
	}
	if !strings.Contains(stdout, "signature  ABSENT") {
		t.Errorf("stdout = %q, want the absence stated rather than implied", stdout)
	}
}

// The package path is accepted before or after the flags. The positional-first
// form is what the README documents; the flags-first form is what decades of
// Unix habit produces, and it used to fail claiming the flag was a missing file.
func TestRun_AcceptsFlagsEitherSideOfThePath(t *testing.T) {
	orderings := [][]string{
		{signedFixture, "--chain-only"},
		{"--chain-only", signedFixture},
		{signedFixture, "--public-key", keyFixture},
		{"--public-key", keyFixture, signedFixture},
		{"--chain-only", signedFixture, "--public-key", keyFixture},
	}
	for _, args := range orderings {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, stdout, stderr := exec(t, args...)
			if code != exitOK {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr)
			}
			if !strings.Contains(stdout, "chain      OK") {
				t.Errorf("stdout = %q", stdout)
			}
		})
	}
}

func TestRun_UsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "usage:"},
		{"only flags, no package", []string{"--chain-only"}, "usage:"},
		{"unknown flag after the path", []string{signedFixture, "--nope"}, "usage:"},
		{"unknown flag before the path", []string{"--nope", signedFixture}, "usage:"},
		{"missing package file", []string{"no/such/package.json"}, "no such file"},
		{"missing key file", []string{signedFixture, "--public-key", "no/such/key.pem"}, "no such file"},
		{"second package path", []string{signedFixture, unsignedFixture}, "unexpected extra argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := exec(t, tt.args...)
			if code != exitUsage {
				t.Errorf("exit = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr = %q, want containing %q", stderr, tt.want)
			}
		})
	}
}

func TestRun_VerificationFailureExitsOne(t *testing.T) {
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	doc, err := os.ReadFile(signedFixture)
	if err != nil {
		t.Fatal(err)
	}
	doc = bytes.Replace(doc, []byte("no claim accounts for it"), []byte("nothing to see here at all"), 1)
	if err := os.WriteFile(tampered, doc, 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := exec(t, tampered, "--public-key", keyFixture)
	if code != exitFailed {
		t.Errorf("exit = %d, want %d", code, exitFailed)
	}
	if !strings.Contains(stderr, "FAILED") || !strings.Contains(stderr, "digest mismatch") {
		t.Errorf("stderr = %q, want the specific failure named", stderr)
	}
}

func TestRun_RejectsUnusableKey(t *testing.T) {
	garbage := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(garbage, []byte("this is not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := exec(t, signedFixture, "--public-key", garbage)
	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "neither PEM nor base64 DER") {
		t.Errorf("stderr = %q", stderr)
	}
}

// A document past the ceiling is refused by size rather than taken into memory.
func TestReadBounded_RefusesOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: the file reports its full length without occupying it on disk.
	if err := f.Truncate(maxDocumentBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	if _, err := readBounded(path); err == nil {
		t.Fatal("oversized document accepted")
	} else if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v, want a size rejection", err)
	}
}

func TestReadBounded_AcceptsOrdinaryFiles(t *testing.T) {
	b, err := readBounded(signedFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("read nothing from a non-empty fixture")
	}
}

// os.Open succeeds on a directory; the failure surfaces at read time, so the
// error path after a successful open is real rather than defensive.
func TestReadBounded_PropagatesReadErrors(t *testing.T) {
	if _, err := readBounded(t.TempDir()); err == nil {
		t.Fatal("reading a directory as a document succeeded")
	}
}

// -h and --help are a request, not a mistake. The pre-refactor command answered
// them with exit 0 via flag.ExitOnError, and that has to survive the move to
// ContinueOnError — a help flag that exits non-zero breaks any script that runs
// `verify --help` to probe for the tool.
func TestRun_HelpExitsZero(t *testing.T) {
	for _, args := range [][]string{
		{"-h"},
		{"--help"},
		{signedFixture, "-h"},
		{signedFixture, "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, _, stderr := exec(t, args...)
			if code != exitOK {
				t.Errorf("exit = %d, want %d for a help request", code, exitOK)
			}
			if !strings.Contains(stderr, "usage:") {
				t.Errorf("stderr = %q, want the usage block", stderr)
			}
		})
	}
}

// The FlagSet prints its own complaint and usage block. Printing a second one
// buries the line that actually says what went wrong.
func TestRun_UsagePrintedOncePerFailure(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag before the path", []string{"--nope", signedFixture}},
		{"unknown flag after the path", []string{signedFixture, "--nope"}},
		{"no arguments", nil},
		{"second package path", []string{signedFixture, unsignedFixture}},
		{"help", []string{"-h"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, stderr := exec(t, tt.args...)
			if n := strings.Count(stderr, usageString); n != 1 {
				t.Errorf("usage block printed %d times, want exactly 1:\n%s", n, stderr)
			}
		})
	}
}

// scenarios covers every distinct outcome the command can reach. The mode
// tests below run the whole set through both output modes rather than
// spot-checking, because the regression this guards against is a path nobody
// exercised — the same shape as -h returning 2 after the ContinueOnError move.
func scenarios(t *testing.T) []struct {
	name string
	args []string
} {
	t.Helper()

	tampered := filepath.Join(t.TempDir(), "tampered.json")
	doc, err := os.ReadFile(signedFixture)
	if err != nil {
		t.Fatal(err)
	}
	doc = bytes.Replace(doc, []byte("no claim accounts for it"), []byte("nothing to see here at all"), 1)
	if err := os.WriteFile(tampered, doc, 0o600); err != nil {
		t.Fatal(err)
	}

	return []struct {
		name string
		args []string
	}{
		{"signed and fully verified", []string{signedFixture, "--public-key", keyFixture}},
		{"signed, unchecked, accepted", []string{signedFixture, "--chain-only"}},
		{"signed, unchecked, refused", []string{signedFixture}},
		{"explicitly unsigned", []string{unsignedFixture}},
		{"tampered content", []string{tampered, "--public-key", keyFixture}},
		{"tampered, chain-only", []string{tampered, "--chain-only"}},
	}
}

// The exit code is the contract a script reads. Adding an output mode must not
// change it for any input — a --json run that exits differently from the prose
// run would make the flag load-bearing for correctness rather than presentation.
func TestRun_ExitCodeIsIdenticalInBothModes(t *testing.T) {
	for _, tt := range scenarios(t) {
		t.Run(tt.name, func(t *testing.T) {
			proseCode, _, _ := exec(t, tt.args...)
			jsonCode, _, _ := exec(t, append(append([]string{}, tt.args...), "--json")...)
			if proseCode != jsonCode {
				t.Fatalf("exit differs by output mode: prose=%d json=%d", proseCode, jsonCode)
			}
		})
	}
}

// The machine-readable verdict and the exit code are the same decision rendered
// twice. A document reporting success beside a failing exit code would be this
// repository's own thesis violated inside its own verifier.
func TestRun_JSONVerdictAgreesWithExitCode(t *testing.T) {
	for _, tt := range scenarios(t) {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, _ := exec(t, append(append([]string{}, tt.args...), "--json")...)

			var report aep.Report
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("stdout is not the published result document: %v\nstdout: %s", err, stdout)
			}
			if report.Verified != (code == exitOK) {
				t.Fatalf("verified=%v but exit=%d — the verdict and the exit code disagree\n%s",
					report.Verified, code, stdout)
			}
			// A failure must say why; a success must not carry an error.
			if report.Verified && report.Error != "" {
				t.Errorf("successful result carries an error: %q", report.Error)
			}
			if !report.Verified && report.Error == "" {
				t.Error("failed result gives no reason")
			}
		})
	}
}

// stdout must carry the result document and nothing else, so it can be piped
// without filtering. Diagnostics belong on stderr in both modes.
func TestRun_JSONStdoutIsOnlyTheDocument(t *testing.T) {
	for _, tt := range scenarios(t) {
		t.Run(tt.name, func(t *testing.T) {
			_, stdout, _ := exec(t, append(append([]string{}, tt.args...), "--json")...)
			var any map[string]any
			if err := json.Unmarshal([]byte(stdout), &any); err != nil {
				t.Fatalf("stdout is not a single JSON document: %v\nstdout: %s", err, stdout)
			}
			if strings.Contains(stdout, "chain      OK") || strings.Contains(stdout, "verify: FAILED") {
				t.Errorf("prose leaked into the JSON stream:\n%s", stdout)
			}
		})
	}
}

// Prose stays the default: a human running this should not need `| jq`.
func TestRun_ProseIsTheDefault(t *testing.T) {
	_, stdout, _ := exec(t, signedFixture, "--public-key", keyFixture)
	if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Fatalf("default output is JSON, want prose:\n%s", stdout)
	}
	if !strings.Contains(stdout, "chain      OK") {
		t.Fatalf("default output is not the prose form:\n%s", stdout)
	}
}

// The reported signature state must distinguish the three cases a consumer
// needs to tell apart, including the two that both exit non-zero.
func TestRun_JSONSignatureStates(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		state string
	}{
		{"verified", []string{signedFixture, "--public-key", keyFixture}, aep.SignatureVerified},
		{"unchecked but accepted", []string{signedFixture, "--chain-only"}, aep.SignatureUnchecked},
		{"unchecked and refused", []string{signedFixture}, aep.SignatureUnchecked},
		{"absent", []string{unsignedFixture}, aep.SignatureAbsent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stdout, _ := exec(t, append(append([]string{}, tt.args...), "--json")...)
			var report aep.Report
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatal(err)
			}
			if report.Signature.State != tt.state {
				t.Errorf("signature.state = %q, want %q", report.Signature.State, tt.state)
			}
		})
	}
}

// failingWriter stands in for a closed pipe: `verify --json | head -1` closes
// stdout while the encoder is still writing, and a tool that reported success
// after failing to deliver its result would be lying about the delivery.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRun_JSONReportsAFailureToWriteTheResult(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{signedFixture, "--public-key", keyFixture, "--json"}, failingWriter{}, &stderr)

	if code == exitOK {
		t.Errorf("exit = %d, want non-zero when the result could not be written", code)
	}
	if !strings.Contains(stderr.String(), "broken pipe") {
		t.Errorf("stderr = %q, want the write failure reported", stderr.String())
	}
}

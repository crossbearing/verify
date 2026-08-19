package aep

import (
	"encoding/json"
	"strings"
	"testing"
)

const resultSchema = "../schema/verify-result-1.schema.json"

// Every outcome the verifier can reach must marshal to a document the published
// result schema accepts. A schema that only covers the happy path would let a
// consumer's parser break on precisely the failures it most needs to read.
func TestReport_EveryOutcomeSatisfiesThePublishedSchema(t *testing.T) {
	tests := []struct {
		name   string
		report Report
	}{
		{
			name: "unsigned package, chain verified",
			report: Report{
				Verified:  true,
				Chain:     ChainReport{Verified: true, Links: 3},
				Signature: SignatureReport{State: SignatureAbsent},
			},
		},
		{
			name: "signed and verified",
			report: Report{
				Verified:  true,
				Chain:     ChainReport{Verified: true, Links: 3},
				Signature: SignatureReport{State: SignatureVerified, KeyRef: "fixture:local-test-key"},
			},
		},
		{
			name: "signature present but deliberately unchecked",
			report: Report{
				Verified:  true,
				Chain:     ChainReport{Verified: true, Links: 3},
				Signature: SignatureReport{State: SignatureUnchecked, KeyRef: "fixture:local-test-key"},
			},
		},
		{
			name: "signed, unchecked, and that is a failure",
			report: Report{
				Verified:  false,
				Chain:     ChainReport{Verified: true, Links: 3},
				Signature: SignatureReport{State: SignatureUnchecked, KeyRef: "fixture:local-test-key"},
				Error:     "package is signed (fixture:local-test-key) but no --public-key was given",
			},
		},
		{
			name: "chain failed before the signature was reached",
			report: Report{
				Verified:  false,
				Chain:     ChainReport{Verified: false, Links: 0},
				Signature: SignatureReport{State: SignatureUnchecked, KeyRef: "fixture:local-test-key"},
				Error:     "finding 1: digest mismatch (content edited)",
			},
		},
		{
			name: "empty package",
			report: Report{
				Verified:  true,
				Chain:     ChainReport{Verified: true, Links: 0},
				Signature: SignatureReport{State: SignatureAbsent},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := json.Marshal(tt.report)
			if err != nil {
				t.Fatal(err)
			}
			if problems := validateAgainstSchema(t, resultSchema, doc); len(problems) > 0 {
				t.Fatalf("a reachable outcome does not satisfy the published schema:\n  %s\n  document: %s",
					strings.Join(problems, "\n  "), doc)
			}
		})
	}
}

// The schema must reject a state outside the published set, or the enum is
// decoration. This is the negative half of the test above: without it, a
// checker that ignored "enum" would still pass everything.
func TestReport_SchemaRejectsAnUnpublishedSignatureState(t *testing.T) {
	doc := []byte(`{"verified":true,"chain":{"verified":true,"links":1},"signature":{"state":"probably-fine"}}`)
	problems := validateAgainstSchema(t, resultSchema, doc)
	if len(problems) == 0 {
		t.Fatal("schema accepted a signature state it does not publish")
	}
	if !strings.Contains(strings.Join(problems, "\n"), "want one of") {
		t.Fatalf("problems = %v, want an enum rejection", problems)
	}
}

func TestReport_SchemaRequiresTheVerdict(t *testing.T) {
	// Dropping "verified" must fail: it is the member a consumer branches on,
	// and its absence would read as false to a naive parser.
	doc := []byte(`{"chain":{"verified":true,"links":1},"signature":{"state":"absent"}}`)
	if problems := validateAgainstSchema(t, resultSchema, doc); len(problems) == 0 {
		t.Fatal("schema accepted a result with no verdict")
	}
}

// KeyRef is omitted rather than emitted empty when there is no signature, so a
// consumer cannot mistake "" for a key reference that happens to be blank.
func TestReport_OmitsKeyRefWhenThereIsNoSignature(t *testing.T) {
	doc, err := json.Marshal(Report{
		Verified:  true,
		Chain:     ChainReport{Verified: true, Links: 1},
		Signature: SignatureReport{State: SignatureAbsent},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "keyRef") {
		t.Errorf("unsigned result carries a keyRef member: %s", doc)
	}
	if strings.Contains(string(doc), `"error"`) {
		t.Errorf("successful result carries an error member: %s", doc)
	}
}

func TestSignatureState_CoversEveryResultShape(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want string
	}{
		{"no signature", Result{}, SignatureAbsent},
		{"present, unchecked", Result{Signed: true}, SignatureUnchecked},
		{"present and verified", Result{Signed: true, SigOK: true}, SignatureVerified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SignatureState(tt.res); got != tt.want {
				t.Errorf("SignatureState = %q, want %q", got, tt.want)
			}
		})
	}
}

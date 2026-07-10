package aep

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The fixtures were produced by the real crossbearing engine (and a
// throwaway local ECDSA key), so these tests hold this verifier honest
// against actual producer bytes — not against this package's own
// assumptions about them.

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerify_SignedFixture(t *testing.T) {
	doc := load(t, "sample-signed.json")
	pub, err := ParsePublicKey(load(t, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}

	res, err := Verify(doc, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.ChainOK || res.Links != 3 {
		t.Errorf("chain: ok=%v links=%d, want ok with 3 links", res.ChainOK, res.Links)
	}
	if !res.Signed || !res.SigOK {
		t.Errorf("signature: signed=%v ok=%v, want both", res.Signed, res.SigOK)
	}
	if res.KeyRef != "fixture:local-test-key" {
		t.Errorf("KeyRef = %q", res.KeyRef)
	}
}

func TestVerify_UnsignedFixture(t *testing.T) {
	res, err := Verify(load(t, "sample-unsigned.json"), nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.ChainOK || res.Signed || res.SigOK {
		t.Errorf("unsigned fixture: %+v", res)
	}
}

func TestVerify_ChainOnlyWithoutKey(t *testing.T) {
	res, err := Verify(load(t, "sample-signed.json"), nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.ChainOK || !res.Signed || res.SigOK {
		t.Errorf("chain-only on signed doc: %+v (SigOK must stay false when unchecked)", res)
	}
}

// Tampering is done textually — byte surgery on the document — so the
// test cannot accidentally re-canonicalize what it claims to corrupt.
func TestVerify_TamperDetection(t *testing.T) {
	doc := load(t, "sample-signed.json")
	pub, _ := ParsePublicKey(load(t, "public.pem"))

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr string
	}{
		{
			name: "finding content edited",
			mutate: func(d []byte) []byte {
				return bytes.Replace(d, []byte("no claim accounts for it"), []byte("totally fine, nothing to see"), 1)
			},
			wantErr: "digest mismatch",
		},
		{
			name: "window transplanted",
			mutate: func(d []byte) []byte {
				return bytes.Replace(d, []byte(`"from": "2026-06-10T02:00:00Z"`), []byte(`"from": "2026-06-09T02:00:00Z"`), 1)
			},
			wantErr: "genesis mismatch",
		},
		{
			name: "signature swapped against payload",
			mutate: func(d []byte) []byte {
				// Edit a field the chain does not cover but the signature does.
				return bytes.Replace(d, []byte(`"generatedAt": "2026-06-10T06:00:00Z"`), []byte(`"generatedAt": "2026-06-10T07:00:00Z"`), 1)
			},
			wantErr: "signature INVALID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := tt.mutate(doc)
			if bytes.Equal(mutated, doc) {
				t.Fatal("mutation did not change the document; fixture text drifted")
			}
			_, err := Verify(mutated, pub)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerify_RejectsUnknownVersionAndAlgo(t *testing.T) {
	doc := load(t, "sample-signed.json")
	if _, err := Verify(bytes.Replace(doc, []byte(`"version": "aep/1"`), []byte(`"version": "aep/9"`), 1), nil); err == nil || !strings.Contains(err.Error(), "unsupported package version") {
		t.Errorf("version: %v", err)
	}
	if _, err := Verify(bytes.Replace(doc, []byte(`"algo": "sha256-hex-concat"`), []byte(`"algo": "md5"`), 1), nil); err == nil || !strings.Contains(err.Error(), "unsupported chain algorithm") {
		t.Errorf("algo: %v", err)
	}
}

func TestCanonicalPayload_StripsOnlySignature(t *testing.T) {
	signed := load(t, "sample-signed.json")
	unsigned := load(t, "sample-unsigned.json")

	p1, err := CanonicalPayload(signed)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := CanonicalPayload(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	// Same package, one signed one not: stripping the signature must make
	// the canonical bytes identical — the exact property the detached
	// signature design depends on.
	if !bytes.Equal(p1, p2) {
		t.Fatal("canonical payloads differ between signed and unsigned forms of the same package")
	}
	if bytes.Contains(p1, []byte(`"signature"`)) {
		t.Fatal("canonical payload still contains the signature member")
	}
}

func TestParsePublicKey_BothEncodings(t *testing.T) {
	pemBytes := load(t, "public.pem")
	k1, err := ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}

	// The base64-DER form is what `aws kms get-public-key` prints: strip
	// the PEM armor and feed the body straight in.
	var b64 []string
	for _, line := range strings.Split(string(pemBytes), "\n") {
		if !strings.HasPrefix(line, "-----") && line != "" {
			b64 = append(b64, line)
		}
	}
	k2, err := ParsePublicKey([]byte(strings.Join(b64, "")))
	if err != nil {
		t.Fatalf("base64 DER: %v", err)
	}
	if !k1.Equal(k2) {
		t.Fatal("PEM and base64-DER parses disagree")
	}

	if _, err := ParsePublicKey([]byte("not a key")); err == nil {
		t.Fatal("garbage accepted as a key")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	signed, _ := os.ReadFile("testdata/sample-signed.json")
	f.Add(signed)
	f.Add([]byte(`{"version":"aep/1","chain":{"algo":"sha256-hex-concat"}}`))
	f.Fuzz(func(t *testing.T, doc []byte) {
		_, _ = Verify(doc, nil) // must never panic on arbitrary input
	})
}

package aep

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

// buildDoc assembles a structurally valid aep/1 document with a correct chain,
// so a test can break exactly one property and watch that property fail. The
// fixtures above prove this verifier against real producer bytes; these built
// documents reach the branches a single fixture cannot.
func buildDoc(t *testing.T, findings ...string) []byte {
	t.Helper()
	const (
		window = `{"from":"2026-01-01T00:00:00Z","to":"2026-01-01T01:00:00Z","region":"us-west-2"}`
		policy = `{"window":"20m0s"}`
	)
	genesis, err := genesisHash(json.RawMessage(window), json.RawMessage(policy))
	if err != nil {
		t.Fatal(err)
	}
	prev := genesis
	links := make([]string, 0, len(findings))
	for i, f := range findings {
		canon, err := compact(json.RawMessage(f))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256Hex(canon)
		link := sha256Hex([]byte(prev + digest))
		links = append(links, fmt.Sprintf(`{"index":%d,"finding":%s,"digest":%q,"prev":%q,"link":%q}`, i, f, digest, prev, link))
		prev = link
	}
	return []byte(fmt.Sprintf(
		`{"version":"aep/1","window":%s,"policy":%s,"findings":[%s],"chain":{"algo":%q,"genesis":%q,"head":%q,"length":%d}}`,
		window, policy, strings.Join(links, ","), ChainAlgo, genesis, prev, len(findings)))
}

// A document that states the same member twice is refused outright. Go resolves
// duplicates last-wins and other readers take the first, so such a document
// verifies here and reads differently elsewhere — including under --chain-only,
// where no signature check exists to notice the disagreement.
func TestVerify_RejectsDuplicateTopLevelMembers(t *testing.T) {
	signed := load(t, "sample-signed.json")
	pub, err := ParsePublicKey(load(t, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}

	dup := func(member, injected string) []byte {
		i := bytes.Index(signed, []byte(`"`+member+`"`))
		if i < 0 {
			t.Fatalf("fixture has no %q member; fixture text drifted", member)
		}
		out := make([]byte, 0, len(signed)+len(injected))
		out = append(out, signed[:i]...)
		out = append(out, []byte(`"`+member+`": `+injected+`, `)...)
		return append(out, signed[i:]...)
	}

	tests := []struct {
		name   string
		doc    []byte
		key    *ecdsa.PublicKey
		member string
	}{
		{
			name:   "second signature member, key supplied",
			doc:    dup("signature", `{"Signature":"AAAA","KeyRef":"evil","Algo":"ECDSA_SHA_256"}`),
			key:    pub,
			member: "signature",
		},
		{
			// The load-bearing case: with no key there is no signature check to
			// catch the disagreement, so the chain path must reject it itself.
			name:   "second findings member, chain-only (no key)",
			doc:    dup("findings", `[]`),
			key:    nil,
			member: "findings",
		},
		{
			name:   "second version member, chain-only",
			doc:    dup("version", `"aep/9"`),
			key:    nil,
			member: "version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Verify(tt.doc, tt.key)
			if err == nil {
				t.Fatalf("duplicate %q accepted: %+v", tt.member, res)
			}
			if !strings.Contains(err.Error(), "duplicate top-level member") ||
				!strings.Contains(err.Error(), tt.member) {
				t.Fatalf("err = %v, want a duplicate-member rejection naming %q", err, tt.member)
			}
			if res.ChainOK || res.SigOK {
				t.Fatalf("refused document still reported checks as passed: %+v", res)
			}
		})
	}
}

// CanonicalPayload is exported for embedding, so it guards itself rather than
// trusting every caller to have gone through Parse first.
func TestCanonicalPayload_RejectsDuplicatesDirectly(t *testing.T) {
	doc := []byte(`{"a":1,"b":2,"a":3}`)
	if _, err := CanonicalPayload(doc); err == nil || !strings.Contains(err.Error(), `duplicate top-level member "a"`) {
		t.Fatalf("err = %v, want duplicate-member rejection", err)
	}
	if _, err := CanonicalPayload([]byte(`{"a":1,"b":2}`)); err != nil {
		t.Fatalf("distinct members rejected: %v", err)
	}
}

func TestCanonicalPayload_RejectsNonObjects(t *testing.T) {
	for _, doc := range []string{`[1,2,3]`, `"a string"`, ``, `{`} {
		if _, err := CanonicalPayload([]byte(doc)); err == nil {
			t.Errorf("CanonicalPayload(%q) accepted a non-object", doc)
		}
	}
}

// Each case breaks exactly one chain property; the error must name that
// property rather than failing generically somewhere downstream.
func TestVerifyChain_EveryInconsistency(t *testing.T) {
	valid := buildDoc(t, `{"id":"f1"}`, `{"id":"f2"}`)

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr string
	}{
		{
			name:    "index out of order",
			mutate:  func(d []byte) []byte { return bytes.Replace(d, []byte(`"index":1`), []byte(`"index":7`), 1) },
			wantErr: "index says 7",
		},
		{
			name:    "declared length disagrees with findings",
			mutate:  func(d []byte) []byte { return bytes.Replace(d, []byte(`"length":2`), []byte(`"length":3`), 1) },
			wantErr: "length mismatch",
		},
		{
			name: "head does not match the last link",
			mutate: func(d []byte) []byte {
				var p Package
				if err := json.Unmarshal(d, &p); err != nil {
					t.Fatal(err)
				}
				return bytes.Replace(d, []byte(`"head":"`+p.Chain.Head+`"`), []byte(`"head":"`+strings.Repeat("0", 64)+`"`), 1)
			},
			wantErr: "head mismatch",
		},
		{
			name: "prev link rewritten",
			mutate: func(d []byte) []byte {
				var p Package
				if err := json.Unmarshal(d, &p); err != nil {
					t.Fatal(err)
				}
				return bytes.Replace(d, []byte(`"prev":"`+p.Findings[1].Prev+`"`), []byte(`"prev":"`+strings.Repeat("1", 64)+`"`), 1)
			},
			wantErr: "prev-link mismatch",
		},
		{
			name: "link rewritten but prev left intact",
			mutate: func(d []byte) []byte {
				var p Package
				if err := json.Unmarshal(d, &p); err != nil {
					t.Fatal(err)
				}
				// Rewrite the final link only: prev still chains, so the failure
				// must surface as a link mismatch, not a prev mismatch.
				return bytes.Replace(d, []byte(`"link":"`+p.Findings[1].Link+`"`), []byte(`"link":"`+strings.Repeat("2", 64)+`"`), 1)
			},
			wantErr: "link mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := tt.mutate(valid)
			if bytes.Equal(mutated, valid) {
				t.Fatal("mutation changed nothing")
			}
			if _, err := Verify(mutated, nil); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyChain_EmptyPackageIsValid(t *testing.T) {
	res, err := Verify(buildDoc(t), nil)
	if err != nil {
		t.Fatalf("a package with no findings is still a well-formed package: %v", err)
	}
	if !res.ChainOK || res.Links != 0 || res.Signed {
		t.Fatalf("res = %+v", res)
	}
}

func TestVerifyChain_GenesisUnderivable(t *testing.T) {
	doc := []byte(`{"version":"aep/1","findings":[],"chain":{"algo":"sha256-hex-concat","genesis":"x","head":"x","length":0}}`)
	if _, err := Verify(doc, nil); err == nil || !strings.Contains(err.Error(), "window/policy") {
		t.Fatalf("err = %v, want a genesis-underivable rejection", err)
	}
}

func TestParse_RejectsNonJSON(t *testing.T) {
	if _, err := Parse([]byte(`not json at all`)); err == nil {
		t.Fatal("garbage accepted as a document")
	}
}

func TestVerifySignature_Preconditions(t *testing.T) {
	pub, err := ParsePublicKey(load(t, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unsigned package", func(t *testing.T) {
		doc := load(t, "sample-unsigned.json")
		p, err := Parse(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifySignature(doc, p, pub); err == nil || !strings.Contains(err.Error(), "no signature") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unknown signing algorithm", func(t *testing.T) {
		doc := bytes.Replace(load(t, "sample-signed.json"), []byte(`"ECDSA_SHA_256"`), []byte(`"RSA_PSS_SHA_512"`), 1)
		p, err := Parse(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifySignature(doc, p, pub); err == nil || !strings.Contains(err.Error(), "unsupported signing algorithm") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParsePublicKey_Rejections(t *testing.T) {
	t.Run("valid base64, not a PKIX key", func(t *testing.T) {
		if _, err := ParsePublicKey([]byte("aGVsbG8gd29ybGQ=")); err == nil || !strings.Contains(err.Error(), "not a PKIX public key") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("PKIX key of the wrong type", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(edPub)
		if err != nil {
			t.Fatal(err)
		}
		armored := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if _, err := ParsePublicKey(armored); err == nil || !strings.Contains(err.Error(), "want ECDSA") {
			t.Fatalf("err = %v, want a wrong-key-type rejection", err)
		}
	})
}

// These branches are defensive: reached directly, not through Verify, because
// encoding/json hands the callers only already-valid JSON.
func TestInternalHelpers_RejectMalformedInput(t *testing.T) {
	if _, err := compact(json.RawMessage(`{`)); err == nil {
		t.Error("compact accepted malformed JSON")
	}
	if _, err := genesisHash(json.RawMessage(`{`), json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "window") {
		t.Error("genesisHash accepted a malformed window")
	}
	if _, err := genesisHash(json.RawMessage(`{}`), json.RawMessage(`{`)); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Error("genesisHash accepted a malformed policy")
	}
	if _, err := genesisHash(nil, json.RawMessage(`{}`)); err == nil {
		t.Error("genesisHash accepted a missing window")
	}
	p := &Package{Window: json.RawMessage(`{}`), Policy: json.RawMessage(`{}`)}
	p.Chain.Genesis, _ = genesisHash(p.Window, p.Policy)
	p.Findings = []ChainedFinding{{Index: 0, Finding: json.RawMessage(`{`)}}
	if err := VerifyChain(p); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("VerifyChain accepted an unreadable finding: %v", err)
	}
}

// Structural validity and type validity are different questions: a document can
// be well-formed JSON with no duplicates and still put a number where the format
// requires a string.
func TestParse_RejectsWellFormedJSONWithWrongTypes(t *testing.T) {
	doc := []byte(`{"version":123,"chain":{"algo":"sha256-hex-concat"}}`)
	if _, err := Parse(doc); err == nil || !strings.Contains(err.Error(), "not a JSON document") {
		t.Fatalf("err = %v, want a decode rejection", err)
	}
}

// Malformed documents must be refused at whichever walker sees them first,
// whether that is Parse's pre-check or CanonicalPayload's own loop.
func TestMalformedDocuments_RefusedByBothWalkers(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"not an object", `[1,2,3]`},
		{"truncated after member name", `{"a":`},
		{"truncated after a complete member", `{"a":1`},
		{"truncated mid-member-list", `{"a":1,`},
		{"trailing content after the object", `{"a":1} {"b":2}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.doc)); err == nil {
				t.Errorf("Parse(%q) accepted a malformed document", tt.doc)
			}
			if _, err := CanonicalPayload([]byte(tt.doc)); err == nil {
				t.Errorf("CanonicalPayload(%q) accepted a malformed document", tt.doc)
			}
		})
	}
}

// VerifySignature is exported, so it can be handed a package parsed from one
// document and asked to canonicalize another. It must surface that rather than
// signing off on bytes it could not derive.
func TestVerifySignature_PropagatesCanonicalizationFailure(t *testing.T) {
	p, err := Parse(load(t, "sample-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(load(t, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature([]byte(`{"version":`), p, pub); err == nil {
		t.Fatal("canonicalization failure was not propagated")
	}
}

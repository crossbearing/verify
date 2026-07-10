// Package aep verifies crossbearing Agent Evidence Packages (format
// aep/1) independently of the engine that produced them. That
// independence is the entire reason this package exists in a separate,
// MIT-licensed module with an empty dependency graph: an auditor — or a
// counterparty who has never heard of crossbearing — can confirm a
// package's integrity and signature with nothing but this code and the
// signing key's public half.
//
// # What verification means here
//
// An aep/1 package makes three falsifiable claims, checked in order:
//
//  1. Chain integrity — findings are hash-chained. Each link is
//     sha256(hex(prev) || hex(sha256(canonical(finding)))), with a genesis
//     hash derived from the package's window and match policy, so a chain
//     cannot be transplanted between packages. Editing, removing, or
//     reordering any finding breaks the chain visibly.
//  2. Signature — a detached ECDSA signature over the package's canonical
//     bytes (the JSON document with the top-level "signature" member
//     removed, all insignificant whitespace stripped). The producer signs
//     with an asymmetric KMS key; this package verifies with the public
//     half and never needs AWS access.
//  3. Self-consistency — declared chain length matches the findings,
//     indexes are sequential, the algorithm is one this verifier knows.
//
// # Canonical form
//
// The producer serializes with Go's encoding/json, whose output for a
// fixed structure is deterministic: object members in struct order,
// HTML-unsafe characters escaped (< et al), non-ASCII as raw UTF-8.
// Compacting any re-serialization of the document therefore reproduces
// the producer's bytes exactly, which is what makes offline re-derivation
// possible: this package re-canonicalizes from the document's own raw
// bytes and never needs the producer's type definitions.
package aep

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// Version is the package format this verifier understands.
const Version = "aep/1"

// ChainAlgo is the only chain algorithm defined for aep/1.
const ChainAlgo = "sha256-hex-concat"

// Package is the slice of an aep/1 document verification reads. Fields
// this verifier does not interpret (sessions, bindings, conventions,
// controls, the findings' interior) stay as raw bytes — they are covered
// by the digests and the signature, not by this struct.
type Package struct {
	Version   string           `json:"version"`
	Window    json.RawMessage  `json:"window"`
	Policy    json.RawMessage  `json:"policy"`
	Findings  []ChainedFinding `json:"findings"`
	Chain     ChainHead        `json:"chain"`
	Signature *SignatureBundle `json:"signature"`
}

// ChainedFinding is one chain link.
type ChainedFinding struct {
	Index   int             `json:"index"`
	Finding json.RawMessage `json:"finding"`
	Digest  string          `json:"digest"`
	Prev    string          `json:"prev"`
	Link    string          `json:"link"`
}

// ChainHead summarizes the chain.
type ChainHead struct {
	Algo    string `json:"algo"`
	Genesis string `json:"genesis"`
	Head    string `json:"head"`
	Length  int    `json:"length"`
}

// SignatureBundle is the detached signature envelope.
type SignatureBundle struct {
	Signature []byte `json:"Signature"`
	KeyRef    string `json:"KeyRef"`
	Algo      string `json:"Algo"`
}

// Result reports what was verified. Booleans are only true for checks
// that actually ran and passed.
type Result struct {
	ChainOK bool
	Links   int
	Signed  bool // a signature bundle is present in the document
	SigOK   bool // the signature verified against the provided key
	KeyRef  string
}

// Parse decodes and structurally validates an aep/1 document.
func Parse(doc []byte) (*Package, error) {
	var p Package
	if err := json.Unmarshal(doc, &p); err != nil {
		return nil, fmt.Errorf("not a JSON document: %w", err)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("unsupported package version %q (this verifier understands %q)", p.Version, Version)
	}
	if p.Chain.Algo != ChainAlgo {
		return nil, fmt.Errorf("unsupported chain algorithm %q (this verifier understands %q)", p.Chain.Algo, ChainAlgo)
	}
	return &p, nil
}

// VerifyChain re-derives the hash chain from the document's own bytes and
// returns the first inconsistency. A nil error means every finding's
// digest, every link, the genesis binding, the head, and the declared
// length all re-derive exactly.
func VerifyChain(p *Package) error {
	genesis, err := genesisHash(p.Window, p.Policy)
	if err != nil {
		return err
	}
	if p.Chain.Genesis != genesis {
		return fmt.Errorf("genesis mismatch: chain anchored to a different window/policy (document derives %s, chain says %s)", genesis, p.Chain.Genesis)
	}
	prev := genesis
	for i, cf := range p.Findings {
		if cf.Index != i {
			return fmt.Errorf("finding %d: index says %d (reordered or spliced)", i, cf.Index)
		}
		canon, err := compact(cf.Finding)
		if err != nil {
			return fmt.Errorf("finding %d: unreadable: %w", i, err)
		}
		digest := sha256Hex(canon)
		if cf.Digest != digest {
			return fmt.Errorf("finding %d: digest mismatch (content edited)", i)
		}
		if cf.Prev != prev {
			return fmt.Errorf("finding %d: prev-link mismatch (chain reordered or truncated)", i)
		}
		if link := sha256Hex([]byte(prev + digest)); cf.Link != link {
			return fmt.Errorf("finding %d: link mismatch", i)
		}
		prev = cf.Link
	}
	if p.Chain.Head != prev {
		return fmt.Errorf("head mismatch: findings derive %s, chain says %s (truncated?)", prev, p.Chain.Head)
	}
	if p.Chain.Length != len(p.Findings) {
		return fmt.Errorf("length mismatch: chain says %d, document holds %d", p.Chain.Length, len(p.Findings))
	}
	return nil
}

// VerifySignature checks the package's detached signature against a
// public key, re-deriving the canonical signed payload from the
// document's own bytes.
func VerifySignature(doc []byte, p *Package, pub *ecdsa.PublicKey) error {
	if p.Signature == nil {
		return fmt.Errorf("package carries no signature")
	}
	if p.Signature.Algo != "ECDSA_SHA_256" {
		return fmt.Errorf("unsupported signing algorithm %q (this verifier understands ECDSA_SHA_256)", p.Signature.Algo)
	}
	payload, err := CanonicalPayload(doc)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], p.Signature.Signature) {
		return fmt.Errorf("signature INVALID for key %s: the document is not the bytes that were signed", p.Signature.KeyRef)
	}
	return nil
}

// Verify runs the full check: chain always; signature when the document
// carries one and a key is supplied. pub may be nil for chain-only
// verification — Result.Signed still reports whether a signature exists,
// so callers can fail closed on unchecked signatures.
func Verify(doc []byte, pub *ecdsa.PublicKey) (Result, error) {
	p, err := Parse(doc)
	if err != nil {
		return Result{}, err
	}
	res := Result{Signed: p.Signature != nil}
	if p.Signature != nil {
		res.KeyRef = p.Signature.KeyRef
	}
	if err := VerifyChain(p); err != nil {
		return res, err
	}
	res.ChainOK, res.Links = true, len(p.Findings)

	if p.Signature != nil && pub != nil {
		if err := VerifySignature(doc, p, pub); err != nil {
			return res, err
		}
		res.SigOK = true
	}
	return res, nil
}

// CanonicalPayload re-derives the bytes the signature covers: the
// document's top-level object with the "signature" member removed and all
// insignificant whitespace stripped, member order and value bytes
// preserved exactly as the document carries them.
func CanonicalPayload(doc []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("unreadable document: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("document is not a JSON object")
	}

	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("unreadable member name: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("non-string member name %v", keyTok)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("unreadable value for %q: %w", key, err)
		}
		if key == "signature" {
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		keyJSON, _ := json.Marshal(key)
		out.Write(keyJSON)
		out.WriteByte(':')
		canon, err := compact(raw)
		if err != nil {
			return nil, fmt.Errorf("value for %q: %w", key, err)
		}
		out.Write(canon)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// ParsePublicKey accepts the public key in either form an operator can
// easily produce: PEM ("BEGIN PUBLIC KEY", as openssl emits) or the raw
// base64 DER that `aws kms get-public-key --query PublicKey --output
// text` prints.
func ParsePublicKey(material []byte) (*ecdsa.PublicKey, error) {
	der := material
	if block, _ := pem.Decode(material); block != nil {
		der = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(material)))
		if err != nil {
			return nil, fmt.Errorf("key material is neither PEM nor base64 DER: %w", err)
		}
		der = decoded
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("not a PKIX public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ECDSA (the aep/1 signing algorithm)", pub)
	}
	return ec, nil
}

// genesisHash mirrors the producer: sha256 over the canonical JSON of
// {"window":…,"policy":…}, re-derived from the document's own raw bytes.
func genesisHash(window, policy json.RawMessage) (string, error) {
	if len(window) == 0 || len(policy) == 0 {
		return "", fmt.Errorf("document lacks window/policy (chain genesis underivable)")
	}
	cw, err := compact(window)
	if err != nil {
		return "", fmt.Errorf("window: %w", err)
	}
	cp, err := compact(policy)
	if err != nil {
		return "", fmt.Errorf("policy: %w", err)
	}
	var b bytes.Buffer
	b.WriteString(`{"window":`)
	b.Write(cw)
	b.WriteString(`,"policy":`)
	b.Write(cp)
	b.WriteByte('}')
	return sha256Hex(b.Bytes()), nil
}

func compact(raw json.RawMessage) ([]byte, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

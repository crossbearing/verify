package aep

// Report is the machine-readable form of a verification outcome, published as
// schema/verify-result-1.schema.json and emitted by `verify --json`.
//
// It lives here rather than in the command because the shape is a contract this
// module offers, not a detail of one binary's output: anything embedding Verify
// can render the same document, and a consumer reading it gets the same fields
// whichever produced it.
//
// # Verified is the whole point
//
// Verified is true only when every check the caller asked for actually ran and
// passed, which is the same condition as the command exiting 0. A consumer that
// reads this field is making the same decision as a script reading the exit
// status, and the two must never disagree — a document reporting success beside
// a failing exit code would be this repository's own thesis violated inside its
// own verifier.
//
// The fields below it are evidence for that verdict, not inputs a reader should
// re-combine into one. In particular a chain that verified says nothing about
// whether a signature went unchecked, so Chain.Verified alone must not be read
// as "the package verified".
type Report struct {
	// Verified is true only if every requested check ran and passed.
	Verified bool `json:"verified"`

	Chain     ChainReport     `json:"chain"`
	Signature SignatureReport `json:"signature"`

	// Error explains a failed verification. Empty when Verified is true.
	Error string `json:"error,omitempty"`
}

// ChainReport describes the hash chain, which is checked on every run.
type ChainReport struct {
	// Verified is true when every finding's digest, every link, the genesis
	// binding, the head, and the declared length all re-derived.
	Verified bool `json:"verified"`

	// Links is the number of findings that re-derived. Zero is a legitimate
	// value: a package may carry no findings and still be well-formed.
	Links int `json:"links"`
}

// Signature states. A signature present but unchecked is not a failure state:
// whether it is a failure depends on what the caller asked for, and that
// judgement belongs in Report.Verified.
const (
	// SignatureAbsent means the package carries no signature and says so.
	SignatureAbsent = "absent"
	// SignatureVerified means a signature was checked against a supplied key
	// and matched.
	SignatureVerified = "verified"
	// SignatureUnchecked means a signature is present and was not checked,
	// because no key was supplied.
	SignatureUnchecked = "unchecked"
)

// SignatureReport describes the detached signature.
type SignatureReport struct {
	// State is one of SignatureAbsent, SignatureVerified, SignatureUnchecked.
	State string `json:"state"`

	// KeyRef is the key identifier the package carries. It is reported, never
	// trusted: verification checks the signature against the key the caller
	// supplied, not against this string. Empty when no signature is present.
	KeyRef string `json:"keyRef,omitempty"`
}

// SignatureState renders the signature state a Result describes.
func SignatureState(res Result) string {
	switch {
	case res.SigOK:
		return SignatureVerified
	case res.Signed:
		return SignatureUnchecked
	default:
		return SignatureAbsent
	}
}

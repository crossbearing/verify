# crossbearing/verify

Offline verifier for crossbearing **Agent Evidence Packages** (format
`aep/1`).

This tool is deliberately boring: MIT-licensed, **zero dependencies**
(there is no `go.sum` at all — the Go standard library is the entire supply
chain, and CI fails if that file ever appears), and it never imports the
engine that produces the packages. Evidence is
only evidence if a counterparty can check it without trusting — or even
contacting — whoever emitted it. This repo is that counterparty's tool.

The packages come from the [crossbearing engine](https://github.com/crossbearing/crossbearing)
([crossbearing.dev](https://crossbearing.dev)); the
[scenario gallery](https://github.com/crossbearing/scenarios) shows the
findings the chain carries, detection through fix.

## Usage

```sh
go install github.com/crossbearing/verify@latest   # or build from source:
go build -o verify .

# full verification: hash chain + detached ECDSA signature, fully offline
verify package.json --public-key key.pem

# the key is the signing key's public half; from AWS KMS it's one command:
aws kms get-public-key --key-id <key-arn> --query PublicKey --output text > key.b64
verify package.json --public-key key.b64     # base64 DER accepted directly

# chain-only (no key available)
verify package.json --chain-only

# machine-readable result on stdout, nothing else — for agents and CI
verify package.json --public-key key.pem --json
```

Exit codes: `0` every requested check passed · `1` verification failed,
or the package is signed and no key was given (fail closed) · `2` usage.

## What gets verified

1. **Chain integrity** — every finding's digest re-derives from the
   document's own bytes; every link re-derives from its predecessor; the
   genesis hash binds the chain to the package's window and match policy
   (a chain cannot be transplanted); the head and declared length match.
   Editing, removing, reordering, or splicing any finding fails with the
   exact index.
2. **Signature** — detached ECDSA P-256 over the package's canonical
   bytes, verified against the public key you supply. The signer is
   typically an AWS KMS key in the producer's account; verification
   needs only the public half.

### Machine-readable output

`--json` writes the result of
[`schema/verify-result-1.schema.json`](schema/verify-result-1.schema.json) to
stdout and nothing else, so it pipes without filtering; diagnostics stay on
stderr in both modes. Prose is the default, because a human runs this.

```json
{
  "verified": false,
  "chain": { "verified": true, "links": 3 },
  "signature": { "state": "unchecked", "keyRef": "alias/crossbearing-evidence" },
  "error": "package is signed (…) but no --public-key was given; pass the key or --chain-only"
}
```

Branch on `verified`. It is true only when every check you asked for actually
ran and passed, and it **agrees with the exit code in every case** — the two are
one decision rendered twice, and a test asserts they cannot diverge. The other
members are evidence for that verdict, not inputs to recombine: a chain that
verified says nothing about whether a signature went unchecked, so
`chain.verified` alone must never be read as "the package verified".

`signature.state` is `absent`, `verified`, or `unchecked`. The last is not by
itself a failure — whether it is one depends on whether you passed
`--chain-only`, which is exactly the judgement `verified` carries.

## The aep/1 format (verifier's contract)

An `aep/1` document is a JSON object. The members this verifier
interprets:

| member | meaning |
| --- | --- |
| `version` | must be `"aep/1"` |
| `window` | `{from, to, region}` — what the evidence covers |
| `policy` | the match policy the corroboration join ran under |
| `findings[]` | chain links: `{index, finding, digest, prev, link}` |
| `chain` | `{algo: "sha256-hex-concat", genesis, head, length}` |
| `signature` | optional `{Signature (base64), KeyRef, Algo}` |

Derivations (all hashes lowercase hex SHA-256):

```
canonical(x)  = x's JSON with insignificant whitespace removed,
                member order and value bytes as the document carries them
genesis       = sha256( {"window":canonical(window),"policy":canonical(policy)} )
digest[i]     = sha256( canonical(findings[i].finding) )
link[i]       = sha256( hex(link[i-1]) || hex(digest[i]) )   with link[-1] = genesis
signed bytes  = canonical(document with top-level "signature" member removed)
signature     = ECDSA_SHA_256 over sha256(signed bytes), ASN.1 DER
```

The producer serializes with Go's `encoding/json`, whose output for a
fixed structure is deterministic; compacting the document's own bytes
therefore reproduces the canonical form exactly. That property is what
makes this verifier possible without sharing any code with the engine.

Other members (`sessions`, `bindings`, `conventions`, `controls`,
`generatedAt`) are evidence content: covered by the signature, carried
verbatim, not interpreted here.

### Machine-readable schema

[`schema/aep-1.schema.json`](schema/aep-1.schema.json) is the JSON Schema
counterpart to the table and derivations above, so a consumer can check a
document's shape without reading English.

It describes **shape**, not **integrity**. No JSON Schema can express that
`link[i]` equals `sha256(link[i-1] || digest[i])`, that the genesis hash binds
the chain to this package's window and policy, or that the signature covers the
canonical bytes. **A document can satisfy the schema completely and still be
forged** — validating against it is a precondition for verification, never a
substitute. That boundary is pinned by a test, not just asserted here: a
document with every hash replaced by a well-formed but wrong digest passes the
schema and fails the verifier.

The schema is checked against the engine-produced fixtures on every CI run, so
it cannot drift from the parser without the build going red.

## Library

`github.com/crossbearing/verify/aep` exposes `Verify`, `VerifyChain`,
`VerifySignature`, `CanonicalPayload`, and `ParsePublicKey` for embedding
verification in your own tooling.

## Reporting a problem

Security reports go through the
[crossbearing security policy](https://github.com/crossbearing/.github/blob/main/SECURITY.md),
which covers this repository. GitHub's **Report a vulnerability** button on this
repo opens a private advisory; email works too. Please don't use a public issue
or pull request for a suspected vulnerability.

The report this tool most wants is a package that **verifies when it should
not** — a way to alter, reorder, drop, splice, or transplant findings that the
hash chain or the signature fails to catch, or any flaw in the canonicalization
the signature depends on. A verifier that wrongly rejects is a bug; a verifier
that wrongly accepts is the failure this repository exists to make impossible.

## License

[MIT](LICENSE). The engine that produces these packages lives in a
separate repository under a different license; this verifier is
independent of it by design.

# crossbearing/verify

Offline verifier for crossbearing **Agent Evidence Packages** (format
`aep/1`).

This tool is deliberately boring: MIT-licensed, **zero dependencies**
(`go.sum` is empty — the Go standard library is the entire supply chain),
and it never imports the engine that produces the packages. Evidence is
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

## Library

`github.com/crossbearing/verify/aep` exposes `Verify`, `VerifyChain`,
`VerifySignature`, `CanonicalPayload`, and `ParsePublicKey` for embedding
verification in your own tooling.

## License

[MIT](LICENSE). The engine that produces these packages lives in a
separate repository under a different license; this verifier is
independent of it by design.

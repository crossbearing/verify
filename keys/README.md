# Archived signing keys

Public halves of keys that have signed `aep/1` packages. Public keys are not
secrets — they are published precisely so a counterparty can verify without
contacting anyone, which is the whole premise of this repo.

A key lands here when it is **retired**. Packages it signed stay verifiable
forever; the key that signed them does not have to stay alive.

## `crossbearing-evidence.pem`

crossbearing's own dogfood evidence key. Used to prove the signing path
end-to-end against real findings — not a customer key. In a customer engagement
the **customer's** key signs, and its public half never comes near this repo.

| | |
|---|---|
| Alias | `alias/crossbearing-evidence` |
| Key spec | `ECC_NIST_P256` (`prime256v1`) |
| Usage | `SIGN_VERIFY`, `ECDSA_SHA_256` |
| Created | 2026-06-10 |
| Archived | 2026-08-13 |
| SPKI SHA-256 | `a481906ffa48a6ded07ab2694b25210b83a02cd8e9ca8ff727f3b46e9fcb1a32` |

Archived because crossbearing's infrastructure moves to a dedicated AWS account
and **KMS keys cannot move between accounts**. Recreating the key elsewhere
produces a different key, so the public half was exported while the original was
still live. The replacement key gets its own entry here when it retires in turn.

### Verifying a package signed by it

```sh
verify package.json --public-key keys/crossbearing-evidence.pem
```

### Provenance

Exported with `kms:GetPublicKey`, then checked by round-trip against the live key
before it was retired: a message signed by KMS verified against this file alone,
with no AWS call, and a modified message was rejected.

```sh
openssl dgst -sha256 -verify keys/crossbearing-evidence.pem \
  -signature sig.bin message.bin
```

Reproduce the fingerprint from this file:

```sh
openssl pkey -pubin -in keys/crossbearing-evidence.pem -outform DER | shasum -a 256
```

That is the check worth running if you ever doubt this file: the fingerprint is
derived from the key material itself, so it cannot be faked by editing the table
above.

# attest: sign and attach attestations

`bedrock attest` signs an image and attaches in-toto attestations to it as OCI
referrers, using the Sigstore bundle format that `cosign` reads by default.

```
bedrock slim IMAGE ... -o ./slim --report slim.json --keep-list keep.toml
skopeo copy oci:./slim docker://registry.example/app:1     # or oras / crane
COSIGN_PASSWORD=... bedrock attest registry.example/app:1 --key cosign.key --report slim.json
cosign verify --key cosign.pub registry.example/app:1
cosign verify-attestation --key cosign.pub --type slsaprovenance1 registry.example/app:1
cosign verify-attestation --key cosign.pub --type spdxjson registry.example/app:1
```

Checked with cosign 3.1.3 against a local `registry:2`: `verify` and
`verify-attestation` succeed for the signature, provenance, SBOM and report
attestations, and fail with a different key.

## What is attached

| Artifact | Predicate type | Content |
|---|---|---|
| Signature | `https://sigstore.dev/cosign/sign/v1` | Empty predicate; the signature binds the image digest |
| Provenance | `https://slsa.dev/provenance/v1` | Builder: Bedrock, its version and binary digest. Materials: the input image and the advisory snapshot digest. Config: the full command line and the digests of the workload and keep-list files |
| SBOM | `https://spdx.dev/Document` | SPDX 2.3 of the *pruned* image, read back from the image itself |
| Report (`--attest-report`) | `https://github.com/NichoHo/Bedrock/report/v1` | The `slim` JSON report, so the before/after delta can be read from the registry |

Provenance needs `--report` pointing at the JSON a `slim --report` run wrote;
without it, the signature and SBOM are attached and `attest` says provenance was
skipped.

Each artifact is an OCI image manifest with a `subject` pointing at the image,
`artifactType` `application/vnd.dev.sigstore.bundle.v0.3+json`, and one layer:
the bundle, whose DSSE envelope holds an in-toto Statement v1. On registries
with the Referrers API the registry lists them. On others (such as `registry:2`)
Bedrock maintains the fallback index tag `sha256-<image digest>`, as the OCI
Distribution spec describes.

## Targets

- **A registry reference**: artifacts are pushed. Credentials come from Docker's
  `config.json`, as for pulls. `localhost` registries use plain HTTP.
- **An OCI layout directory** (what `slim -o` writes): artifacts are added to its
  `blobs/` and `index.json`, for signing before the image is pushed. Copy it with
  a tool that follows referrers (`oras copy -r`). `skopeo copy` refuses a layout
  with more than one `index.json` entry, so push before attesting if you use it.

## Keys

`--key` takes a `cosign generate-key-pair` key (set `COSIGN_PASSWORD`; an unset
password is treated as empty) or an unencrypted ECDSA P-256 PEM key (PKCS#8 or
SEC1). Bedrock does not create, store or rotate keys. Signatures are ECDSA
P-256 over SHA-256, deterministic per RFC 6979.

## Limits

- **Keyless signing is not implemented** (Fulcio certificates, Rekor, OIDC).
  `attest` without `--key` exits 4. It was not testable without a real identity
  provider, and a signing path that was never run end to end is worse than none.
- **No transparency log or timestamp** is recorded. Verify with
  `--insecure-ignore-tlog` (cosign 3: also pass no `--use-signed-timestamps`), or
  accept that key-based signatures here prove key possession only, not when.
- Running `attest` twice adds a new SBOM artifact each time (the SPDX document
  carries a creation time); the signature and provenance artifacts are
  identical and are not duplicated.
- The SBOM predicate is read from the image, so attesting a registry image pulls
  its layers.

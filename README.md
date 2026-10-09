# Bedrock

Container scanners tell you what's wrong with an image; minimal base images only
help if you rebuild from one. Nobody closes the loop: measure what an image's
entrypoint actually touches, remove the rest, and prove the result still works.
Bedrock is a command-line tool aimed at that gap: trace a container workload,
remove what it never reached, verify the result, sign the proof. See
[`BEDROCK_SPEC.md`](BEDROCK_SPEC.md) for the full design and roadmap.

## What it does

```bash
bedrock slim python:3.12-slim \
  --workload-http requests.http --ready-port 8000 \
  -o ./slim --report slim.json -- python3 -m http.server 8000
```

This runs the image, replays your requests against it under `ptrace`, removes every
package and file that nothing used, builds a new image, then runs that image with
the same requests. It writes the result only if the answers match.

| Command | What it does | Details |
|---|---|---|
| `inspect` | Layers, file counts, size, setuid and setgid binaries | |
| `sbom` | SPDX 2.3 or CycloneDX 1.5 SBOM (dpkg, apk, rpm, npm, Python, Go and `cargo auditable` binaries) | |
| `db update`, `db status` | Fetch and inspect the advisory snapshot (OSV, Debian, Alpine, Red Hat) | |
| `scan` | Vulnerabilities in an image, with `--fail-on`, JSON and SARIF output | [scan comparison](docs/scan-comparison.md) |
| `trace` | Run the entrypoint with a workload and list the files it reached (Linux) | [docs/reachability-trace.md](docs/reachability-trace.md) |
| `slim` | Trace, prune, assemble a new OCI image and verify it (Linux) | [docs/slim.md](docs/slim.md) |
| `attest` | Sign an image and attach SLSA provenance and an SBOM as OCI referrers | [docs/attest.md](docs/attest.md) |
| `report` | Re-render a saved report as Markdown, HTML, terminal text, JSON or SARIF | |

`<image>` can be a registry reference (`alpine:3.19`, `ghcr.io/org/image@sha256:...`),
a local OCI image layout directory, or a `docker save` archive (`image.tar`).
Private registries work after `docker login`: Bedrock reads Docker's `config.json`
and credential helpers on each run and stores nothing. `--platform` defaults to your
machine's architecture.

Exit codes: 0 success, 1 findings above `--fail-on` or a failed run, 2 verification
failed, 3 usage error, 4 environment problem (no ptrace, no snapshot, unsupported host).

## Results

On a corpus of 21 public images, each with a workload, `bedrock slim` produced a
verified image for all 21, from 1% to 90% smaller (typically 60% or more for Debian
and Python based images). See [docs/corpus.md](docs/corpus.md) for the table and what
it does and does not prove. `bedrock scan` agrees with grype on every finding that
comes from an advisory feed; [docs/scan-comparison.md](docs/scan-comparison.md)
explains each difference.

## Limits you should know about

- **Dynamic tracing is incomplete by construction.** Code the workload does not run
  is not seen. A pass means your workload still works, not that the image is safe to
  ship. `slim` is for reducing an image you must keep, not a replacement for a
  maintained minimal base.
- **`trace` and `slim` need Linux** on x86-64 or arm64, with `ptrace` and either root
  or unprivileged user namespaces. On macOS or Windows, run them in a Linux container.
  The sandbox isolates the filesystem and credentials only. It is not a security
  boundary: do not trace an image you do not trust on a machine you care about.
- **Keyless signing is not implemented.** `attest` signs with a key you provide.
- **rpm databases in Berkeley DB or NDB format** (RHEL 7 and 8, openSUSE) are read but
  not rewritten, so a pruned image's SBOM still lists removed packages there. SQLite
  rpm databases (Fedora, RHEL 9 family, Amazon Linux 2023) are rewritten.
- **`scan` does not guess from product names.** It matches package feeds only, so it
  misses what grype finds by recognising a binary such as the CPython interpreter.

## Build and run

Requires a stable Rust toolchain ([rustup.rs](https://rustup.rs)).

```bash
cargo build --release
./target/release/bedrock --help
```

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

CI runs these on every push and pull request, plus the suite as root so the `ptrace`
tests run, and a self-test that slims Bedrock's own release image (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)). A weekly workflow re-runs the
corpus against a fresh advisory snapshot.

## License

MIT, see [`LICENSE`](LICENSE). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security disclosure: [`SECURITY.md`](SECURITY.md).

# Bedrock

Container scanners tell you what's wrong with an image; minimal base images only
help if you rebuild from one. Nobody closes the loop: measure what an image's
entrypoint actually touches, remove the rest, and prove the result still works.
Bedrock is a command-line tool aimed at that gap — trace a container workload,
remove what it never reached, sign the proof. See [`BEDROCK_SPEC.md`](BEDROCK_SPEC.md)
for the full design and roadmap.

## Project status

Early development. Working today:

- `bedrock inspect <image>` — layers, file/directory/symlink counts, size, setuid/setgid binaries
- `bedrock sbom <image>` — SPDX 2.3 or CycloneDX 1.5 SBOM. It reads these package sources:
  - dpkg, including the per-package `status.d` layout of distroless images
  - apk
  - rpm (SQLite, Berkeley DB, and NDB databases)
  - npm (`node_modules`)
  - Python (`.dist-info` and `.egg-info`)

  Each package lists the files it owns in the image, with SHA-1 and SHA-256 checksums.
  CI checks the output with the official SPDX and CycloneDX validators.
- `bedrock db status` — reports on the cached vulnerability snapshot, if any

`<image>` can be a registry reference (`alpine:3.19`, `ghcr.io/org/image@sha256:...`),
a local OCI image layout directory, or a `docker save` archive (`image.tar`).
Private registries work after `docker login`: Bedrock reads Docker's `config.json`
and credential helpers on each run and stores nothing.
`--platform` defaults to your machine's architecture (for example `linux/arm64` on Apple silicon).

`bedrock db update` fetches the advisory snapshot (OSV for PyPI, npm, Go and
crates.io; the Debian, Alpine and Red Hat trackers for distro packages) into your
cache dir. It is the only command that needs the network besides image pulls.
`bedrock db status` shows its digest, counts and age.

`bedrock scan <image>` matches the image's packages against that snapshot.
Distro packages match only their own distribution's feed (so backported fixes
are respected); npm and PyPI packages match OSV. Releases the snapshot has no
data for (Ubuntu, Fedora, EOL Debian) are listed as "not assessed", never
reported as clean. `--format terminal|json|sarif`, `--output FILE`, and
`--fail-on low|medium|high|critical` (exit 1; findings with no rating never
fail the gate). A missing or damaged snapshot exits 4.

`bedrock trace` runs the entrypoint under ptrace with a workload and prints the
set of image files it reached (Linux only; see
[docs/reachability-trace.md](docs/reachability-trace.md) for usage and limits).

`bedrock slim` traces, prunes, writes a new OCI image and verifies it still
works under the same workload; see [docs/slim.md](docs/slim.md).

`bedrock attest` signs the pruned image and attaches SLSA provenance and an SBOM
as OCI referrers that `cosign` verifies; see [docs/attest.md](docs/attest.md).
Key-based only: keyless signing is not implemented.

`bedrock report report.json --format markdown|html|terminal|json|sarif` re-renders a
saved report (from `scan --format json` or `slim --report`). The HTML output is one
self-contained file: no scripts, no external requests, light and dark themes, a print
stylesheet, and severity drawn as a shape as well as a colour.

## Results

On a corpus of 18 public images, each with a workload, `bedrock slim` produced a verified image for all 18, from -1% to -90% smaller (typically 60%+ for Debian and Python based images). See [docs/corpus.md](docs/corpus.md) for the table and what it does and does not prove.

## Build and run

Requires a stable Rust toolchain ([rustup.rs](https://rustup.rs)).

```bash
cargo build --release
./target/release/bedrock --help
```

Or run directly without a release build:

```bash
cargo run -- inspect alpine:3.19
cargo run -- sbom alpine:3.19 --format spdx
```

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

All four run in CI on every push and pull request (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## License

MIT, see [`LICENSE`](LICENSE). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security disclosure: [`SECURITY.md`](SECURITY.md).

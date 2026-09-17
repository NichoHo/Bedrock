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
- `bedrock sbom <image>` — SPDX or CycloneDX SBOM from dpkg, apk, npm (`node_modules`), and Python (`.dist-info`) packages
- `bedrock db status` — reports on the cached vulnerability snapshot, if any

`<image>` can be a registry reference (`alpine:3.19`, `ghcr.io/org/image@sha256:...`)
or a local OCI image layout directory.

Everything else — `scan`, `trace`, `slim`, `attest`, `report`, `db update` — parses
its arguments (so `--help` shows the intended interface) but exits 4 with
"not implemented yet". Reachability tracing, pruning, vulnerability matching,
and signing don't exist yet; nothing in this tool fakes success on an
unimplemented path.

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
```

All three run in CI on every push and pull request (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## License

MIT, see [`LICENSE`](LICENSE). Security disclosure: see [`SECURITY.md`](SECURITY.md).

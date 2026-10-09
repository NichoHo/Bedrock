# Contributing

Read [`BEDROCK_SPEC.md`](BEDROCK_SPEC.md) first. It sets the scope and the phases.

## Checks

Run these before you push. CI runs the same ones.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

## Crate map

Everything lives in `crates/bedrock-cli`.

| Path | Job |
|---|---|
| `src/main.rs` | CLI arguments, image resolution, output, exit codes |
| `src/image.rs` | Build the file inventory and package list for an image |
| `src/oci/` | Image sources: registry (`registry.rs`, `auth.rs`), OCI layout directory (`layout.rs`), `docker save` archive (`archive.rs`), manifest and platform selection (`manifest.rs`) |
| `src/fs/` | `FileInventory`: applies layers and whiteouts, hashes files, extracts a rootfs, enforces size limits |
| `src/sbom/` | One parser per package source (dpkg, apk, rpm, npm, Python, compiled Go and Rust binaries), plus the SPDX and CycloneDX writers |
| `src/vuln/` | Advisory snapshot (`db.rs`, `feeds/`), per-ecosystem version comparison (`version.rs`), matching (`matcher.rs`) |
| `src/trace/` | The `ptrace` sandbox (`tracer.rs`), path resolution, static ELF closure, workloads |
| `src/slim/` | Keep set (`keep.rs`), OCI image assembly (`assemble.rs`), package database rewriting, verify |
| `src/attest/` | Signing keys, DSSE and Sigstore bundles, in-toto statements |
| `src/report/` | The report model and its renderers (terminal, Markdown, HTML, SARIF) |
| `tests/` | Integration tests (`integration.rs`), property tests (`properties.rs`), fixture builder (`support/`) |
| `fuzz/` | `cargo fuzz` targets for the text and binary parsers (nightly only) |

## Add a package database parser

1. Add `src/sbom/<name>.rs` with a `parse_<name>(inventory, resolver) -> Result<Vec<Package>>`.
   Read files with `read_file` or `read_files`. Get the distro from `OsRelease::read`.
   Build the PURL with the distro as the namespace.
2. Put the text parsing in a separate `parse_status`-style function that takes `&str`.
   Fuzz targets and property tests call it directly.
3. Declare the module in `src/sbom/mod.rs` and add it to the `parsers` array in `parse_all_packages` (`src/image.rs`).
4. Add a unit test, a round-trip case in `tests/properties.rs`, and a fuzz target in `fuzz/fuzz_targets/`.
5. Add an image to the `sbom-validate` job in `.github/workflows/ci.yml`.

A parser must return an error or an empty list on bad input. It must never panic.

## Add a test fixture

Do not commit image blobs. `tests/support/mod.rs` has `LayoutBuilder`, which writes a
small OCI layout at test time:

```rust
let dir = tempfile::tempdir().unwrap();
let builder = LayoutBuilder::new(dir.path());
let layer = builder.layer(&[("lib/apk/db/installed", b"P:musl\nV:1.2.4-r2\n\n")]);
builder.finish(&[layer]);
// run: Command::cargo_bin("bedrock")... .arg(dir.path())
```

Use `layer_with_symlinks`, `layer_with_modes` or `finish_with_config` when the test needs links, file modes or an image config.

## Rules

- Anything read from an image is untrusted. Escape it before you print it (`escape_control` in `lib.rs`).
- Never fake success on an unimplemented path. Use `not_implemented`.
- Add a line to `CHANGELOG.md` for user-visible changes.

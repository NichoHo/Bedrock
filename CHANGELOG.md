# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `report`: re-render a saved report as Markdown, a self-contained HTML page, terminal text,
  JSON or SARIF.
- `attest`: key-based signing with cosign-compatible keys; SLSA provenance, SPDX SBOM and
  report attestations as Sigstore-bundle OCI referrers; registry push support (plain HTTP
  for loopback registries). Keyless signing is not implemented.
- `slim`: keep-set computation (package or file granularity, keep-list, mandatory list),
  deterministic OCI image assembly, dpkg/apk database rewriting, verify gate, and a
  report with removals, delta and CVEs removed.
- `trace`: ptrace sandbox with script, HTTP and duration workloads, symlink-aware
  path resolution, static ELF/shebang closure, and package coverage figures.
- `db update` / `db status`: OSV (PyPI, npm, Go, crates.io) plus the Debian, Alpine and
  Red Hat trackers, stored as digest-checked files with a manifest.
- `scan`: dpkg, apk, rpm, semver and PEP 440 version comparison; distro
  packages match only their own feed; `--fail-on`, JSON (`schema_version` 1) and
  SARIF 2.1 output.
- `inspect` and `sbom` read `docker save` archives (`image.tar`).
- Private registries: credentials come from Docker's `config.json`
  (`auths`, `credHelpers`, `credsStore`). Bedrock never stores them.
- Retry with backoff when a registry answers 429 or 503, honouring `Retry-After`.
- `cargo deny` licence and advisory checks in CI.
- `CONTRIBUTING.md`.

### Changed
- `--platform` defaults to the host architecture (was `linux/amd64`).
- An image whose config names a different platform than `--platform` is now
  refused, including images reached without a manifest index.
- apk packages use the distro from `/etc/os-release` as the PURL namespace
  (`wolfi`, `chainguard`, ...) instead of always `alpine`.
- Paths and error text from inside an image are escaped before printing.
- Release workflow builds the snap but no longer publishes it, until signing
  exists (Phase 5).
- `SECURITY.md` now gives a private reporting route.

### Fixed
- CI also runs on `main`, not only `master`.
- apk packages are found in merged-`/usr` images (Wolfi, Chainguard), where
  the database is at `usr/lib/apk/db/installed`. Before, these images
  reported no packages.
- `--platform` default on big-endian 64-bit PowerPC is `linux/ppc64`, not `ppc64le`.

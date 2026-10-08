# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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

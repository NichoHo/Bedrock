# scan versus a reference scanner

BEDROCK_SPEC.md Phase 2 asks that findings agree with a reference scanner within a documented tolerance, with every disagreement explained. This is that note.

**Setup.** `bedrock scan` against advisory snapshot `a22d035c3863`, and grype 0.120.1 (`anchore/grype`, its own database of 2026-10-09), both on the same images pulled from the registry the same day. Each finding is counted once by its primary ID (the CVE where one exists), and two findings match when they share any ID or alias.

| Image | Bedrock findings | grype findings | Bedrock found by grype | Only Bedrock | Only grype | Only grype, not a CPE guess |
|---|---:|---:|---:|---:|---:|---:|
| `debian:12-slim` | 102 | 101 | 101 | 1 | 0 | 0 |
| `python:3.12-slim-bookworm` | 115 | 121 | 114 | 1 | 7 | 0 |
| `node:22-alpine` | 21 | 35 | 21 | 0 | 14 | 0 |
| `alpine:3.20` | 0 | 2 | 0 | 0 | 2 | 0 |
| `traefik/whoami` (Go) | 12 | 8 | 8 | 4 | 0 | 0 |
| `caddy:alpine` (Go) | 2 | 16 | 1 | 1 | 15 | 0 |
| `golang:1.23-alpine` | 99 | 157 | 98 | 1 | 25 | 0 |

**Result.** Every match grype makes from a distribution or ecosystem advisory feed is also a Bedrock finding, on all seven images. Everything grype reports that Bedrock does not is a `cpe-match`: grype's fallback that guesses from NVD product names. Bedrock has no such fallback by design.

## Every disagreement, explained

**Only grype (all `cpe-match`, none from a feed):**

- *Alpine packages* (`busybox`, `zlib`, `libcrypto3`, `libssl3`; 2 IDs on `alpine:3.20`, 14 on `node:22-alpine`). Alpine's security database (secdb) lists only vulnerabilities with a fix. grype also matches by NVD CPE, reporting vulnerabilities Alpine has not fixed or triaged, with fix state `unknown` or empty. Bedrock reports nothing for them because no Alpine advisory exists.
- *The Python interpreter* (`python` 3.12.15 at `/usr/local/bin/python3.12`; 7 CVEs on `python:3.12-slim-bookworm`). The official image builds CPython into `/usr/local`, so no package database lists it, and OSV's PyPI feed does not cover the interpreter. grype finds it by recognising the binary. Bedrock does not. **This is a real coverage gap** for runtimes that no package manager knows about (CPython, Node's own binary, and so on). Go and `cargo auditable` Rust binaries are now read from the metadata they embed (see below); other runtimes are not.

**Only Bedrock:**

- *Go modules and the Go standard library* (4 on `traefik/whoami`, 1 on `caddy:alpine`). Bedrock reads the module list and toolchain version a Go binary embeds and matches them against OSV's Go feed, which grype's matches on these images did not cover. Each one was checked against its advisory: `stdlib` 1.26.5 against fixes in 1.26.6, `google.golang.org/grpc` v1.82.1 against 1.83.1, `golang.org/x/text` v0.40.0 against 0.41.0. The `caddy:alpine` entry, `golang.org/x/crypto` v0.57.0, is an advisory with no fixed version at all (every version affected), so it has no fix to report.
- *Alpine `zlib`, CVE-2026-22184* (`golang:1.23-alpine`). A fixed-in-1.3.2-r0 entry in Alpine's secdb; the image has 1.3.1-r2.

- *`zlib1g`, CVE-2023-45853* (one entry on both Debian-based images). The Debian tracker marks bookworm `open` for source package `zlib`, with `nodsa_reason: ignored` and the note "contrib/minizip not built and src:zlib not producing binary packages", meaning the installed binary packages are not affected. grype omits it; Bedrock reports it. This is a false positive in practice, but there is no simple rule that fixes it: on the same image grype reports 16 other findings that carry `nodsa_reason: ignored` (and 40 `postponed`), so dropping all `ignored` entries would swap this disagreement for sixteen others. Telling "ignored because minor" from "ignored because not built" needs the free-text note, which Bedrock does not interpret.

## What was and was not detected in compiled binaries

Go binaries built with Go 1.18 or later are read through their embedded build info (`golang.org/x/net`-style modules plus the toolchain as `stdlib`). Rust binaries are read only if built with `cargo auditable`. That path was run end to end on a real binary (a small crate depending on `serde_json` and `time` 0.1.45, built with cargo-auditable in a container): all 7 crates were read, and `scan` reported `CVE-2020-26235` in `time` 0.1.45 with fix 0.2.23. It was not compared against grype. Go binaries before 1.18, and stripped or obfuscated binaries, are not detected.

## Not compared

- Ubuntu, Fedora and Debian 11 and 10: the Debian tracker feed no longer carries releases it has retired, and Bedrock has no feed for the others, so `scan` lists those packages as not assessed rather than comparing.
- Severity: grype and Bedrock take severity from different sources and were not compared.
- Fixed versions were spot-checked, not compared across the whole set.

## Reproducing

```
bedrock scan IMAGE --format json -o ours.json
docker run --rm anchore/grype "registry:IMAGE" -o json -q > grype.json
```

Counts move daily with both databases.

# scan versus a reference scanner

BEDROCK_SPEC.md Phase 2 asks that findings agree with a reference scanner within a documented tolerance, with every disagreement explained. This is that note.

**Setup.** `bedrock scan` against advisory snapshot `a22d035c3863`, and grype 0.120.1 (`anchore/grype`, its own database of 2026-10-09), both on the same images pulled from the registry the same day. Each finding is counted once by its primary ID (the CVE where one exists), and two findings match when they share any ID or alias.

| Image | Bedrock IDs | grype IDs | In both | Only Bedrock | Only grype |
|---|---:|---:|---:|---:|---:|
| `debian:12-slim` | 102 | 101 | 101 | 1 | 0 |
| `python:3.12-slim-bookworm` | 115 | 121 | 114 | 1 | 7 |
| `node:22-alpine` | 21 | 35 | 21 | 0 | 14 |
| `alpine:3.20` | 0 | 2 | 0 | 0 | 2 |

**Result.** Every match grype makes from a distribution or ecosystem advisory feed is also a Bedrock finding, on all four images. Everything grype reports that Bedrock does not is a `cpe-match`: grype's fallback that guesses from NVD product names. Bedrock has no such fallback by design.

## Every disagreement, explained

**Only grype (all `cpe-match`, none from a feed):**

- *Alpine packages* (`busybox`, `zlib`, `libcrypto3`, `libssl3`; 2 IDs on `alpine:3.20`, 14 on `node:22-alpine`). Alpine's security database (secdb) lists only vulnerabilities with a fix. grype also matches by NVD CPE, reporting vulnerabilities Alpine has not fixed or triaged, with fix state `unknown` or empty. Bedrock reports nothing for them because no Alpine advisory exists.
- *The Python interpreter* (`python` 3.12.15 at `/usr/local/bin/python3.12`; 7 CVEs on `python:3.12-slim-bookworm`). The official image builds CPython into `/usr/local`, so no package database lists it, and OSV's PyPI feed does not cover the interpreter. grype finds it by recognising the binary. Bedrock does not. **This is a real coverage gap**: runtimes and Go or Rust binaries that no package manager knows about are not scanned (BEDROCK_SPEC.md lists Go build info and `cargo-auditable` as in scope; neither is implemented).

**Only Bedrock:**

- *`zlib1g`, CVE-2023-45853* (one entry on both Debian-based images). The Debian tracker marks bookworm `open` for source package `zlib`, with `nodsa_reason: ignored` and the note "contrib/minizip not built and src:zlib not producing binary packages", meaning the installed binary packages are not affected. grype omits it. Bedrock does not yet read the tracker's `nodsa` fields, so it reports a false positive here. A fix is to treat `ignored` entries as not applicable; it was left because hiding tracker entries needs a decision about `postponed` and `end-of-life` entries too.

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

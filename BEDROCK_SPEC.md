# Bedrock Project Spec

**Status:** greenfield. This document is the blueprint for a new repository and
becomes that repository's `BLUEPRINT.md` on day one.

**What it is:** a command line tool that takes a container image and returns a
smaller, signed, attested replacement, with a report that proves what it removed
and why removing it was safe.

**What it is not:** a scanner. Scanners list problems. Bedrock removes them, then
proves the result still runs.

**Language:** Rust, single binary. This is a deliberate learning investment. The
author has no Rust on record and the ecosystem this tool needs (OCI, ELF parsing,
Sigstore, eBPF) is strongest in Rust. The risk is real and Section 12 accounts for it.

---

## Table of contents

1. [Problem](#1-problem)
2. [Target state](#2-target-state)
3. [Scope and non-goals](#3-scope-and-non-goals)
4. [Architecture](#4-architecture)
5. [The pipeline](#5-the-pipeline)
6. [Formats and data model](#6-formats-and-data-model)
7. [Command line and output design](#7-command-line-and-output-design)
8. [Cross-cutting concerns](#8-cross-cutting-concerns)
9. [Test strategy](#9-test-strategy)
10. [Evidence plan](#10-evidence-plan)
11. [Repository and release engineering](#11-repository-and-release-engineering)
12. [Phases](#12-phases)
13. [Security and hardening](#13-security-and-hardening)
14. [Documentation plan](#14-documentation-plan)

---

## 1. Problem

Most production container images carry far more than they run. A typical
application image built on a full distribution base ships a shell, a package
manager, compilers' runtime libraries, documentation, locales, and hundreds of
packages the entrypoint never touches. Every one of those is attack surface and
every one of those can carry a CVE.

The existing tooling splits into two camps that do not talk to each other:

- **Scanners** (SBOM generators and vulnerability matchers) tell you what is in
  the image and what is wrong with it. They do not remove anything.
- **Minimal bases** (distroless, chiselled, scratch) give you a small image if you
  rebuild from them. They do nothing for the image you already have, and they
  require you to know in advance exactly which files your application needs.

Nobody closes the loop: measure what the running application actually touches,
remove everything else, prove the result still works, and sign the proof.

That gap is the product.

---

## 2. Target state

**Bedrock** takes an image reference, a local image tarball, or a Dockerfile. It
produces:

1. A software bill of materials for the input image.
2. A vulnerability report for the input image.
3. A trace of every file the image's entrypoint opens under a representative
   workload.
4. A new image containing only reached files (or only the packages that own them).
5. A verification run proving the new image passes the same workload.
6. A signature and a provenance attestation for the new image, with the SBOM
   attached as an attestation.
7. A report showing size, package count, and CVE count before and after, with
   the evidence behind every removal.

The whole pipeline runs from one command in CI. The report attaches to a pull
request. The signed image pushes to the registry alongside the original.

### Design commitments

1. **Never emit an image that failed verification.** The prune step is only
   trusted because the verify step runs after it. If verification fails, the tool
   exits non-zero and explains which paths it missed.
2. **Every removal has evidence.** The report names each removed package or file
   and states why it was judged unreachable: not opened during trace, not a
   dynamic dependency of anything opened, not on a keep-list.
3. **Machine output is a stable contract.** JSON and SARIF outputs are versioned.
   A field is never renamed or removed within a major version.
4. **The tool eats its own cooking.** Bedrock's own release images are built,
   pruned, verified, signed, and attested by Bedrock. Its own SBOM is published.
5. **Offline by default.** Vulnerability data is a local snapshot. Network access
   is opt-in and named per command.

### Honest framing

Dynamic reachability is incomplete by construction. A code path not exercised
during the trace is a file the tool does not see. The mitigations are real but
they are mitigations: the verify step, package-level granularity as the default,
static dependency analysis unioned with the dynamic trace, keep-lists, and a
reported trace coverage figure. Bedrock is a tool for reducing an image you must
keep, not a replacement for building on a maintained minimal base when you can.

Signing is only as strong as key custody. The tool supports keyless signing in CI
and key-based signing elsewhere. It does not manage keys for you.

---

## 3. Scope and non-goals

### In scope

- Linux images in OCI or Docker v2 manifest format, single-platform, `amd64` and
  `arm64`.
- Package databases: `dpkg`, `apk`, `rpm`.
- Language ecosystems: Python (`METADATA` and `RECORD`), Node (`package.json` in
  `node_modules`), Go (embedded build info), Rust (`cargo-auditable` metadata).
- Vulnerability sources: OSV, plus the Debian, Ubuntu, and Alpine advisory feeds.
- Dynamic tracing via `ptrace` on any Linux host. eBPF tracing as a later
  upgrade on hosts that permit it.
- Output: terminal, JSON, SARIF 2.1, Markdown, single-file HTML.
- Signing: Sigstore (keyless via OIDC, or key-based), attestations in in-toto
  statement format, pushed as OCI referrers.
- A GitHub Action wrapper and a snap package.

### Non-goals

- Windows images.
- Multi-architecture manifest lists (process one platform at a time).
- Rebuilding from source. Bedrock works on the image as built.
- A hosted service, dashboard, or database. This is a CLI.
- Replacing a full scanner's advisory coverage. Bedrock matches what it needs to
  justify removals and report the delta. Deep advisory analysis stays with tools
  built for it.
- Python or other language bindings. If needed later, the JSON output is the API.

---

## 4. Architecture

One binary, one crate workspace, no daemon.

```
bedrock/
  crates/
    bedrock-cli/        clap entrypoint, output rendering, exit codes
    bedrock-oci/        registry client, OCI layout on disk, layer unpacking
    bedrock-fs/         merged filesystem view, whiteouts, file inventory
    bedrock-sbom/       package DB parsers, ecosystem parsers, SPDX + CycloneDX
    bedrock-vuln/       advisory snapshot, PURL matching, severity
    bedrock-trace/      sandbox, ptrace tracer, workload runner, ELF deps
    bedrock-prune/      reachability closure, keep-lists, image assembly
    bedrock-verify/     re-run workload against pruned image, diff outcomes
    bedrock-attest/     Sigstore signing, in-toto statements, referrer push
    bedrock-report/     report model, renderers (terminal/json/sarif/md/html)
  action/               GitHub Action (composite, calls the binary)
  snap/                 snapcraft.yaml
  corpus/               evidence corpus definitions (Section 10)
```

Each crate exposes a small typed API and owns its own errors. `bedrock-cli` is the
only crate that knows about terminals.

### Data flow

```
reference / tarball / Dockerfile
        │
        ▼
   bedrock-oci  ──► OCI layout on disk (content-addressed cache)
        │
        ▼
   bedrock-fs   ──► FileInventory (path, layer, size, mode, digest, owner pkg)
        │
        ├──► bedrock-sbom  ──► Sbom (packages, files per package, PURLs)
        │         │
        │         ▼
        │    bedrock-vuln  ──► Findings (per package: advisories, severity, fix)
        │
        ├──► bedrock-trace ──► ReachSet (opened paths + ELF closure + coverage)
        │
        ▼
   bedrock-prune ──► pruned OCI layout + RemovalEvidence
        │
        ▼
   bedrock-verify ──► VerifyResult (pass/fail, missed paths)
        │
        ├── fail ──► report + exit 2, nothing emitted
        │
        ▼
   bedrock-attest ──► signature + provenance + SBOM attestation, pushed
        │
        ▼
   bedrock-report ──► terminal / json / sarif / md / html
```

### Key decisions

- **Content-addressed local cache.** Layers are stored by digest under
  `$XDG_CACHE_HOME/bedrock/blobs/`. A second run on the same image does no
  network I/O.
- **Merged filesystem is virtual.** `bedrock-fs` never extracts a full rootfs
  unless a downstream step needs it (trace and verify do). The inventory is
  computed from tar headers plus whiteout rules.
- **Package granularity is the default prune mode.** File granularity is
  available behind `--granularity=file` and is documented as higher risk.
- **The trace sandbox is a plain process tree, not a VM.** `ptrace` requires no
  privileges beyond the ability to run the container's entrypoint in a
  user namespace. This works in CI runners. eBPF is an upgrade, not a baseline.

`ponytail:` no plugin system, no config file format beyond a flat TOML for
keep-lists, no daemon. Add any of these only when a second real user asks.

---

## 5. The pipeline

### 5.1 Ingest

Accepts three input forms, detected by argument shape:

| Input | Detection | Handling |
|---|---|---|
| `registry/repo:tag` or `@sha256:...` | contains `/` or `:` and no file exists at the path | pull manifest and layers via OCI distribution API |
| `path/to/image.tar` | file exists, tar magic | read as OCI layout or Docker save format |
| `path/to/Dockerfile` | file exists, named `Dockerfile` or ends `.Dockerfile` | build with BuildKit via `docker buildx` or `buildctl`, then treat as tarball |

Resolves the platform (`--platform`, default host). Records the input digest.
Every later artifact references this digest.

Registry auth uses the standard Docker config credential helpers. No credentials
are stored by Bedrock.

### 5.2 Inventory

Walks layers in manifest order. Applies OCI whiteout rules (`.wh.` files and
`.wh..wh..opq`). Produces a `FileInventory`: every path in the final view with
its originating layer, size, mode, and content digest.

Hard links and symlinks are recorded with their targets. Symlink resolution is
deferred to the reachability step, which needs both the link and its target.

### 5.3 SBOM

Detects package databases by well-known paths:

- `/var/lib/dpkg/status` and `/var/lib/dpkg/info/*.list` (Debian family)
- `/lib/apk/db/installed` (Alpine)
- `/var/lib/rpm/` or `/usr/lib/sysimage/rpm/` (RPM family)

Parses each into packages with name, version, architecture, and the list of
files the package owns. The file lists are the bridge to reachability: a reached
file maps to the package that owns it.

Detects language ecosystems by walking the inventory for marker files. Each
ecosystem parser yields packages with a PURL.

Emits SPDX 2.3 JSON and CycloneDX 1.5 JSON. Both include a relationship from each
package to the files it owns, because that relationship is what makes the SBOM
useful to the prune step and to anyone auditing the result.

### 5.4 Vulnerability matching

Loads a local advisory snapshot (`bedrock db update` fetches it). The snapshot
contains OSV in its native JSON plus the three distribution feeds normalised to
the same shape.

Matches by PURL and version range. Distribution packages match against their
distribution's feed first, because distributions backport fixes without changing
the upstream version string, and OSV alone produces false positives on them.

Each finding records: advisory ID, aliases (CVE IDs), severity (CVSS v3 base if
present, else the feed's own rating), whether a fixed version exists in the same
distribution release, and the package that carries it.

### 5.5 Reachability trace

This is the differentiating step.

**Setup.** Extract the merged rootfs to a temporary directory. Create a user
namespace and mount namespace. `chroot` into the rootfs. Set the image's
configured user, working directory, environment, entrypoint, and command.

**Trace.** Run the entrypoint under `ptrace`, following forks and clones.
Intercept `open`, `openat`, `openat2`, `execve`, `execveat`, `stat` family calls,
`readlink`, `access`, and `mmap` of file-backed regions. Record every absolute
path resolved, after symlink resolution, together with the syscall and the
process that made it.

**Workload.** Tracing an idle entrypoint captures startup only. The user provides
a workload in one of three ways:

- `--workload ./script.sh`: a script run from the host once the entrypoint
  reports ready (readiness by `--ready-port` or `--ready-log-pattern`).
- `--workload-http ./requests.http`: a list of HTTP requests replayed against the
  container.
- `--workload-duration 30s`: run idle for a duration. Weakest option, documented
  as such.

**Static closure.** For every executable or shared object reached, parse the ELF
headers and add `DT_NEEDED` dependencies resolved through the image's
`ld.so.conf` and `RPATH`/`RUNPATH`. For every script reached, add its interpreter
from the shebang. Union with the dynamic set.

**Coverage figure.** Report `reached_files / total_files` and, more usefully,
`reached_packages / total_packages`. Also report the set of packages that were
partially reached, which is where file-level pruning has the most risk.

**Output.** A `ReachSet`: paths, owning packages, and per-path evidence (which
syscall, which process, dynamic or static).

### 5.6 Prune

Computes the keep set:

```
keep = reached_paths
     ∪ static_closure(reached_paths)
     ∪ files_of(packages_owning(reached_paths))        [package granularity only]
     ∪ keep_list_paths
     ∪ mandatory_paths
```

`mandatory_paths` is a small built-in list that every image needs to boot and
that traces routinely miss: the dynamic loader, `libc`, `/etc/passwd`,
`/etc/group`, `/etc/nsswitch.conf`, CA certificates, timezone data if any reached
binary links to a timezone-aware library. This list is documented, versioned,
and overridable with `--no-mandatory` for people who know what they are doing.

`keep_list_paths` come from a TOML file:

```toml
[keep]
paths = ["/app/locales/**", "/usr/share/zoneinfo/Asia/**"]
packages = ["ca-certificates", "tzdata"]
```

Assembles a new OCI image: the image config copied from the input with the same
entrypoint, user, environment, and ports, and a single new layer containing the
keep set. `--preserve-layers` keeps the original layer structure and only
removes files, which preserves registry cache hits at the cost of a larger result.

Records `RemovalEvidence`: for every removed package, the reason
(`no_file_reached`, `only_docs_reached`, `not_in_closure`), and for every
removed file in file mode, the same.

### 5.7 Verify

Runs the pruned image in the same sandbox with the same workload. Compares:

- Entrypoint exit status (or, for a long-running service, readiness within
  the same timeout).
- Workload outcome (script exit status, or HTTP response status codes and
  body digests).
- Any `ENOENT` returned to the traced process during the verification run. A
  missing file that the application swallowed silently is still a missing file,
  and the report lists it as a warning even when the workload passed.

On failure, the report names every path the pruned run tried to open and could
not, and suggests the keep-list entry that would fix it. Nothing is emitted.

### 5.8 Attest

Signs the pruned image with Sigstore. In CI with an OIDC token available, keyless
signing is the default. Elsewhere, `--key` takes a cosign-compatible private key.

Produces two attestations as in-toto statements and pushes them as OCI referrers
on the pruned image:

1. **SLSA provenance** (`slsa-provenance` predicate): builder is Bedrock at
   version and digest, materials are the input image digest and the advisory
   snapshot digest, the build config is the full resolved command line including
   workload and keep-list digests.
2. **SBOM attestation** (`spdx` predicate): the SPDX document for the *pruned*
   image, so a consumer can verify what is in the thing they are pulling rather
   than the thing it came from.

A third, optional: **Bedrock report attestation**, a custom predicate carrying
the JSON report. Consumers can read the before/after delta directly from the
registry.

### 5.9 Report

One report model, five renderers. The model is the contract:

```
Report {
  schema_version, tool_version, timestamp,
  input  { reference, digest, platform, size_bytes, layers, packages, findings_by_severity },
  output { digest, size_bytes, layers, packages, findings_by_severity } | null,
  delta  { size_bytes, size_pct, packages, findings_by_severity },
  trace  { workload_kind, duration, reached_files, total_files, reached_packages,
           total_packages, partially_reached_packages[] },
  removals[]  { kind: package|file, name, reason, findings_removed[] },
  retained_unreached[]  { name, reason: keep_list|mandatory|closure },
  verify { status: pass|fail|skipped, missed_paths[], enoent_warnings[] },
  attest { signature_ref, provenance_ref, sbom_ref } | null
}
```

`retained_unreached` is the list of things the tool kept but never saw touched.
It is the user's next target for a stricter run, and it is what makes the tool
honest about its own conservatism.

---

## 6. Formats and data model

| Artifact | Format | Standard |
|---|---|---|
| Input and output images | OCI image layout | OCI Image Spec v1.1 |
| SBOM | JSON | SPDX 2.3, CycloneDX 1.5 |
| Vulnerability snapshot | JSON, one file per ecosystem | OSV schema |
| Findings export | JSON | SARIF 2.1 |
| Attestations | JSON | in-toto Statement v1, SLSA Provenance v1 |
| Signatures | OCI referrer | Sigstore bundle format |
| Keep-list | TOML | Bedrock, versioned |
| Report | JSON | Bedrock, versioned, schema published |

Package identity is a PURL everywhere internally. Distribution packages use the
`deb`, `apk`, and `rpm` PURL types with the distribution as a qualifier.

---

## 7. Command line and output design

This is the design system for a tool whose interface is a terminal.

### 7.1 Commands

```
bedrock inspect  <image>                 list layers, files, config
bedrock sbom     <image> [--format]      emit SBOM
bedrock scan     <image>                 SBOM + vulnerability findings
bedrock trace    <image> --workload ...  reachability only, no prune
bedrock slim     <image> --workload ...  full pipeline through verify
bedrock attest   <image> [--key]         sign + attest an existing image
bedrock db       update | status         advisory snapshot
bedrock report   <report.json> --format  re-render a saved report
```

`slim` is the headline command and runs everything. The others exist so each
stage is testable and usable alone.

### 7.2 Output channels

- **stdout** carries the report, in the requested format, and nothing else.
- **stderr** carries progress, logs, and diagnostics.
- Piping stdout to a file or another tool always works. Logs never corrupt it.

### 7.3 Terminal rendering

- Colour is semantic only: red for critical and high, amber for medium, blue for
  low and informational, green for pass. Never decorative.
- Honours `NO_COLOR`, `TERM=dumb`, and non-TTY stdout by rendering plain text
  with the same layout.
- Tables use fixed column widths computed from content, right-aligned numbers,
  and thousands separators. Digests are truncated to 12 characters in tables and
  printed in full in JSON.
- Progress uses a single updating line per stage on stderr. In non-TTY mode,
  each stage prints one line on start and one on finish.
- The summary block is always the last thing printed and always fits in 24 rows:

```
bedrock slim ghcr.io/example/api:1.4.2

  Input    sha256:3fa1…8c2e   187.4 MB   412 packages   CVEs  3 crit  11 high  27 med  40 low
  Output   sha256:91bd…04aa    38.1 MB    61 packages   CVEs  0 crit   1 high   3 med   5 low
  Delta                      −79.7 %   −351 packages         −3      −10      −24     −35

  Trace    workload script (14.2 s)   reached 1,203 / 18,440 files   61 / 412 packages
  Verify   PASS   0 missed paths   2 ENOENT warnings (see report)
  Attest   signed (keyless)   provenance + sbom pushed as referrers

  Retained but unreached: ca-certificates, tzdata (keep-list), libgcc-s1 (closure)
```

### 7.4 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `scan`, no findings above `--fail-on` threshold. |
| 1 | Findings above threshold (`scan`), or policy failure. |
| 2 | Verification failed. Nothing emitted. |
| 3 | Usage error. Bad arguments, missing workload. |
| 4 | Environment error. No `ptrace` permission, no network when needed, no snapshot. |
| 5 | Registry or I/O error. |

Exit codes are documented and tested. CI users depend on them.

### 7.5 Error messages

Every error states what happened, what the tool was trying to do, and what to do
next. One sentence each, in that order.

```
error: cannot trace: ptrace is not permitted in this environment
  while: starting the entrypoint sandbox for ghcr.io/example/api:1.4.2
  fix:   run with --cap-add SYS_PTRACE, or use --trace-backend=static for a static-only closure
```

### 7.6 HTML report

A single self-contained file. No external requests, so it opens offline, attaches
to a ticket, and passes any content security policy. Print stylesheet included.

Design tokens:

| Token | Light | Dark | Role |
|---|---|---|---|
| `--ground` | `#F3F1EC` | `#17191C` | page |
| `--ink` | `#1B1D21` | `#E8E6E1` | text |
| `--stone` | `#8C877D` | `#8A8578` | secondary text, rules |
| `--seam` | `#2B5F73` | `#6FB1C7` | accent, links, the "after" column |
| `--crit` | `#8E2A2A` | `#E07A7A` | critical and high |
| `--warn` | `#9A6412` | `#E5A94A` | medium |
| `--pass` | `#2F6B3C` | `#6FBE7F` | verified, removed-clean |

The name is the concept. Warm stone neutrals, one mineral blue seam as the
accent. No gradients, no cards inside cards. Severity is encoded by a shape as
well as colour (filled square for critical, half-filled for high, outline for
medium, dot for low) so the report reads in monochrome print.

Type: a humanist sans for prose, a monospace with a slashed zero for every
digest, path, and package name, and `tabular-nums` on every number. Digests and
paths are the content of this report and they must be compared character by
character.

Layout: the summary block from 7.3 rendered as the header, then two columns,
before and after, aligned row by row so the eye can compare. Below that, the
removal table, sorted by findings removed descending, each row expandable to its
evidence. Below that, `retained_unreached` and the verify detail.

---

## 8. Cross-cutting concerns

### 8.1 Configuration

Flags first, environment variables second (`BEDROCK_*`), a project-local
`bedrock.toml` third. The only things that belong in the file are keep-lists and
default workload paths. There is no global config file.

### 8.2 Logging

Structured logs to stderr via `tracing`. Human format on a TTY, JSON with
`--log-format=json`. Levels are `error`, `warn`, `info`, `debug`, `trace`.
`-v` and `-vv` map to `debug` and `trace`. Paths from inside the image are
logged verbatim; they are data, and the log renderer escapes control characters
so a hostile filename cannot forge a log line.

### 8.3 Caching

The blob cache is content-addressed and safe to share between runs and users.
The advisory snapshot is versioned by its own digest and `bedrock db status`
prints its age. A snapshot older than seven days produces a warning on every
`scan` and `slim`.

### 8.4 Concurrency

Layer downloads and layer parsing run in parallel with a bounded pool sized by
`--jobs`, default to the number of cores. The trace is single-process by
nature. Report rendering is trivial.

### 8.5 Reproducibility

Given the same input digest, the same advisory snapshot digest, the same
workload, and the same keep-list, the output image digest is identical. The
assembled layer uses fixed timestamps and sorted entries. This is tested.

---

## 9. Test strategy

### 9.1 Unit

Each crate has unit tests for its parsers and its pure logic. Parsers are tested
against fixture files committed to the repository: real `dpkg` status files,
real `apk` databases, real ELF headers, real OSV records, with the sensitive parts
removed.

### 9.2 Property-based

`proptest` on: whiteout application (random layer stacks must produce the
inventory the reference implementation produces), PURL version range matching
(random versions against random ranges must agree with a simple oracle), and
report JSON round-tripping (serialise then deserialise is identity).

### 9.3 Integration

A fixture image set built in CI from small Dockerfiles, committed as OCI layouts:

- `alpine-hello`: static binary, one package, tests the trivial path.
- `debian-python-web`: a Python web app on a full Debian base. Tests dpkg,
  Python ecosystem, dynamic closure, HTTP workload.
- `node-multi-stage`: a Node app, tests the ecosystem parser and `node_modules`
  reachability.
- `rust-static-musl`: tests that a static binary with no package DB produces a
  sensible SBOM and a near-empty prune.
- `busybox-symlink-farm`: every command is a symlink to one binary, tests
  symlink resolution in the trace.

Each fixture has a workload script and an expected report committed alongside.
The integration test runs `slim` and diffs the report against the expectation,
ignoring timestamps and tool version.

### 9.4 The invariant suite

These are build-breaking:

1. **Verify gate.** For every fixture, corrupt the keep set by removing one
   reached file, run verify, and assert it fails and names that file.
2. **Reproducibility.** Run `slim` twice on the same fixture. Output digests
   must be identical.
3. **Evidence completeness.** Every removed package in the report must have a
   reason, and every reason must be one of the documented enum values.
4. **Mandatory paths.** Every pruned image must still contain every path on the
   mandatory list unless `--no-mandatory` was passed.
5. **Nothing emitted on failure.** After a failed verify, the output path must
   not exist and the registry must not have received a push.
6. **Stdout purity.** Run every command with `--format=json` and assert stdout
   parses as JSON with nothing before or after.

### 9.5 Chaos

- Kill the traced process mid-run. The tool must report a partial trace and
  refuse to prune on it unless `--allow-partial-trace`.
- Registry returns a 429 on layer pull. The tool must back off and resume.
- Advisory snapshot file is truncated. The tool must refuse to scan with a
  clear error, not scan against half a database.

### 9.6 Self-test

Bedrock runs `slim` on its own release image as the last CI step. The pruned
image must pass verify, and the `bedrock --version` workload must produce the
same version string.

---

## 10. Evidence plan

Published numbers, not claims.

A corpus of twenty public images, chosen to span bases and languages. For each:
a documented workload, a `slim` run, and a row in a results table committed to
the repository and rendered in the README.

Columns: image, base, size before, size after, reduction percent, packages before
and after, CVEs before and after by severity, verify result, trace coverage,
runtime of the whole pipeline.

Honesty rules for the table:

- Every failure stays in the table. An image that cannot be verified is a row
  marked `FAIL` with the reason, not a row deleted.
- The workloads are committed. Anyone can rerun the corpus.
- The advisory snapshot digest used is recorded, because CVE counts change daily.

The corpus reruns weekly in CI against a fresh snapshot, and the table updates
by pull request so the history is visible.

---

## 11. Repository and release engineering

### 11.1 Repository hygiene

- `README.md` that a stranger can follow to a first `slim` in under ten minutes.
- `CONTRIBUTING.md` with the crate map, how to add a package DB parser, how to
  add a fixture.
- `CHANGELOG.md` in Keep a Changelog format, updated per release.
- Issue and pull request templates.
- A `SECURITY.md` with a disclosure address.
- MIT or Apache-2.0 dual licence, standard for Rust tooling.

### 11.2 Continuous integration

On every push: `cargo fmt --check`, `cargo clippy -D warnings`, unit and
property tests, integration tests against the fixture set, `cargo deny` for
licence and advisory checks on Bedrock's own dependencies.

On tag: build for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and
`x86_64-unknown-linux-musl` (static, the one the snap and the Action use).
Produce the release image, run the self-test from 9.6, sign everything with
keyless Sigstore, publish the SBOM, create the GitHub release with checksums.

### 11.3 Distribution

- **Binary releases** on the releases page with a `cosign verify` snippet in
  the notes.
- **Snap** (`snap install bedrock`), strictly confined, with the `docker` and
  `home` interfaces. The snap is built by CI from the tag, not by hand.
- **Container image** (`ghcr.io/…/bedrock`), pruned by itself.
- **GitHub Action** (`uses: …/bedrock-action@v1`) that installs the pinned
  binary, runs `slim`, uploads the SARIF to code scanning, and posts the
  Markdown report as a pull request comment.

### 11.4 Versioning

Semantic versioning. The JSON report schema and the SARIF mapping are part of the
public API. The CLI flags are part of the public API. Internal crate APIs are not.

---

## 12. Phases

Ordered by value per hour and by dependency. Each phase ends with something that
runs and is demonstrable on its own. Estimates assume evenings and weekends
alongside other commitments, and assume Rust is being learned during Phase 0
and Phase 1.

### Phase 0: Foundations and `inspect`

Rust toolchain, workspace layout, CI skeleton with fmt, clippy, and tests.
`bedrock-oci` pulls a manifest and layers into the content-addressed cache.
`bedrock-fs` builds the inventory with whiteouts. `bedrock inspect` lists layers
and files. The first three fixtures exist as OCI layouts in the repository.

This is where Rust is learned. The scope is deliberately narrow: tar parsing,
HTTP, a cache, one command.

**Exit criteria:** `bedrock inspect` on all committed fixtures produces the
expected file counts. CI is green. Estimated four weeks.

### Phase 1: SBOM

`dpkg`, `apk`, and `rpm` parsers with file ownership. Python and Node ecosystem
parsers. SPDX and CycloneDX writers. `bedrock sbom`. Property tests on the
parsers.

**Exit criteria:** SBOMs for all fixtures validate against the official SPDX and
CycloneDX validators. Package counts match `dpkg -l` and `apk info` run inside
the fixture. Estimated three weeks.

### Phase 2: Vulnerability matching

`bedrock db update` fetches OSV and the three distribution feeds into a
snapshot. PURL matching with backport-aware distribution precedence. `bedrock
scan` with `--fail-on`. SARIF renderer. The first Action wrapper, `scan` only.

**Exit criteria:** on the `debian-python-web` fixture, findings agree with a
reference scanner within a documented tolerance, and every disagreement is
explained in a committed note. Estimated three weeks.

### Phase 3: Reachability trace

The sandbox, the `ptrace` tracer, the three workload modes, readiness detection,
the static ELF closure, the coverage figure. `bedrock trace` outputs the reach
set as JSON.

Hardest engineering in the project. Symlink resolution, `mmap`-loaded libraries,
and processes that `exec` themselves are the known traps.

**Exit criteria:** on `busybox-symlink-farm` and `debian-python-web`, the reach
set contains every file the workload demonstrably needs (verified by hand once,
then frozen as a fixture expectation). Estimated five weeks.

### Phase 4: Prune and verify

Keep set computation, mandatory list, keep-list TOML, image assembly with fixed
timestamps, `--preserve-layers`. The verify run. `RemovalEvidence`. `bedrock slim`
end to end. The full invariant suite from 9.4.

**Exit criteria:** the verify gate test passes on every fixture. Reproducibility
test passes. `slim` on `debian-python-web` produces a pruned image that serves
the workload. Estimated four weeks.

### Phase 5: Attest

Sigstore keyless and key-based signing. SLSA provenance and SBOM attestations
as OCI referrers. `bedrock attest`. The Action gains `slim` and referrer push.

**Exit criteria:** `cosign verify` and `cosign verify-attestation` succeed on a
pruned fixture pushed to a test registry. Estimated two weeks.

### Phase 6: Reports, corpus, release

Markdown and HTML renderers. The corpus of twenty images with workloads. Weekly
corpus CI. Snap packaging. Release pipeline with self-test. README with the
results table. One long-form write-up on the reachability trace: what it catches,
what it misses, and the numbers.

**Exit criteria:** `snap install bedrock` works from the store. The corpus table
is in the README with at least fifteen `PASS` rows. The write-up is published.
Estimated four weeks.

### Phase 7: Security and hardening

See Section 13. Last phase by rule. Estimated two weeks.

### If time runs short

Phases 0 through 4 finished, documented, and released as `0.x` beat all eight
half-built. Phase 3 carries the most engineering value. Phase 6 carries the most
demonstrable value. Phase 5 is the smallest and should not be skipped, because a
tool about supply chain security that does not sign its own output is not
credible.

---

## 13. Security and hardening

**Tier: T2, Internal/Team.** Bedrock is a published tool. It handles signing
keys, runs untrusted image contents in a sandbox, and produces attestations
that downstream systems will trust. It holds no user database and runs no
service, so most T2 rows about databases, sessions, and rate limiting do not
apply and are omitted. The rows below are the ones that do, plus rows specific
to a tool of this kind.

**Scaling: none.** A CLI has no user base to scale for. No scaling rows apply.

The T1 ground rules (secrets out of git from the first commit, no secrets in
logs, dependency scanning) are enforced from Phase 0, not deferred to here.
This phase is the audit that proves they held.

### Secrets and keys

- No signing key is ever read from an environment variable that CI would echo.
  Keys come from a file path or from the OIDC keyless flow. The tool refuses a
  key passed as a flag value and explains why.
- `bedrock` never persists a credential. Registry auth is read from the standard
  credential store on each run.
- The release signing identity is keyless with an OIDC issuer pinned to the CI
  provider. The expected identity is documented in `SECURITY.md` so users can
  verify against it.
- Rotate the snap store and registry publishing tokens on a schedule and
  immediately on any suspected exposure.

### Untrusted input

- Layer tarballs are untrusted. Reject absolute paths, `..` components, and
  symlinks that escape the extraction root before writing anything to disk.
- Enforce a maximum uncompressed size per layer and per image, configurable,
  to stop decompression bombs.
- Package database parsers are fuzzed with `cargo fuzz` against malformed
  input. A hostile `dpkg` status file must produce an error, never a panic or
  unbounded memory.
- Advisory snapshot files are verified against a published digest before use.
- Paths and package names from inside the image are escaped before they reach
  any log line or terminal output, so a crafted filename cannot inject ANSI
  sequences or forge a log entry.

### Sandbox

- The trace runs in a user namespace and a mount namespace with no network
  unless `--workload-http` needs loopback, and never with host network.
- The sandbox rootfs is mounted read-only except for a scratch tmpfs at the
  paths the image config marks as volumes.
- Resource limits on the traced process tree: CPU time, memory, file
  descriptors, process count. Runaway entrypoints are killed and reported.
- The sandbox never runs as host root. Running the CLI as root prints a warning.

### Dependencies and supply chain

- `cargo deny` in CI blocks known-vulnerable and unlicensed dependencies.
- `Cargo.lock` is committed. Dependency updates arrive by pull request with the
  diff reviewed, not by unattended CI.
- Before adding any crate an AI assistant suggested, confirm it exists on
  crates.io, check download count and repository, and confirm it is the crate
  and not a lookalike name.
- Bedrock's own SBOM is published per release and its own image is pruned and
  signed by itself.

### Operations

- Release binaries and the snap are reproducible. A second build from the same
  tag produces byte-identical output, and CI asserts it.
- `SECURITY.md` names a disclosure address and a response target.
- Two-factor authentication on the source host, the registry, the snap store
  account, and the domain if one is used for documentation.
- Full error detail goes to stderr at `debug`. The default error output never
  includes host paths outside the working directory or environment variable
  values.

---

## 14. Documentation plan

The README is problem-first, not tool-first. Its order:

1. One paragraph: the gap between scanners and minimal bases, and what Bedrock
   does about it.
2. The summary block from 7.3, real output from a real image.
3. Install (snap, binary, container, Action) in four short blocks.
4. A first run in three commands.
5. The corpus results table.
6. How it works, one paragraph per pipeline stage, linking to the docs site.
7. Honest framing, verbatim from Section 2.
8. Contributing, licence, security.

The docs site (mdBook, built from `docs/`) carries: the full command reference,
the keep-list format, the report schema, the SARIF mapping, the attestation
predicates, and the write-up from Phase 6.

Every documented command has its exact output committed as a fixture and tested
in CI, so the docs cannot drift from the tool.

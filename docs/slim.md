# slim: prune and verify

`bedrock slim` traces an image (see [reachability-trace.md](reachability-trace.md)),
removes what the workload never needed, writes a new OCI image, then runs that
image under the same workload to check it still behaves the same. Like `trace`,
it needs Linux on x86-64 or arm64.

```
bedrock slim IMAGE --workload-http requests.http --ready-port 8000 -o ./slim -- python3 -m http.server 8000
bedrock slim IMAGE --workload ./smoke.sh --ready-log-pattern "listening" -o ./slim --keep-list keep.toml
```

Measured on `python:3.12-slim-bookworm` serving `http.server`: 47.6 MB to
17.6 MB (-63%), 106 to 49 packages, verification passed, and the pruned image
traced and served the same requests. Your numbers depend on your workload.

## What is kept

```
keep = reached files
     + static closure of reached programs (loader, DT_NEEDED libraries, shebang interpreters)
     + every file of any package that has a reached file          [--granularity package, default]
     + keep-list paths and packages
     + the mandatory list                                          [unless --no-mandatory]
     + every directory, and the targets of kept symlinks and hard links
```

- `--granularity file` keeps only the reached files of a package. It is smaller
  and riskier: a program that works on the traced path can break on the next.
- A package whose only reached files are docs (`usr/share/doc`, `man`, `info`)
  is removed (`only_docs_reached`). Tools that merely `stat` a doc do not keep it.
- Directories are always kept. They cost nothing, and removing one breaks mount
  points, `/tmp` and permissions.
- Ownership and modes are preserved. Timestamps are set to the Unix epoch.
  Extended attributes (for example file capabilities) are not carried over.

### Keep-list

```toml
[keep]
paths = ["/app/locales/**", "/usr/share/zoneinfo/Asia/**"]
packages = ["ca-certificates", "tzdata"]
```

Globs: `*` and `?` match within one path segment, `**` matches any number of
segments. When verification fails, the report prints a ready-to-paste `paths`
line for each missing file.

### Mandatory list (version 1)

Files every image needs and traces routinely miss, kept unless `--no-mandatory`:
`/etc/passwd`, `group`, `nsswitch.conf`, `hosts`, `resolv.conf`, `os-release`,
`localtime`; `/etc/ssl` and CA certificates; the dynamic loader; libc; glibc's
`dlopen`ed `libnss_*` modules; and the package databases (`/var/lib/dpkg`,
`/lib/apk/db`, rpm). Timezone data under `/usr/share/zoneinfo` is not on the
list: keep it with the keep-list if your program needs it.

## Package databases

Removing a package's files without editing the database would leave `dpkg -l`
and every scanner reporting it. So `slim` rewrites dpkg `status` (and drops the
package's `info/` files), apk `installed`, and the SQLite rpm database
(`rpmdb.sqlite`: Fedora, RHEL, Rocky and Alma 9, Amazon Linux 2023), deleting each
removed package's row and its index rows the way `rpm -e --justdb` would.
**Berkeley DB and NDB rpm databases** (RHEL 7 and 8, openSUSE) are not rewritten:
on those images the pruned SBOM still lists removed packages, and the report says so.

## Output

`-o DIR` is an OCI image layout, written only if verification passes. The
default is one new layer; `--preserve-layers` keeps the layer structure and
reuses untouched layers byte for byte, which keeps registry cache hits at the
cost of size. The image config is copied (entrypoint, user, environment, ports,
labels) with build time and container details removed.

The same input, workload outcome, keep-list and options give a byte-identical
image. The trace itself is not deterministic, so a workload that behaves
differently between runs can give a different keep set.

## Verify

The pruned image runs in the same sandbox with the same workload. It must match:

- the entrypoint's exit status, or, for a service, that it stayed up
- the script's exit code, or each HTTP request's status **and** body digest
- (reported as warnings even on a pass) any `ENOENT` the pruned run hit that the
  original did not

On failure `slim` writes nothing, prints the paths the pruned run could not
find, and exits 2. A response body that legitimately changes between runs
(timestamps, ids) will fail the digest check: point `--workload-http` at
stable endpoints.

Pruning refuses to start from a trace that looks incomplete (workload script
failed, an HTTP request failed or returned 5xx, the entrypoint crashed or was killed by a signal, the run
timed out) unless you pass `--allow-partial-trace`.

## Report

`--report FILE` writes the JSON report (`--format json` prints it). It is the
`scan` report plus `output`, `delta`, `trace`, `removals[]` (each package or file
removed, why, and which findings went with it), `retained_unreached[]` (kept
though never touched: your next target for a stricter run), and `verify`.
Finding counts need an advisory snapshot (`bedrock db update`); without one,
`slim` still prunes and says the counts are missing.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pruned image written and verified (or `--no-verify`) |
| 1 | Error, including a trace that looks incomplete |
| 2 | Verification failed; nothing written |
| 3 | Usage error (workload flags) |
| 4 | Environment: no ptrace or user namespaces, unsupported host |

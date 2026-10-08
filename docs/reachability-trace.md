# Reachability trace: what it catches and misses

`bedrock trace` runs an image's entrypoint under Linux `ptrace`, drives it with
a workload, and reports which image files it touched (the "reach set"). It
needs Linux on x86-64 or arm64. On macOS or Windows, run it in a Linux
container with `--cap-add SYS_PTRACE --cap-add SYS_ADMIN --security-opt
seccomp=unconfined --security-opt apparmor=unconfined`.

## Usage

```
bedrock trace IMAGE --workload-duration 30s
bedrock trace IMAGE --workload-http requests.http --ready-port 8000
bedrock trace IMAGE --workload ./smoke.sh --ready-log-pattern "listening"
bedrock trace IMAGE --workload-duration 5s -- python3 -c 'print(1)'   # replace Cmd
```

Give exactly one workload (else exit 3).

- `--workload SCRIPT`: run on the host once the entrypoint is ready. The port
  is passed as `$BEDROCK_PORT`. Needs `--ready-port` or `--ready-log-pattern`.
- `--workload-http FILE`: replay a `.http` file (`METHOD target`, headers, blank
  line, body, requests separated by `###`) against `127.0.0.1:--ready-port`.
  Status codes and body digests are recorded.
- `--workload-duration T`: wait. This captures startup and idle behaviour only,
  and is the weakest option.

When the workload ends, Bedrock sends SIGTERM to the process group (so
shutdown paths are traced), and SIGKILL after 3 seconds. `--timeout` (default
10m) bounds the whole run. The JSON reach set goes to stdout or `--output`.
The entrypoint's own output goes to stderr.

## How it works

1. The merged image filesystem is extracted to a temporary directory.
   Symlinks are resolved inside that directory, so a hostile layer cannot write
   outside it.
2. A child process gets a mount namespace (plus a user namespace when you are
   not root, mapping the image user onto you), chroots into the rootfs, sets the
   image's user, working directory and environment, and execs the entrypoint
   under ptrace. Host `/proc` and a few `/dev` nodes are bind-mounted in.
3. Every syscall that names a file is decoded and recorded with the process that
   made it: `open`, `openat`, `openat2`, `execve`, `execveat`, `stat`, `lstat`,
   `newfstatat`, `statx`, `access`, `faccessat`, `faccessat2`, `readlink`,
   `readlinkat`, and `mmap` of file-backed regions. Forks, vforks and clones are
   followed. Nothing is recorded until the first `exec`.
4. Each path is resolved through symlinks. Every symlink crossed is reached too,
   because a pruned image that keeps `libc.so.6` but not the link to it is broken.
5. Static closure: for each reached ELF file, `PT_INTERP` and `DT_NEEDED`
   libraries are added (searching `RPATH`/`RUNPATH`, `LD_LIBRARY_PATH`,
   `/etc/ld.so.conf`, and the default directories). For each reached script,
   the shebang interpreter is added, including `env`-style ones.
6. Coverage is reported as reached files over total files, reached packages
   over total packages, and the packages reached only in part.

Each path in the output says whether it was found `dynamic`, `static` or
`both`, with the syscall and process (or `DT_NEEDED`/`PT_INTERP`/`shebang` and
the file that needs it) as evidence. Paths the program looked for and did not
find (`ENOENT`) are listed under `missing`; `verify` will use them.

## Limits you should know about

- **Not a security sandbox.** Only the filesystem view and credentials are
  isolated. Network, process and IPC namespaces are shared with the host, because
  HTTP workloads need the network and signals must reach the process. Do not
  trace an image you do not trust on a machine you care about.
- **Code paths the workload does not run are missed.** An error handler that
  opens a config file, a plugin loaded by `dlopen` with a computed name, a
  Python module imported lazily, a Node `require` in a branch never taken: none
  of these appear unless the workload triggers them.
- **`stat` counts as reached.** `ls /usr/bin` stats every entry, so it marks them
  all. This errs toward keeping files.
- **Files the kernel opens for the process are covered statically, not
  dynamically.** The ELF interpreter and shebang interpreters are mapped by
  `execve` itself; the static closure supplies them.
- **x86-64 programs using the 32-bit `int 0x80` syscall path** are not decoded.
- **Ownership is flattened.** Extracted files belong to the image user (or to
  you), not to their original owners. A program that depends on file ownership
  may behave differently than in a real container.
- **Hosts that restrict unprivileged user namespaces** (Ubuntu 24.04 by
  default) make `trace` fail with exit 4 unless you run as root or set
  `kernel.apparmor_restrict_unprivileged_userns=0`.
- The sandbox directory is under `TMPDIR`. A `noexec` temp directory stops the
  entrypoint from starting.

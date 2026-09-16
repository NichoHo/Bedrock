# Reachability Trace: What it Catches, What it Misses, and the Numbers

## Overview
Bedrock’s reachability trace leverages Linux `ptrace` to dynamically observe what files an application touches during a workload run. This trace constructs the "ReachSet" which forms the baseline of the pruning phase.

## Status

Reachability tracing is currently a stub. The descriptions of `ptrace` hooking, symlink-chain resolution, static `DT_NEEDED` dependencies, and dynamic shared library capture represent the target architecture from Phase 3 of the project specification.

At present, tracing returns an empty `ReachSet` and does not actually perform the operations listed below.

## Planned Features

- **Direct file opens:** Standard `open` and `openat` syscalls.
- **Library loading:** `mmap` calls that map shared objects (.so files) into executable memory.
- **Execution:** `execve` and `execveat` syscalls for tracing subprocesses and scripts.
- **Symlinks:** All symlinks in a resolved chain will be automatically included.
- **Static Dependencies:** `DT_NEEDED` segments from all reached ELF binaries will be statically resolved.

## Planned Limitations

- **Conditional paths:** If the workload does not exercise a specific code path (e.g., an error handler that opens a specific log configuration), the trace will miss it.
- **Dlopen by name:** If an application dynamically loads plugins using `dlopen` without explicit linkage, and those plugins aren't loaded during the workload, they will be missed.
- **JIT & Interpreters:** Interpreted languages that lazily load modules (like Python's `import` or Node's `require`) will only pull what they execute. If a module is never imported during the trace, it will be removed.

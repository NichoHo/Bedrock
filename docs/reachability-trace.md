# Reachability Trace (planned): What it Will Catch and Miss

## Overview
Bedrock's reachability trace is meant to use Linux `ptrace` to dynamically observe
what files an application touches during a workload run, building a "ReachSet"
that the pruning phase uses as its baseline.

## Status

Not implemented. `bedrock trace` and `bedrock slim` both exit 4 ("not
implemented"). The descriptions below are the target design from Phase 3 of
[`BEDROCK_SPEC.md`](../BEDROCK_SPEC.md), not a description of current
behavior — there is no numbers section here yet because there's nothing to
measure.

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

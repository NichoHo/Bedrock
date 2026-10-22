# Bedrock

Container scanners tell you what is wrong with an image. Minimal base images only
help if you rebuild from one. Nobody closes the loop: measure what an image's
entrypoint actually touches, remove the rest, and prove the result still works.

Bedrock is a command-line tool for that gap. It traces a container workload,
removes what the workload never reached, verifies the result, and signs the proof.

```
bedrock slim python:3.12-slim \
  --workload-http requests.http --ready-port 8000 \
  -o ./slim --report slim.json -- python3 -m http.server 8000
```

## Where to start

- [Reachability trace](reachability-trace.md): how `trace` decides what a workload used, and what it misses.
- [Slim](slim.md): how `slim` prunes, assembles and verifies.
- [Attest](attest.md): signing and attaching provenance and an SBOM.
- [Scan comparison](scan-comparison.md): `scan` against grype, with every difference explained.
- [Corpus](corpus.md): 21 public images slimmed and verified, with the numbers.

## What to keep in mind

Dynamic tracing is incomplete by construction. Code the workload does not run is
not seen. A pass means your workload still works, not that the image is safe to
ship. See the limits in each page, and the
[README](https://github.com/NichoHo/Bedrock#limits-you-should-know-about) for the
full list.

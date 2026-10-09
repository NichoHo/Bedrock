# Corpus results

18 of 18 images pass: `bedrock slim` exits 0 and the pruned image verifies (same exit status, same HTTP status and body digest as the original, under the same workload).

| Entry | Image | Result | Size MB | Change | Packages | Findings | Files reached | Notes |
|---|---|---|---:|---:|---:|---:|---:|---|
| python-http | `python:3.12-slim-bookworm` | **PASS** | 45.4 to 16.0 | -64.7% | 106 to 49 | 265 to 133 | 107/5052 |  |
| python-alpine-http | `python:3.12-alpine` | **PASS** | 19.7 to 6.8 | -65.6% | 39 to 12 | 7 to 1 | 97/2377 |  |
| python-imports | `python:3.12-slim-bookworm` | **PASS** | 45.4 to 15.1 | -66.8% | 106 to 36 | 265 to 106 | 59/5052 |  |
| node-alpine-http | `node:22-alpine` | **PASS** | 57.9 to 47.3 | -18.2% | 215 to 9 | 22 to 0 | 7/2587 |  |
| node-slim-http | `node:22-slim` | **PASS** | 76.1 to 51.6 | -32.3% | 285 to 39 | 251 to 104 | 12/5772 |  |
| nginx-alpine | `nginx:alpine` | **PASS** | 25.1 to 5.1 | -79.5% | 71 to 14 | 6 to 2 | 29/1231 |  |
| httpd-alpine | `httpd:alpine` | **PASS** | 22.2 to 3.8 | -82.7% | 41 to 14 | 1 to 0 | 38/2286 |  |
| caddy | `caddy:alpine` | **PASS** | 23.7 to 19.5 | -17.9% | 180 to 157 | 2 to 1 | 6/235 |  |
| whoami-scratch | `traefik/whoami` | **PASS** | 4.9 to 4.6 | -5.2% | 9 to 9 | 12 to 12 | 1/605 |  |
| busybox-httpd | `busybox:stable` | **PASS** | 2.1 to 2.1 | -1.2% | 0 to 0 | 0 to 0 | 7/420 |  |
| redis-alpine | `redis:7-alpine` | **PASS** | 15.5 to 9.7 | -37.4% | 19 to 11 | 21 to 20 | 11/702 |  |
| memcached-alpine | `memcached:alpine` | **PASS** | 5.7 to 5.0 | -12.3% | 20 to 11 | 1 to 0 | 8/106 |  |
| alpine-shell | `alpine:3.20` | **PASS** | 3.5 to 3.1 | -9.4% | 14 to 10 | 0 to 0 | 11/87 |  |
| debian-shell | `debian:12-slim` | **PASS** | 26.9 to 9.2 | -66.0% | 88 to 28 | 230 to 80 | 12/3265 |  |
| ubuntu-dpkg | `ubuntu:24.04` | **PASS** | 28.4 to 9.0 | -68.2% | 92 to 9 | 0 to 0 | 16/2587 |  |
| ruby-alpine | `ruby:3.3-alpine` | **PASS** | 37.6 to 17.1 | -54.4% | 21 to 9 | 1 to 1 | 130/2612 |  |
| php-cli-alpine | `php:8-cli-alpine` | **PASS** | 42.6 to 13.9 | -67.5% | 41 to 28 | 2 to 2 | 29/818 |  |
| golang-version | `golang:1.23-alpine` | **PASS** | 74.5 to 7.6 | -89.8% | 18 to 7 | 152 to 94 | 2/13512 |  |

## How this was measured

- One `bedrock slim` per entry of `corpus/corpus.toml`, run with `scripts/corpus.py` on x86-64 Linux in a Docker container as root, on 2026-10-09. Image tags are whatever was current that day.
- Advisory snapshot `a22d035c3863`. Finding counts are Bedrock's own `scan` of the image before and after; they include unrated and unfixed Debian entries, and Go modules and standard library read from Go binaries.
- `traefik/whoami` uses `/health` because its `/` page echoes the client's ephemeral port, so the body differs on every request and can never verify.
- The weekly workflow (`.github/workflows/corpus.yml`) reruns this against a fresh snapshot and publishes the table.

## Reading it honestly

- **A pass proves the workload still works, not that the image is safe to ship.** `golang:1.23-alpine` shrinks 89.8% because the workload is `go version`, which touches two files. It would not compile anything afterwards. Use a workload that covers what you run.
- **Entries with `duration` workloads capture startup and idle behaviour only.** The HTTP entries exercise one request.
- **Small images shrink little.** Alpine, busybox and memcached have little to remove; static single-binary images such as `traefik/whoami` have nothing but the binary.
- **`node:22-alpine` and `caddy:alpine` keep most of their size** because the runtime binary is most of the image.
- **Compiled-in modules count as packages** (`caddy:alpine` goes from 180 to 157 "packages", most of them Go modules in one binary). They are pruned per file, never as a group.

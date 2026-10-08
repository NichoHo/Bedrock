# Corpus results

18 of 18 images pass: `bedrock slim` exits 0 and the pruned image verifies (same exit status, same HTTP status and body digest as the original, under the same workload).

| Entry | Image | Result | Size MB | Change | Packages | Findings | Files reached | Notes |
|---|---|---|---:|---:|---:|---:|---:|---|
| python-http | `python:3.12-slim-bookworm` | **PASS** | 45.4 to 16.8 | -63.1% | 106 to 49 | 265 to 133 | 107/5052 |  |
| python-alpine-http | `python:3.12-alpine` | **PASS** | 19.7 to 7.1 | -64.1% | 39 to 12 | 7 to 1 | 97/2377 |  |
| python-imports | `python:3.12-slim-bookworm` | **PASS** | 45.4 to 15.7 | -65.3% | 106 to 36 | 265 to 106 | 59/5052 |  |
| node-alpine-http | `node:22-alpine` | **PASS** | 57.9 to 49.0 | -15.3% | 215 to 9 | 22 to 0 | 7/2587 |  |
| node-slim-http | `node:22-slim` | **PASS** | 76.1 to 53.5 | -29.7% | 285 to 39 | 251 to 104 | 12/5772 |  |
| nginx-alpine | `nginx:alpine` | **PASS** | 25.1 to 5.3 | -78.7% | 71 to 14 | 6 to 2 | 29/1231 |  |
| httpd-alpine | `httpd:alpine` | **PASS** | 22.2 to 4.0 | -82.0% | 41 to 14 | 1 to 0 | 38/2286 |  |
| caddy | `caddy:alpine` | **PASS** | 23.7 to 20.0 | -15.5% | 32 to 9 | 1 to 0 | 6/235 |  |
| whoami-scratch | `traefik/whoami` | **PASS** | 4.9 to 4.6 | -5.2% | 0 to 0 | 0 to 0 | 1/605 |  |
| busybox-httpd | `busybox:stable` | **PASS** | 2.1 to 2.1 | -1.2% | 0 to 0 | 0 to 0 | 7/420 |  |
| redis-alpine | `redis:7-alpine` | **PASS** | 15.5 to 10.0 | -35.4% | 19 to 11 | 21 to 20 | 11/702 |  |
| memcached-alpine | `memcached:alpine` | **PASS** | 5.7 to 5.1 | -9.1% | 20 to 11 | 1 to 0 | 8/106 |  |
| alpine-shell | `alpine:3.20` | **PASS** | 3.5 to 3.3 | -5.8% | 14 to 10 | 0 to 0 | 11/87 |  |
| debian-shell | `debian:12-slim` | **PASS** | 26.9 to 9.6 | -64.2% | 88 to 28 | 230 to 80 | 12/3265 |  |
| ubuntu-dpkg | `ubuntu:24.04` | **PASS** | 28.4 to 9.5 | -66.7% | 92 to 9 | 0 to 0 | 16/2587 |  |
| ruby-alpine | `ruby:3.3-alpine` | **PASS** | 37.6 to 17.4 | -53.7% | 21 to 9 | 1 to 1 | 130/2612 |  |
| php-cli-alpine | `php:8-cli-alpine` | **PASS** | 42.6 to 14.4 | -66.2% | 41 to 28 | 2 to 2 | 29/818 |  |
| golang-version | `golang:1.23-alpine` | **PASS** | 74.5 to 7.9 | -89.5% | 17 to 6 | 107 to 49 | 2/13512 |  |

## How this was measured

- Run with `scripts/corpus.py` over `corpus/corpus.toml`, one `bedrock slim` per entry, on x86-64 Linux in a Docker container as root, on 2026-10-09. Image tags are whatever was current that day.
- Advisory snapshot `a22d035c3863`. Finding counts are Bedrock's own `scan` of the image before and after; they include unrated and unfixed Debian entries.
- Two entries were re-run after a fix: `traefik/whoami` first failed because the `/` endpoint echoes the client's ephemeral port (so its body differs on every request), and now uses `/health`; `busybox` came out 2% larger until the pruned layers used maximum gzip.
- The weekly workflow (`.github/workflows/corpus.yml`) reruns this against a fresh snapshot and publishes the table.

## Reading it honestly

- **A pass proves the workload still works, not that the image is safe to ship.** `golang:1.23-alpine` shrinks 89.5% because the workload is `go version`, which touches two files. It would not compile anything afterwards. Use a workload that covers what you run.
- **Entries with `duration` workloads capture startup and idle behaviour only.** The HTTP entries exercise one request.
- **Small images shrink little.** Alpine, busybox and memcached have little to remove; static single-binary images such as `traefik/whoami` have nothing but the binary.
- **`node:22-alpine` and `caddy:alpine` keep most of their size** because the runtime binary is most of the image.

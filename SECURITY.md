# Security Policy

## Supported versions

Bedrock is in early development and has no stable release yet.
Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue.

Use GitHub's private vulnerability reporting: on the repository page, open
the **Security** tab and choose **Report a vulnerability**. You will get a
reply within 7 days.

Useful reports include a way to reproduce the issue, such as a crafted image,
archive or package database. Bedrock reads untrusted container images, so
parser crashes, path escapes and terminal-escape injection are in scope.

## Release signing identity

Bedrock can sign and attest images with `bedrock attest` (key-based). Its own
releases are not signed yet. Until they are, release binaries carry only a
SHA-256 checksum file. That proves the download is intact, not who built it.

## What the tracing sandbox is not

`bedrock trace` and `bedrock slim` run an image's entrypoint under `ptrace` in a
chroot and mount namespace. That isolates the filesystem and credentials only.
Network, process and IPC namespaces are shared with the host, so it is not a
security boundary. Run them on a throwaway host for images you do not trust.

# Security Policy

## Supported versions

Bedrock is in early development (Phase 0/1) and has no stable release yet.
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

Release signing is planned for Phase 5 and is not implemented yet. Until then,
release binaries carry only a SHA-256 checksum file. That proves the download
is intact, not who built it.

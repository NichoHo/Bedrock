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

Bedrock can sign and attest images with `bedrock attest` (key-based).

No release has been published yet. From the first tagged release, the release
workflow signs every asset and the container image keylessly with cosign
(Sigstore), and the signature is recorded in the Sigstore transparency log. The
signing identity is the workflow on its tag:

- identity: `https://github.com/NichoHo/Bedrock/.github/workflows/release.yml@refs/tags/vX.Y.Z`
- issuer: `https://token.actions.githubusercontent.com`

Each release asset has a `.sigstore.json` bundle next to it. To check one:

```
cosign verify-blob --bundle bedrock-x86_64-unknown-linux-musl.sigstore.json \
  --certificate-identity "https://github.com/NichoHo/Bedrock/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  bedrock-x86_64-unknown-linux-musl
```

The `.sha256` files only prove a download is intact, not who built it.

## What the tracing sandbox is not

`bedrock trace` and `bedrock slim` run an image's entrypoint under `ptrace` in a
chroot and mount namespace, under resource limits. That isolates the filesystem and
credentials, and the network for plain timed runs. Process and IPC namespaces are
shared with the host, and script and HTTP workloads share the host's network, so it
is not a security boundary. Run them on a throwaway host for images you do not trust.

# Bedrock's own release image: a static musl binary on a minimal base. CI slims
# this image with Bedrock itself and checks `bedrock --version` still works
# (scripts/self-test.sh), so the tool eats its own cooking.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p bedrock && cp target/release/bedrock /bedrock

FROM alpine:3.20
COPY --from=build /bedrock /usr/local/bin/bedrock
ENTRYPOINT ["/usr/local/bin/bedrock"]

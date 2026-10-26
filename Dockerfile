# A small image for CI systems without a Rust toolchain (Jenkins, Azure
# DevOps, GitLab CI). The binary is static (musl); Alpine stays underneath so
# CI runners that need a shell in the job container (Jenkins `inside`, GitLab
# `image:`) can use it.
#
#   docker run --rm -v "$PWD:/src" ghcr.io/erwinquantum/shorwatch scan

FROM rust:1.99-alpine3.22 AS build
# tree-sitter grammars are C code.
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY shorwatch-core shorwatch-core
COPY shorwatch-rules shorwatch-rules
COPY shorwatch-langs shorwatch-langs
COPY shorwatch-report shorwatch-report
COPY shorwatch-cli shorwatch-cli
RUN cargo build --release --locked --bin shorwatch

FROM alpine:3.22
LABEL org.opencontainers.image.title="shorwatch" \
      org.opencontainers.image.description="Find quantum-vulnerable cryptography in Java, Kotlin and Spring code and configuration" \
      org.opencontainers.image.source="https://github.com/ErwinQuantum/shorwatch" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /build/target/release/shorwatch /usr/local/bin/shorwatch
# Root by default so reports can be written into any mounted workspace; pass
# `--user "$(id -u):$(id -g)"` to keep file ownership on Linux hosts.
WORKDIR /src
ENTRYPOINT ["shorwatch"]
CMD ["scan", "."]

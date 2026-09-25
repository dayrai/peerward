# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG RUST_VERSION=1.95.0
FROM rust:${RUST_VERSION}-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
ARG RUST_VERSION
ARG CARGO_BUILD_JOBS=2
# The pinned base already provides the build toolchain; host-only lint components
# in rust-toolchain.toml do not need downloading for every image rebuild.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
ARG SOURCE_DATE_EPOCH=0
ENV CARGO_INCREMENTAL=0 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY apps/peerward-console/Cargo.toml apps/peerward-console/Cargo.toml
COPY apps/peerward-ui ./apps/peerward-ui
COPY apps/peerward-android-ui ./apps/peerward-android-ui
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release -p peerward-cli && \
    install -Dm0755 target/release/peerward /out/peerward

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS peerward-runtime
LABEL org.opencontainers.image.source="https://github.com/dayrai/peerward" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="Peerward unified runtime" \
      org.opencontainers.image.ref.name="ghcr.io/dayrai/peerward"
RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 65532 peerward && \
    useradd --uid 65532 --gid 65532 --home-dir /var/lib/peerward --no-create-home --shell /usr/sbin/nologin peerward && \
    install -d -o 65532 -g 65532 -m 0755 /var/lib/peerward /run/peerward /etc/peerward
COPY --from=build --chown=65532:65532 /out/peerward /usr/local/bin/peerward
COPY third_party /usr/share/doc/peerward/third_party
USER 65532:65532
WORKDIR /var/lib/peerward
EXPOSE 8080 7777 7778 9090
ENTRYPOINT ["peerward"]

FROM peerward-runtime AS control
ARG VERSION=0.1.0
LABEL org.opencontainers.image.ref.name="ghcr.io/dayrai/peerward:${VERSION}-control" \
      io.peerward.image.role="control"
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:9090/readyz"]

FROM peerward-runtime AS relay
ARG VERSION=0.1.0
LABEL org.opencontainers.image.ref.name="ghcr.io/dayrai/peerward:${VERSION}-relay" \
      io.peerward.image.role="relay"
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:9090/readyz"]

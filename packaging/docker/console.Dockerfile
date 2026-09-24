# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG RUST_VERSION=1.95.0
FROM rust:${RUST_VERSION}-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
ARG RUST_VERSION
ARG CARGO_BUILD_JOBS=2
# The pinned base already provides the build toolchain; host-only lint components
# in rust-toolchain.toml do not need downloading for every image rebuild.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
ARG WASM_BINDGEN_VERSION=0.2.100
ARG SOURCE_DATE_EPOCH=0
ENV CARGO_INCREMENTAL=0 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /src
COPY rust-toolchain.toml ./
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    set -eu; \
    retry() { \
        attempt=1; \
        until "$@"; do \
            if [ "${attempt}" -ge 5 ]; then return 1; fi; \
            sleep "$((attempt * 2))"; \
            attempt="$((attempt + 1))"; \
        done; \
    }; \
    retry rustup target add wasm32-unknown-unknown; \
    retry cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/peerward-console ./apps/peerward-console
COPY apps/peerward-ui ./apps/peerward-ui
COPY apps/peerward-android-ui ./apps/peerward-android-ui
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release -p peerward-console --features ssr && \
    apps/peerward-console/build-web.sh && \
    install -Dm0755 target/release/peerward-console /out/peerward-console && \
    cp -a apps/peerward-console/dist /out/dist

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS console
ARG VERSION=0.1.0
LABEL org.opencontainers.image.source="https://github.com/dayrai/peerward" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="Peerward Console" \
      org.opencontainers.image.ref.name="ghcr.io/dayrai/peerward:${VERSION}-console" \
      io.peerward.image.role="console"
RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 65532 peerward && \
    useradd --uid 65532 --gid 65532 --home-dir /var/lib/peerward --no-create-home --shell /usr/sbin/nologin peerward && \
    install -d -o 65532 -g 65532 -m 0750 /var/lib/peerward /run/peerward
COPY --from=build --chown=65532:65532 /out/peerward-console /usr/local/bin/peerward-console
COPY third_party /usr/share/doc/peerward/third_party
COPY --from=build --chown=65532:65532 /out/dist /usr/share/peerward-console
ENV PEERWARD_CONSOLE_LISTEN=0.0.0.0:8081 \
    PEERWARD_CONSOLE_ASSET_DIR=/usr/share/peerward-console
USER 65532:65532
WORKDIR /var/lib/peerward
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8081/"]
ENTRYPOINT ["peerward-console"]

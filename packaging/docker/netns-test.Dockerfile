FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       build-essential ca-certificates iproute2 iputils-ping nftables pkg-config \
    && rm -rf /var/lib/apt/lists/*

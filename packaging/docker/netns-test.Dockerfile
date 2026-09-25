FROM ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       build-essential ca-certificates iproute2 iputils-ping nftables pkg-config \
    && rm -rf /var/lib/apt/lists/*

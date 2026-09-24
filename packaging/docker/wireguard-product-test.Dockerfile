# Isolated test fixture. Build the pinned netns-test Dockerfile first.
FROM peerward-netns-test:ubuntu26
RUN apt-get update && apt-get install --yes --no-install-recommends \
    python3 python3-cryptography openssl procps conntrack tayga iperf3 \
    && rm -rf /var/lib/apt/lists/*

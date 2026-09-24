FROM peerward-update-systemd-test:local
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd-resolved ca-certificates iproute2 nftables polkitd && rm -rf /var/lib/apt/lists/*

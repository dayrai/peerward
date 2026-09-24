# Test fixture only; the base is built from the pinned netns-test Dockerfile.
FROM peerward-netns-test:ubuntu26
RUN apt-get update && apt-get install --yes --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

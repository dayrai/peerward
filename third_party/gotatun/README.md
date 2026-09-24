Peerward uses the unmodified `gotatun` crate, version **0.9.2**, under MPL-2.0.

- Upstream: https://github.com/mullvad/gotatun
- Corresponding source: https://crates.io/api/v1/crates/gotatun/0.9.2/download
- Upstream commit: `ad58de51e859f458384fe4759eabdff478a6b133`
- License: the accompanying `LICENSE`, retained verbatim from that commit.
- Build: default features disabled; only `ring` enabled. Peerward supplies its
  own platform and carrier adapters; GotaTun's device, socket and TUN drivers
  are not enabled.

The dependency version and archive checksum are pinned in `Cargo.lock`.
The license exception in `deny.toml` applies to this version only. Peerward's
own files remain Apache-2.0. Distributions must include this directory so
recipients receive the license and corresponding source location.

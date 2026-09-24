# Reviewed fuzz inputs

Run `python3 scripts/seed-fuzz-corpus.py` to copy these files into ignored
`fuzz/corpus/` directories without overwriting existing or minimized inputs.
All seven targets in [Cargo.toml](../Cargo.toml) have initial seeds, so a fresh
checkout can run both smoke and nightly checks.

The credential `authority-shape` seed is a synthetic 144-byte authority record:
two fixed UUIDv4 values, a repeated public-key field, validity 1–2 and a zero
signature. It exercises decoding, not successful trust verification, and contains
no private key. `nat-pmp-map` is the fixed mapping response used by the mapping
codec regression (internal 41000, external 42000, lifetime 3600).
`wss-endpoint` exercises endpoint parsing and canonical serialization.

`wire_reassembly_update/release-manifest` is a synthetic, unsigned 0.1.0
manifest with an intentionally unusable download URL and digest. It exercises
candidate validation at publication/expiry, sequence rollback and schema bounds;
it is not a release artifact. The harness derives compatibility inputs from each
document instead of pinning a retired product or protocol version.

The other packet, STUN, reassembly and QUIC seeds retain boundary and regression
cases. The empty STUN/WireGuard input deliberately tests short-input rejection.
These seeds and the browser screenshot baselines are maintained test inputs;
generated corpora, crash artifacts and test reports remain ignored.

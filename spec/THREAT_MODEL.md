# Peerward threat model

## Protected assets

Peerward protects Peer identity, mesh membership, virtual packet and service
confidentiality/integrity, address ownership, policy/signed-state integrity,
credential/update ordering, administrative sessions, and audit authenticity.

## Trust and adversaries

The offline root, endpoint kernels, Android Keystore, configured OIDC issuer,
Control signing keys, and PostgreSQL integrity are trusted as scoped. Internet,
Relay operators, other Peers, upstream DNS, telemetry collectors, and update
transport are untrusted. A compromised admitted Peer is restricted to its own
identity/address and policy permissions. Denial of service is bounded, not
eliminated.

## Relay disclosure boundary

Relay can observe connection addresses, authenticated source/destination Peer
IDs, mesh, opaque frame class/length, timestamps, duration, and byte volume.
It cannot observe decrypted IP versions/addresses, ports, DNS names/messages,
Service content, or application payload. Memory/crash diagnostics must never
contain plaintext frames. Peerward is not an anonymity network and does not
hide communication relationships or traffic analysis.

## Required controls

Strict parsing/checksums, bounded non-overlapping fragment reassembly,
authenticated source-IP verification, endpoint policy, replay windows,
signalled generation changes, fail-closed hard key limits, signed monotonic
state, transactional audit/outbox, OIDC PKCE/CSRF, CSP nonce/security headers,
non-exportable Android key wrapping, default-deny deployment policy, and
monotonic signed updates address the identified threats.

Payload-free Peer denial/anomaly summaries are encrypted to an
Authority-certified Control X25519 key and signed by the enrolled Ed25519 Peer
identity. Relay sees only the already disclosed source, Mesh, audit frame class,
length, timing, and volume. A forged database row, client-supplied source, key
substitution, ciphertext replay, or altered batch fails source/signature/HPKE
verification or the transactional batch-ID uniqueness check.

HTTP clients preflight `Content-Length` when present and otherwise stream at
most `limit + 1` bytes before strict UTF-8/JSON decoding. Console accepts only a
credential-free HTTP(S) origin with no query, fragment, or subpath, strips all
hop-by-hop and `Connection`-nominated headers, and enforces 5-second connect,
15-second request, and 45-second SSE-idle deadlines. These bounds prevent a
trusted-but-stalled or malicious Control from forcing unbounded allocation.

SSE parsing is byte-oriented across arbitrary chunks: UTF-8 sequences, CRLF,
and field state remain incomplete until a whole event is delimited. The parser
fails above 256 KiB, and its replay set retains at most 1024 event IDs. Durable
high-water capture plus stream-before-snapshot ordering prevents both initial
load and expired-cursor reset races.

Signed distributions are independently chunked below the Noise record bound;
each family has separate assembly state, at most 1024 chunks, and an 32 MiB total
limit. Mixed revisions, duplicate chunks, over-bound totals, and incomplete or
invalid bodies never replace the last verified state.

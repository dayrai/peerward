# Wire 5 credential and profile contract

This is the migration contract, not a release-readiness claim. The implementation
and outstanding runtime work are tracked in
[`wireguard-migration-status.zh-CN.md`](../docs/analysis/wireguard-migration-status.zh-CN.md).

## Independent keys

Each Peer credential generation owns three independently generated keys: an
Ed25519 identity key, a Noise X25519 Relay authentication key, and a WireGuard
X25519 data key. The WireGuard public key is contributory (zero and low-order
points are rejected) and differs from the other two public keys. Relay credentials reserve the identity and WireGuard fields as
32 zero bytes. They retain their Noise key and do not become WireGuard endpoints.

## Subject credential

The exact encoding is 225 bytes. No 193-byte credential is accepted. Integers
are unsigned big-endian; UUIDs are the 16 network-order UUIDv4 bytes.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | Role: Peer 1, Relay 2 |
| 1 | 16 | Mesh UUID |
| 17 | 16 | Subject UUID |
| 33 | 32 | Ed25519 identity public key |
| 65 | 32 | Noise public key |
| 97 | 32 | WireGuard public key |
| 129 | 16 | Exact credential serial |
| 145 | 8 | Inclusive not_before, Unix seconds |
| 153 | 8 | Exclusive not_after, Unix seconds |
| 161 | 64 | Authority Ed25519 signature |

The signature transcript is `peerward/subject-credential/v3` followed by one NUL
byte and encoding bytes 0 through 160. The Root/Authority trust chain, role,
Mesh, exact serial revocation and time checks are mandatory.

## Join and rotation

Join request schema is 2. `wireguard_public_key` is a required 32-byte unpadded
Base64URL value, alongside `identity_public_key` and `session_public_key`.
The identity-signed transcript begins with `peerward/join-claim/v2` and NUL,
then schema u32, claim UUID, ticket SHA-256, identity/Noise/WireGuard public keys,
Wire major u32, and the length-prefixed client version, nonce, device name,
device model, platform and platform version, in that order. Each length is u32.
The client verifies that all three issued public keys match its own keys before
persisting the response. Replay continues to bind the whole signed transcript.

The rotation request domain is `peerward/credential-rotation/request/v2` and NUL,
followed by Mesh UUID, Peer UUID, rotation UUID, current serial, and new
identity/Noise/WireGuard public keys. Protobuf rotation request tag 7 carries
the new WireGuard public key. The activation proof remains unchanged: the
new identity signs the exact issued serial and one-time challenge. An OIDC
management session cannot request replacement Peer private keys.

## Signed directory

The entry domain is `peerward/peer-directory-entry/v4` and NUL. After the primary
address encoding, the transcript includes a secondary-address discriminator:
0 for absent, 4 followed by four IPv4 octets, or 6 followed by sixteen IPv6
octets. If present, the secondary address is in the other family and belongs
exclusively to that Peer. Duplicate ownership or same-family secondary values
are rejected. All remaining fields keep their order; the accepted-credential section is
a u32 count followed by complete 225-byte subject credentials, sorted by serial.
Each credential is followed by a one-byte overlap tag: 0 for active, or 1 and
an eight-byte exclusive overlap deadline. The remaining enabled, labels and
not_after fields retain their encoding. There is exactly one active binding
and at most one previous binding. A previous deadline is later than not_before
and no later than not_after. Active summary fields must match the active binding.

JSON `accepted_credentials` contains objects with `serial`, `identity_public_key`,
`noise_public_key`, `wireguard_public_key`, `not_before`, `not_after`,
`overlap_until` and `signature`. Bare serials, duplicate keys, duplicate serials,
missing active credentials and reused WireGuard keys across Peers are rejected.
A pending or staged credential is not published as authorized.

The Authority signature in each binding is retained so the runtime can verify
Root authorization independently of the directory signature before installing
a key. A signed directory revision alone cannot authorize public-key substitution.
Revocation and expiry remove the exact generation; any valid replacement and
unrelated Peer remain eligible. Starting a third generation retires the oldest
previous generation in the same transaction as activation and revocation revision.

## Persistence and compatibility

Wire major 5, persistent schema compatibility 4, Linux Peer configuration 4,
Android profile/envelope 4 and Android key-record schema 3 are mandatory. Control
and shared Relay configuration syntax remains version 2. Older device profiles
must rejoin; there is no implicit Noise-key-to-WireGuard conversion.

Migration 0018 adds nullable columns only to preserve historical rows. NULL
legacy keys are excluded from new admission and directory projections; they
are never synthesized. Fresh keys have strict constraints and per-Mesh unique
indexes. Historical migrations remain immutable. Signed state is bounded to
32 MiB and 1024 chunks, with each chunk body at most 48 KiB.

Linux persists `peer.identity.key`, `peer.key`, `peer.wireguard.key` and
`peer.credential`. The three next private keys and a `requested` journal are
durable before the request is sent. Recovery reuses the exact request UUID,
keys and proof, including after a crash before issuance. All four next files
and a `staged` journal precede activation.
After observing the exact signed active binding, a committing journal precedes
file renames; recovery completes a started commit or preserves a complete staged
transaction for authenticated replacement redelivery. A stage is never deleted
merely because the client restarted: activation may already have happened on the
server. A cached signed directory allows recovery when directory delivery precedes
replacement delivery. Parent directories are synced before journal removal. Private in-memory
rotation material is zeroized on drop.

If activation completed remotely before a crash, Linux tries the staged identity
before loading the possibly expired committed identity. Recovery authenticates a
Relay with the candidate's Noise key, verifies Root/Authority and distribution
bindings, and requires both signed Peer directory and revocation state. Only the
exact locally held credential published as active may commit. Directory and
revocation delivery may arrive in either order; overlap-only, revoked, expired,
cross-Mesh or key-substituted credentials cannot authorize commit. All three
private/public bindings and the staged credential are rechecked before the
existing four-file transaction. A three-second network budget preserves the
unactivated old-identity activation flow when recovery cannot yet confirm it.
A trusted Mesh termination is persisted and blocks recovery.

Android creates an independent software WireGuard scalar in Rust and wraps it
with a separate Keystore AES key and authenticated public-key binding. Kotlin
stores only wrapped material and the public key. All three pending public keys
and the key-record identity participate in the existing atomic profile commit.
The optional `pending_credential` field stores the exact verified replacement,
as unpadded Base64URL, before the activation proof is sent. It does not replace
the committed identity. Before opening TUN, Android may construct an in-memory
candidate profile, authenticate using its protected keys, and apply the same
shared directory/revocation commit predicate. Failed recovery leaves the staged
record intact; successful atomic commit clears it. VPN stop, network changes and
profile deletion cancel the startup owner and dispose of its temporary carriers.

This recovery requires an activated, still-valid candidate and usable persisted
Root/Authority trust. A candidate never activated before its predecessor expired
cannot activate itself. Recovery across unavailable/expired Authority trust remains
a separate release requirement.

Both production runtimes attach a Root/Mesh/Peer-bound private checkpoint before
TUN data or carrier ownership becomes available. The checkpoint stores independent
revision and SHA-256 digest floors for Authority, Peer, policy, revocation, service
and Relay snapshots. Complete signature, identity and semantic validation precedes
atomic write, file fsync, rename and parent-directory fsync; publication follows.
An older revision or different canonical signed contents at the same revision is
rejected. Identical signed state may be revalidated and restored after restart.
A legitimate initial revision 0 is distinct from an absent snapshot. Data and DNS
stay closed until Peer, policy and revocations are restored, plus any persisted
Authority floor. Rotation recovery uses the same guard but does not require policy.

Linux uses `private_key_file.with_extension("wireguard-state")`; Android uses the
app-private `noBackupFilesDir/wireguard/<mesh>/<peer>` directory. An exclusively locked
stable `owner.lock` inode prevents simultaneous owners, and an initialization marker
rejects missing committed state. Corrupt files, identity mismatches, unsafe permissions,
symlinks and failed durable writes fail closed. A failed write clears sessions,
queued plaintext, output authorizations and policy visibility. Closing the owner
releases the lock; rotation, underlay changes and profile removal do not reset history.
No credentials, private keys, candidate addresses or packet data are stored here.

Exact subject and Authority revocations remain sticky when a newer bundle omits
serials, including across restart and local key rotation. The checkpoint bounds history
to 1,000,000 subject serials, 65,536 Authority serials and 48 MiB encoded state; capacity
exhaustion fails closed without evicting revocations. Stored time floors advance on
signed-state commits, startup and observed credential expiry. This prevents reversing
an already observed expiry, but does not supply a trusted wall clock while powered off.
An attacker able to restore the entire device filesystem (including all checkpoints)
can still roll back local history: hardware monotonic storage is not implemented.
Backup restoration must retain current history or use a fresh device enrollment.

Versioned updates persist the verified artifact digest and signed compatibility
ranges before changing the current symlink. Automatic rollback rejects missing
metadata, changed artifact bytes, versions below the signed rollback floor and
any candidate outside the current schema/Wire ranges.

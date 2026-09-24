# Wire v4 state machine

```text
DISCONNECTED
  -> LINK_HANDSHAKE (5 s timeout, global/per-IP permits)
  -> LINK_AUTHENTICATED (exact Wire major 5 and active/overlap credential)
  -> WIREGUARD_HANDSHAKE (standard packets over authenticated Relay)
  -> WIREGUARD_ACTIVE (receiver-index lookup, replay window, engine timers)
  -> WIREGUARD_REKEY (same credential and path-independent state)
  -> WIREGUARD_ACTIVE

any state -> REMOVE_EXACT_CREDENTIAL on trusted revocation or expiry
any state -> CLOSED on verified Mesh deletion or shutdown
malformed, unauthenticated or replayed packets are discarded without teardown
```

Direct and Relay path changes do not change the Peer session state. A direct
failure changes only the outer carrier. Link key replacement uses a separate
parallel link and drains the previous link after routing switch.

```text
ROTATION_IDLE
  -> REQUEST_SIGNED_BY_CURRENT(mesh, peer, rotation, old serial, new Ed, new Noise X, new WireGuard X)
  -> PENDING_WITH_CHALLENGE
  -> STAGED_CREDENTIAL_ISSUED
  -> ACTIVATION_SIGNED_BY_NEW(issued serial, one-time challenge)
  -> ACTIVE_WITH_OLD_OVERLAP + AUDIT/OUTBOX
  -> EXACT_SIGNED_DIRECTORY_OBSERVED
  -> LOCAL_FOUR_ARTIFACT_COMMIT

any repeated edge with identical canonical fields -> same result
any repeated rotation/ticket identity with different fields -> conflict/close
```

Join likewise commits ticket consumption and the canonical response document
in one database transaction. A retry with the same UUIDv4 claim ID and signed
transcript returns the stored response bytes; no live issuer state is needed
for replay.

```text
LOCAL_DENIAL/ANOMALY -> BOUNDED_AGGREGATE(direction, reason, count)
  -> HPKE_PREPARED(mesh, authenticated peer, UUIDv4 batch, observed_at)
  -> IDENTITY_SIGNED
  -> RELAY_BOUNDED_INBOX (opaque only)
  -> CONTROL_SOURCE+SIGNATURE+HPKE_VERIFIED
  -> PROCESSED_BATCH + IMMUTABLE_AUDIT + INBOX_DELETE (one transaction)

same batch ID -> no duplicate audit rows
invalid source/signature/ciphertext/time -> bounded retry then discard + metric
```

# Incident response

## Triage

Preserve timestamps, request/event IDs, version/image digests, signed
revisions, PostgreSQL timeline, fence generations, and rate-limited metadata
audit. Do not collect private keys, join tokens, session cookies, plaintext
packets, or full database dumps into general ticket systems.

Classify whether the incident affects control identity, database integrity,
relay availability/fencing, endpoint compromise, policy distribution, DNS,
release supply chain, or root custody. Freeze only the mutations and ingress
needed to contain the affected boundary.

## Containment

- Revoke exact peer/relay credential serials and disable affected identities.
- For an online authority, stop ticket claims/issuance, activate a clean
  authority, rotate its subjects and distribution keys, then revoke it.
- For a relay, disable it in control and wait for stale fence rejection before
  trusting replacement traffic.
- For a bad release, stop rollout, verify signatures/provenance, use package or
  updater rollback only when the database schema remains compatible.
- For PostgreSQL compromise, isolate control/relays, preserve evidence, and
  restore a tested consistent backup rather than editing audit history.

## Recovery and follow-up

Re-establish root-to-authority-to-subject trust, advance signed revisions,
invalidate flow/session state, rotate tickets/sessions, verify primary/standby
and cross-relay paths, and monitor denial/fencing/outbox behavior. Record the
timeline, affected UUIDs/serials, recovery point, user impact, and permanent
controls. Treat root compromise as explicit re-anchoring/re-enrollment.

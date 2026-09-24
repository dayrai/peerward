# Key rotation and revocation

Keep the root offline and encrypted with documented quorum/recovery custody.
Routine rotation uses a new online authority key and root certificate with an
explicit overlap interval. Stage it, distribute the rooted certificate, mark
it active, issue replacement peer/relay credentials, verify adoption, then end
overlap and revoke the old authority serial.

Subject rotation creates a new UUIDv4 credential serial and may overlap the
old credential briefly. Revoke the exact old serial only after the replacement
is observed on primary and standby sessions. Exact matching prevents an old
revocation from disabling the replacement.

Each Peer credential generation has its own WireGuard data key, separate from
the device signing identity and Relay Noise key. The signed directory binds
each active/overlap credential to its public key, validity, and overlap
deadline. A candidate/address change only updates path state; it does not
rotate credentials or replace the WireGuard session.

Device rotation stages the new keys, proves activation, observes the new
credential in the signed directory, and atomically commits the profile/key
transaction. Linux recovers interrupted identity-file transactions before
startup. Android keeps wrapped WireGuard material under its own Keystore alias
and recovers pending rotation from encrypted profile metadata. A trusted
revocation removes only the corresponding credential's engine state and
pending traffic; valid replacements remain usable.

Directory and service verifier changes require a new authority-signed
distribution certificate. Ship the certificate and verifier pair atomically;
clients reject unbound keys. Advancing policy/directory revisions invalidates
return-flow state so old authorization cannot survive replacement.

For suspected authority compromise, stop issuance, remove public ticket claim
ingress, activate a separately protected authority, revoke the compromised
authority serial, rotate every credential it issued, replace distribution
keys, and inspect audit/outbox history. Root compromise requires a new mesh
trust anchor and deliberate re-enrollment; do not silently replace a pinned
root fingerprint.

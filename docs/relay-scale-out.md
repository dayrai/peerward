# Scale from one Relay to multiple Relays

1. Generate a new Relay identity on the destination host. Never copy the old
   Relay private key or reuse its Relay ID.
2. Register the new Peer and backbone endpoints in Control, then deploy the
   Relay with its own read-only identity Secret.
3. Verify private `/livez`, `/readyz`, database access, certificate serial, and
   current signed-state revision before exposing Peer traffic.
4. Verify the topology API reports the Relay online/present and observe Peer
   adoption. Do not infer or collect Peer-to-Peer direct edges.
5. Exercise a controlled failure of the original Relay and confirm Peers
   reconnect with bounded backoff and healthy signed state.
6. Restore both Relays and observe a stable adoption window. Only then disable
   the old Relay in Control.
7. Wait for presence to drain, stop its process, close ingress/firewall rules,
   revoke its credential, and archive its audit evidence. Destroy its private
   key under the local key-destruction policy.

Never replace an identity in place. If readiness, signed state, or failover is
not healthy, re-enable the previous Relay and stop the procedure.

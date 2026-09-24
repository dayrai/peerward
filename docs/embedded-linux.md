# Embedded Linux, Alpine, OpenWrt, and containers

Peerward can manage host split DNS without D-Bus. Keep the network recovery
journal on persistent local storage and choose the least invasive available
backend. `dns_backend = "auto"` probes systemd-resolved, a named and usable
NetworkManager profile, openresolv, then guarded `resolv.conf` management.

An OpenWrt peer normally installs `kmod-tun`, `ip-full`, `nftables`, and
`resolveip`, enables `/dev/net/tun`, and uses:

```toml
nat_mapping = "auto"
symmetric_nat_prediction = false
relay_pool_size = 3

[linux]
interface = "pwd0"
address = "10.94.0.10/24"
routes = ["10.94.0.0/24"]
dns_suffix = "mesh.peerward"
dns_server = "10.94.0.1"
dns_backend = "resolv_conf"
resolv_conf_path = "/tmp/resolv.conf.d/resolv.conf.auto"
platform_state_file = "/etc/peerward/network-state-v1.json"
mtu = 1280
```

On Alpine, install `iproute2`, `nftables`, `openresolv`, and `tun`; prefer
`dns_backend = "openresolv"`. The legacy spelling `open_resolv` remains accepted
during rolling upgrades. If openresolv is absent, select
`resolv_conf` explicitly only after confirming that `resolv_conf_path` is a
regular writable resolver file with at least one nonlocal upstream.

For a host-network container, grant `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`
(the latter permits the managed DNS listener on port 53), pass
`/dev/net/tun`, mount the selected resolver path at the same absolute path, and
mount `/var/lib/peerward` read/write. All other config and identity mounts stay
read-only. Peerward first captures nonlocal upstream nameservers and preserves
`search` and `options`. A normal file is atomically replaced; a bind-mounted
file may require guarded in-place replacement, which occurs only after the
mode-0600 recovery journal is fsynced.

Recovery is compare-and-swap: Peerward reverts a value only while the installed
value still equals its own replacement. If DHCP, an init script, or an operator
changed it, recovery preserves that value, retains diagnostic state, and stops
automatic takeover. Resolve the ownership conflict, restore a working upstream,
then restart. Do not delete the journal before inspecting it.

To roll back, stop the Peer gracefully and verify the journal disappeared. If
the process was killed, restart the same or newer binary once so `recover`
runs before removing the package. Confirm the original resolver content,
routes, nftables table, and TUN device, then archive the service logs and only
then remove the binary.

With `nat_mapping = "auto"`, the Peer maps the already-bound direct UDP port and
tries PCP, NAT-PMP, then UPnP. DHCP/default-route changes force discovery from a
clean mapping state. PCP/NAT-PMP epoch rollback is a gateway-restart signal;
Peerward withdraws the stale candidate, rediscovers, and retains Relay fallback.
An expired lease is never advertised while recovery retries continue.

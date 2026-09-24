"""Console API -> signed configuration -> actual isolated Linux TUN traffic."""
import uuid
import lab


def verify(installation, base, client, gateway, call, probe, echo, report):
    # Separate target avoids changing any other scenario's route/deny shadows.
    address = "192.168.81.11"
    namespace = "console-lan"
    lab.run("ip", "netns", "add", namespace)
    lab.run("ip", "-n", namespace, "link", "set", "lo", "up")
    lab.run("ip", "-n", gateway["namespace"], "link", "add", "consolelan0", "type", "veth", "peer", "name", "edge0", "netns", namespace)
    for ns, interface, cidr in [(gateway["namespace"], "consolelan0", "192.168.81.1/24"), (namespace, "edge0", address + "/24")]:
        lab.run("ip", "-n", ns, "link", "set", interface, "up")
        lab.run("ip", "-n", ns, "address", "add", cidr, "dev", interface)
    echo(namespace, address, "console-lan-echo.log")
    identity = str(uuid.uuid4())
    draft = {
        "request_id": identity, "name": "console-printer", "provider": gateway["peer_id"],
        "target": {"kind": "network", "definition": {"name": "console-printer", "target": {
            "kind": "subnet", "prefix": address + "/32", "site_id": str(uuid.uuid4())}},
            "dns_name": None, "dns_address": None},
        "source": {"kind": "peer", "id": client["peer_id"]},
        "protocol": 17, "port": 52002, "reason": "Isolated console TUN acceptance",
    }
    preview = call(installation, base + "/console/sharing/preview", "POST", draft)
    submitted = {"draft": draft, "preview_digest": preview["digest"]}
    result = call(installation, base + "/console/sharing/apply", "POST", submitted, preview["version"])
    retry = call(installation, base + "/console/sharing/apply", "POST", submitted, preview["version"])
    assert result == retry
    lab.wait(lambda: probe(client, address, "192.168.81.1"), "console-created grant reaches real LAN", 60)
    grants_path = base + f"/console/network-resources/{identity}/grants"
    for enabled in (False, True):
        grant = call(installation, grants_path)["items"][0]
        assert not grant["advanced"]
        call(installation, grants_path + "/" + grant["id"], "PUT",
             {"enabled": enabled, "reason": "Validate signed grant application"}, grant["version"])
        lab.wait(lambda: probe(client, address) == enabled,
                 "console grant restored" if enabled else "console grant revoked blocks packets", 60)
    for paused in (True, False):
        current = call(installation, base + f"/network-resources/{identity}")
        call(installation, base + f"/console/resources/{identity}/state", "PUT",
             {"paused": paused, "reason": "Validate real pause and resume"}, current["version"])
        lab.wait(lambda: probe(client, address) != paused,
                 "console pause blocks packets" if paused else "console resume restores packets", 60)
    report["scenarios"].append("console_atomic_create_retry_grant_revoke_restore_pause_resume_real_TUN_LAN")

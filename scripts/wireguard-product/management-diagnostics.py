"""Owned network fixture: real TCP target evidence and stopped-profile switching."""
import json
import signal
import tomllib
import lab


def catalog_command(catalog, operation, *args, check=True):
    return lab.run(lab.BINARY, "client", "profiles", operation, "--catalog", catalog, *args, check=check)


def start_catalog(peer, catalog):
    peer["child"] = lab.spawn(["ip", "netns", "exec", peer["namespace"], lab.BINARY,
                              "peer", "run", "--catalog", catalog], peer["profile"] / "catalog-runtime.log")
    lab.wait(lambda: lab.query(peer, "health").get("tun_up") is True or peer["child"].poll() is not None,
             "catalog runtime TUN creation")
    assert peer["child"].poll() is None


def start_saved(installation, mesh):
    peer = lab.configure(installation, mesh, 0, start=False)
    catalog = lab.BASE / "saved-networks"
    catalog_command(catalog, "save", "--name", "Office", "--config", peer["profile"] / "peer.toml")
    start_catalog(peer, catalog)
    assert catalog_command(catalog, "deactivate", check=False).returncode != 0
    assert catalog_command(catalog, "select", "--name", "Office", check=False).returncode != 0
    return peer, catalog


def verify_switch(installation, peer, catalog, report):
    # Caller has explicitly recovered the killed old runtime in its original netns.
    old_config = (peer["profile"] / "peer.toml").read_bytes()
    mesh = installation.create("saved-secondary")
    other = lab.configure(installation, mesh, 4, start=False)
    catalog_command(catalog, "save", "--name", "Home", "--config", other["profile"] / "peer.toml")
    catalog_command(catalog, "select", "--name", "Home")
    start_catalog(other, catalog)
    lab.wait(lambda: lab.query(other, "health").get("tun_up") is True, "selected network active")
    assert catalog_command(catalog, "select", "--name", "Office", check=False).returncode != 0
    other["child"].send_signal(signal.SIGINT)
    assert other["child"].wait(timeout=30) == 0
    catalog_command(catalog, "select", "--name", "Office")
    assert (peer["profile"] / "peer.toml").read_bytes() == old_config
    assert json.loads(catalog_command(catalog, "list").stdout)["active"] == peer["peer_id"]
    report["scenarios"].append("saved_catalog_real_start_exclusive_lock_clean_switch_and_identity_preservation")


def target_health(installation, base, resource, call, report):
    endpoint = base + "/network-resources/" + resource["id"]
    current = call(installation, endpoint)
    definition = current["definition"]
    definition["health_probe"] = {"address": "192.168.80.10", "port": 52003}
    call(installation, endpoint, "PUT", definition, current["version"])
    script = "import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('192.168.80.10',52003));s.listen()\nwhile True:\n c,a=s.accept();c.settimeout(3);assert c.recv(1)==b'';c.close();print('connect_without_payload',flush=True)"
    server = lab.spawn(["ip", "netns", "exec", "managed-lan", "python3", "-u", "-c", script], lab.OUT / "target-probe-server.log")
    def observed(expected):
        value = call(installation, endpoint + "/health")
        return len(value["bindings"]) == 2 and all(b["status"] == expected for b in value["bindings"])
    lab.wait(lambda: observed("reachable"), "both approved gateways report live TCP target", 90)
    (lab.OUT / "target-health-reachable.json").write_text(json.dumps(call(installation, endpoint + "/health"), indent=2))
    server.terminate(); server.wait(timeout=5)
    lab.wait(lambda: observed("refused"), "target failure independent of transport HA", 75)
    (lab.OUT / "target-health-refused.json").write_text(json.dumps(call(installation, endpoint + "/health"), indent=2))
    current = call(installation, endpoint)
    definition.pop("health_probe")
    call(installation, endpoint, "PUT", definition, current["version"])
    assert observed("unknown")
    report["scenarios"].append("signed_gateway_target_TCP_evidence_no_payload_failure_and_configuration_fencing")


def device_conditions(installation, base, client, gateway, call, probe, report):
    version = tomllib.loads((lab.ROOT / "release.toml").read_text())["product_version"]
    endpoint=base+"/device-conditions"
    def observation(peer):
        return call(installation,base+"/peers/"+peer["peer_id"]+"/device-condition")
    lab.wait(lambda:observation(client)["evidence"] is not None and observation(gateway)["evidence"] is not None,"Linux signed software evidence",60)
    current=call(installation,endpoint)
    definition=current["definition"]
    definition.update(enabled=True,minimum_version=version,scope={"peers":[client["peer_id"],gateway["peer_id"]]},platforms=["linux"],required_capabilities=["managed_dns"])
    current=call(installation,endpoint,"PUT",definition,current["version"])
    assert observation(client)["decision"]["allowed"]
    lab.wait(lambda:probe(client,"192.168.80.10","192.168.80.1"),"admitted subnet remains usable",60)
    definition["minimum_version"]="9.0.0"
    current=call(installation,endpoint,"PUT",definition,current["version"])
    lab.wait(lambda:not probe(client,"192.168.80.10"),"quarantine blocks actual subnet traffic",60)
    (lab.OUT/"device-condition-quarantine.json").write_text(json.dumps(observation(client),indent=2))
    assert observation(client)["decision"]["reasons"]==["version"]
    definition["minimum_version"]=version
    current=call(installation,endpoint,"PUT",definition,current["version"])
    lab.wait(lambda:probe(client,"192.168.80.10","192.168.80.1"),"admission recovery without reenrollment",60)
    definition["enabled"]=False
    call(installation,endpoint,"PUT",definition,current["version"])
    report["scenarios"].append("Linux_signed_software_evidence_admission_quarantine_actual_LAN_drop_and_recovery")

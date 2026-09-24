"""HA fault injection only inside the management gate's owned network namespaces."""
import json
import signal
import time
import lab


def attach(backup, namespace, interface, primary_address, target_address, backup_address,
           primary_v6, target_v6, backup_v6):
    run = lab.run
    run("ip", "-n", namespace, "link", "add", "shared", "type", "bridge")
    run("ip", "-n", namespace, "address", "del", target_address, "dev", "edge0")
    run("ip", "-n", namespace, "address", "del", target_v6, "dev", "edge0")
    run("ip", "-n", namespace, "link", "set", "edge0", "master", "shared")
    run("ip", "-n", namespace, "link", "set", "shared", "up")
    for address in (target_address, target_v6):
        run("ip", "-n", namespace, "address", "add", address, "dev", "shared", "nodad")
    run("ip", "-n", backup["namespace"], "link", "add", interface, "type", "veth",
        "peer", "name", "edge1", "netns", namespace)
    run("ip", "-n", namespace, "link", "set", "edge1", "master", "shared")
    run("ip", "-n", namespace, "link", "set", "edge1", "up")
    run("ip", "-n", backup["namespace"], "link", "set", interface, "up")
    for address in (backup_address, backup_v6):
        run("ip", "-n", backup["namespace"], "address", "add", address, "dev", interface, "nodad")


def verify(client, primary, backup, probe, local, report):
    def healthy():
        paths = local(client, "preferences")["gateway_paths"]
        return len(paths) >= 6 and all(path["health"] == "healthy" for path in paths)

    lab.wait(healthy, "both approved providers have authenticated healthy paths", 60)
    started = time.monotonic()
    primary["child"].send_signal(signal.SIGSTOP)
    stream = None
    try:
        def failed_over():
            view = local(client, "preferences")
            with (lab.OUT / "ha-path-observations.log").open("a") as log:
                log.write(json.dumps({"elapsed":round(time.monotonic()-started,3),"view":view}) + "\n")
            return probe(client, "1.1.1.1", "10.206.0.3")
        lab.wait(failed_over, "exit HA after three failed probes", 30)
        report["ha_failover_observed_seconds"] = round(time.monotonic() - started, 3)
        lab.wait(lambda: probe(client, "192.168.80.10", "192.168.80.2"), "LAN IPv4 backup")
        lab.wait(lambda: probe(client, "fd80::10", "fd80::2"), "LAN IPv6 backup")
        lab.wait(lambda: probe(client, "2606:4700:4700::1111", "fd20:6::3"), "exit IPv6 backup")
        log = lab.OUT / "ha-sticky-flow.log"
        script = """import json,socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
while True:
 try:
  s.sendto(b'sticky',('1.1.1.1',52002));print(json.dumps({'source':s.recv(128).decode()}),flush=True)
 except OSError as error: print(json.dumps({'error':type(error).__name__}),flush=True)
 time.sleep(1)
"""
        stream = lab.spawn(["ip", "netns", "exec", client["namespace"], "python3", "-u", "-c", script], log)
        lab.wait(lambda: log.exists() and '"source": "10.206.0.3"' in log.read_text(), "persistent flow starts on backup")
        primary["child"].send_signal(signal.SIGCONT)
        lab.wait(lambda: probe(client, "1.1.1.1", "10.206.0.2"), "new exit connections return after recovery stability", 70)
        samples = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        received = [sample for sample in samples if "source" in sample]
        timeouts = [sample for sample in samples if "error" in sample]
        # Clearing already-encrypted queued output can lose a datagram. The connection
        # guarantee is provider affinity, not loss-free UDP delivery during convergence.
        assert len(received) >= 20 and all(sample["source"] == "10.206.0.3" for sample in received), samples
        assert len(timeouts) <= 3 and samples[-1].get("source") == "10.206.0.3", samples
        report["ha_sticky_backup_samples"] = len(received)
        report["ha_sticky_udp_timeouts"] = len(timeouts)
        report["scenarios"].append("dual_stack_LAN_and_exit_HA_three_failures_recovery_window_and_sticky_backup_flow")
    finally:
        for index, peer in enumerate((client, backup)):
            (lab.OUT / f"ha-final-{index}.json").write_text(json.dumps({
                "preferences":local(peer, "preferences"),
                "metrics":lab.query(peer, "metrics"),
                "routes4":lab.run("ip", "-n", peer["namespace"], "-4", "route", "show", "table", "all").stdout,
                "routes6":lab.run("ip", "-n", peer["namespace"], "-6", "route", "show", "table", "all").stdout,
            }, indent=2))
        primary["child"].send_signal(signal.SIGCONT)
        if stream is not None and stream.poll() is None:
            stream.terminate()
            stream.wait(timeout=5)

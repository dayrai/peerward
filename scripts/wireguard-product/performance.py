"""Five real iperf3 rounds with product process and Relay-host accounting."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request

import lab


def ping_summary(output):
    for line in reversed(output.splitlines()):
        if " = " not in line or not line.startswith("rtt "):
            continue
        values = line.split(" = ", 1)[1].split()[0].split("/")
        if len(values) == 4:
            try:
                minimum, average, maximum, deviation = map(float, values)
            except ValueError:
                return None
            return {"minimum_ms": minimum, "average_ms": average,
                    "maximum_ms": maximum, "deviation_ms": deviation}
    return None


def resources(peers):
    pids = [peer["child"].pid for peer in peers] + [int((lab.BASE / "relay.pid").read_text())]
    result = []
    for pid in pids:
        proc = Path("/proc") / str(pid)
        stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        result.append({"rss_pages": int((proc / "statm").read_text().split()[1]),
                       "cpu_ticks": int(stat[11]) + int(stat[12]), "fds": len(list((proc / "fd").iterdir()))})
    counters = json.loads(lab.run("nft", "-j", "list", "table", "inet", "fixture_meter").stdout)["nftables"]
    return {"processes": result, "relay_host_l3_bytes": sum(item["counter"].get("bytes", 0) for item in counters if "counter" in item)}


def measure(peers, index, seconds, streams):
    """Keep partial iperf output and live diagnostics even if the client hangs."""
    path = lab.OUT / f"performance-{index}-client.json"
    with path.open("w") as output:
        client = subprocess.Popen(["ip", "netns", "exec", peers[0]["namespace"], "iperf3",
            "-c", peers[1]["address"], "-p", "24445", "-t", str(seconds), "-P", str(streams), "-J"],
            stdout=output, stderr=subprocess.STDOUT)
        lab.children.append(client)
        started = time.monotonic()
        timed_out = False
        try:
            with (lab.OUT / f"performance-{index}-observations.jsonl").open("w") as observations:
                while client.poll() is None:
                    elapsed = time.monotonic() - started
                    with urllib.request.urlopen("http://127.0.0.1:28991/readyz", timeout=2) as response:
                        relay_health = response.read(65_536).decode()
                    observations.write(json.dumps({"elapsed_seconds": elapsed, "relay_health_response": relay_health,
                        "peers": [{"status": lab.query(peer, "status"), "metrics": lab.query(peer, "metrics"),
                                   "tcp": lab.run("ip", "netns", "exec", peer["namespace"], "ss", "-tin", check=False).stdout,
                                   "links": json.loads(lab.run("ip", "-s", "-j", "-n", peer["namespace"], "link").stdout)}
                                  for peer in peers]}) + "\n")
                    observations.flush()
                    if elapsed >= seconds + 20:
                        timed_out = True
                        client.send_signal(signal.SIGINT)
                        try:
                            client.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            client.kill()
                            client.wait(timeout=3)
                        break
                    try:
                        client.wait(timeout=min(5, seconds + 20 - elapsed))
                    except subprocess.TimeoutExpired:
                        pass
        finally:
            if client.poll() is None:
                client.kill()
            client.wait(timeout=3)
    return client.returncode, timed_out, path.read_text()


def run(peers, rounds, seconds, streams=1):
    for index, peer in enumerate(peers):
        peer["child"] = lab.spawn(["ip", "netns", "exec", peer["namespace"], lab.BINARY, "peer", "run", "--config", peer["profile"] / "peer.toml"], lab.OUT / f"performance-peer-{index}.log")
    lab.wait(lambda: all(lab.query(peer, "status").get("tun_up") for peer in peers), "performance TUN readiness")
    lab.wait(lambda: lab.run("ip", "netns", "exec", peers[0]["namespace"], "ping", "-c", "1", "-W", "1", peers[1]["address"], check=False).returncode == 0, "performance first packet")
    time.sleep(5)  # Fixed settling period; distinct from cold-connection timing.
    lab.run("nft", "-f", "-", input='''table inet fixture_meter {
 counter inbound { }
 counter outbound { }
 chain input { type filter hook input priority 100; policy accept; iifname "brpwd" counter name inbound; }
 chain output { type filter hook output priority 100; policy accept; oifname "brpwd" counter name outbound; }
}
''')
    output = []
    for index in range(1, rounds + 1):
        server = lab.spawn(["ip", "netns", "exec", peers[1]["namespace"], "iperf3", "-s", "-1", "-B", peers[1]["address"], "-p", "24445", "-J"], lab.OUT / f"performance-{index}-server.json")
        lab.wait(lambda: "24445" in lab.run("ip", "netns", "exec", peers[1]["namespace"], "ss", "-ln", "sport", "=", ":24445").stdout, "iperf server")
        before = resources(peers)
        start = time.monotonic()
        exit_code, timed_out, raw = measure(peers, index, seconds, streams)
        after = resources(peers)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.send_signal(signal.SIGINT)
            server.wait(timeout=3)
        try:
            body = json.loads(raw)
        except ValueError:
            body = {"error": "iperf output missing or invalid; original bytes preserved"}
        latency = lab.run("ip", "netns", "exec", peers[0]["namespace"], "ping", "-n", "-c", "10", "-i", ".05", "-W", "1", "-s", "1200", peers[1]["address"], check=False)
        (lab.OUT / f"performance-{index}-latency.txt").write_text(latency.stdout)
        latency_summary = ping_summary(latency.stdout)
        summary = {"round": index, "seconds": time.monotonic() - start, "passed": exit_code == 0 and not timed_out and "error" not in body and latency.returncode == 0,
                   "exit_code": exit_code, "timed_out": timed_out, "error": body.get("error"),
                   "before": before, "after": after, "relay_host_l3_bytes": after["relay_host_l3_bytes"] - before["relay_host_l3_bytes"],
                   "iperf_end": body.get("end"), "latency": latency_summary,
                   "peer_status": [lab.query(peer, "status") for peer in peers]}
        output.append(summary)
        (lab.OUT / "performance.json").write_text(json.dumps({"clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "page_size_bytes": os.sysconf("SC_PAGE_SIZE"), "streams": streams, "scope": f"Linux {streams} concurrent TCP streams, {rounds} {seconds}-second rounds; host L3 bytes include control/STUN and transport overhead", "not_claimed": ["Android energy", "Internet cloud billing", "maximum sustainable capacity"], "rounds": output}, indent=2) + "\n")
        if not summary["passed"]:
            raise RuntimeError("performance round failed; raw results preserved")
    return {"passed": True, "rounds": rounds, "streams": streams, "file": "performance.json"}

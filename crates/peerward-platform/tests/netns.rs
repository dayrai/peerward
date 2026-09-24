use std::{
    io::{BufRead as _, BufReader},
    process::{Child, Command, Stdio},
};

const NETNS_PROBE: &str = env!("CARGO_BIN_EXE_peerward-netns-probe");

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Namespaces {
    peer: String,
    edge: String,
    outside: String,
}

impl Drop for Namespaces {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.peer])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.edge])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.outside])
            .status();
    }
}

fn run_failure(program: &str, arguments: &[&str]) {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("cannot execute {program}: {error}"));
    assert!(
        !status.success(),
        "{program} {arguments:?} unexpectedly succeeded"
    );
}

fn run(program: &str, arguments: &[&str]) -> String {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("cannot execute {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn namespace_nat_netem_and_authenticated_peerward_udp_are_operational() {
    assert_eq!(
        std::env::var("PEERWARD_RUN_PRIVILEGED").as_deref(),
        Ok("1"),
        "privileged test must be invoked explicitly with PEERWARD_RUN_PRIVILEGED=1"
    );
    let suffix = std::process::id() % 10_000;
    let namespaces = Namespaces {
        peer: format!("pw-peer-{suffix}"),
        edge: format!("pw-edge-{suffix}"),
        outside: format!("pw-out-{suffix}"),
    };
    let peer_link = format!("pwp{suffix}");
    let edge_link = format!("pwe{suffix}");
    let edge_out = format!("pwx{suffix}");
    let outside_link = format!("pwo{suffix}");
    run("ip", &["netns", "add", &namespaces.peer]);
    run("ip", &["netns", "add", &namespaces.edge]);
    run("ip", &["netns", "add", &namespaces.outside]);
    run(
        "ip",
        &[
            "link", "add", &peer_link, "type", "veth", "peer", "name", &edge_link,
        ],
    );
    run(
        "ip",
        &[
            "link",
            "add",
            &edge_out,
            "type",
            "veth",
            "peer",
            "name",
            &outside_link,
        ],
    );
    run(
        "ip",
        &["link", "set", &peer_link, "netns", &namespaces.peer],
    );
    run(
        "ip",
        &["link", "set", &edge_link, "netns", &namespaces.edge],
    );
    run("ip", &["link", "set", &edge_out, "netns", &namespaces.edge]);
    run(
        "ip",
        &["link", "set", &outside_link, "netns", &namespaces.outside],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "address",
            "add",
            "10.250.0.2/24",
            "dev",
            &peer_link,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.edge,
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            &edge_out,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.outside,
            "address",
            "add",
            "192.0.2.2/24",
            "dev",
            &outside_link,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.edge,
            "address",
            "add",
            "10.250.0.1/24",
            "dev",
            &edge_link,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.edge,
            "address",
            "add",
            "10.250.0.254/24",
            "dev",
            &edge_link,
        ],
    );
    for (namespace, interface) in [
        (&namespaces.peer, &peer_link),
        (&namespaces.edge, &edge_link),
        (&namespaces.edge, &edge_out),
        (&namespaces.outside, &outside_link),
    ] {
        run("ip", &["-n", namespace, "link", "set", "lo", "up"]);
        run("ip", &["-n", namespace, "link", "set", interface, "up"]);
    }
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "route",
            "add",
            "default",
            "via",
            "10.250.0.1",
        ],
    );

    // Prove that the two-second /proc fingerprint fallback remains functional
    // when the netlink listener is unavailable.
    let mut polling = ChildGuard(Some(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.peer,
                NETNS_PROBE,
                "underlay-poll",
                "10.250.0.1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot start underlay polling probe"),
    ));
    wait_ready(&mut polling, "underlay polling probe");
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "address",
            "add",
            "10.250.0.3/24",
            "dev",
            &peer_link,
        ],
    );
    wait_success(polling, "underlay polling probe");
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "address",
            "del",
            "10.250.0.3/24",
            "dev",
            &peer_link,
        ],
    );

    // A link-down event advances the generation once and exposes the bounded
    // no-default-gateway state instead of returning a stale route.
    let mut missing = ChildGuard(Some(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.peer,
                NETNS_PROBE,
                "underlay-missing",
                "10.250.0.1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot start underlay link-down probe"),
    ));
    wait_ready(&mut missing, "underlay link-down probe");
    run(
        "ip",
        &["-n", &namespaces.peer, "link", "set", &peer_link, "down"],
    );
    wait_success(missing, "underlay link-down probe");
    run(
        "ip",
        &["-n", &namespaces.peer, "link", "set", &peer_link, "up"],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "route",
            "replace",
            "default",
            "via",
            "10.250.0.1",
        ],
    );

    // Exercise an actual IPv6 default route replacement through the same
    // netlink path rather than relying only on parser fixtures.
    for (namespace, address, interface) in [
        (&namespaces.peer, "fd00:250::2/64", &peer_link),
        (&namespaces.edge, "fd00:250::1/64", &edge_link),
        (&namespaces.edge, "fd00:250::fe/64", &edge_link),
    ] {
        run(
            "ip",
            &[
                "-n", namespace, "-6", "address", "add", address, "dev", interface,
            ],
        );
    }
    run("ip", &["-n", &namespaces.peer, "route", "del", "default"]);
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "-6",
            "route",
            "add",
            "default",
            "via",
            "fd00:250::1",
        ],
    );
    let mut ipv6 = ChildGuard(Some(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.peer,
                NETNS_PROBE,
                "underlay",
                "fd00:250::1",
                "fd00:250::fe",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot start IPv6 underlay probe"),
    ));
    wait_ready(&mut ipv6, "IPv6 underlay probe");
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "-6",
            "route",
            "replace",
            "default",
            "via",
            "fd00:250::fe",
        ],
    );
    wait_success(ipv6, "IPv6 underlay probe");
    run(
        "ip",
        &["-n", &namespaces.peer, "-6", "route", "del", "default"],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            NETNS_PROBE,
            "gateway-missing",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "route",
            "add",
            "default",
            "via",
            "10.250.0.1",
        ],
    );
    let mut underlay = ChildGuard(Some(
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespaces.peer,
                NETNS_PROBE,
                "underlay",
                "10.250.0.1",
                "10.250.0.254",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot start underlay netlink probe"),
    ));
    let stdout = underlay
        .0
        .as_mut()
        .and_then(|child| child.stdout.take())
        .expect("underlay probe stdout is unavailable");
    let mut ready = String::new();
    BufReader::new(stdout)
        .read_line(&mut ready)
        .expect("cannot read underlay probe readiness");
    assert_eq!(ready.trim(), "ready");
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "route",
            "replace",
            "default",
            "via",
            "10.250.0.254",
        ],
    );
    let output = underlay
        .0
        .take()
        .expect("underlay probe is missing")
        .wait_with_output()
        .expect("cannot wait for underlay probe");
    assert!(
        output.status.success(),
        "underlay probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    run(
        "ip",
        &[
            "-n",
            &namespaces.peer,
            "route",
            "replace",
            "default",
            "via",
            "10.250.0.1",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.edge,
            "sysctl",
            "-q",
            "-w",
            "net.ipv4.ip_forward=1",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "ip",
            "tuntap",
            "add",
            "dev",
            "pwtun0",
            "mode",
            "tun",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "ip",
            "link",
            "set",
            "pwtun0",
            "up",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "10.250.0.1",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.edge,
            "nft",
            "add",
            "table",
            "ip",
            "pwnat",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.edge,
            "nft",
            "add",
            "chain",
            "ip",
            "pwnat",
            "postrouting",
            "{ type nat hook postrouting priority 100; policy accept; }",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.edge,
            "nft",
            "add",
            "rule",
            "ip",
            "pwnat",
            "postrouting",
            "oifname",
            &edge_out,
            "masquerade",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "tc",
            "qdisc",
            "add",
            "dev",
            &peer_link,
            "root",
            "netem",
            "delay",
            "20ms",
            "loss",
            "100%",
        ],
    );
    run_failure(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "192.0.2.2",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "tc",
            "qdisc",
            "replace",
            "dev",
            &peer_link,
            "root",
            "netem",
            "delay",
            "20ms",
        ],
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "192.0.2.2",
        ],
    );
    let netem = run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "tc",
            "qdisc",
            "show",
            "dev",
            &peer_link,
        ],
    );
    assert!(netem.contains("netem"));
    let nat = run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.edge,
            "nft",
            "list",
            "table",
            "ip",
            "pwnat",
        ],
    );
    assert!(nat.contains("masquerade"));

    let server = Command::new("ip")
        .args([
            "netns",
            "exec",
            &namespaces.outside,
            NETNS_PROBE,
            "server",
            "192.0.2.2:45000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cannot start Peerward netns server probe");
    let mut server = ChildGuard(Some(server));
    std::thread::sleep(std::time::Duration::from_millis(200));
    let client = run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            NETNS_PROBE,
            "client",
            "192.0.2.2:45000",
        ],
    );
    assert!(client.is_empty());
    let output = server
        .0
        .take()
        .expect("Peerward netns server probe is missing")
        .wait_with_output()
        .expect("cannot wait for Peerward netns server probe");
    assert!(
        output.status.success(),
        "Peerward netns server probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    run(
        "ip",
        &[
            "netns",
            "exec",
            &namespaces.peer,
            "ip",
            "tuntap",
            "del",
            "dev",
            "pwtun0",
            "mode",
            "tun",
        ],
    );
}

fn wait_ready(child: &mut ChildGuard, context: &str) {
    let stdout = child
        .0
        .as_mut()
        .and_then(|process| process.stdout.take())
        .unwrap_or_else(|| panic!("{context} stdout is unavailable"));
    let mut ready = String::new();
    BufReader::new(stdout)
        .read_line(&mut ready)
        .unwrap_or_else(|error| panic!("cannot read {context} readiness: {error}"));
    assert_eq!(ready.trim(), "ready", "{context} did not become ready");
}

fn wait_success(mut child: ChildGuard, context: &str) {
    let output = child
        .0
        .take()
        .unwrap_or_else(|| panic!("{context} is missing"))
        .wait_with_output()
        .unwrap_or_else(|error| panic!("cannot wait for {context}: {error}"));
    assert!(
        output.status.success(),
        "{context} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

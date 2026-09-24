//! Real Linux forwarding and recovery, with a veth standing in for decrypted TUN ingress.
//! Cryptographic source ownership and resource ACLs are tested separately in peer-core.
use peerward_platform::{GatewayForward, ResourceNetworkIntent};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

const PROBE: &str = env!("CARGO_BIN_EXE_peerward-netns-probe");

struct Lab {
    names: [String; 3],
    directory: PathBuf,
}
impl Drop for Lab {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = Command::new("ip").args(["netns", "del", name]).output();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(namespace: &str, program: &str, args: &[&str]) -> Command {
    let mut command = Command::new("ip");
    command
        .args(["netns", "exec", namespace, program])
        .args(args);
    command
}
fn run(program: &str, args: &[&str]) -> String {
    let result = Command::new(program).args(args).output().unwrap();
    assert!(
        result.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn inside(namespace: &str, program: &str, args: &[&str]) -> String {
    let result = command(namespace, program, args).output().unwrap();
    assert!(
        result.status.success(),
        "{namespace}: {program} {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn ready(mut command: Command) -> Process {
    // Bound startup and test-child lifetime even if the test fails before readiness.
    let mut process = Process(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = process.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send((result, line));
    });
    let (result, line) = receiver
        .recv_timeout(std::time::Duration::from_secs(15))
        .expect("child readiness timed out");
    result.unwrap();
    assert_eq!(line.trim(), "ready");
    process
}
fn request(namespace: &str) -> String {
    inside(
        namespace,
        "python3",
        &[
            "-c",
            "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'probe',('192.168.46.10',52001)); print(s.recv(128).decode())",
        ],
    )
}
fn blocked(namespace: &str, address: &str, source: Option<&str>) {
    let mut cmd = command(namespace, "ping", &["-c", "1", "-W", "1"]);
    let source = source.or_else(|| address.contains(':').then_some("fd42::1"));
    if let Some(source) = source {
        cmd.args(["-I", source]);
    }
    assert!(
        !cmd.arg(address).output().unwrap().status.success(),
        "unexpected access to {address}"
    );
}

fn ipv6_topology(client: &str, gateway: &str, lan: &str) {
    for (namespace, interface, address) in [
        (client, "c0", "fd42::1/64"),
        (gateway, "pwtun0", "fd42::2/64"),
        (gateway, "lan0", "fd46::1/64"),
        (lan, "l0", "fd46::10/64"),
        (gateway, "lan0", "fd47::1/64"),
        (lan, "l0", "fd47::10/64"),
        (client, "c0", "fd43::1/128"),
    ] {
        run(
            "ip",
            &[
                "-n", namespace, "address", "add", address, "dev", interface, "nodad",
            ],
        );
    }
    // A real TUN needs no NDP. Fixed veth neighbours keep this fixture equivalent at ingress.
    run(
        "ip",
        &[
            "-n",
            client,
            "link",
            "set",
            "c0",
            "address",
            "02:00:00:42:00:01",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            gateway,
            "link",
            "set",
            "pwtun0",
            "address",
            "02:00:00:42:00:02",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            client,
            "-6",
            "neigh",
            "replace",
            "fd42::2",
            "lladdr",
            "02:00:00:42:00:02",
            "dev",
            "c0",
            "nud",
            "permanent",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            gateway,
            "-6",
            "neigh",
            "replace",
            "fd42::1",
            "lladdr",
            "02:00:00:42:00:01",
            "dev",
            "pwtun0",
            "nud",
            "permanent",
        ],
    );
    for prefix in ["fd46::/64", "fd47::/64"] {
        run(
            "ip",
            &["-n", client, "-6", "route", "add", prefix, "via", "fd42::2"],
        );
    }
    inside(gateway, "sysctl", &["-w", "net.ipv6.conf.all.forwarding=0"]);
    assert_eq!(
        inside(gateway, "sysctl", &["-n", "net.ipv6.conf.all.forwarding"]).trim(),
        "0"
    );
}
fn request_v6(namespace: &str) -> String {
    inside(
        namespace,
        "python3",
        &[
            "-c",
            "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(('fd42::1',0)); s.settimeout(2); s.sendto(b'probe',('fd46::10',52001)); print(s.recv(128).decode())",
        ],
    )
}

#[test]
fn subnet_snat_routed_mode_source_bounds_and_crash_recovery() {
    assert_eq!(
        std::env::var("PEERWARD_RUN_PRIVILEGED").as_deref(),
        Ok("1"),
        "requires an isolated privileged lab"
    );
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let lab = Lab {
        names: [
            format!("pw-client-{suffix}"),
            format!("pw-gateway-{suffix}"),
            format!("pw-lan-{suffix}"),
        ],
        directory: std::env::temp_dir().join(format!("pw-resource-{suffix}")),
    };
    std::fs::create_dir(&lab.directory).unwrap();
    let [client, gateway, lan] = &lab.names;
    for namespace in &lab.names {
        run("ip", &["netns", "add", namespace]);
        run("ip", &["-n", namespace, "link", "set", "lo", "up"]);
    }
    for (left, left_name, right, right_name) in [
        (client, "c0", gateway, "pwtun0"),
        (gateway, "lan0", lan, "l0"),
    ] {
        run(
            "ip",
            &[
                "-n", left, "link", "add", left_name, "type", "veth", "peer", "name", right_name,
                "netns", right,
            ],
        );
        run("ip", &["-n", left, "link", "set", left_name, "up"]);
        run("ip", &["-n", right, "link", "set", right_name, "up"]);
    }
    for (namespace, interface, address) in [
        (client, "c0", "10.42.0.1/24"),
        (gateway, "pwtun0", "10.42.0.2/24"),
        (gateway, "lan0", "192.168.46.1/24"),
        (lan, "l0", "192.168.46.10/24"),
        (gateway, "lan0", "192.168.47.1/24"),
        (lan, "l0", "192.168.47.10/24"),
        (client, "c0", "10.42.1.1/32"),
    ] {
        run(
            "ip",
            &["-n", namespace, "address", "add", address, "dev", interface],
        );
    }
    for prefix in ["192.168.46.0/24", "192.168.47.0/24"] {
        run(
            "ip",
            &["-n", client, "route", "add", prefix, "via", "10.42.0.2"],
        );
    }
    // Use a known baseline owned exclusively by this network namespace.
    inside(gateway, "sysctl", &["-w", "net.ipv4.ip_forward=0"]);
    assert_eq!(
        inside(gateway, "sysctl", &["-n", "net.ipv4.ip_forward"]).trim(),
        "0",
        "container must permit namespace-local sysctl writes"
    );
    inside(gateway, "sysctl", &["-w", "net.ipv4.conf.all.rp_filter=0"]);
    inside(
        gateway,
        "sysctl",
        &["-w", "net.ipv4.conf.pwtun0.rp_filter=0"],
    );
    ipv6_topology(client, gateway, lan);
    let _echo_v6 = ready(command(
        lan,
        "python3",
        &[
            "-u",
            "-c",
            "import socket\ns=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(('fd46::10',52001)); print('ready',flush=True)\nwhile True:\n data,source=s.recvfrom(128); s.sendto(source[0].encode(),source)",
        ],
    ));
    let _echo = ready(command(
        lan,
        "python3",
        &[
            "-u",
            "-c",
            "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('192.168.46.10',52001)); print('ready',flush=True)\nwhile True:\n data,source=s.recvfrom(128); s.sendto(source[0].encode(),source)",
        ],
    ));
    let intent_file = lab.directory.join("intent.json");
    let journal = lab.directory.join("state.json");
    let mut intent = ResourceNetworkIntent {
        interface: "pwtun0".into(),
        local_addresses: vec!["10.42.0.2".parse().unwrap(), "fd42::2".parse().unwrap()],
        mesh_prefixes: vec![
            "10.42.0.0/24".parse().unwrap(),
            "fd42::/64".parse().unwrap(),
        ],
        accepted_routes: vec![],
        gateway_routes: vec![
            GatewayForward {
                prefix: "192.168.46.0/24".parse().unwrap(),
                masquerade: true,
            },
            GatewayForward {
                prefix: "fd46::/64".parse().unwrap(),
                masquerade: true,
            },
        ],
    };
    std::fs::write(&intent_file, serde_json::to_vec(&intent).unwrap()).unwrap();
    let mut forwarding = ready(command(
        gateway,
        PROBE,
        &[
            "resource-apply",
            intent_file.to_str().unwrap(),
            journal.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        request(client).trim(),
        "192.168.46.1",
        "SNAT permits return without a LAN return route"
    );
    blocked(client, "192.168.46.1", None);
    blocked(client, "192.168.47.10", None);
    blocked(client, "192.168.46.10", Some("10.42.1.1"));
    assert_eq!(request_v6(client).trim(), "fd46::1");
    blocked(client, "fd46::1", None);
    blocked(client, "fd47::10", None);
    blocked(client, "fd46::10", Some("fd43::1"));
    assert!(journal.exists());
    forwarding.0.kill().unwrap();
    forwarding.0.wait().unwrap();
    inside(
        gateway,
        PROBE,
        &["resource-recover", journal.to_str().unwrap()],
    );
    assert!(!journal.exists());
    assert_eq!(
        inside(gateway, "sysctl", &["-n", "net.ipv4.ip_forward"]).trim(),
        "0"
    );
    assert!(!inside(gateway, "nft", &["list", "tables"]).contains("pw_shared_"));
    blocked(client, "192.168.46.10", None);
    assert_eq!(
        inside(gateway, "sysctl", &["-n", "net.ipv6.conf.all.forwarding"]).trim(),
        "0"
    );
    blocked(client, "fd46::10", None);

    intent.gateway_routes[0].masquerade = false;
    intent.gateway_routes[1].masquerade = false;
    run(
        "ip",
        &[
            "-n",
            lan,
            "-6",
            "route",
            "add",
            "fd42::/64",
            "via",
            "fd46::1",
        ],
    );
    std::fs::write(&intent_file, serde_json::to_vec(&intent).unwrap()).unwrap();
    run(
        "ip",
        &[
            "-n",
            lan,
            "route",
            "add",
            "10.42.0.0/24",
            "via",
            "192.168.46.1",
        ],
    );
    // Clear only this disposable namespace's prior NAT state before changing mode.
    inside(gateway, "conntrack", &["-F"]);
    let mut routed = ready(command(
        gateway,
        PROBE,
        &[
            "resource-apply",
            intent_file.to_str().unwrap(),
            journal.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        request(client).trim(),
        "10.42.0.1",
        "routed mode preserves the authenticated virtual source"
    );
    assert_eq!(request_v6(client).trim(), "fd42::1");
    routed.0.stdin.take().unwrap().write_all(b"\n").unwrap();
    assert!(routed.0.wait().unwrap().success());
    assert!(!journal.exists());
    assert_eq!(
        inside(gateway, "sysctl", &["-n", "net.ipv4.ip_forward"]).trim(),
        "0"
    );
    assert!(!inside(gateway, "nft", &["list", "tables"]).contains("pw_shared_"));
}

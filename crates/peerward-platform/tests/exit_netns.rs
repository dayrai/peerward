//! Host exit blocking in an isolated namespace; never changes the host ruleset.
use peerward_platform::{EXIT_UNDERLAY_MARK, ExitProtectionIntent};
use std::{
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};
const PROBE: &str = env!("CARGO_BIN_EXE_peerward-netns-probe");
struct Lab {
    names: [String; 2],
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
fn run(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn inside(namespace: &str, args: &[&str]) -> String {
    run(&[&["netns", "exec", namespace][..], args].concat())
}
fn request(namespace: &str, address: &str, marked: bool, allowed: bool) {
    // Loopback is intentionally unaffected. The echo endpoint is on a real veth underlay.
    let script = format!(
        "import socket\ns=socket.socket({},socket.SOCK_DGRAM);s.settimeout(.5)\n{}\ntry:\n s.sendto(b'probe',('{address}',52002))\n assert s.recv(128)==b'probe';success=True\nexcept (TimeoutError,PermissionError):\n success=False\nassert success=={allowed},success",
        if address.contains(':') {
            "socket.AF_INET6"
        } else {
            "socket.AF_INET"
        },
        if marked {
            format!("s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,{EXIT_UNDERLAY_MARK})")
        } else {
            String::new()
        },
        allowed = if allowed { "True" } else { "False" }
    );
    inside(namespace, &["python3", "-c", &script]);
}
fn ready(namespace: &str, args: &[&str]) -> Process {
    let mut process = Process(
        Command::new("ip")
            .args(["netns", "exec", namespace])
            .args(args)
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
        .expect("probe readiness timed out");
    result.unwrap();
    assert_eq!(line.trim(), "ready");
    process
}
#[test]
fn exit_guard_survives_crash_and_tun_loss_with_explicit_disable() {
    assert_eq!(
        std::env::var("PEERWARD_RUN_PRIVILEGED").as_deref(),
        Ok("1"),
        "requires an isolated privileged lab"
    );
    let id = uuid::Uuid::new_v4().simple().to_string();
    let lab = Lab {
        names: [format!("pw-exit-client-{id}"), format!("pw-exit-net-{id}")],
        directory: std::env::temp_dir().join(format!("pw-exit-{id}")),
    };
    std::fs::create_dir(&lab.directory).unwrap();
    let [client, internet] = &lab.names;
    for name in &lab.names {
        run(&["netns", "add", name]);
        run(&["-n", name, "link", "set", "lo", "up"]);
    }
    run(&[
        "-n", client, "link", "add", "c0", "type", "veth", "peer", "name", "n0", "netns", internet,
    ]);
    for (name, iface, v4, v6) in [
        (client, "c0", "192.0.2.1/24", "2001:db8::1/64"),
        (internet, "n0", "192.0.2.2/24", "2001:db8::2/64"),
    ] {
        run(&["-n", name, "link", "set", iface, "up"]);
        run(&["-n", name, "address", "add", v4, "dev", iface]);
        run(&["-n", name, "address", "add", v6, "dev", iface, "nodad"]);
    }
    run(&["-n", client, "link", "add", "pwtun0", "type", "dummy"]);
    run(&["-n", client, "link", "set", "pwtun0", "up"]);
    let echoes:Vec<_>=[("socket.AF_INET","192.0.2.2"),("socket.AF_INET6","2001:db8::2")].into_iter().map(|(family,address)|{
        let script=format!("import socket\ns=socket.socket({family},socket.SOCK_DGRAM);s.bind(('{address}',52002));print('ready',flush=True)\nwhile True:\n data,source=s.recvfrom(128);s.sendto(data,source)");
        ready(internet,&["python3","-u","-c",&script])
    }).collect();
    for address in ["192.0.2.2", "2001:db8::2"] {
        request(client, address, false, true);
    }
    let journal = lab.directory.join("exit.json");
    let intent_file = lab.directory.join("intent.json");
    let mut intent = ExitProtectionIntent {
        interface: "pwtun0".into(),
        exit_resource: uuid::Uuid::new_v4(),
        local_lan: vec![],
    };
    std::fs::write(&intent_file, serde_json::to_vec(&intent).unwrap()).unwrap();
    let mut owner = ready(
        client,
        &[
            PROBE,
            "exit-arm",
            journal.to_str().unwrap(),
            intent_file.to_str().unwrap(),
        ],
    );
    for address in ["192.0.2.2", "2001:db8::2"] {
        request(client, address, false, false);
        request(client, address, true, true);
    }
    run(&[
        "-n",
        client,
        "address",
        "add",
        "10.40.0.1/24",
        "dev",
        "pwtun0",
    ]);
    run(&[
        "-n",
        client,
        "address",
        "add",
        "fd42::1/64",
        "dev",
        "pwtun0",
        "nodad",
    ]);
    let routing = peerward_platform::ExitRoutingIntent {
        interface: "pwtun0".into(),
        ipv4: "10.40.0.1".parse().unwrap(),
        ipv6: "fd42::1".parse().unwrap(),
        local_lan: vec![],
    };
    let route_file = lab.directory.join("route-intent.json");
    let route_journal = lab.directory.join("routes.json");
    std::fs::write(&route_file, serde_json::to_vec(&routing).unwrap()).unwrap();
    let mut capture = ready(
        client,
        &[
            PROBE,
            "exit-routes",
            route_file.to_str().unwrap(),
            route_journal.to_str().unwrap(),
        ],
    );
    for address in ["192.0.2.2", "2001:db8::2"] {
        assert!(inside(client, &["ip", "route", "get", address]).contains("dev pwtun0"));
        assert!(
            inside(
                client,
                &[
                    "ip",
                    "route",
                    "get",
                    address,
                    "mark",
                    &EXIT_UNDERLAY_MARK.to_string()
                ]
            )
            .contains("dev c0")
        );
    }
    for address in ["192.0.2.2:52002", "[2001:db8::2]:52002"] {
        inside(client, &[PROBE, "protected-echo", address]);
    }
    capture.0.kill().unwrap();
    capture.0.wait().unwrap();
    inside(
        client,
        &[PROBE, "resource-recover", route_journal.to_str().unwrap()],
    );
    assert!(!route_journal.exists());
    for address in ["192.0.2.2", "2001:db8::2"] {
        request(client, address, false, false);
        request(client, address, true, true);
    }
    assert!(journal.exists());
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    run(&["-n", client, "link", "del", "pwtun0"]);
    inside(client, &[PROBE, "exit-restore", journal.to_str().unwrap()]);
    for address in ["192.0.2.2", "2001:db8::2"] {
        request(client, address, false, false);
        request(client, address, true, true);
    }
    // Explicit local-LAN exception is exact and opt-in; IPv6 stays blocked.
    intent.local_lan = vec!["192.0.2.0/24".parse().unwrap()];
    std::fs::write(&intent_file, serde_json::to_vec(&intent).unwrap()).unwrap();
    let exception = ready(
        client,
        &[
            PROBE,
            "exit-arm",
            journal.to_str().unwrap(),
            intent_file.to_str().unwrap(),
        ],
    );
    request(client, "192.0.2.2", false, true);
    request(client, "2001:db8::2", false, false);
    drop(exception);
    inside(client, &[PROBE, "exit-disable", journal.to_str().unwrap()]);
    assert!(!journal.exists());
    assert!(!inside(client, &["nft", "list", "tables"]).contains("pw_exit_"));
    for address in ["192.0.2.2", "2001:db8::2"] {
        request(client, address, false, true);
    }
    drop(echoes);
}

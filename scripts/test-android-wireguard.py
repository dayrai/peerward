#!/usr/bin/env python3
"""Run WireGuard Android gates on an emulator or an explicitly selected phone.

Installs the debug/test APKs and clears the app's test profile. The full gate uses
fresh PostgreSQL, Control and Relay instances, and toggles emulator airplane mode.
Never reads the workspace .env. Phones require --allow-physical --validation-app;
only the separate validation package is installed/cleared. --tun-peer adds a fresh
Linux TUN peer in a Docker bridge container and checks 1200-byte overlay echoes
before and after Wi-Fi replacement using one Android application socket. The full phone gate
requires a reachable --lan-address and briefly disables/restores Wi-Fi.
Build first: ANDROID_HOME=/path/to/sdk scripts/verify.sh android
"""

import argparse
import base64
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from android_console_renewal import console_renewal
from android_console_ui import console_process
from android_gate_evidence import IdleWake, apply_diagnostic_intervention, collect_report, collect_process_snapshot
from wireguard_gate_state import process_identity
from types import SimpleNamespace
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "io.github.peerward.peerward"
NATIVE_TEST_COUNT = 23  # Pinned to CLASSES, including storage and diagnostic regressions.
CLASSES = [
    "WireguardKeyInstrumentedTest", "JoinStorageInstrumentedTest", "DeviceMetadataPersistenceInstrumentedTest",
    "VpnPacketLifecycleInstrumentedTest", "NativePortMappingInstrumentedTest",
    "ProtectedDnsInstrumentedTest", "SavedProfilesInstrumentedTest",
]


class GateError(RuntimeError):
    """A diagnostic label that contains no generated credential material."""


def run(command, label, timeout=180):
    result = subprocess.run([str(arg) for arg in command], cwd=ROOT, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        # Arguments can contain generated database credentials or one-use Join material.
        raise GateError(f"{label} failed (exit {result.returncode})")
    return result.stdout


def record_device_clock(adb, output, stage):
    """Observe host/device skew without changing either clock or trust state."""
    before = time.time()
    result = subprocess.run([*adb, "shell", "date", "+%s"], text=True, capture_output=True, timeout=5)
    after = time.time()
    value = result.stdout.strip()
    record = {"stage": stage, "host_before": before, "host_after": after, "observed_at": datetime.now(timezone.utc).isoformat()}
    if result.returncode == 0 and value.isdecimal():
        record.update(device_epoch=int(value), skew_seconds=int(value) - (before + after) / 2)
    else:
        record["device_epoch"] = None
    with (output / "clock-observations.jsonl").open("a") as log:
        log.write(json.dumps(record) + "\n")


def instrument(adb, arguments, output, expected, package=PACKAGE):
    restarting = "StoredRuntimeRestartInstrumentedTest" in str(arguments)
    backend_active = any(name in str(arguments) for name in ("RealBackendInstrumentedTest", "StoredRuntimeRestartInstrumentedTest"))
    attempts = int(arguments[arguments.index("peerwardNetworkAttempts") + 1]) if not restarting and "peerwardNetworkAttempts" in arguments else 0
    power_seconds = int(arguments[arguments.index("peerwardPowerSeconds") + 1]) if not restarting and "peerwardPowerSeconds" in arguments else 0
    command = ["am", "instrument", "-w", "-r", *arguments,
               f"{package}.test/androidx.test.runner.AndroidJUnitRunner"]
    log = output / "instrumentation.log"
    capture = None
    selected_pid = None
    record_device_clock(adb, output, "backend_start" if backend_active else "native_start")
    next_clock_observation = time.monotonic() + 30
    with log.open("w") as stream, (output / "application-runtime.log").open("a") as application_log:
        result = subprocess.Popen([*adb, "shell", shlex.join(command)], cwd=ROOT,
                                  text=True, stdout=stream, stderr=subprocess.STDOUT)
        try:
            for _ in range(20):
                lookup = subprocess.run([*adb, "shell", "pidof", package], text=True, capture_output=True, timeout=5)
                pids = lookup.stdout.strip().split()
                if len(pids) == 1 and pids[0].isdigit():
                    selected_pid = pids[0]
                    if restarting:
                        # This scenario verifies an explicit foreground app launch,
                        # not unattended boot recovery. Launch at process creation,
                        # before waiting for any progress or observing a stall.
                        entrypoint = {"scope": "foreground app launch after process death/reboot",
                                      "pid": int(selected_pid), "trigger": "restart instrumentation process created"}
                        (output / "restart-entrypoint.json").write_text(json.dumps(entrypoint, indent=2) + "\n")
                        run([*adb, "shell", "am", "start", "-W", "-n", f"{package}/{PACKAGE}.MainActivity"],
                            "open selected validation application after restart", 30)
                    capture = subprocess.Popen([*adb, "logcat", "--pid=" + pids[0], "-T", "1", "-v", "threadtime",
                                                "PeerwardRelay:V", "PeerwardStop:I", "PeerwardEnrollment:V", "PeerwardVpnStart:V", "AndroidRuntime:E", "*:S"], stdout=application_log, stderr=subprocess.STDOUT)
                    break
                if result.poll() is not None:
                    break
                time.sleep(.1)
            deadline = time.monotonic() + attempts * 100 + power_seconds + (360 if "peerwardTunPeer" in arguments else 240)
            idle = IdleWake(adb, package, power_seconds if "StoredRuntimeRestartInstrumentedTest" not in str(arguments) else 0, output)
            last_progress = time.monotonic()
            log_size = 0
            snapshot_at = 8
            snapshots = 0
            while result.poll() is None:
                if time.monotonic() >= next_clock_observation:
                    record_device_clock(adb, output, "backend_wait" if backend_active else "native_wait")
                    next_clock_observation = time.monotonic() + 30
                size = log.stat().st_size
                if size != log_size:
                    last_progress = time.monotonic()
                    snapshot_at = 8
                    log_size = size
                if (selected_pid and package == PACKAGE + ".validation" and snapshots < 6
                        and time.monotonic() - last_progress >= snapshot_at):
                    try:
                        collect_process_snapshot(adb, package, selected_pid, output)
                    except Exception as error:
                        with (output / "native-stall-process.log").open("a") as diagnostic:
                            diagnostic.write("snapshot failed: " + type(error).__name__ + "\n")
                    snapshots += 1
                    snapshot_at += 120 if backend_active and snapshots >= 3 else 20
                if not backend_active and time.monotonic() - last_progress > 60:
                    run([*adb, "shell", "am", "force-stop", package], "stop stalled validation instrumentation")
                    raise GateError("native/platform test stalled for 60 seconds; original output retained")
                if time.monotonic() >= deadline:
                    raise GateError("instrumentation timed out; original output retained")
                idle.poll()
                try:
                    result.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if capture is not None:
                capture.terminate()
                capture.wait(timeout=5)
            if result.poll() is None:
                result.terminate()
                result.wait(timeout=5)
    noun = "test" if expected == 1 else "tests"
    return result.returncode == 0 and f"OK ({expected} {noun})" in log.read_text()


def restart_device_runtime(adb, output, arguments, package, reboot, enrollment_port):
    before = json.loads(run([*adb, "exec-out", "run-as", package, "cat", "files/wireguard-restart-baseline.json"], "restart baseline"))
    processes = subprocess.run([*adb, "shell", "pidof", package], text=True, capture_output=True, timeout=10)
    pids = processes.stdout.strip().split()
    restart = {"old_process": "SIGKILL" if pids else "instrumentation exit", "requested_reboot": reboot, "passed": False}
    try:
        if pids:
            if pids != [str(before["pid"])]:
                raise GateError("test application PID changed before the controlled restart")
            run([*adb, "shell", "run-as", package, "kill", "-9", pids[0]], "kill validation process")
        if reboot:
            boot_command = [*adb, "shell", "cat", "/proc/sys/kernel/random/boot_id"]
            restart["boot_id_before"] = run(boot_command, "original boot identity").strip()
            run([*adb, "reboot"], "reboot selected validation device")
            run([*adb, "wait-for-device"], "wait for rebooted device", 180)
            deadline = time.monotonic() + 180
            while True:
                boot_id = run(boot_command, "new boot identity").strip()
                completed = run([*adb, "shell", "getprop", "sys.boot_completed"], "boot state").strip() == "1"
                if boot_id and boot_id != restart["boot_id_before"] and completed:
                    restart["boot_id_after"] = boot_id
                    restart["reboot_observed"] = True
                    break
                if time.monotonic() >= deadline:
                    raise GateError("device did not complete a new boot")
                time.sleep(1)
            print("Device rebooted; unlock the phone once to restore credential-encrypted storage.", flush=True)
            restart["state"] = "waiting_for_user_unlock"
            (output / "host-restart.json").write_text(json.dumps(restart, indent=2) + "\n")
            deadline = time.monotonic() + 600
            while run([*adb, "shell", "am", "get-started-user-state", "0"], "user unlock state").strip() != "RUNNING_UNLOCKED":
                if time.monotonic() >= deadline:
                    raise GateError("phone requires user unlock after reboot")
                time.sleep(1)
            restart["state"] = "restoring_runtime"
            (output / "host-restart.json").write_text(json.dumps(restart, indent=2) + "\n")
            # Reboot removes ADB reverse rules; restore only this isolated enrollment listener.
            run([*adb, "reverse", enrollment_port, enrollment_port], "restore isolated enrollment loopback")
        resumed = list(arguments)
        resumed[resumed.index("class") + 1] = f"{PACKAGE}.StoredRuntimeRestartInstrumentedTest"
        (output / "instrumentation.log").rename(output / "instrumentation-before-restart.log")
        restart["passed"] = instrument(adb, resumed, output, 1, package)
        return restart["passed"]
    except Exception as error:
        restart["error"] = str(error) if isinstance(error, GateError) else type(error).__name__
        raise
    finally:
        # A timeout can occur before instrumentation returns. Preserve its last
        # completed phase before app cleanup removes the only local evidence.
        try:
            collect_report(adb, package, output, "process-restart")
        except Exception:
            pass
        restart["state"] = "passed" if restart["passed"] else "failed"
        (output / "host-restart.json").write_text(json.dumps(restart, indent=2) + "\n")


def full_gate(adb, output, arguments, package=PACKAGE, lan_address=None, tun_peer=False, relay_carrier="tcp", network_attempts=0, power_seconds=0, restart_process=False, reboot_device=False, os_revoke=False, console_ui=False):
    public_host = lan_address or "10.0.2.2"
    spec = importlib.util.spec_from_file_location("mesh_lifecycle", ROOT / "scripts/dynamic-mesh/lifecycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    database = os.environ["PEERWARD_TEST_DATABASE_URL"]
    # Build diagnostics contain compiler output, not generated runtime arguments.
    # Preserve them separately; the generic runner deliberately hides commands
    # because later invocations carry disposable database and invitation secrets.
    with (output / "backend-build.log").open("w") as build_log:
        build = subprocess.run(["cargo", "build", "--locked", "-p", "peerward-cli"],
                               cwd=ROOT, stdout=build_log, stderr=subprocess.STDOUT, timeout=600)
    if build.returncode:
        raise GateError(f"backend build failed (exit {build.returncode}); see backend-build.log")
    with tempfile.TemporaryDirectory(prefix="peerward-dynamic-android-", dir="/tmp") as temporary:
        binary = Path(temporary) / "peerward"
        shutil.copy2(ROOT / "target/debug/peerward", binary)
        (output / "backend-binary.json").write_text(json.dumps({"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "build_profile": "debug"}, indent=2) + "\n")
        installation_path = Path(temporary) / "installation"
        reserved = [socket.socket() for _ in range(6)] + [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        try:
            for sock in reserved:
                sock.bind(("127.0.0.1", 0))
            ports = [sock.getsockname()[1] for sock in reserved]
            command = [sys.executable, ROOT / "deploy/compose/install.py", "--native",
                       "--output", installation_path, "--public-host", public_host, "--database-url", database]
            names = ["host-port", "control-port", "management-port", "peer-port", "backbone-port", "relay-health-port", "stun-port"]
            for name, port in zip(names, ports):
                command += ["--" + name, str(port)]
            run(command, "isolated installation")
            for relative in ["control/control.toml", "control/dynamic.toml", "relay/relay.toml"]:
                path = installation_path / relative
                path.write_text(path.read_text().replace("0.0.0.0:", "127.0.0.1:"))
            if lan_address:
                # Expose only the test peer/STUN listeners, never Control or management.
                relay = installation_path / "relay/relay.toml"
                contents = relay.read_text()
                for port in (ports[3], ports[6]):
                    contents = contents.replace(f"127.0.0.1:{port}", f"{lan_address}:{port}")
                relay.write_text(contents)
        finally:
            for sock in reserved:
                sock.close()
        carrier_options, proxy = {}, None
        if relay_carrier != "tcp":
            carrier_spec = importlib.util.spec_from_file_location("relay_carrier", ROOT / "scripts/wireguard-product/relay-carrier.py")
            carrier_module = importlib.util.module_from_spec(carrier_spec)
            carrier_spec.loader.exec_module(carrier_module)
            carrier_options, proxy = carrier_module.configure(installation_path, public_host, ports[3], ports[4], output, relay_carrier == "wss-connect", use_quic=relay_carrier == "quic")
        services = [sys.executable, ROOT / "scripts/dynamic-mesh/native-services.py", installation_path, "--binary", binary]
        reversed_port = f"tcp:{ports[1]}"
        reverse_installed = False
        try:
            run([binary, "db", "migrate", "--database-url", database], "isolated migration")
            run(services, "isolated services")
            verify_shared_stun(ports[6], lan_address or "127.0.0.1")
            installation = module.Installation(SimpleNamespace(
                environment=installation_path / ".env", control=f"http://127.0.0.1:{ports[1]}", timeout=90, binary=binary))
            mesh = installation.create("android-wireguard")
            peer_context = nullcontext(None)
            if tun_peer:
                path = "/meshes/" + mesh["id"] + "/policy"
                status, current = installation.call(path)
                if status != 200:
                    raise GateError("test policy lookup failed")
                status, _ = installation.call(path, "PUT", {
                    "revision": current["revision"] + 1, "default_action": "allow", "rules": [],
                }, {"If-Match": '"' + str(current["revision"]) + '"'})
                if status != 200:
                    raise GateError("test policy installation failed")
                peer_spec = importlib.util.spec_from_file_location("android_tun_peer", ROOT / "scripts/wireguard-product/android-peer.py")
                peer_module = importlib.util.module_from_spec(peer_spec)
                peer_spec.loader.exec_module(peer_module)
                peer_context = peer_module.linux_peer(installation, mesh, installation_path, output, carrier_options)
            status, ticket = installation.call("/meshes/" + mesh["id"] + "/join-tickets", "POST", {"expires_in_seconds": 900})
            if status != 201:
                raise RuntimeError("isolated Join ticket creation failed")
            bundle = {
                "claim_url": f"http://127.0.0.1:{ports[1]}/api/v1/join/{ticket['token']}/claim",
                "root_fingerprint": ticket["root_fingerprint"], "expires_at": ticket["expires_at_unix"],
                "nonce": base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("="),
            }
            link = "peerward://join?bundle=" + base64.urlsafe_b64encode(json.dumps(bundle).encode()).decode().rstrip("=")
            # Only enrollment uses USB loopback. Relay/STUN use real protected Network sockets.
            for attempt in range(3):
                try:
                    run([*adb, "reverse", reversed_port, reversed_port], "enrollment loopback")
                    reverse_installed = True
                    break
                except GateError:
                    if attempt == 2:
                        raise
                    time.sleep(.2)
            arguments += ["-e", "peerwardJoinLink", link, "-e", "peerwardExpectedRelayHost", public_host,
                          "-e", "peerwardExpectedRelayPort", str(ports[3]),
                          "-e", "peerwardExpectedStunServer", f"{public_host}:{ports[6]}",
                          "-e", "peerwardConsoleRenewal", "true"]
            if carrier_options:
                encoded = base64.b64encode(json.dumps(carrier_options).encode()).decode()
                arguments += ["-e", "peerwardRelayTransport", encoded, "-e", "peerwardExpectedCarrier", "quic" if relay_carrier == "quic" else "wss"]
            if lan_address:
                arguments += ["-e", "peerwardUnderlayChange", "wifi"]
            with peer_context as address, (console_process(installation, output) if console_ui else nullcontext(None)) as console_url:
                if address:
                    arguments += ["-e", "peerwardTunPeer", address]
                if network_attempts:
                    arguments += ["-e", "peerwardNetworkAttempts", str(network_attempts)]
                if power_seconds:
                    arguments += ["-e", "peerwardPowerSeconds", str(power_seconds)]
                if restart_process:
                    arguments += ["-e", "peerwardHostRestart", "true"]
                if os_revoke:
                    arguments += ["-e", "peerwardOsRevoke", "true"]
                with console_renewal(installation, mesh, adb, package, output, console_url):
                    passed = instrument(adb, arguments, output, 1, package)
                # Preserve completed phases before process death/reboot. Later
                # failure or locked credential storage must not erase this evidence.
                if power_seconds:
                    metrics = collect_report(adb, package, output, "power-lifecycle")
                    passed = passed and metrics.get("passed") is True
                if network_attempts:
                    recovery = collect_report(adb, package, output, "network-recovery")
                    passed = passed and recovery.get("passed") is True and len(recovery.get("trials", [])) == network_attempts
                if restart_process and passed:
                    passed = restart_device_runtime(adb, output, arguments, package, reboot_device, reversed_port)
                for enabled, name in [(restart_process, "process-restart"), (os_revoke, "os-revocation")]:
                    if enabled:
                        report = collect_report(adb, package, output, name)
                        passed = report.get("passed") is True and passed
                if address:
                    counts = json.loads((output / "linux-echo.json").read_text())
                    passed = passed and counts["full_size_datagrams"] >= 40
                return passed, hashlib.sha256(binary.read_bytes()).hexdigest()
        except Exception as error:
            (output / "backend-failure.json").write_text(json.dumps({
                "error": str(error) if isinstance(error, GateError) else type(error).__name__,
                "locations": [Path(frame.filename).name + ":" + str(frame.lineno) for frame in traceback.extract_tb(error.__traceback__)],
            }, indent=2))
            raise
        finally:
            pending_error = sys.exc_info()[0] is not None
            for role in ("control", "relay"):
                log = installation_path / (role + ".log")
                if log.exists():
                    (output / (role + ".log")).write_bytes(log.read_bytes())
            if proxy:
                proxy.stop()
            cleanup_failed = False
            for command, label in [
                *([([*adb, "shell", "dumpsys", "deviceidle", "unforce"], "restore OS idle state")] if power_seconds else []),
                *([([*adb, "reverse", "--remove", reversed_port], "remove enrollment loopback")] if reverse_installed else []),
                ([*adb, "shell", *(["svc", "wifi", "enable"] if lan_address else
                                  ["cmd", "connectivity", "airplane-mode", "disable"])], "restore underlay"),
                ([*services, "--stop"], "stop isolated services"),
            ]:
                try:
                    run(command, label, 30)
                except Exception as error:
                    cleanup_failed = True
                    with (output / "cleanup-errors.log").open("a") as log:
                        log.write(label + ": " + type(error).__name__ + "\n")
            if cleanup_failed and not pending_error:
                raise GateError("isolated backend cleanup failed; see cleanup-errors.log")


def verify_shared_stun(port, host="127.0.0.1"):
    """Probe the installed host listener; it exists even before any Mesh is created."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((host, 0))
        probe.settimeout(2)
        transaction = secrets.token_bytes(12)
        request = bytes.fromhex("000100002112a442") + transaction
        probe.sendto(request, (host, port))
        reply, source = probe.recvfrom(1024)
        expected = (bytes.fromhex("0101000c2112a442") + transaction + bytes.fromhex("002000080001") +
                    (probe.getsockname()[1] ^ 0x2112).to_bytes(2, "big") +
                    bytes(a ^ b for a, b in zip(socket.inet_aton(host), bytes.fromhex("2112a442"))))
        if source != (host, port) or reply != expected:
            raise GateError("shared STUN listener returned an invalid binding")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="Explicit ADB target; the selected test app profile is cleared")
    parser.add_argument("--allow-physical", action="store_true")
    parser.add_argument("--validation-app", action="store_true", help="Require APKs built with -PpeerwardValidation=true")
    parser.add_argument("--lan-address", help="Host IPv4 address reachable over the phone's Wi-Fi; full phone gate only")
    parser.add_argument("--relay-carrier", choices=["tcp", "quic", "wss", "wss-connect"], default="tcp")
    parser.add_argument("--apk-root", type=Path, default=ROOT / "apps/peerward-android/app/build/outputs/apk")
    parser.add_argument("--network-attempts", type=int, default=0, help="1..100 physical Wi-Fi recovery trials on the same TUN/socket")
    parser.add_argument("--power-seconds", type=int, default=0, help="30..300 seconds of screen-off forced deep Doze followed by a real TUN echo")
    parser.add_argument("--restart-process", action="store_true", help="kill only the validation process and verify stored-key/TUN recovery in a new process")
    parser.add_argument("--reboot-device", action="store_true", help="also reboot the selected test device; its user must unlock it once after boot")
    parser.add_argument("--os-revoke", action="store_true", help="the separate test APK obtains VPN permission so Android revokes the product VPN")
    parser.add_argument("--tun-peer", action="store_true", help="Add an isolated Linux TUN peer and verify 1200-byte traffic before/after Wi-Fi replacement")
    parser.add_argument("--console-ui", action="store_true", help="Submit renewal from a real isolated browser Console and capture completion across reload")
    parser.add_argument("--native-only", action="store_true", help=f"{NATIVE_TEST_COUNT} native/platform tests, no backend/UI gate")
    parser.add_argument("--backend-only", action="store_true", help="Run only the isolated product/lifecycle scenario; does not establish native/platform acceptance")
    parser.add_argument("--isolated-database", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/wireguard/android-runtime")
    args = parser.parse_args()
    if args.native_only and args.backend_only:
        parser.error("--native-only and --backend-only are mutually exclusive")
    if args.console_ui and args.native_only:
        parser.error("--console-ui requires the real backend scenario")
    if not 0 <= args.network_attempts <= 100 or (args.network_attempts and not (args.tun_peer and args.allow_physical)):
        parser.error("network attempts require --tun-peer and --allow-physical, and must be 0..100")
    if args.power_seconds and (not args.tun_peer or not 30 <= args.power_seconds <= 300):
        parser.error("power lifecycle requires --tun-peer and 30..300 seconds")
    if (args.restart_process or args.os_revoke or args.reboot_device) and not (args.validation_app and args.tun_peer):
        parser.error("OS lifecycle tests require --validation-app and --tun-peer")
    if args.reboot_device and not args.restart_process:
        parser.error("device reboot requires --restart-process")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", args.serial):
        parser.error("invalid ADB serial")
    if args.allow_physical and not args.validation_app:
        parser.error("physical tests require the separate --validation-app package")
    if not args.allow_physical and not re.fullmatch(r"emulator-[0-9]+", args.serial):
        parser.error("physical-device serials require --allow-physical --validation-app")
    if args.tun_peer and (not args.lan_address or args.native_only):
        parser.error("--tun-peer requires the full gate and --lan-address")
    if args.lan_address:
        address = ipaddress.IPv4Address(args.lan_address)
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            parser.error("LAN address must be a host interface IPv4 address")
        with socket.socket() as probe:
            probe.bind((args.lan_address, 0))
    if not args.native_only and not args.isolated_database:
        return subprocess.call([ROOT / "scripts/with-postgres.sh", sys.executable, __file__, *sys.argv[1:], "--isolated-database"], cwd=ROOT)
    if not args.native_only and "PEERWARD_TEST_DATABASE_URL" not in os.environ:
        parser.error("disposable PostgreSQL was not provisioned")
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk:
        parser.error("ANDROID_HOME or ANDROID_SDK_ROOT is required")
    adb = [str(Path(sdk) / "platform-tools/adb"), "-s", args.serial]
    physical = run([*adb, "shell", "getprop", "ro.kernel.qemu"], "target check").strip() != "1"
    if physical and not (args.allow_physical and args.validation_app):
        parser.error("physical target requires explicit selection and the validation package")
    if physical and not args.native_only:
        if not args.lan_address:
            parser.error("full phone gate requires --lan-address")
        if run([*adb, "shell", "settings", "get", "global", "wifi_on"], "Wi-Fi state").strip() != "1":
            parser.error("full phone gate requires Wi-Fi already enabled")
        if run([*adb, "shell", "settings", "get", "global", "airplane_mode_on"], "airplane state").strip() != "0":
            parser.error("full phone gate requires airplane mode already disabled")
        connectivity = run([*adb, "shell", "dumpsys", "connectivity"], "VPN state")
        if re.search(r"NetworkAgentInfo[^\n]*\bVPN\b", connectivity):
            parser.error("disconnect the existing VPN before the full phone gate")
    package = PACKAGE + (".validation" if args.validation_app else "")
    api = int(run([*adb, "shell", "getprop", "ro.build.version.sdk"], "API level").strip())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = args.output.resolve() / f"api{api}-{stamp}"
    output.mkdir(parents=True)
    report = {"schema_version": 1, "release_gate_eligible": False, "api": api,
              "state": "running", "process": process_identity(),
              "physical": physical, "application_id": package, "relay_carrier": args.relay_carrier,
              "console_ui": args.console_ui,
              "scope": "native" if args.native_only else "isolated_backend" if args.backend_only else "native_and_isolated_backend",
              "network_attempts": args.network_attempts,
              "power_seconds": args.power_seconds,
              "restart_process": args.restart_process, "reboot_device": args.reboot_device, "os_revoke": args.os_revoke,
              "passed": False, "expected_tests": NATIVE_TEST_COUNT if args.native_only else 1 if args.backend_only else NATIVE_TEST_COUNT + 1,
              "not_claimed": ["TUN-to-TUN data throughput", "100-attempt NAT/SLO matrix", "Doze", "24-hour stability"]}
    if not physical:
        report["not_claimed"].append("physical device")
    if args.backend_only:
        report["not_claimed"].append("native/platform component suite")
    if not args.native_only:
        report["underlay_change"] = "wifi" if args.lan_address else "airplane_mode"
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    try:
        report["apk_sha256"] = {}
        original_root = args.apk_root
        args.apk_root = output / "tested-apks"
        apks = []
        for name in ["debug/app-debug.apk", "androidTest/debug/app-debug-androidTest.apk"]:
            copied = args.apk_root / name
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original_root / name, copied)
            apks.append(copied)
        analyzer = Path(sdk) / "cmdline-tools/latest/bin/apkanalyzer"
        for apk, expected_id in zip(apks, [package, package + ".test"]):
            manifest = ET.fromstring(run([analyzer, "manifest", "print", apk], "APK manifest"))
            if manifest.get("package") != expected_id:
                raise GateError("APK application ID differs from selected test package; nothing installed")
            target = manifest.find("instrumentation")
            if expected_id == package + ".test" and target is None:
                raise GateError("test APK has no instrumentation target; nothing installed")
            if target is not None and target.get("{http://schemas.android.com/apk/res/android}targetPackage") != package:
                raise GateError("instrumentation target differs from selected test package; nothing installed")
        for apk in apks:
            name = str(apk.relative_to(args.apk_root))
            digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            report["apk_sha256"][name] = digest
            selected = package + (".test" if "androidTest" in apk.parts else "")
            lookup = subprocess.run([*adb, "shell", "pm", "path", selected], text=True,
                                    capture_output=True, timeout=30)
            installed = lookup.stdout.strip().splitlines() if lookup.returncode == 0 else []
            matches = False
            if len(installed) == 1 and installed[0].startswith("package:/data/app/"):
                current = run([*adb, "shell", "sha256sum", installed[0].removeprefix("package:")], "installed APK digest")
                matches = current.split()[0] == digest
            if not matches:
                run([*adb, "install", "-r", apk], "install test APK")
        run([*adb, "shell", "am", "force-stop", package], "start clean app process")
        run([*adb, "shell", "run-as", package, "rm", "-f", *[
            f"files/wireguard-{name}.json" for name in ("process-restart", "os-revocation", "restart-baseline", "power-lifecycle", "network-recovery", "stop-diagnostics")]], "clear selected validation evidence")
        arguments = ["-e", "class", ",".join(f"{PACKAGE}.{name}" for name in CLASSES)]
        if args.backend_only:
            report["native_platform"] = {"state": "not_run", "expected_tests": 0, "passed": False}
        else:
            native_passed = instrument(adb, arguments, output, NATIVE_TEST_COUNT, package)
            report["native_platform"] = {"expected_tests": NATIVE_TEST_COUNT, "passed": native_passed}
            if args.native_only:
                report["passed"] = native_passed
            else:
                (output / "instrumentation.log").rename(output / "instrumentation-native.log")
                if not native_passed:
                    raise GateError("native/platform phase failed; backend phase not started")
        if not args.native_only:
            # The UI enrollment phase owns a fresh process. Synthetic native
            # test workers and its temporary foreground Activity must not leak
            # into the real service lifecycle/Doze/network measurements.
            run([*adb, "shell", "am", "force-stop", package], "finish native/platform process")
            arguments = ["-e", "class", f"{PACKAGE}.RealBackendInstrumentedTest"]
            if not physical:
                run([*adb, "shell", "cmd", "connectivity", "airplane-mode", "disable"], "enable test underlay")
            report["passed"], report["backend_sha256"] = full_gate(adb, output, arguments, package, args.lan_address, args.tun_peer, args.relay_carrier, args.network_attempts, args.power_seconds, args.restart_process, args.reboot_device, args.os_revoke, args.console_ui)
            for name in ("process-restart", "os-revocation", "host-restart"):
                if (output / (name + ".json")).exists():
                    report[name.replace("-", "_")] = json.loads((output / (name + ".json")).read_text())
            if (output / "power-lifecycle.json").exists():
                report["power_lifecycle"] = json.loads((output / "power-lifecycle.json").read_text())
                if report["power_lifecycle"].get("passed"):
                    report["not_claimed"].remove("Doze")
            if (output / "network-recovery.json").exists():
                report["network_recovery"] = json.loads((output / "network-recovery.json").read_text())
            report["shared_stun_listener_and_join_advertisement"] = report["passed"]
            if args.tun_peer:
                report["linux_android_tun_before_after_underlay"] = report["passed"]
                report["linux_echo"] = json.loads((output / "linux-echo.json").read_text())
    except Exception as error:
        report["error"] = str(error) if isinstance(error, GateError) else type(error).__name__
        report["error_locations"] = [Path(frame.filename).name + ":" + str(frame.lineno) for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        try:
            collect_report(adb, package, output, "stop-diagnostics")
        except Exception:
            pass
        if (output / "backend-binary.json").exists():
            report["backend_sha256"] = json.loads((output / "backend-binary.json").read_text())["sha256"]
        for name in ("network-recovery", "power-lifecycle", "process-restart", "os-revocation", "host-restart"):
            path = output / (name + ".json")
            if path.exists():
                report[name.replace("-", "_")] = json.loads(path.read_text())
        if report.get("power_lifecycle", {}).get("passed") and "Doze" in report["not_claimed"]:
            report["not_claimed"].remove("Doze")
        for stopped_package in [package + ".test", package]:
            try:
                run([*adb, "shell", "am", "force-stop", stopped_package], "stop test app", 30)
            except Exception:
                report["passed"] = False
                report["error"] = "test app cleanup failed"
        apply_diagnostic_intervention(report, output)
        report["state"] = "passed" if report["passed"] else "failed"
        temporary = output / "verification.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(output / "verification.json")
    print(f"Android gate {'passed' if report['passed'] else 'FAILED'}: {output}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

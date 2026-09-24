"""Physical-device evidence collection without assuming ADB exit status means valid JSON."""
import json
import re
import shlex
import subprocess
import time


def collect_process_snapshot(adb, package, pid, output):
    """Read only the selected validation process before a watchdog destroys evidence."""
    if package != "io.github.peerward.peerward.validation" or not str(pid).isdigit():
        raise ValueError("process diagnostics require the selected validation process")
    script = f'''for name in status stat schedstat cgroup; do
  echo "PROCESS $name"
  cat /proc/{pid}/$name
done
count=0
for task in /proc/{pid}/task/*; do
  [ "$count" -ge 64 ] && break
  echo "TASK $task"
  cat "$task/stat" "$task/schedstat" "$task/wchan"
  echo
  count=$((count + 1))
done'''
    result = subprocess.run([*adb, "shell", shlex.join([
        "run-as", package, "sh", "-c", script])], text=True, capture_output=True, timeout=10)
    with (output / "native-stall-process.log").open("a") as log:
        log.write(f"HOST monotonic={time.monotonic()} pid={pid} exit={result.returncode}\n")
        log.write(result.stdout + result.stderr + "\n")
    policy = subprocess.run([*adb, "shell", "dumpsys", "window", "policy"],
                            text=True, capture_output=True, timeout=10)
    # Keep screen/keyguard booleans only; never retain other apps, window titles,
    # notification text or unrelated device diagnostics from a physical phone.
    fields = re.findall(
        r"\b(screenState|interactiveState|showing|inputRestricted|occluded|"
        r"mAwake|mScreenOnEarly|mScreenOnFully|mDeviceInteractive)=(true|false|ON|OFF|AWAKE|ASLEEP)\b",
        policy.stdout)
    with (output / "native-stall-window.jsonl").open("a") as log:
        log.write(json.dumps({"monotonic": time.monotonic(), "pid": int(pid),
                              "exit_code": policy.returncode, "state": dict(fields)}) + "\n")


def apply_diagnostic_intervention(report, output):
    """A manually rescued attempt cannot become an unattended acceptance PASS."""
    path = output / "diagnostic-intervention.json"
    if path.exists():
        report["diagnostic_intervention"] = json.loads(path.read_text())
        report["passed"] = False
        report.setdefault("error", "diagnostic intervention; unattended acceptance not established")


def collect_report(adb, package, output, name):
    result = subprocess.run([*adb, "exec-out", "run-as", package, "cat",
                             f"files/wireguard-{name}.json"], text=True,
                            capture_output=True, timeout=10)
    try:
        report = json.loads(result.stdout)
        if result.returncode != 0 or not isinstance(report, dict):
            raise ValueError("invalid report")
    except (ValueError, TypeError):
        (output / (name + "-collection.log")).write_text(result.stdout + result.stderr)
        report = {"passed": False, "error": "device evidence missing or invalid"}
    (output / (name + ".json")).write_text(json.dumps(report, indent=2) + "\n")
    return report


class IdleWake:
    """Host elapsed time wakes a suspended test process; no app wake lock bypasses Doze."""
    def __init__(self, adb, package, seconds, output):
        self.adb, self.package, self.seconds, self.output = adb, package, seconds, output
        self.entered, self.finished = None, False

    def poll(self):
        if not self.seconds or self.finished:
            return
        if self.entered is None:
            result = subprocess.run([*self.adb, "exec-out", "run-as", self.package,
                                     "cat", "files/wireguard-power-lifecycle.json"],
                                    text=True, capture_output=True, timeout=5)
            try:
                report = json.loads(result.stdout)
            except ValueError:
                return
            if report.get("deep_idle_entered") and not report.get("passed"):
                self.entered = time.monotonic()
            return
        if time.monotonic() - self.entered < self.seconds:
            return
        elapsed = time.monotonic() - self.entered
        observations = []
        for command in (["dumpsys", "deviceidle", "unforce"], ["input", "keyevent", "KEYCODE_WAKEUP"]):
            result = subprocess.run([*self.adb, "shell", *command], text=True,
                                    capture_output=True, timeout=10)
            observations.append({"command": command, "exit_code": result.returncode,
                                 "response": result.stdout.strip()})
        (self.output / "host-idle-wake.json").write_text(json.dumps({
            "host_wait_seconds": elapsed, "wake_commands": observations,
        }, indent=2) + "\n")
        self.finished = True

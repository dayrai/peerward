"""A disposable browser console for a live Android acceptance installation."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def console_process(installation, output):
    # All administrative credentials stay in this host process/environment.
    # The browser only sees the same-origin Console API, as in normal use.
    with (output / "console-build.log").open("w") as log:
        for command in [
            ["cargo", "build", "--locked", "-p", "peerward-console", "--bin", "peerward-console"],
            ["cargo", "build", "--locked", "-p", "peerward-console", "--bin", "peerward-console-web",
             "--target", "wasm32-unknown-unknown", "--no-default-features", "--features", "web"],
        ]:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
    with tempfile.TemporaryDirectory(prefix="peerward-android-console-") as directory:
        assets = Path(directory)
        with (output / "console-build.log").open("a") as log:
            subprocess.run(["wasm-bindgen", str(ROOT / "target/wasm32-unknown-unknown/debug/peerward-console-web.wasm"),
                            "--target", "web", "--out-dir", str(assets), "--out-name", "peerward-console-web"],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
        shutil.copy2(ROOT / "apps/peerward-console/assets/main.css", assets / "main.css")
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        environment = {**os.environ, "PEERWARD_CONSOLE_LISTEN": f"127.0.0.1:{port}",
                       "PEERWARD_CONTROL_URL": installation.args.control,
                       "PEERWARD_CONSOLE_ASSET_DIR": str(assets),
                       "PEERWARD_DEV_BEARER": installation.headers["Authorization"].removeprefix("Bearer ")}
        with (output / "console-server.log").open("w") as log:
            process = subprocess.Popen([ROOT / "target/debug/peerward-console"], cwd=ROOT, env=environment,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("isolated Console exited before readiness")
                    try:
                        with urllib.request.urlopen(origin + "/api/v1/meshes", timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("isolated Console readiness")
                    time.sleep(.1)
                yield origin
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

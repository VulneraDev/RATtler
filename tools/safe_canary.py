#!/usr/bin/env python3
"""Benign macOS adversary-emulation canary for RATtler.

The canary never accepts remote connections, transfers data, invokes launchctl,
or survives cleanup. It exists only to exercise process, socket, and persistence
detections using clearly labeled artifacts.
"""

import argparse
import json
import os
import plistlib
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


LABEL = "com.rattler.safe-canary"
PLIST_NAME = LABEL + ".plist"
CANARY_SOURCE = r"""
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 3;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((unsigned short)atoi(argv[1]));
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) return 4;
    if (listen(server, 1) != 0) return 5;
    int client = accept(server, NULL, NULL);
    if (client < 0) return 6;
    sleep(300);
    close(client);
    close(server);
    return 0;
}
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a harmless local RATtler detection canary.")
    parser.add_argument("--duration", type=int, default=45, help="maximum runtime in seconds")
    return parser


def _install_signal_cleanup() -> None:
    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


def _wait_for_listener(port: int, process: subprocess.Popen) -> socket.socket:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("local canary listener exited unexpectedly")
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=0.25)
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("local canary listener did not become ready")


def run_canary(duration: int) -> int:
    if duration <= 0 or duration > 300:
        raise ValueError("duration must be between 1 and 300 seconds")
    if os.uname().sysname != "Darwin":
        raise RuntimeError("the safe canary currently supports macOS only")
    compiler = Path("/usr/bin/cc")
    if not compiler.exists():
        raise RuntimeError("/usr/bin/cc is unavailable; install Apple command-line tools")

    launch_agents = Path.home() / "Library/LaunchAgents"
    launch_agents.mkdir(mode=0o700, parents=True, exist_ok=True)
    plist_path = launch_agents / PLIST_NAME
    if plist_path.exists():
        raise RuntimeError("safe-canary plist already exists; inspect it before retrying")

    process: Optional[subprocess.Popen] = None
    connection: Optional[socket.socket] = None
    with tempfile.TemporaryDirectory(prefix="rattler-safe-canary-") as directory:
        executable = Path(directory) / "rattler-safe-canary"
        source = Path(directory) / "safe_canary.c"
        source.write_text(CANARY_SOURCE, encoding="utf-8")
        compiled = subprocess.run(
            [str(compiler), str(source), "-o", str(executable)],
            capture_output=True, check=False, text=True, timeout=20,
        )
        if compiled.returncode != 0:
            raise RuntimeError("could not compile the local canary helper")
        executable.chmod(0o700)

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        plist = {
            "Label": LABEL,
            "Disabled": True,
            "ProgramArguments": [str(executable), str(port)],
            "RATtlerSafeCanary": True,
        }
        descriptor = os.open(str(plist_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                plistlib.dump(plist, handle)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

        try:
            process = subprocess.Popen(
                [str(executable), str(port)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            connection = _wait_for_listener(port, process)
            print(json.dumps({
                "status": "ready",
                "pid": process.pid,
                "listener": "127.0.0.1:%d" % port,
                "launch_agent": str(plist_path),
                "disabled": True,
                "network_scope": "loopback-only",
                "duration": duration,
            }, sort_keys=True), flush=True)
            time.sleep(duration)
        finally:
            if connection:
                connection.close()
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if plist_path.exists():
                try:
                    with plist_path.open("rb") as handle:
                        current = plistlib.load(handle)
                    if current.get("RATtlerSafeCanary") is True and current.get("Label") == LABEL:
                        plist_path.unlink()
                except (OSError, plistlib.InvalidFileException, AttributeError):
                    pass
    print(json.dumps({"status": "cleaned"}), flush=True)
    return 0


def main() -> int:
    args = _parser().parse_args()
    _install_signal_cleanup()
    try:
        return run_canary(args.duration)
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"status": "error", "detail": str(error)}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

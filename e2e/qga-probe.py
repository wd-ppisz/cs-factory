#!/usr/bin/env python3
"""Probe of a LIVE qemu-guest-agent — gate for the boundary "the agent is not a way
into the customer's system".

Connects to the unix socket QEMU exposes for the `org.qemu.guest_agent.0` channel
(smoke-boot.sh) and, for EVERY command the template must block, makes a real call
with harmless arguments. qemu-ga rejects a blocked command before even looking at
its arguments ("Command ... has been disabled"). Any other answer — success or a
semantic error such as "no such user" — means the command WORKS, so the gate must
fail.

Why a call and not a grep of /etc/qemu/qemu-ga.conf: the file can be dead. The
qemu-ga unit on Debian does not read /etc/default, RHEL takes the list from a
variable in /etc/sysconfig, and the variable names changed between releases. A
configuration that "looks fine" is exactly the class of green gate over a broken
feature.

Arguments are chosen so that an UNBLOCKED command changes nothing: a nonexistent
user, a nonexistent file, a nonexistent handle, /bin/true.

Usage: qga-probe.py <socket> [limit_seconds]
Exit code: 0 = boundary intact, 1 = violation, 2 = agent did not answer.
"""
import json
import random
import socket
import sys
import time

NO_SUCH_USER = "csf-probe-nonexistent"
HANDLE = 987654321

# name -> harmless arguments (in case the command does work)
MUST_BE_BLOCKED = {
    "guest-exec": {"path": "/bin/true"},
    "guest-exec-status": {"pid": 1},
    "guest-file-open": {"path": "/nonexistent/csf-probe", "mode": "r"},
    "guest-file-read": {"handle": HANDLE},
    "guest-file-write": {"handle": HANDLE, "buf-b64": ""},
    "guest-file-seek": {"handle": HANDLE, "offset": 0, "whence": 0},
    "guest-file-flush": {"handle": HANDLE},
    "guest-file-close": {"handle": HANDLE},
    "guest-ssh-get-authorized-keys": {"username": NO_SUCH_USER},
    "guest-ssh-add-authorized-keys": {"username": NO_SUCH_USER, "keys": ["ssh-ed25519 AAAA csf-probe"]},
    "guest-ssh-remove-authorized-keys": {"username": NO_SUCH_USER, "keys": ["ssh-ed25519 AAAA csf-probe"]},
    "guest-set-user-password": {"username": NO_SUCH_USER, "password": "AAAA", "crypted": False},
    "guest-get-users": {},
}
# What the platform needs: fsfreeze = consistent snapshots and backups (backup tooling
# calls `virsh domfsfreeze/domfsthaw`), ping/sync = libvirt checks the agent is alive.
MUST_WORK = ["guest-ping", "guest-sync", "guest-info",
             "guest-fsfreeze-status", "guest-fsfreeze-freeze", "guest-fsfreeze-thaw"]


class Agent:
    def __init__(self, path, timeout=15):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect(path)
        self.buf = b""
        self.timeout = timeout

    def _receive(self, matches):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                line = line.replace(b"\xff", b"").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if matches(obj):
                    return obj
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                raise ConnectionError("agent closed the connection")
            self.buf += chunk
        raise TimeoutError("no answer from the agent")

    def sync(self):
        # A virtio-serial channel may hold garbage left by a previous client —
        # hence 0xFF (resets the agent-side parser) and waiting for OUR identifier.
        ident = random.randint(1, 2**31 - 1)
        self.s.sendall(b"\xff" + json.dumps({"execute": "guest-sync",
                                             "arguments": {"id": ident}}).encode() + b"\n")
        self._receive(lambda o: o.get("return") == ident)

    def call(self, name, arguments=None):
        command = {"execute": name}
        if arguments:
            command["arguments"] = arguments
        self.s.sendall(json.dumps(command).encode() + b"\n")
        return self._receive(lambda o: "return" in o or "error" in o)


def connect(path, limit):
    deadline = time.monotonic() + limit
    last = "no attempts"
    while time.monotonic() < deadline:
        try:
            a = Agent(path)
            a.sync()
            return a
        except (OSError, TimeoutError, ConnectionError) as e:
            last = str(e)
            time.sleep(5)
    print(f"FAIL QEMU agent did not answer within {limit}s ({last}) — the qemu-guest-agent "
          "service is not running in the guest or the org.qemu.guest_agent.0 channel is missing")
    sys.exit(2)


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    a = connect(path, limit)
    info = a.call("guest-info")
    if "return" not in info:
        print(f"FAIL guest-info did not return the command list: {info}")
        return 1
    version = info["return"].get("version", "?")
    known = {c["name"]: c.get("enabled") for c in info["return"].get("supported_commands", [])}
    print(f"QEMU agent {version}, commands in guest-info: {len(known)}")
    bad = 0

    for name in MUST_WORK:
        if known.get(name):
            print(f"  OK   {name} available (needed by the platform)")
        else:
            print(f"  FAIL {name} UNAVAILABLE — the platform needs it (snapshots/backup/libvirt)")
            bad = 1
    resp = a.call("guest-ping")
    if "return" not in resp:
        print(f"  FAIL guest-ping does not work: {resp}")
        bad = 1

    for name, arguments in MUST_BE_BLOCKED.items():
        resp = a.call(name, arguments)
        err = resp.get("error") or {}
        desc = " ".join(str(err.get("desc", "")).split())
        if "disabled" in desc.lower():
            print(f"  OK   {name} blocked")
        elif name not in known and err.get("class") == "CommandNotFound":
            # an older agent does not know the command at all — nothing to block
            print(f"  OK   {name} unknown to agent {version} (not applicable)")
        elif "return" in resp:
            print(f"  FAIL {name} EXECUTED — the agent gives access to the customer's system")
            bad = 1
        else:
            print(f"  FAIL {name} AVAILABLE (rejected only semantically: {desc[:120]})")
            bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main())

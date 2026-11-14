#!/usr/bin/env python3
"""Minimal beacon server for smoke-boot: logs GET paths to a file.

Port 0 = pick a FREE port and report it in the `<log>.port` file. A fixed port
collided when the CI runner ran two builds in parallel: the second server could
not bind, the beacon had nowhere to go and smoke-boot reported "user-data did NOT
run" on a perfectly healthy image. Reporting the port through a file is race-free —
unlike "find a free port, then bind it".

`/wait` is a valve for the guest probe: it answers "go" only once smoke-boot has
created the `<log>.go` file (done querying the QEMU agent). Until then the guest
does not finish its user-data, so it does not power off during the measurement.
"""
import http.server
import os
import sys

port = int(sys.argv[1])
logf = sys.argv[2]


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/wait"):
            body = b"go" if os.path.exists(logf + ".go") else b"wait"
        else:
            body = b"ok"
            with open(logf, "a") as f:
                f.write(self.path + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# Loopback only: the QEMU guest (`-netdev user`, slirp) connects to 10.0.2.2, and
# slirp forwards that to the host's 127.0.0.1. Listening on 0.0.0.0 would expose
# the server to the build host's network for the duration of the test (bandit B104).
srv = http.server.HTTPServer((os.environ.get("BEACON_BIND", "127.0.0.1"), port), H)
with open(logf + ".port", "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()

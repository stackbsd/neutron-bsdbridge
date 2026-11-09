"""Supervisor of the vxlan slow path process."""

import json
import queue
import socket
import subprocess
import sys
import threading
import time

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

RESTART_DELAY = 5
REQUEST_TIMEOUT = 5
POLL_INTERVAL = 0.5
COUNTERS = ("answered", "forwarded", "dropped")


class SlowPathProcess:
    """The slow path child with its networks and the ports it reports."""

    def __init__(self, local, port, rate, ports=None, on_restart=None, command=None):
        """Hold the child's command line, the known ports and no child."""
        command = command or [
            sys.executable,
            "-m",
            "neutron_bsdbridge.l2_agent.slowpath",
        ]
        self.argv = [
            *command,
            "--local",
            local,
            "--port",
            str(port),
            "--rate",
            str(rate),
        ]
        self.ports = dict(ports or {})
        self.networks = {vni: {} for vni in self.ports}
        self.on_restart = on_restart
        self.requests = queue.Queue()
        self.stopping = False
        self.proc = None
        self.sock = None
        self.counts = dict.fromkeys(COUNTERS, 0)

    def describe(self):
        """Return the networks as the child takes them, with their ports."""
        return {
            str(vni): dict(desc, port=self.ports.get(vni))
            for vni, desc in self.networks.items()
        }

    def request(self, message):
        """Hand a message to the supervising thread and return the reply."""
        done = threading.Event()
        box = {}
        self.requests.put((message, box, done))
        done.wait(2 * REQUEST_TIMEOUT)
        return box.get("reply")

    def ports_for(self, vnis):
        """Return the loopback port of every wanted network, opening new ones."""
        self.networks = {vni: self.networks.get(vni, {}) for vni in vnis}
        self.request({"networks": self.describe()})
        return {vni: self.ports[vni] for vni in vnis if vni in self.ports}

    def update(self, tables):
        """Replace every network's peers, ARP table and local addresses."""
        self.networks = {
            vni: {"peers": list(peers), "arp": arp, "local": list(local)}
            for vni, (peers, arp, local) in tables.items()
        }
        self.request({"networks": self.describe()})

    def stats(self):
        """Return whether the child answers, with its counters."""
        alive = self.request({}) is not None
        return dict(self.counts, networks=len(self.ports), alive=alive)

    def stop(self):
        """Stop the child and the restart loop."""
        self.stopping = True
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()

    def spawn(self):
        """Start the child with a socket pair as its standard streams."""
        ours, theirs = socket.socketpair()
        try:
            self.proc = subprocess.Popen(
                self.argv, stdin=theirs.fileno(), stdout=theirs.fileno()
            )
        finally:
            theirs.close()
        ours.settimeout(REQUEST_TIMEOUT)
        self.sock = ours

    def exchange(self, message):
        """Send one message to the child and return its reply, or None."""
        try:
            self.sock.sendall((json.dumps(message) + "\n").encode())
            line = b""
            while not line.endswith(b"\n"):
                chunk = self.sock.recv(65536)
                if not chunk:
                    return None
                line += chunk
            reply = json.loads(line)
        except (OSError, ValueError):
            return None
        self.counts = {key: reply[key] for key in COUNTERS}
        self.ports = {int(vni): port for vni, port in reply["ports"].items()}
        return reply

    def answer(self, proc, until):
        """Answer queued requests until the child dies or a deadline passes."""
        while not self.stopping and time.monotonic() < until:
            if proc is not None and proc.poll() is not None:
                return
            try:
                message, box, done = self.requests.get(timeout=POLL_INTERVAL)
            except queue.Empty:
                continue
            box["reply"] = self.exchange(message) if proc is not None else None
            done.set()
            # a child that stops answering is replaced
            if proc is not None and box["reply"] is None:
                proc.kill()

    def run(self):
        """Keep the child running, resending its networks after a restart."""
        started = 0
        while not self.stopping:
            try:
                self.spawn()
            except OSError:
                LOG.exception("slow path failed to start; retrying")
                self.answer(None, time.monotonic() + RESTART_DELAY)
                continue
            started += 1
            before = dict(self.ports)
            self.exchange({"networks": self.describe()})
            if started > 1:
                LOG.info("slow path restarted with %d network(s)", len(self.ports))
                if self.ports != before and self.on_restart is not None:
                    self.on_restart()
            self.answer(self.proc, float("inf"))
            code = self.proc.wait()
            self.sock.close()
            if self.stopping:
                return
            LOG.error("slow path exited with %s; restarting", code)
            self.answer(None, time.monotonic() + RESTART_DELAY)

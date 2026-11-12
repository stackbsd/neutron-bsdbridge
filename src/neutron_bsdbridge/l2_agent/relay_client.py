"""Client of the vxlan relay service."""

import json
import socket

REQUEST_TIMEOUT = 5
COUNTERS = ("answered", "forwarded", "dropped")


class RelayClient:
    """The relay's control socket with the networks and ports last exchanged."""

    def __init__(self, path, local, port, rate, ports=None):
        """Hold the socket path, the sender settings and the known ports."""
        self.path = path
        self.settings = {"local": local, "port": port, "rate": rate}
        self.ports = dict(ports or {})
        self.networks = {vni: {} for vni in self.ports}
        self.counts = dict.fromkeys(COUNTERS, 0)

    def request(self, message):
        """Send one message to the relay and return its reply, or None."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(REQUEST_TIMEOUT)
                sock.connect(self.path)
                sock.sendall((json.dumps(message) + "\n").encode())
                line = b""
                while not line.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        return None
                    line += chunk
            reply = json.loads(line)
            counts = {key: reply[key] for key in COUNTERS}
            ports = {int(vni): port for vni, port in reply["ports"].items()}
        except (OSError, ValueError, KeyError):
            return None
        self.counts = counts
        self.ports = ports
        return reply

    def configure(self):
        """Send the sender settings and every network with its port."""
        networks = {
            str(vni): dict(desc, port=self.ports.get(vni))
            for vni, desc in self.networks.items()
        }
        return self.request(dict(self.settings, networks=networks))

    def ports_for(self, vnis):
        """Return the loopback port of every wanted network, opening new ones."""
        self.networks = {vni: self.networks.get(vni, {}) for vni in vnis}
        self.configure()
        return {vni: self.ports[vni] for vni in vnis if vni in self.ports}

    def update(self, tables):
        """Replace every network's peers, ARP table and local addresses."""
        self.networks = {
            vni: {"peers": list(peers), "arp": arp, "local": list(local)}
            for vni, (peers, arp, local) in tables.items()
        }
        self.configure()

    def stats(self):
        """Return whether the relay answers, with its counters."""
        alive = self.request({}) is not None
        return dict(self.counts, networks=len(self.ports), alive=alive)

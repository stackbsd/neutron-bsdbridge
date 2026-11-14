"""vxlan relay service for ARP, DHCP and neighbour discovery."""

import argparse
import dataclasses
import json
import logging
import os
import select
import socket
import sys
import time

from neutron_bsdbridge.constants import (
    DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT,
    DHCPV6_CLIENT_PORT,
    DHCPV6_SERVER_PORT,
    DHCPV6_SERVERS,
    ND_TYPES,
    RELAY_ADDR,
    RELAY_SOCKET,
    RELAY_STATE,
)

LOG = logging.getLogger(__name__)

BUFSIZE = 65535
CONTROL_TIMEOUT = 5
VXLAN_HEADER = 8
ETHER_MIN = 60
ETHERTYPE_ARP = b"\x08\x06"
ETHERTYPE_IPV4 = b"\x08\x00"
ETHERTYPE_IPV6 = b"\x86\xdd"
# ethernet hardware with IPv4 protocol addresses
ARP_IPV4 = b"\x00\x01\x08\x00\x06\x04"
ARP_REQUEST = b"\x00\x01"
ARP_REPLY = b"\x00\x02"
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
DHCP_PORTS = (
    (DHCP_CLIENT_PORT, DHCP_SERVER_PORT),
    (DHCP_SERVER_PORT, DHCP_CLIENT_PORT),
)
DHCPV6_PORTS = (DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT)
DHCPV6_GROUP = socket.inet_pton(socket.AF_INET6, DHCPV6_SERVERS)


@dataclasses.dataclass
class Network:
    """One vxlan network's loopback socket, peers, addresses and budget."""

    sock: socket.socket
    tokens: float
    last: float
    resume: float = 0.0
    peers: tuple = ()
    arp: dict = dataclasses.field(default_factory=dict)
    local: frozenset = frozenset()
    tables: dict = dataclasses.field(default_factory=dict)


def action(frame, arp, local):
    """Return whether a frame is answered, forwarded or dropped."""
    ethertype = frame[12:14]
    if ethertype == ETHERTYPE_ARP:
        if frame[14:22] != ARP_IPV4 + ARP_REQUEST:
            return "forward"
        spa, tpa = frame[28:32], frame[38:42]
        # gratuitous ARP announces a change so it must reach every host
        if spa == tpa:
            return "forward"
        if tpa in arp:
            return "answer"
        # a local VM answers for itself over the bridge
        if tpa in local:
            return "drop"
        return "forward"
    if ethertype == ETHERTYPE_IPV4:
        if frame[23] == IPPROTO_UDP:
            offset = 14 + (frame[14] & 0x0F) * 4
            ports = (
                int.from_bytes(frame[offset : offset + 2], "big"),
                int.from_bytes(frame[offset + 2 : offset + 4], "big"),
            )
            if ports in DHCP_PORTS:
                return "forward"
        return "drop"
    if ethertype == ETHERTYPE_IPV6:
        if frame[20] == IPPROTO_ICMPV6 and frame[54] in ND_TYPES:
            return "forward"
        if frame[20] == IPPROTO_UDP and frame[38:54] == DHCPV6_GROUP:
            ports = (
                int.from_bytes(frame[54:56], "big"),
                int.from_bytes(frame[56:58], "big"),
            )
            if ports == DHCPV6_PORTS:
                return "forward"
        return "drop"
    return "drop"


def arp_reply(frame, arp):
    """Return the ARP reply a table gives for a request frame."""
    sha, spa, tpa = frame[22:28], frame[28:32], frame[38:42]
    mac = arp[tpa]
    body = ARP_IPV4 + ARP_REPLY + mac + tpa + sha + spa
    return (sha + mac + ETHERTYPE_ARP + body).ljust(ETHER_MIN, b"\x00")


class Relay:
    """Loopback sockets and tables for every vxlan network on the host."""

    def __init__(self, state=None, clock=time.monotonic):
        """Start with no sender and no networks."""
        self.state = state
        self.clock = clock
        self.local = None
        self.port = None
        self.rate = 1
        self.tx = None
        self.networks = {}
        self.counts = {"answered": 0, "forwarded": 0, "dropped": 0}

    def configure(self, message):
        """Bind the sender and match the network sockets to a description."""
        if message["local"] != self.local:
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.bind((message["local"], 0))
            if self.tx is not None:
                self.tx.close()
            self.tx = tx
            self.local = message["local"]
        self.port = message["port"]
        self.rate = message["rate"]
        wanted = {int(vni): desc for vni, desc in message["networks"].items()}
        for vni in set(self.networks) - set(wanted):
            self.networks.pop(vni).sock.close()
        for vni, desc in wanted.items():
            net = self.networks.get(vni)
            if net is None:
                now = self.clock()
                net = Network(self.open(desc.get("port")), self.rate, now)
                self.networks[vni] = net
            # a description without tables keeps the ones already held
            for key in ("peers", "arp", "local"):
                if key in desc:
                    net.tables[key] = desc[key]
            net.peers = tuple(net.tables.get("peers", ()))
            net.arp = {
                socket.inet_aton(ip): bytes.fromhex(mac.replace(":", ""))
                for ip, mac in net.tables.get("arp", {}).items()
            }
            net.local = frozenset(
                socket.inet_aton(ip) for ip in net.tables.get("local", ())
            )

    def snapshot(self):
        """Return the description that rebuilds the current networks."""
        ports = self.ports()
        return {
            "local": self.local,
            "port": self.port,
            "rate": self.rate,
            "networks": {
                str(vni): dict(net.tables, port=ports[vni])
                for vni, net in self.networks.items()
            },
        }

    def save(self):
        """Write the snapshot to the state file."""
        if self.state is None:
            return
        scratch = self.state + ".tmp"
        with open(scratch, "w") as f:
            json.dump(self.snapshot(), f)
        os.replace(scratch, self.state)

    def load(self):
        """Configure from the state file of a previous run."""
        try:
            with open(self.state) as f:
                self.configure(json.load(f))
        except FileNotFoundError:
            return
        except (OSError, ValueError, KeyError) as exc:
            LOG.warning("state file ignored: %s", exc)
            return
        LOG.info("resumed %d network(s) from the state file", len(self.networks))

    def open(self, port):
        """Bind a loopback socket on a port, or on any port if it is taken."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((RELAY_ADDR, port or 0))
        except OSError:
            # the agent recreates the interface for the new port
            sock.bind((RELAY_ADDR, 0))
        return sock

    def ports(self):
        """Return the loopback port of every network."""
        return {vni: net.sock.getsockname()[1] for vni, net in self.networks.items()}

    def status(self):
        """Return the counters and the ports."""
        return dict(self.counts, ports=self.ports())

    def allow(self, net):
        """Take a token from a network's bucket, pausing it when empty."""
        now = self.clock()
        net.tokens = min(self.rate, net.tokens + (now - net.last) * self.rate)
        net.last = now
        if net.tokens < 1:
            net.resume = now + (1 - net.tokens) / self.rate
            return False
        net.tokens -= 1
        return True

    def handle(self, vni, data):
        """Return the (payload, address) sends one received packet produces."""
        net = self.networks.get(vni)
        frame = data[VXLAN_HEADER:]
        try:
            what = action(frame, net.arp, net.local) if net else "drop"
        except IndexError:
            what = "drop"
        if what == "answer":
            self.counts["answered"] += 1
            reply = data[:VXLAN_HEADER] + arp_reply(frame, net.arp)
            return [(reply, (self.local, self.port))]
        if what == "forward":
            self.counts["forwarded"] += 1
            return [(data, (peer, self.port)) for peer in net.peers]
        self.counts["dropped"] += 1
        return []

    def serve(self, vni):
        """Read one packet from a network and send what it produces."""
        net = self.networks[vni]
        if not self.allow(net):
            return
        data, _addr = net.sock.recvfrom(BUFSIZE)
        for payload, address in self.handle(vni, data):
            try:
                self.tx.sendto(payload, address)
            except OSError as exc:
                self.counts["dropped"] += 1
                LOG.debug("send to %s failed: %s", address[0], exc)

    def control(self, listener):
        """Answer one request on the control socket."""
        conn, _addr = listener.accept()
        with conn:
            conn.settimeout(CONTROL_TIMEOUT)
            try:
                line = b""
                while not line.endswith(b"\n"):
                    chunk = conn.recv(BUFSIZE)
                    if not chunk:
                        return
                    line += chunk
                message = json.loads(line)
                if "networks" in message:
                    self.configure(message)
                    self.save()
                conn.sendall((json.dumps(self.status()) + "\n").encode())
            except (OSError, ValueError, KeyError) as exc:
                LOG.warning("control request failed: %s", exc)

    def run(self, listener):
        """Serve the network sockets and the control socket forever."""
        poller = select.poll()
        poller.register(listener, select.POLLIN)
        polled = {}
        while True:
            # a closed socket's descriptor can already belong to a new one
            for fd, vni in list(polled.items()):
                net = self.networks.get(vni)
                if net is None or net.sock.fileno() != fd:
                    poller.unregister(fd)
                    del polled[fd]
            now = self.clock()
            timeout = None
            for vni, net in self.networks.items():
                fd = net.sock.fileno()
                if net.resume > now:
                    timeout = min(timeout or 1.0, net.resume - now)
                    if fd in polled:
                        poller.unregister(fd)
                        del polled[fd]
                elif fd not in polled:
                    poller.register(fd, select.POLLIN)
                    polled[fd] = vni
            for fd, _event in poller.poll(None if timeout is None else timeout * 1000):
                if fd in polled:
                    self.serve(polled[fd])
                else:
                    self.control(listener)


def listen(path):
    """Bind the control socket for its owner only."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    mask = os.umask(0o077)
    try:
        listener.bind(path)
    finally:
        os.umask(mask)
    listener.listen()
    return listener


def main(argv=None):
    """Console entrypoint for the vxlan relay service."""
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default=RELAY_SOCKET)
    parser.add_argument("--state", default=RELAY_STATE)
    args = parser.parse_args(argv)
    relay = Relay(args.state)
    relay.load()
    relay.run(listen(args.socket))


if __name__ == "__main__":
    sys.exit(main())

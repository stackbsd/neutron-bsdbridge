"""vxlan slow path process for ARP, DHCP and neighbour discovery."""

import argparse
import dataclasses
import json
import logging
import select
import socket
import sys
import time

from neutron_bsdbridge.constants import SLOW_PATH_ADDR

LOG = logging.getLogger(__name__)

BUFSIZE = 65535
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
DHCP_PORTS = ((68, 67), (67, 68))
# router solicitation and advertisement, neighbour solicitation and advertisement
ND_TYPES = (133, 134, 135, 136)


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
        return "drop"
    return "drop"


def arp_reply(frame, arp):
    """Return the ARP reply a table gives for a request frame."""
    sha, spa, tpa = frame[22:28], frame[28:32], frame[38:42]
    mac = arp[tpa]
    body = ARP_IPV4 + ARP_REPLY + mac + tpa + sha + spa
    return (sha + mac + ETHERTYPE_ARP + body).ljust(ETHER_MIN, b"\x00")


class SlowPath:
    """Loopback sockets and tables for every vxlan network on the host."""

    def __init__(self, local, port, rate, clock=time.monotonic):
        """Bind the sending socket and start with no networks."""
        self.local = local
        self.port = port
        self.rate = rate
        self.clock = clock
        self.networks = {}
        self.counts = {"answered": 0, "forwarded": 0, "dropped": 0}
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tx.bind((local, 0))

    def configure(self, networks):
        """Open, update and close network sockets to match a description."""
        wanted = {int(vni): desc for vni, desc in networks.items()}
        for vni in set(self.networks) - set(wanted):
            self.networks.pop(vni).sock.close()
        for vni, desc in wanted.items():
            net = self.networks.get(vni)
            if net is None:
                now = self.clock()
                net = Network(self.open(desc.get("port")), self.rate, now)
                self.networks[vni] = net
            net.peers = tuple(desc.get("peers", ()))
            net.arp = {
                socket.inet_aton(ip): bytes.fromhex(mac.replace(":", ""))
                for ip, mac in desc.get("arp", {}).items()
            }
            net.local = frozenset(socket.inet_aton(ip) for ip in desc.get("local", ()))

    def open(self, port):
        """Bind a loopback socket on a port, or on any port if it is taken."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((SLOW_PATH_ADDR, port or 0))
        except OSError:
            # the agent recreates the interface for the new port
            sock.bind((SLOW_PATH_ADDR, 0))
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

    def run(self, control=sys.stdin.buffer, reply=sys.stdout.buffer):
        """Serve the sockets and the control pipe until the pipe closes."""
        poller = select.poll()
        poller.register(control, select.POLLIN)
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
                    continue
                line = control.readline()
                if not line:
                    return
                message = json.loads(line)
                if "networks" in message:
                    self.configure(message["networks"])
                reply.write((json.dumps(self.status()) + "\n").encode())
                reply.flush()


def main(argv=None):
    """Console entrypoint for the slow path process."""
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--rate", type=int, required=True)
    args = parser.parse_args(argv)
    SlowPath(args.local, args.port, args.rate).run()


if __name__ == "__main__":
    sys.exit(main())

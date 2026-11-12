"""vxlan relay tests."""

import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import relay

MAC_A = bytes.fromhex("589cfc10ea53")
MAC_B = bytes.fromhex("fa163eaabb02")
BROADCAST = b"\xff" * 6
ALL_NODES = bytes.fromhex("333300000001")


def vxlan(vni, frame):
    return b"\x08\x00\x00\x00" + vni.to_bytes(3, "big") + b"\x00" + frame


def arp_request(spa, tpa, sha=MAC_A):
    body = (
        relay.ARP_IPV4
        + relay.ARP_REQUEST
        + sha
        + socket.inet_aton(spa)
        + b"\x00" * 6
        + socket.inet_aton(tpa)
    )
    return BROADCAST + sha + relay.ETHERTYPE_ARP + body


def ipv4(dst, sport, dport, proto=17, dmac=BROADCAST):
    header = bytearray(20)
    header[0] = 0x45
    header[9] = proto
    header[16:20] = socket.inet_aton(dst)
    udp = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 12
    return dmac + MAC_A + relay.ETHERTYPE_IPV4 + bytes(header) + udp


def ipv6(icmp_type, next_header=58):
    header = bytearray(40)
    header[0] = 0x60
    header[6] = next_header
    header[24:40] = socket.inet_pton(socket.AF_INET6, "ff02::1")
    body = bytes([icmp_type]) + b"\x00" * 23
    return ALL_NODES + MAC_A + relay.ETHERTYPE_IPV6 + bytes(header) + body


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def message(networks, rate=100, port=4789):
    return {"local": "127.0.0.1", "port": port, "rate": rate, "networks": networks}


def make(rate=100, clock=None, port=4789, state=None):
    sp = relay.Relay(state, clock or Clock())
    sp.configure(
        message(
            {
                "5042": {
                    "peers": ["192.0.2.2", "192.0.2.3"],
                    "arp": {"10.99.0.2": MAC_B.hex(":")},
                    "local": ["10.99.0.1"],
                }
            },
            rate,
            port,
        )
    )
    return sp


def close(sp):
    if sp.tx is not None:
        sp.configure(message({}))
        sp.tx.close()


class ActionTestCase(unittest.TestCase):
    def setUp(self):
        self.sp = make()
        self.addCleanup(close, self.sp)

    def peers(self, frame):
        return [
            address for _payload, address in self.sp.handle(5042, vxlan(5042, frame))
        ]

    def test_arp_for_an_unknown_address_goes_to_every_peer(self):
        data = vxlan(5042, arp_request("10.99.0.1", "10.99.0.9"))
        self.assertEqual(
            [(data, ("192.0.2.2", 4789)), (data, ("192.0.2.3", 4789))],
            self.sp.handle(5042, data),
        )
        self.assertEqual(1, self.sp.counts["forwarded"])

    def test_arp_for_a_known_address_is_answered_locally(self):
        request = vxlan(5042, arp_request("10.99.0.1", "10.99.0.2"))
        ((payload, address),) = self.sp.handle(5042, request)
        self.assertEqual(("127.0.0.1", 4789), address)
        self.assertEqual(request[:8], payload[:8])
        frame = payload[8:]
        self.assertEqual(60, len(frame))
        self.assertEqual(MAC_A + MAC_B + relay.ETHERTYPE_ARP, frame[:14])
        self.assertEqual(relay.ARP_IPV4 + relay.ARP_REPLY, frame[14:22])
        self.assertEqual(MAC_B + socket.inet_aton("10.99.0.2"), frame[22:32])
        self.assertEqual(MAC_A + socket.inet_aton("10.99.0.1"), frame[32:42])
        self.assertEqual(1, self.sp.counts["answered"])

    def test_arp_for_a_local_address_is_dropped(self):
        self.assertEqual([], self.peers(arp_request("10.99.0.5", "10.99.0.1")))
        self.assertEqual(1, self.sp.counts["dropped"])

    def test_gratuitous_arp_is_forwarded(self):
        frame = arp_request("10.99.0.2", "10.99.0.2", sha=MAC_B)
        self.assertEqual(2, len(self.peers(frame)))

    def test_dhcp_is_forwarded_and_other_broadcast_is_dropped(self):
        self.assertEqual(2, len(self.peers(ipv4("255.255.255.255", 68, 67))))
        self.assertEqual(2, len(self.peers(ipv4("255.255.255.255", 67, 68))))
        self.assertEqual([], self.peers(ipv4("255.255.255.255", 5000, 9999)))
        self.assertEqual([], self.peers(ipv4("10.99.0.255", 68, 67, proto=6)))
        self.assertEqual([], self.peers(ipv4("239.1.1.1", 5000, 5000)))

    def test_neighbour_discovery_is_forwarded_and_other_ipv6_is_dropped(self):
        for icmp_type in (133, 134, 135, 136):
            self.assertEqual(2, len(self.peers(ipv6(icmp_type))))
        self.assertEqual([], self.peers(ipv6(128)))
        self.assertEqual([], self.peers(ipv6(135, next_header=17)))

    def test_non_ip_truncated_and_unknown_vni_are_dropped(self):
        self.assertEqual([], self.peers(BROADCAST + MAC_A + b"\x88\xb5" + b"\x00" * 46))
        self.assertEqual([], self.peers(b"\x00" * 6))
        self.assertEqual(
            [], self.sp.handle(7, vxlan(7, arp_request("1.1.1.1", "2.2.2.2")))
        )
        self.assertEqual(3, self.sp.counts["dropped"])


class RateTestCase(unittest.TestCase):
    def test_bucket_pauses_the_network_until_it_refills(self):
        clock = Clock()
        sp = make(rate=2, clock=clock)
        self.addCleanup(close, sp)
        net = sp.networks[5042]
        self.assertTrue(sp.allow(net))
        self.assertTrue(sp.allow(net))
        self.assertFalse(sp.allow(net))
        self.assertEqual(100.5, net.resume)
        clock.now += 0.5
        self.assertTrue(sp.allow(net))


class ConfigureTestCase(unittest.TestCase):
    def test_networks_open_on_their_port_and_close_when_dropped(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        holder.bind(("127.0.0.1", 0))
        self.addCleanup(holder.close)
        taken = holder.getsockname()[1]
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
        probe.close()
        sp = relay.Relay(clock=Clock())
        self.addCleanup(close, sp)
        sp.configure(
            message({"5042": {"port": free}, "5043": {"port": taken}, "5044": {}})
        )
        ports = sp.ports()
        self.assertEqual(free, ports[5042])
        self.assertNotEqual(taken, ports[5043])
        self.assertEqual(3, len(set(ports.values())))
        sock = sp.networks[5044].sock
        sp.configure(message({"5042": {"port": free}}))
        self.assertEqual([5042], list(sp.networks))
        self.assertEqual(-1, sock.fileno())
        self.assertEqual({5042: free}, sp.status()["ports"])

    def test_a_description_without_tables_keeps_the_ones_held(self):
        sp = make()
        self.addCleanup(close, sp)
        sp.configure(message({"5042": {"port": sp.ports()[5042]}}))
        net = sp.networks[5042]
        self.assertEqual(("192.0.2.2", "192.0.2.3"), net.peers)
        self.assertEqual({socket.inet_aton("10.99.0.2"): MAC_B}, net.arp)
        sp.configure(message({"5042": {"peers": []}}))
        self.assertEqual((), net.peers)
        self.assertEqual({socket.inet_aton("10.99.0.2"): MAC_B}, net.arp)


class StateTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = os.path.join(tmp.name, "state.json")

    def test_a_new_process_resumes_the_saved_networks_on_their_ports(self):
        first = make(state=self.state)
        first.save()
        port = first.ports()[5042]
        close(first)
        second = relay.Relay(self.state, Clock())
        self.addCleanup(close, second)
        second.load()
        self.assertEqual({5042: port}, second.ports())
        self.assertEqual(("192.0.2.2", "192.0.2.3"), second.networks[5042].peers)
        self.assertEqual("127.0.0.1", second.local)

    def test_a_missing_or_broken_state_file_starts_empty(self):
        sp = relay.Relay(self.state, Clock())
        self.addCleanup(close, sp)
        sp.load()
        self.assertEqual({}, sp.networks)
        with open(self.state, "w") as f:
            f.write("{not json")
        sp.load()
        self.assertEqual({}, sp.networks)

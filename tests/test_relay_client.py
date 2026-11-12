"""vxlan relay client tests."""

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge.l2_agent import relay_client

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
COMMAND = [
    sys.executable,
    "-c",
    f"import sys; sys.path.insert(0, {SRC!r}); "
    "from neutron_bsdbridge.relay import main; main()",
]

MAC_A = bytes.fromhex("589cfc10ea53")
MAC_B = bytes.fromhex("fa163eaabb02")
ARP_REQUEST = (
    b"\xff" * 6
    + MAC_A
    + b"\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01"
    + MAC_A
    + socket.inet_aton("10.99.0.1")
    + b"\x00" * 6
    + socket.inet_aton("10.99.0.2")
)


class RelayClientTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "control.sock")
        self.state = os.path.join(tmp.name, "state.json")

    def serve(self):
        argv = [*COMMAND, "--socket", self.path, "--state", self.state]
        proc = subprocess.Popen(argv)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        deadline = time.monotonic() + 5
        while not self.client().stats()["alive"]:
            if time.monotonic() > deadline:
                raise AssertionError("timed out")
            time.sleep(0.05)
        return proc

    def arp_answer(self, kernel, port):
        header = b"\x08\x00\x00\x00" + (5042).to_bytes(3, "big") + b"\x00"
        kernel.sendto(header + ARP_REQUEST, ("127.0.0.1", port))
        answer, _addr = kernel.recvfrom(65535)
        self.assertEqual(header, answer[:8])
        return answer[8:22]

    def kernel(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)
        self.addCleanup(sock.close)
        return sock

    def client(self, port=4789, **kw):
        return relay_client.RelayClient(self.path, "127.0.0.1", port, 100, **kw)

    def test_the_control_socket_is_for_its_owner_only(self):
        self.serve()
        self.assertEqual(0, os.stat(self.path).st_mode & 0o077)

    def test_ports_follow_the_wanted_networks(self):
        self.serve()
        sp = self.client()
        ports = sp.ports_for([5042, 5043])
        self.assertEqual({5042, 5043}, set(ports))
        self.assertEqual(2, len(set(ports.values())))
        sp.update({5042: (["192.0.2.2"], {"10.99.0.2": "fa:16:3e:aa:bb:02"}, [])})
        self.assertEqual({5042: ports[5042]}, sp.ports_for([5042]))
        self.assertEqual(
            {"answered": 0, "forwarded": 0, "dropped": 0, "networks": 1, "alive": True},
            sp.stats(),
        )

    def test_the_relay_answers_arp_from_the_tables_it_was_sent(self):
        kernel = self.kernel()
        self.serve()
        sp = self.client(port=kernel.getsockname()[1])
        port = sp.ports_for([5042])[5042]
        sp.update({5042: ([], {"10.99.0.2": MAC_B.hex(":")}, [])})
        self.assertEqual(MAC_A + MAC_B + b"\x08\x06", self.arp_answer(kernel, port))
        self.assertEqual(1, sp.stats()["answered"])

    def test_a_new_client_keeps_the_tables_the_relay_holds(self):
        kernel = self.kernel()
        self.serve()
        first = self.client(port=kernel.getsockname()[1])
        ports = first.ports_for([5042])
        first.update({5042: ([], {"10.99.0.2": MAC_B.hex(":")}, [])})
        second = self.client(port=kernel.getsockname()[1], ports=ports)
        self.assertEqual(ports, second.ports_for([5042]))
        self.assertEqual(
            MAC_A + MAC_B + b"\x08\x06", self.arp_answer(kernel, ports[5042])
        )

    def test_a_restarted_relay_resumes_its_ports_and_tables(self):
        kernel = self.kernel()
        proc = self.serve()
        sp = self.client(port=kernel.getsockname()[1])
        ports = sp.ports_for([5042])
        sp.update({5042: ([], {"10.99.0.2": MAC_B.hex(":")}, [])})
        proc.kill()
        proc.wait()
        self.assertFalse(sp.stats()["alive"])
        self.serve()
        self.assertEqual(
            MAC_A + MAC_B + b"\x08\x06", self.arp_answer(kernel, ports[5042])
        )
        self.assertEqual(ports, sp.ports_for([5042]))

    def test_an_absent_relay_is_reported_and_keeps_the_known_ports(self):
        sp = self.client(ports={5042: 61234})
        self.assertEqual({5042: 61234}, sp.ports_for([5042, 5043]))
        self.assertFalse(sp.stats()["alive"])

"""Slow path supervisor tests."""

import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_bsdbridge.l2_agent import supervisor
except ImportError:
    raise unittest.SkipTest("needs oslo libs; run under the neutron venv")

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
COMMAND = [
    sys.executable,
    "-c",
    f"import sys; sys.path.insert(0, {SRC!r}); "
    "from neutron_bsdbridge.l2_agent.slowpath import main; main()",
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


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("timed out")
        time.sleep(0.05)


def start(port=4789, **kw):
    sp = supervisor.SlowPathProcess("127.0.0.1", port, 100, command=COMMAND, **kw)
    thread = threading.Thread(target=sp.run, daemon=True)
    thread.start()
    wait_for(lambda: sp.stats()["alive"])
    return sp


def stop(sp):
    sp.stop()


class SlowPathProcessTestCase(unittest.TestCase):
    def setUp(self):
        supervisor.RESTART_DELAY = 0.1
        self.addCleanup(setattr, supervisor, "RESTART_DELAY", 5)

    def test_ports_follow_the_wanted_networks(self):
        sp = start()
        self.addCleanup(stop, sp)
        ports = sp.ports_for([5042, 5043])
        self.assertEqual({5042, 5043}, set(ports))
        self.assertEqual(2, len(set(ports.values())))
        sp.update({5042: (["192.0.2.2"], {"10.99.0.2": "fa:16:3e:aa:bb:02"}, [])})
        self.assertEqual({5042: ports[5042]}, sp.ports_for([5042]))
        self.assertEqual(
            {"answered": 0, "forwarded": 0, "dropped": 0, "networks": 1, "alive": True},
            sp.stats(),
        )

    def test_the_child_answers_arp_from_the_tables_it_was_sent(self):
        kernel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        kernel.bind(("127.0.0.1", 0))
        kernel.settimeout(5)
        self.addCleanup(kernel.close)
        sp = start(port=kernel.getsockname()[1])
        self.addCleanup(stop, sp)
        port = sp.ports_for([5042])[5042]
        sp.update({5042: ([], {"10.99.0.2": MAC_B.hex(":")}, [])})
        header = b"\x08\x00\x00\x00" + (5042).to_bytes(3, "big") + b"\x00"
        kernel.sendto(header + ARP_REQUEST, ("127.0.0.1", port))
        answer, _addr = kernel.recvfrom(65535)
        self.assertEqual(header, answer[:8])
        self.assertEqual(MAC_A + MAC_B + b"\x08\x06", answer[8:22])
        self.assertEqual(1, sp.stats()["answered"])

    def test_known_ports_are_rebound_at_start(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
        probe.close()
        sp = start(ports={5042: free})
        self.addCleanup(stop, sp)
        self.assertEqual({5042: free}, sp.ports_for([5042]))

    def test_a_dead_child_is_restarted_with_its_networks(self):
        restarts = []
        sp = start(on_restart=lambda: restarts.append(True))
        self.addCleanup(stop, sp)
        ports = sp.ports_for([5042])
        sp.proc.kill()
        wait_for(lambda: not sp.stats()["alive"])
        wait_for(lambda: sp.stats()["alive"])
        self.assertEqual(ports, sp.ports_for([5042]))
        self.assertEqual([], restarts)

    def test_a_port_lost_over_a_restart_is_announced(self):
        restarts = []
        sp = start(on_restart=lambda: restarts.append(True))
        self.addCleanup(stop, sp)
        ports = sp.ports_for([5042])
        sp.proc.kill()
        wait_for(lambda: not sp.stats()["alive"])
        holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", ports[5042]))
        self.addCleanup(holder.close)
        wait_for(lambda: sp.stats()["alive"])
        self.assertNotEqual(ports, sp.ports_for([5042]))
        self.assertEqual([True], restarts)

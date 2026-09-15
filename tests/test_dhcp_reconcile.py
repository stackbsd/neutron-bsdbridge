"""dhcp reconcile tests against a scripted, stateful fake kernel."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge.dhcp_agent import dnsmasq
from neutron_bsdbridge.dhcp_agent import reconcile as dhcp_reconcile
from tests import jail_fake

NET = dnsmasq.DhcpNetwork(
    network_id="590dc57a-8b5e-4b94-b743-74e7d9a1b792",
    port_id="aaaa1111-2222-3333-4444-555566667777",
    mac="fa:16:3e:00:00:01",
    ips=(("10.99.0.2", 24),),
    subnets=(
        dnsmasq.Subnet(
            id="daa048b5-450c-4c4b-97a6-c5f5542289c4",
            cidr="10.99.0.0/24",
            gateway_ip="10.99.0.1",
        ),
    ),
    hosts=(dnsmasq.HostEntry(mac="fa:16:3e:aa:bb:01", ip="10.99.0.5"),),
)

DNSMASQ_PID = "4242"


class FakeKernel(jail_fake.FakeKernel):
    """The jail plane plus a dnsmasq that daemonizes and writes its pidfile."""

    def __init__(self):
        super().__init__()
        self.dnsmasq_running = False

    def pkill(self, argv):
        killed = self.dnsmasq_running
        self.dnsmasq_running = False
        return (0, "", "") if killed else (1, "", "")

    def host(self, argv):
        prog = argv[0]
        if prog == dhcp_reconcile.PS:
            pid = argv[2]
            if self.dnsmasq_running and pid == DNSMASQ_PID:
                return 0, "dnsmasq --conf-file=/dev/null ...\n", ""
            return 1, "", ""
        if prog == dhcp_reconcile.KILL:
            if argv[1] == "-HUP":
                return 0, "", ""
            self.dnsmasq_running = False
            return 0, "", ""
        raise AssertionError(f"unscripted argv: {argv}")

    def jexec(self, jail_name, inner):
        if inner[0].endswith("dnsmasq"):
            pid_arg = next(a for a in inner if a.startswith("--pid-file="))
            path = pid_arg.split("=", 1)[1]
            with open(path, "w") as f:
                f.write(DNSMASQ_PID + "\n")
            self.dnsmasq_running = True
            return 0, "", ""
        raise AssertionError(f"unscripted jexec: {jail_name} {inner}")


class ReconcileTestCase(unittest.TestCase):
    """Build, idempotence, drift, and GC on the fake kernel."""

    def setUp(self):
        """Give every test a fresh kernel and state directory."""
        super().setUp()
        self.kernel = FakeKernel()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _reconcile(self, desired):
        """Run one reconcile against the fake kernel."""
        return dhcp_reconcile.reconcile(
            desired,
            self.tmp.name,
            run=self.kernel,
            dnsmasq_path="/usr/local/sbin/dnsmasq",
        )

    def test_cold_build_manufactures_everything_in_order(self):
        """A cold start builds jail, epair, address, and dnsmasq, in order."""
        result = self._reconcile([NET])
        self.assertEqual([], result.failed, [str(r) for r in result.failed])
        labels = [r.op for r in result.receipts]
        for expected in (
            "CreateJail",
            "JailLoopback",
            "CreateEpair",
            "NameHostIf",
            "MoveJailIf",
            "NameJailIf",
            "SetJailIfMac",
            "SetJailIfInet",
            "StartDnsmasq",
        ):
            self.assertIn(expected, labels)
        self.assertLess(
            labels.index("NameJailIf"),
            labels.index("StartDnsmasq"),
            "the interface exists before dnsmasq binds it",
        )
        self.assertIn(NET.jail, self.kernel.jails)
        self.assertIn(NET.dhcp_if, self.kernel.host_ifaces)
        self.assertEqual(
            "fa:16:3e:00:00:01", self.kernel.jail_ifaces[(NET.jail, "dhcp0")]["mac"]
        )
        self.assertTrue(self.kernel.dnsmasq_running)

    def test_second_reconcile_does_nothing(self):
        """The contract: reconcile twice, the second pass is empty."""
        self._reconcile([NET])
        again = self._reconcile([NET])
        self.assertEqual([], [str(r) for r in again.receipts])
        self.assertFalse(again.changed)

    def test_hosts_drift_is_one_reload(self):
        """A changed allocation rewrites hosts and HUPs dnsmasq, only."""
        self._reconcile([NET])
        grown = dnsmasq.DhcpNetwork(
            network_id=NET.network_id,
            port_id=NET.port_id,
            mac=NET.mac,
            ips=NET.ips,
            subnets=NET.subnets,
            hosts=(
                *NET.hosts,
                dnsmasq.HostEntry(mac="fa:16:3e:aa:bb:02", ip="10.99.0.6"),
            ),
        )
        result = self._reconcile([grown])
        self.assertEqual(
            ["WriteHosts", "ReloadDnsmasq"], [r.op for r in result.receipts]
        )

    def test_subnet_drift_restarts_dnsmasq(self):
        """A changed range restarts dnsmasq."""
        self._reconcile([NET])
        changed = dnsmasq.DhcpNetwork(
            network_id=NET.network_id,
            port_id=NET.port_id,
            mac=NET.mac,
            ips=NET.ips,
            hosts=NET.hosts,
            subnets=(
                *NET.subnets,
                dnsmasq.Subnet(id="s2", cidr="10.98.0.0/24"),
            ),
        )
        result = self._reconcile([changed])
        labels = [r.op for r in result.receipts]
        self.assertIn("StopDnsmasq", labels)
        self.assertIn("StartDnsmasq", labels)
        self.assertLess(labels.index("StopDnsmasq"), labels.index("StartDnsmasq"))

    def test_departed_network_is_garbage_collected(self):
        """An undesired network loses its processes, epair, jail, and state."""
        self._reconcile([NET])
        result = self._reconcile([])
        labels = [r.op for r in result.receipts]
        self.assertEqual(
            ["KillJailProcs", "DestroyEpair", "RemoveJail", "RemoveState"], labels
        )
        self.assertEqual({}, self.kernel.jails)
        self.assertNotIn(NET.dhcp_if, self.kernel.host_ifaces)
        self.assertFalse(
            os.path.exists(os.path.join(self.tmp.name, "dhcp", NET.network_id))
        )

    def test_stale_address_is_dropped(self):
        """An address the port no longer carries is removed from the jail end."""
        self._reconcile([NET])
        self.kernel.jail_ifaces[(NET.jail, "dhcp0")]["inets"].append(("10.99.0.9", 24))
        result = self._reconcile([NET])
        self.assertEqual(["DropJailIfInet"], [r.op for r in result.receipts])
        self.assertEqual(
            [("10.99.0.2", 24)], self.kernel.jail_ifaces[(NET.jail, "dhcp0")]["inets"]
        )

    def test_dead_dnsmasq_is_restarted(self):
        """A dnsmasq that died is simply started again."""
        self._reconcile([NET])
        self.kernel.dnsmasq_running = False
        result = self._reconcile([NET])
        self.assertEqual(["StartDnsmasq"], [r.op for r in result.receipts])

    def test_foreign_jails_and_ifaces_are_untouched(self):
        """Only qdhcp-named jails and group-carrying epairs are collected."""
        self.kernel.jails["operators-jail"] = 99
        self.kernel.host_ifaces["epair9a"] = {"groups": set(), "descr": ""}
        result = self._reconcile([])
        self.assertEqual([], [r.op for r in result.receipts])
        self.assertIn("operators-jail", self.kernel.jails)
        self.assertIn("epair9a", self.kernel.host_ifaces)


class EpairDescriptionTestCase(unittest.TestCase):
    """The epair description is the L2 discovery channel: healed on drift."""

    def setUp(self):
        """Fresh kernel and state dir."""
        super().setUp()
        self.kernel = FakeKernel()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_epair_carries_the_port_uuid_and_drift_heals(self):
        """The epair descr is 'neutron port <uuid>' and is repaired if lost."""
        dhcp_reconcile.reconcile([NET], self.tmp.name, run=self.kernel)
        self.assertEqual(
            "neutron port " + NET.port_id, self.kernel.host_ifaces[NET.dhcp_if]["descr"]
        )
        self.kernel.host_ifaces[NET.dhcp_if]["descr"] = "mangled"
        result = dhcp_reconcile.reconcile([NET], self.tmp.name, run=self.kernel)
        self.assertEqual(["FixEpairDescr"], [r.op for r in result.receipts])
        self.assertEqual(
            "neutron port " + NET.port_id, self.kernel.host_ifaces[NET.dhcp_if]["descr"]
        )

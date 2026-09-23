"""l3 reconcile tests against a scripted, stateful fake kernel."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import constants
from neutron_bsdbridge.l3_agent import reconcile as l3_reconcile
from neutron_bsdbridge.l3_agent import router
from tests import jail_fake

ROUTER_ID = "7c3f1c2e-9a4b-4f0d-8e6a-1b2c3d4e5f60"
GW = router.Port(
    id="aaaa1111-2222-3333-4444-555566667777",
    mac="fa:16:3e:00:00:10",
    ips=(("203.0.113.10", 24),),
    cidrs=("203.0.113.0/24",),
    gateway_ip="203.0.113.1",
)
INT = router.Port(
    id="bbbb1111-2222-3333-4444-555566667777",
    mac="fa:16:3e:00:00:20",
    ips=(("10.0.0.1", 24),),
    cidrs=("10.0.0.0/24",),
    gateway_ip="10.0.0.1",
)
FIP = router.FloatingIp(id="fip-1", floating="203.0.113.50", fixed="10.0.0.5")
RTR = router.Router(
    id=ROUTER_ID,
    gateway=GW,
    interfaces=(INT,),
    floating_ips=(FIP,),
    routes=(("192.168.7.0/24", "10.0.0.7"),),
    enable_snat=True,
)
QG = RTR.jail_if(GW)
QR = RTR.jail_if(INT)


class FakeKernel(jail_fake.FakeKernel):
    """The jail plane plus per-jail forwarding, routes and pf."""

    def __init__(self):
        super().__init__()
        self.forwarding = {}  # jail -> "0" | "1"
        self.routes = {}  # jail -> {(dest, gw)}
        self.pf_enabled = {}  # jail -> bool
        self.pf_rules = {}  # jail -> text

    def jexec(self, jail_name, inner):
        prog = inner[0]
        if prog == constants.SYSCTL:
            if inner[1] == "-n":
                return 0, self.forwarding.get(jail_name, "0") + "\n", ""
            key, value = inner[1].split("=")
            self.forwarding[jail_name] = value
            return 0, f"{key}: 0 -> {value}\n", ""
        if prog == constants.NETSTAT:
            lines = [
                "Routing tables",
                "",
                "Internet:",
                "Destination Gateway Flags Netif",
            ]
            for dest, gw in sorted(self.routes.get(jail_name, set())):
                shown = "default" if dest == "0.0.0.0/0" else dest.removesuffix("/32")
                lines.append(f"{shown:18} {gw:18} UGS  qg-x")
            lines.append("10.0.0.0/24        link#2             U    qr-x")
            return 0, "\n".join(lines) + "\n", ""
        if prog == constants.ROUTE:
            routes = self.routes.setdefault(jail_name, set())
            dest = router.normalize_destination(inner[3])
            if inner[2] == "add":
                routes.add((dest, inner[4]))
                return 0, "", ""
            routes.difference_update({r for r in routes if r[0] == dest})
            return 0, "", ""
        if prog == constants.PFCTL:
            if inner[1] == "-si":
                state = "Enabled" if self.pf_enabled.get(jail_name) else "Disabled"
                return 0, f"Status: {state} for 0 days 00:00:01\n", ""
            if inner[1] == "-e":
                self.pf_enabled[jail_name] = True
                return 0, "", ""
            if inner[1] == "-sr":
                text = self.pf_rules.get(jail_name, "")
                return (
                    0,
                    "".join(
                        line + "\n" for line in text.splitlines() if "pass" in line
                    ),
                    "",
                )
            if inner[1] == "-f":
                with open(inner[2]) as f:
                    self.pf_rules[jail_name] = f.read()
                return 0, "", ""
        raise AssertionError(f"unscripted jexec: {jail_name} {inner}")


class ReconcileTestCase(unittest.TestCase):
    """Build, idempotence, drift, and GC on the fake kernel."""

    def setUp(self):
        super().setUp()
        self.kernel = FakeKernel()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _reconcile(self, desired):
        return l3_reconcile.reconcile(desired, self.tmp.name, run=self.kernel)

    def test_cold_build_manufactures_everything_in_order(self):
        result = self._reconcile([RTR])
        self.assertEqual([], result.failed, [str(r) for r in result.failed])
        labels = [r.op for r in result.receipts]
        for expected in (
            "CreateJail",
            "JailLoopback",
            "EnableForwarding",
            "CreateEpair",
            "NameHostIf",
            "MoveJailIf",
            "NameJailIf",
            "SetJailIfMac",
            "SetJailIfInet",
            "AddRoute",
            "WritePf",
            "EnablePf",
            "LoadPf",
        ):
            self.assertIn(expected, labels)
        self.assertEqual(2, labels.count("CreateEpair"), "one epair per port")
        self.assertLess(labels.index("SetJailIfInet"), labels.index("AddRoute"))
        self.assertLess(labels.index("EnablePf"), labels.index("LoadPf"))
        self.assertIn(RTR.jail, self.kernel.jails)
        self.assertIn(GW.host_if, self.kernel.host_ifaces)
        self.assertIn(INT.host_if, self.kernel.host_ifaces)
        self.assertEqual({"l3-neutron"}, self.kernel.host_ifaces[GW.host_if]["groups"])
        self.assertEqual("1", self.kernel.forwarding[RTR.jail])
        self.assertEqual(
            [("203.0.113.10", 24), ("203.0.113.50", 32)],
            self.kernel.jail_ifaces[(RTR.jail, QG)]["inets"],
        )
        self.assertEqual(
            {("0.0.0.0/0", "203.0.113.1"), ("192.168.7.0/24", "10.0.0.7")},
            self.kernel.routes[RTR.jail],
        )
        self.assertIn("binat on " + QG, self.kernel.pf_rules[RTR.jail])
        self.assertIn("nat on " + QG, self.kernel.pf_rules[RTR.jail])

    def test_second_reconcile_does_nothing(self):
        self._reconcile([RTR])
        again = self._reconcile([RTR])
        self.assertEqual([], [str(r) for r in again.receipts])
        self.assertFalse(again.changed)

    def test_floating_ip_removal_drops_the_alias_and_reloads_pf(self):
        self._reconcile([RTR])
        bare = router.Router(
            id=RTR.id,
            gateway=GW,
            interfaces=RTR.interfaces,
            floating_ips=(),
            routes=RTR.routes,
        )
        result = self._reconcile([bare])
        self.assertEqual(
            ["DropJailIfInet", "WritePf", "LoadPf"], [r.op for r in result.receipts]
        )
        self.assertEqual(
            [("203.0.113.10", 24)], self.kernel.jail_ifaces[(RTR.jail, QG)]["inets"]
        )
        self.assertNotIn("binat", self.kernel.pf_rules[RTR.jail])

    def test_route_change_is_a_delete_and_an_add(self):
        self._reconcile([RTR])
        moved = router.Router(
            id=RTR.id,
            gateway=GW,
            interfaces=RTR.interfaces,
            floating_ips=RTR.floating_ips,
            routes=(("192.168.7.0/24", "10.0.0.8"),),
        )
        result = self._reconcile([moved])
        self.assertEqual(["DeleteRoute", "AddRoute"], [r.op for r in result.receipts])
        self.assertIn(("192.168.7.0/24", "10.0.0.8"), self.kernel.routes[RTR.jail])
        self.assertNotIn(("192.168.7.0/24", "10.0.0.7"), self.kernel.routes[RTR.jail])

    def test_forwarding_drift_is_reset(self):
        self._reconcile([RTR])
        self.kernel.forwarding[RTR.jail] = "0"
        result = self._reconcile([RTR])
        self.assertEqual(["EnableForwarding"], [r.op for r in result.receipts])

    def test_lost_pf_rules_are_reloaded_without_a_rewrite(self):
        self._reconcile([RTR])
        self.kernel.pf_rules[RTR.jail] = ""
        self.kernel.pf_enabled[RTR.jail] = False
        result = self._reconcile([RTR])
        self.assertEqual(["EnablePf", "LoadPf"], [r.op for r in result.receipts])

    def test_router_without_gateway_has_no_default_route_or_nat(self):
        internal = router.Router(
            id=RTR.id, gateway=None, interfaces=(INT,), floating_ips=(), routes=()
        )
        result = self._reconcile([internal])
        self.assertEqual([], result.failed)
        labels = [r.op for r in result.receipts]
        self.assertEqual(1, labels.count("CreateEpair"))
        self.assertNotIn("AddRoute", labels)
        self.assertNotIn("nat on", self.kernel.pf_rules[RTR.jail])

    def test_departed_router_is_garbage_collected(self):
        self._reconcile([RTR])
        result = self._reconcile([])
        labels = [r.op for r in result.receipts]
        self.assertEqual(
            [
                "KillJailProcs",
                "DestroyEpair",
                "DestroyEpair",
                "RemoveJail",
                "RemoveState",
            ],
            labels,
        )
        self.assertEqual({}, self.kernel.jails)
        self.assertNotIn(GW.host_if, self.kernel.host_ifaces)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "l3", ROUTER_ID)))

    def test_dhcp_jails_and_epairs_are_untouched(self):
        self.kernel.jails["qdhcp-590dc57a8b5e"] = 99
        self.kernel.host_ifaces["dhaaaa1111-222"] = {
            "groups": {"dhcp-neutron"},
            "descr": "neutron port x",
        }
        result = self._reconcile([])
        self.assertEqual([], [r.op for r in result.receipts])
        self.assertIn("qdhcp-590dc57a8b5e", self.kernel.jails)
        self.assertIn("dhaaaa1111-222", self.kernel.host_ifaces)


class ParseTestCase(unittest.TestCase):
    def test_parse_routes_keeps_gateway_routes_only(self):
        text = (
            "Routing tables\n\nInternet:\n"
            "Destination        Gateway            Flags     Netif Expire\n"
            "default            203.0.113.1        UGS       qg-aa\n"
            "10.0.0.0/24        link#2             U         qr-bb\n"
            "10.0.0.1           link#2             UHS       lo0\n"
            "192.168.7.0/24     10.0.0.7           UGS       qr-bb\n"
            "192.168.9.9        10.0.0.9           UGHS      qr-bb\n"
        )
        self.assertEqual(
            {
                ("0.0.0.0/0", "203.0.113.1"),
                ("192.168.7.0/24", "10.0.0.7"),
                ("192.168.9.9/32", "10.0.0.9"),
            },
            l3_reconcile.parse_routes(text),
        )

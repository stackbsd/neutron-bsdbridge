"""l3 reconcile tests against a scripted, stateful fake kernel."""

import dataclasses
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
GW6 = router.Port(
    id=GW.id,
    mac=GW.mac,
    ips=(*GW.ips, ("2001:db8:ffff::10", 64)),
    cidrs=GW.cidrs,
    gateway_ip=GW.gateway_ip,
    gateway_ip6="fe80::1",
)
INT6 = router.Port(
    id=INT.id,
    mac=INT.mac,
    ips=(*INT.ips, ("2001:db8:1::1", 64)),
    cidrs=INT.cidrs,
    gateway_ip=INT.gateway_ip,
    prefixes=(router.Prefix(cidr="2001:db8:1::/64", mode="slaac"),),
)
RTR6 = router.Router(
    id=ROUTER_ID,
    gateway=GW6,
    interfaces=(INT6,),
    floating_ips=(),
    routes=(("2001:db8:7::/64", "2001:db8:1::7"),),
)
RTADVD_PID = "4242"
QR = RTR.jail_if(INT)


class FakeKernel(jail_fake.FakeKernel):
    """The jail plane plus per-jail forwarding, routes and pf."""

    def __init__(self):
        super().__init__()
        self.forwarding = {}  # jail -> "0" | "1"
        self.forwarding6 = {}  # jail -> "0" | "1"
        self.rtadvd = {}  # pid -> argv of a running rtadvd
        self.signals = []
        self.routes = {}  # jail -> {(dest, gw)}
        self.pf_enabled = {}  # jail -> bool
        self.pf_rules = {}  # jail -> text

    def jexec(self, jail_name, inner):
        prog = inner[0]
        if prog == constants.SYSCTL:
            knob = inner[-1].split("=")[0]
            table = self.forwarding6 if "inet6" in knob else self.forwarding
            if inner[1] == "-n":
                return 0, table.get(jail_name, "0") + "\n", ""
            key, value = inner[1].split("=")
            table[jail_name] = value
            return 0, f"{key}: 0 -> {value}\n", ""
        if prog == constants.NETSTAT:
            v6 = inner[-1] == "inet6"
            lines = [
                "Routing tables",
                "",
                "Internet6:" if v6 else "Internet:",
                "Destination Gateway Flags Netif",
            ]
            for dest, gw in sorted(self.routes.get(jail_name, set())):
                if (":" in dest) != v6:
                    continue
                shown = dest.removesuffix("/32").removesuffix("/128")
                if dest in ("0.0.0.0/0", "::/0"):
                    shown = "default"
                lines.append(f"{shown:18} {gw:18} UGS  qg-x")
            if v6:
                lines.append("fe80::%qr-x/64     link#2             U    qr-x")
            else:
                lines.append("10.0.0.0/24        link#2             U    qr-x")
            return 0, "\n".join(lines) + "\n", ""
        if prog == constants.RTADVD:
            pid = str(int(RTADVD_PID) + len(self.rtadvd))
            self.rtadvd[pid] = inner
            with open(inner[inner.index("-p") + 1], "w") as f:
                f.write(pid)
            return 0, "", ""
        if prog == constants.ROUTE:
            routes = self.routes.setdefault(jail_name, set())
            dest = inner[4]
            if dest == "default":
                dest = "::/0" if inner[3] == "-inet6" else "0.0.0.0/0"
            dest = router.normalize_destination(dest)
            if inner[2] == "add":
                routes.add((dest, inner[5]))
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

    def host(self, argv):
        if argv[0] == constants.PS:
            if argv[2] in self.rtadvd:
                return 0, " ".join(self.rtadvd[argv[2]]) + "\n", ""
            return 1, "", ""
        if argv[0] == constants.KILL:
            self.signals.append(argv[1:])
            if argv[1] != "-HUP":
                del self.rtadvd[argv[1]]
            return 0, "", ""
        raise AssertionError(f"unscripted argv: {argv}")


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

    def test_epairs_carry_each_port_mtu_on_both_ends(self):
        gw = dataclasses.replace(GW, mtu=1500)
        port = dataclasses.replace(INT, mtu=1450)
        rtr = dataclasses.replace(RTR, gateway=gw, interfaces=(port,))
        result = self._reconcile([rtr])
        self.assertEqual([], result.failed, [str(r) for r in result.failed])
        self.assertEqual(1500, self.kernel.host_ifaces[gw.host_if]["mtu"])
        self.assertEqual(1450, self.kernel.host_ifaces[port.host_if]["mtu"])
        self.assertEqual(1450, self.kernel.jail_ifaces[(rtr.jail, QR)]["mtu"])

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

    def test_port_forwarding_adds_the_alias_and_the_redirect(self):
        self._reconcile([RTR])
        fwd = router.PortForwarding(
            id="pf-1",
            fip_id="fip-2",
            floating="203.0.113.60",
            protocol="tcp",
            external="8080",
            fixed="10.0.0.7",
            internal="80",
        )
        result = self._reconcile([dataclasses.replace(RTR, forwardings=(fwd,))])
        self.assertEqual(
            ["SetJailIfInet", "WritePf", "LoadPf"], [r.op for r in result.receipts]
        )
        self.assertIn(
            ("203.0.113.60", 32), self.kernel.jail_ifaces[(RTR.jail, QG)]["inets"]
        )
        self.assertIn(
            f"rdr on {QG} inet proto tcp to 203.0.113.60 port 8080 -> 10.0.0.7 port 80",
            self.kernel.pf_rules[RTR.jail],
        )
        result = self._reconcile([RTR])
        self.assertEqual(
            ["DropJailIfInet", "WritePf", "LoadPf"], [r.op for r in result.receipts]
        )
        self.assertNotIn("rdr", self.kernel.pf_rules[RTR.jail])

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

    def test_ipv6_router_gets_addresses_routes_and_rtadvd(self):
        result = self._reconcile([RTR6])
        self.assertEqual([], result.failed, [str(r) for r in result.failed])
        self.assertEqual("1", self.kernel.forwarding6[RTR.jail])
        self.assertEqual(
            [("2001:db8:1::1", 64)], self.kernel.jail_ifaces[(RTR.jail, QR)]["inet6s"]
        )
        self.assertEqual(
            {
                ("0.0.0.0/0", "203.0.113.1"),
                ("::/0", "fe80::1%" + QG),
                ("2001:db8:7::/64", "2001:db8:1::7"),
            },
            self.kernel.routes[RTR.jail],
        )
        (argv,) = self.kernel.rtadvd.values()
        self.assertEqual(QR, argv[-1])
        self.assertIn("-s", argv)
        conf = os.path.join(self.tmp.name, "l3", ROUTER_ID, f"rtadvd-{QR}.conf")
        with open(conf) as f:
            self.assertIn('addr0="2001:db8:1::"', f.read())
        self.assertEqual([], [r.op for r in self._reconcile([RTR6]).receipts])

    def test_changed_prefix_reloads_rtadvd(self):
        self._reconcile([RTR6])
        stateful = router.Prefix(cidr="2001:db8:1::/64", mode="dhcpv6-stateful")
        changed = router.Router(
            id=ROUTER_ID,
            gateway=GW6,
            interfaces=(dataclasses.replace(INT6, prefixes=(stateful,)),),
            floating_ips=(),
            routes=RTR6.routes,
        )
        result = self._reconcile([changed])
        self.assertEqual(["ReloadRtadvd"], [r.op for r in result.receipts])
        self.assertEqual([("-HUP", RTADVD_PID)], self.kernel.signals)

    def test_rtadvd_stops_when_no_prefix_is_left(self):
        self._reconcile([RTR6])
        quiet = router.Router(
            id=ROUTER_ID,
            gateway=GW6,
            interfaces=(dataclasses.replace(INT6, prefixes=()),),
            floating_ips=(),
            routes=RTR6.routes,
        )
        result = self._reconcile([quiet])
        self.assertEqual(["StopRtadvd"], [r.op for r in result.receipts])
        self.assertEqual({}, self.kernel.rtadvd)
        self.assertEqual([], [r.op for r in self._reconcile([quiet]).receipts])

    def test_second_advertising_interface_leaves_the_first_running(self):
        self._reconcile([RTR6])
        other = router.Port(
            id="cccc1111-2222-3333-4444-555566667777",
            mac="fa:16:3e:00:00:30",
            ips=(("2001:db8:2::1", 64),),
            cidrs=(),
            prefixes=(router.Prefix(cidr="2001:db8:2::/64", mode="slaac"),),
        )
        both = dataclasses.replace(RTR6, interfaces=(INT6, other))
        result = self._reconcile([both])
        self.assertEqual(1, [r.op for r in result.receipts].count("StartRtadvd"))
        self.assertEqual([], self.kernel.signals)
        self.assertEqual(2, len(self.kernel.rtadvd))

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

    def test_parse_routes_reads_the_inet6_table(self):
        text = (
            "Routing tables\n\nInternet6:\n"
            "Destination                       Gateway                       Flags\n"
            "::1                               link#11                       UHS\n"
            "default                           fe80::1%qg-aa                 UGS\n"
            "2001:db8:1::/64                   link#13                       U\n"
            "2001:db8:7::/64                   2001:db8:1::7                 UGS\n"
            "fe80::%qr-bb/64                   link#13                       U\n"
        )
        self.assertEqual(
            {("::/0", "fe80::1%qg-aa"), ("2001:db8:7::/64", "2001:db8:1::7")},
            l3_reconcile.parse_routes(text, "inet6"),
        )

"""Router spec tests."""

import dataclasses
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import names
from neutron_bsdbridge.l3_agent import router

ROUTER_ID = "7c3f1c2e-9a4b-4f0d-8e6a-1b2c3d4e5f60"
GW_PORT_ID = "aaaa1111-2222-3333-4444-555566667777"
INT_PORT_ID = "bbbb1111-2222-3333-4444-555566667777"
EXT_SUBNET = "e1e1e1e1-0000-0000-0000-000000000001"
INT_SUBNET = "1111aaaa-0000-0000-0000-000000000001"


def gw_port(**kw):
    base = {
        "id": GW_PORT_ID,
        "mac_address": "FA:16:3E:00:00:10",
        "fixed_ips": [{"subnet_id": EXT_SUBNET, "ip_address": "203.0.113.10"}],
        "subnets": [
            {"id": EXT_SUBNET, "cidr": "203.0.113.0/24", "gateway_ip": "203.0.113.1"}
        ],
    }
    base.update(kw)
    return base


def int_port(**kw):
    base = {
        "id": INT_PORT_ID,
        "mac_address": "fa:16:3e:00:00:20",
        "fixed_ips": [{"subnet_id": INT_SUBNET, "ip_address": "10.0.0.1"}],
        "subnets": [
            {"id": INT_SUBNET, "cidr": "10.0.0.0/24", "gateway_ip": "10.0.0.1"}
        ],
    }
    base.update(kw)
    return base


def fip(**kw):
    base = {
        "id": "f1f1f1f1-0000-0000-0000-000000000001",
        "floating_ip_address": "203.0.113.50",
        "fixed_ip_address": "10.0.0.5",
        "port_id": "some-vm-port",
        "status": "DOWN",
    }
    base.update(kw)
    return base


def rpc_router(**kw):
    base = {
        "id": ROUTER_ID,
        "admin_state_up": True,
        "external_gateway_info": {"network_id": "ext", "enable_snat": True},
        "enable_snat": True,
        "gw_port": gw_port(),
        "_interfaces": [int_port()],
        "_floatingips": [fip()],
        "routes": [{"destination": "192.168.7.0/24", "nexthop": "10.0.0.7"}],
    }
    base.update(kw)
    return base


class FromRpcTestCase(unittest.TestCase):
    def test_full_router_builds(self):
        r = router.from_rpc(rpc_router())
        self.assertEqual(ROUTER_ID, r.id)
        self.assertEqual("fa:16:3e:00:00:10", r.gateway.mac, "mac canonicalizes")
        self.assertEqual((("203.0.113.10", 24),), r.gateway.ips)
        self.assertEqual("203.0.113.1", r.gateway.gateway_ip)
        self.assertEqual(1, len(r.interfaces))
        self.assertEqual(("10.0.0.0/24",), r.interfaces[0].cidrs)
        self.assertEqual(("203.0.113.50",), tuple(f.floating for f in r.floating_ips))
        self.assertEqual((("192.168.7.0/24", "10.0.0.7"),), r.routes)
        self.assertTrue(r.enable_snat)

    def test_port_mtu_is_carried_and_zero_means_unknown(self):
        r = router.from_rpc(
            rpc_router(gw_port=gw_port(mtu=0), _interfaces=[int_port(mtu=1450)])
        )
        self.assertIsNone(r.gateway.mtu)
        self.assertEqual(1450, r.interfaces[0].mtu)

    def test_router_without_gateway(self):
        r = router.from_rpc(rpc_router(gw_port=None, _floatingips=[]))
        self.assertIsNone(r.gateway)
        self.assertEqual(
            (("192.168.7.0/24", "10.0.0.7"),),
            router.routes(r),
            "extra routes survive, the default does not",
        )
        self.assertEqual((r.interfaces[0],), r.ports)

    def test_ipv6_interface_carries_its_address_and_prefix(self):
        v6 = int_port(
            id="cccc1111-2222-3333-4444-555566667777",
            fixed_ips=[{"subnet_id": "v6", "ip_address": "fd00::1"}],
            subnets=[
                {
                    "id": "v6",
                    "cidr": "fd00::/64",
                    "gateway_ip": "fd00::1",
                    "ipv6_ra_mode": "dhcpv6-stateless",
                    "dns_nameservers": ["fd00::53"],
                }
            ],
        )
        r = router.from_rpc(rpc_router(_interfaces=[int_port(), v6]))
        port = r.interfaces[1]
        self.assertEqual((("fd00::1", 64),), port.ips)
        self.assertEqual((), port.cidrs)
        self.assertEqual(
            (
                router.Prefix(
                    cidr="fd00::/64", mode="dhcpv6-stateless", dns=("fd00::53",)
                ),
            ),
            port.prefixes,
        )

    def test_subnet_without_ra_mode_is_not_advertised(self):
        v6 = int_port(
            fixed_ips=[{"subnet_id": "v6", "ip_address": "fd00::1"}],
            subnets=[{"id": "v6", "cidr": "fd00::/64", "ipv6_ra_mode": None}],
        )
        r = router.from_rpc(rpc_router(_interfaces=[v6]))
        self.assertEqual((), r.interfaces[0].prefixes)
        self.assertEqual({}, router.rtadvd_confs(r))

    def test_dual_stack_gateway_has_a_default_route_per_family(self):
        gw = gw_port(
            fixed_ips=[
                {"subnet_id": EXT_SUBNET, "ip_address": "203.0.113.10"},
                {"subnet_id": "ext6", "ip_address": "2001:db8:ffff::10"},
            ],
            subnets=[
                {
                    "id": EXT_SUBNET,
                    "cidr": "203.0.113.0/24",
                    "gateway_ip": "203.0.113.1",
                },
                {
                    "id": "ext6",
                    "cidr": "2001:db8:ffff::/64",
                    "gateway_ip": "2001:db8:ffff::1",
                },
            ],
        )
        r = router.from_rpc(rpc_router(gw_port=gw, routes=[]))
        self.assertEqual(
            (("0.0.0.0/0", "203.0.113.1"), ("::/0", "2001:db8:ffff::1")),
            router.routes(r),
        )
        self.assertNotIn("2001:db8", router.pf_text(r)[0])

    def test_rtadvd_text_sets_flags_by_mode(self):
        def text_for(mode):
            v6 = int_port(
                fixed_ips=[{"subnet_id": "v6", "ip_address": "fd00::1"}],
                subnets=[{"id": "v6", "cidr": "fd00::/64", "ipv6_ra_mode": mode}],
            )
            confs = router.rtadvd_confs(router.from_rpc(rpc_router(_interfaces=[v6])))
            return confs[qr]

        qr = names.router_jail_if_name(INT_PORT_ID)
        self.assertEqual(
            f'{qr}:\\\n\t:raflags#0:addr0="fd00::":prefixlen0#64:pinfoflags0="la":\n',
            text_for("slaac"),
        )
        self.assertIn('raflags="o"', text_for("dhcpv6-stateless"))
        stateful = text_for("dhcpv6-stateful")
        self.assertIn('raflags="m"', stateful)
        self.assertIn('pinfoflags0="l":', stateful)

    def test_unassociated_floating_ip_is_skipped(self):
        r = router.from_rpc(rpc_router(_floatingips=[fip(fixed_ip_address=None)]))
        self.assertEqual((), r.floating_ips)

    def test_enable_snat_falls_back_to_gateway_info(self):
        body = rpc_router()
        del body["enable_snat"]
        body["external_gateway_info"]["enable_snat"] = False
        self.assertFalse(router.from_rpc(body).enable_snat)

    def test_route_destinations_normalize(self):
        r = router.from_rpc(
            rpc_router(
                routes=[
                    {"destination": "default", "nexthop": "10.0.0.9"},
                    {"destination": "192.168.7.3", "nexthop": "10.0.0.7"},
                    {"destination": "192.168.8.1/24", "nexthop": "10.0.0.8"},
                ]
            )
        )
        self.assertEqual(
            (
                ("0.0.0.0/0", "10.0.0.9"),
                ("192.168.7.3/32", "10.0.0.7"),
                ("192.168.8.0/24", "10.0.0.8"),
            ),
            r.routes,
        )


class RenderTestCase(unittest.TestCase):
    def setUp(self):
        self.r = router.from_rpc(rpc_router())
        self.qg = names.router_jail_if_name(GW_PORT_ID, gateway=True)
        self.qr = names.router_jail_if_name(INT_PORT_ID)

    def test_jail_names(self):
        self.assertEqual("qrouter-7c3f1c2e9a4b", self.r.jail)
        self.assertEqual("qg-aaaa1111-22", self.qg)
        self.assertEqual("qr-bbbb1111-22", self.qr)
        self.assertLessEqual(len(self.qg), 15)

    def test_addresses_put_floating_ips_on_the_gateway_as_host_routes(self):
        addrs = router.addresses(self.r)
        self.assertEqual((("203.0.113.10", 24), ("203.0.113.50", 32)), addrs[self.qg])
        self.assertEqual((("10.0.0.1", 24),), addrs[self.qr])

    def test_routes_include_the_default_via_the_external_gateway(self):
        self.assertEqual(
            (("0.0.0.0/0", "203.0.113.1"), ("192.168.7.0/24", "10.0.0.7")),
            router.routes(self.r),
        )

    def test_pf_text_orders_binat_before_nat_and_ends_with_the_marker(self):
        text, cfg_hash = router.pf_text(self.r)
        lines = text.splitlines()
        self.assertEqual("set skip on lo0", lines[0])
        self.assertEqual(
            f"binat on {self.qg} inet from 10.0.0.5 to any -> 203.0.113.50", lines[1]
        )
        self.assertEqual(
            f"nat on {self.qg} inet from {{ 10.0.0.0/24 }} to any -> 203.0.113.10",
            lines[2],
        )
        self.assertEqual(f'pass quick all label "l3-neutron:cfg:{cfg_hash}"', lines[3])
        self.assertEqual(4, len(lines))

    def test_snat_off_drops_the_nat_rule_and_moves_the_hash(self):
        _text, with_snat = router.pf_text(self.r)
        off = router.from_rpc(rpc_router(enable_snat=False))
        text, without = router.pf_text(off)
        self.assertNotIn("\nnat on", text)
        self.assertIn("binat on", text)
        self.assertNotEqual(with_snat, without)

    def test_a_gateway_without_an_ipv4_address_gets_no_nat_rule(self):
        r = dataclasses.replace(
            self.r,
            floating_ips=(),
            gateway=dataclasses.replace(
                self.r.gateway, ips=(("2001:db8:ffff::b4", 64),)
            ),
        )
        text, _hash = router.pf_text(r)
        self.assertNotIn("nat on", text)

    def test_no_gateway_means_no_translation(self):
        text, _ = router.pf_text(router.from_rpc(rpc_router(gw_port=None)))
        self.assertEqual(2, len(text.splitlines()))

    def test_hash_is_stable_for_equal_specs(self):
        self.assertEqual(
            router.pf_text(self.r)[1], router.pf_text(router.from_rpc(rpc_router()))[1]
        )


class ScopeRulesTestCase(unittest.TestCase):
    def setUp(self):
        self.qg = names.router_jail_if_name(GW_PORT_ID, gateway=True)
        self.qr = names.router_jail_if_name(INT_PORT_ID)

    def rules(self, gw_scopes, int_scopes, **kw):
        body = rpc_router(
            gw_port=gw_port(address_scopes=gw_scopes),
            _interfaces=[int_port(address_scopes=int_scopes)],
            **kw,
        )
        return router.scope_rules(router.from_rpc(body))

    def test_ports_without_scopes_render_no_rules(self):
        self.assertEqual([], router.scope_rules(router.from_rpc(rpc_router())))

    def test_scopes_are_read_with_integer_or_string_keys(self):
        port = router.port_from_rpc(int_port(address_scopes={4: "a", "6": "b"}))
        self.assertEqual(("a", "b"), (port.scope4, port.scope6))

    def test_matching_scopes_render_no_rules(self):
        scopes = {"4": "s4", "6": "s6"}
        self.assertEqual([], self.rules(scopes, scopes))

    def test_ipv6_scope_mismatch_is_blocked_both_ways(self):
        rules = self.rules({"4": None, "6": "s6"}, {"4": None, "6": None})
        self.assertEqual(
            [
                f"block drop out quick on {self.qg} inet6 received-on {self.qr}",
                f"block drop out quick on {self.qr} inet6 received-on {self.qg}",
            ],
            rules,
        )

    def test_ipv4_mismatch_with_snat_still_leaves_through_the_gateway(self):
        rules = self.rules({"4": "ext", "6": None}, {"4": None, "6": None})
        self.assertEqual(
            [
                f"pass out quick inet to 10.0.0.5 received-on {self.qg}",
                f"pass out quick on {self.qg} inet from 203.0.113.50",
                f"block drop out quick on {self.qr} inet received-on {self.qg}",
            ],
            rules,
        )

    def test_ipv4_mismatch_without_snat_is_blocked_both_ways(self):
        rules = self.rules(
            {"4": "ext", "6": None},
            {"4": None, "6": None},
            enable_snat=False,
            _floatingips=[],
        )
        self.assertEqual(
            [
                f"block drop out quick on {self.qg} inet received-on {self.qr}",
                f"block drop out quick on {self.qr} inet received-on {self.qg}",
            ],
            rules,
        )

    def test_scope_rules_sit_before_the_marker_and_move_the_hash(self):
        scoped = rpc_router(gw_port=gw_port(address_scopes={"4": None, "6": "s6"}))
        text, cfg_hash = router.pf_text(router.from_rpc(scoped))
        lines = text.splitlines()
        self.assertTrue(lines[-2].startswith("block drop out quick"))
        self.assertTrue(lines[-1].endswith(f'cfg:{cfg_hash}"'))
        self.assertNotEqual(cfg_hash, router.pf_text(router.from_rpc(rpc_router()))[1])

"""Port config builder tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_bsdbridge import names
    from neutron_bsdbridge.l2_agent import port_config
except ImportError:
    raise unittest.SkipTest("needs oslo libs; run under the neutron venv")


def port(port_id="3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d", network_type="local", **kw):
    base = {
        "port_id": port_id,
        "device": "tap" + port_id[:11],
        "network_id": "b716de99-4bd1-4b58-a52e-b0b8ab779b74",
        "network_type": network_type,
        "physical_network": None,
        "segmentation_id": None,
        "mac_address": "fa:16:3e:aa:bb:01",
        "fixed_ips": [{"subnet_id": "s1", "ip_address": "10.99.0.5"}],
    }
    base.update(kw)
    return base


SG_INFO = {
    "devices": {
        "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d": {"security_groups": ["sg-one"]},
        "99999999-4bd1-4b58-a52e-b0b8ab779b74": {"security_groups": ["sg-one"]},
    },
    "security_groups": {
        "sg-one": [
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "port_range_min": 22,
                "port_range_max": 22,
                "source_ip_prefix": "10.0.0.0/8",
            },
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "port_range_min": 8000,
                "port_range_max": 8100,
                "remote_group_id": "sg-one",
            },
            {"direction": "egress", "ethertype": "IPv4"},
            {"direction": "egress", "ethertype": "IPv6"},
            {
                "direction": "egress",
                "ethertype": "IPv4",
                "protocol": "udp",
                "port_range_min": 53,
                "port_range_max": 53,
                "dest_ip_prefix": "192.0.2.0/24",
            },
        ]
    },
    "sg_member_ips": {
        "sg-one": {"IPv4": [("10.99.0.5", None), ("10.99.0.6", None)], "IPv6": []}
    },
}


class DesiredTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.cfg, self.devices = port_config.build([port()], SG_INFO, {})

    def _filter(self):
        return self.cfg.filter[
            names.filter_name("3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d")
        ]

    def test_bridge_and_member(self):
        bridge = names.bridge_name(
            "local", None, None, "b716de99-4bd1-4b58-a52e-b0b8ab779b74"
        )
        member = self.cfg.bridge[bridge].member["tap3fb01977-a4"]
        self.assertEqual("tap", member.type)
        self.assertEqual("fa:16:3e:aa:bb:01", member.bind.mac)
        self.assertEqual("10.99.0.5", member.bind.address)
        self.assertEqual(
            "neutron port 3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d", member.description
        )
        self.assertIsNone(
            self.cfg.bridge[bridge].segment, "local networks have no realization"
        )

    def test_ingress_rule_renders_as_in_with_from(self):
        rules = list(self._filter().in_.values())
        ssh = [r for r in rules if r.port == 22]
        self.assertEqual(1, len(ssh))
        self.assertEqual("10.0.0.0/8", ssh[0].from_)
        self.assertEqual("pass", ssh[0].action)
        self.assertEqual("tcp", ssh[0].proto)

    def test_port_range_survives(self):
        rules = list(self._filter().in_.values())
        self.assertIn("8000-8100", [r.port for r in rules])

    def test_single_port_and_range_with_same_remote_sort(self):
        sg_info = {
            "devices": {
                "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d": {"security_groups": ["sg"]}
            },
            "security_groups": {
                "sg": [
                    {
                        "direction": "ingress",
                        "ethertype": "IPv4",
                        "protocol": "tcp",
                        "port_range_min": lo,
                        "port_range_max": hi,
                    }
                    for lo, hi in ((22, 22), (8000, 8100))
                ]
            },
        }
        in_rules, _ = port_config.sg_rules_for_port(port(), sg_info, set())
        self.assertEqual([22, "8000-8100"], [r["port"] for r in in_rules.values()])

    def test_remote_group_becomes_a_table(self):
        rules = list(self._filter().in_.values())
        froms = [r.from_ for r in rules]
        self.assertIn("@" + names.table_name("sg-one"), froms)
        self.assertEqual(
            ["10.99.0.5", "10.99.0.6"],
            self.cfg.table[names.table_name("sg-one")].members,
        )

    def test_egress_allow_renders_as_out(self):
        out = list(self._filter().out.values())
        self.assertTrue(
            any(r.action == "pass" and r.proto is None and r.to == "any" for r in out)
        )

    def test_egress_rule_renders_as_out_with_to(self):
        out = list(self._filter().out.values())
        dns = [r for r in out if r.port == 53]
        self.assertEqual(1, len(dns))
        self.assertEqual("192.0.2.0/24", dns[0].to)
        self.assertEqual("any", dns[0].from_)

    def _build_with_rules(self, rules, member_ips=None, **port_kw):
        info = {
            "devices": {
                "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d": {"security_groups": ["sg-v6"]}
            },
            "security_groups": {"sg-v6": rules},
            "sg_member_ips": member_ips or {},
        }
        cfg, _ = port_config.build([port(**port_kw)], info, {})
        return cfg

    def _sg_rules(self, cfg, direction="in_"):
        f = cfg.filter[names.filter_name("3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d")]
        return [v for k, v in sorted(getattr(f, direction).items()) if k >= 100]

    def test_ipv6_tcp_rule_carries_its_family(self):
        cfg = self._build_with_rules(
            [
                {
                    "direction": "ingress",
                    "ethertype": "IPv6",
                    "protocol": "tcp",
                    "port_range_min": 80,
                    "port_range_max": 80,
                    "source_ip_prefix": "2001:db8::/64",
                }
            ]
        )
        (rule,) = self._sg_rules(cfg)
        self.assertEqual("inet6", rule.family)
        self.assertEqual("tcp", rule.proto)
        self.assertEqual(80, rule.port)
        self.assertEqual("2001:db8::/64", rule.from_)

    def test_any_protocol_rule_is_limited_to_its_ethertype(self):
        cfg = self._build_with_rules([{"direction": "egress", "ethertype": "IPv4"}])
        (rule,) = self._sg_rules(cfg, "out")
        self.assertEqual("inet", rule.family)
        self.assertIsNone(rule.proto)

    def test_icmp_type_and_code_come_from_the_port_range(self):
        cfg = self._build_with_rules(
            [
                {
                    "direction": "ingress",
                    "ethertype": "IPv4",
                    "protocol": "icmp",
                    "port_range_min": 0,
                    "port_range_max": 0,
                },
                {
                    "direction": "ingress",
                    "ethertype": "IPv6",
                    "protocol": "icmp",
                    "port_range_min": 128,
                },
            ]
        )
        v4, v6 = sorted(self._sg_rules(cfg), key=lambda r: r.family)
        self.assertEqual(("icmp", 0, 0), (v4.proto, v4.icmp_type, v4.icmp_code))
        self.assertEqual(("icmp6", 128, None), (v6.proto, v6.icmp_type, v6.icmp_code))
        self.assertIsNone(v4.port)

    def test_remote_group_table_holds_both_families(self):
        cfg = self._build_with_rules(
            [{"direction": "ingress", "ethertype": "IPv6", "remote_group_id": "sg-v6"}],
            member_ips={
                "sg-v6": {
                    "IPv4": [("10.99.0.5", None)],
                    "IPv6": [("2001:db8::5", None)],
                }
            },
        )
        self.assertEqual(
            ["10.99.0.5", "2001:db8::5"],
            cfg.table[names.table_name("sg-v6")].members,
        )

    def test_bind_locks_ipv6_sources_to_fixed_and_link_local(self):
        cfg = self._build_with_rules(
            [],
            fixed_ips=[
                {"subnet_id": "s1", "ip_address": "10.99.0.5"},
                {"subnet_id": "s2", "ip_address": "2001:db8::5"},
            ],
        )
        bind = next(iter(cfg.bridge.values())).member["tap3fb01977-a4"].bind
        self.assertEqual("10.99.0.5", bind.address)
        self.assertEqual(["2001:db8::5", "fe80::f816:3eff:feaa:bb01"], bind.addresses6)

    def test_ipv6_only_port_is_bound_without_an_ipv4_address(self):
        cfg = self._build_with_rules(
            [], fixed_ips=[{"subnet_id": "s2", "ip_address": "2001:db8::5"}]
        )
        bind = next(iter(cfg.bridge.values())).member["tap3fb01977-a4"].bind
        self.assertIsNone(bind.address)
        self.assertEqual("fa:16:3e:aa:bb:01", bind.mac)

    def test_infra_allowances_are_visible_rules(self):
        f = self._filter()
        self.assertEqual(
            ("inet", "udp", 68), (f.in_[10].family, f.in_[10].proto, f.in_[10].port)
        )
        self.assertEqual(
            ("inet6", "udp", 546), (f.in_[20].family, f.in_[20].proto, f.in_[20].port)
        )
        self.assertEqual(67, f.out[10].port)
        self.assertEqual(547, f.out[20].port)
        infra_in = [r.icmp_type for k, r in sorted(f.in_.items()) if 20 < k < 100]
        infra_out = [r.icmp_type for k, r in sorted(f.out.items()) if 20 < k < 100]
        self.assertEqual([130, 134, 135, 136], infra_in)
        self.assertEqual([131, 132, 133, 135, 136, 143], infra_out)

    def test_infra_allowances_do_not_pass_echo(self):
        f = self._filter()
        infra = [r for k, r in f.in_.items() if k < 100 and r.proto == "icmp6"]
        self.assertTrue(all(r.icmp_type is not None for r in infra))

    def test_two_ports_one_network_share_the_bridge_stanza(self):
        p2 = port(port_id="99999999-4bd1-4b58-a52e-b0b8ab779b74")
        cfg, devices = port_config.build([port(), p2], SG_INFO, {})
        self.assertEqual(1, len(cfg.bridge))
        members = next(iter(cfg.bridge.values())).member
        self.assertEqual(2, len(members))
        # wire identifiers are full port uuids, not tap names
        self.assertEqual(
            [
                "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d",
                "99999999-4bd1-4b58-a52e-b0b8ab779b74",
            ],
            devices,
        )

    def test_vlan_port_gets_its_segment_via_the_mapping(self):
        p = port(network_type="vlan", physical_network="physnet1", segmentation_id=210)
        cfg, _ = port_config.build([p], SG_INFO, {"physnet1": "vtnet1"})
        bridge = names.bridge_name("vlan", "physnet1", 210, "x")
        seg = cfg.bridge[bridge].segment
        self.assertEqual("physnet1", seg.physnet)
        self.assertEqual(210, seg.vlan)
        # the physnet is synthesized from the mapping
        self.assertEqual("vtnet1", cfg.physnet["physnet1"].trunk)

    def test_flat_port_gets_a_flat_segment(self):
        p = port(network_type="flat", physical_network="physnet1")
        cfg, _ = port_config.build([p], SG_INFO, {"physnet1": "vtnet1"})
        bridge = names.bridge_name("flat", "physnet1", None, "x")
        seg = cfg.bridge[bridge].segment
        self.assertEqual("physnet1", seg.physnet)
        self.assertIsNone(seg.vlan)

    def test_unmapped_physnet_renders_without_uplink(self):
        p = port(network_type="vlan", physical_network="ghostnet", segmentation_id=210)
        cfg, devices = port_config.build([p], SG_INFO, {})
        bridge = names.bridge_name("vlan", "ghostnet", 210, "x")
        self.assertIsNone(cfg.bridge[bridge].segment)
        self.assertEqual(1, len(devices))


VXLAN_CONF = {"local": "10.255.0.11", "port": 4789, "ttl": 64}
SLOW_PORTS = {5042: 61234}


class VxlanPortTestCase(unittest.TestCase):
    def test_vxlan_port_builds_its_segment_from_the_conf(self):
        p = port(network_type="vxlan", segmentation_id=5042, mtu=1450)
        cfg, _ = port_config.build([p], SG_INFO, {}, VXLAN_CONF, SLOW_PORTS)
        bridge = cfg.bridge[names.bridge_name("vxlan", None, 5042, "x")]
        vx = bridge.segment.vxlan
        self.assertEqual(5042, vx.vni)
        self.assertEqual("10.255.0.11", vx.local)
        self.assertEqual(4789, vx.port)
        self.assertEqual(61234, vx.remote_port)
        self.assertEqual(64, vx.ttl)
        self.assertEqual(1450, vx.mtu)
        self.assertIsNone(bridge.segment.physnet)
        self.assertEqual({}, cfg.physnet)

    def test_every_member_carries_the_network_mtu(self):
        ports = [
            port(network_type="vxlan", segmentation_id=5042, mtu=1450),
            port(
                port_id="99999999-4bd1-4b58-a52e-b0b8ab779b74",
                network_type="vxlan",
                segmentation_id=5042,
                mtu=1450,
                device_owner="network:dhcp",
            ),
        ]
        cfg, _ = port_config.build(ports, SG_INFO, {}, VXLAN_CONF, SLOW_PORTS)
        bridge = cfg.bridge[names.bridge_name("vxlan", None, 5042, "x")]
        self.assertEqual({1450}, {m.mtu for m in bridge.member.values()})

    def test_unknown_mtu_is_left_unset(self):
        cfg, _ = port_config.build([port(mtu=0)], SG_INFO, {})
        member = next(iter(cfg.bridge.values())).member["tap3fb01977-a4"]
        self.assertIsNone(member.mtu)

    def test_vxlan_port_without_conf_renders_without_uplink(self):
        p = port(network_type="vxlan", segmentation_id=5042, mtu=1450)
        with self.assertLogs(port_config.LOG.logger, "WARNING"):
            cfg, devices = port_config.build([p], SG_INFO, {})
        bridge = names.bridge_name("vxlan", None, 5042, "x")
        self.assertIsNone(cfg.bridge[bridge].segment)
        self.assertEqual(1, len(devices))

    def test_vxlan_port_without_a_slow_path_socket_renders_without_uplink(self):
        p = port(network_type="vxlan", segmentation_id=5042, mtu=1450)
        with self.assertLogs(port_config.LOG.logger, "WARNING"):
            cfg, devices = port_config.build([p], SG_INFO, {}, VXLAN_CONF, {})
        bridge = names.bridge_name("vxlan", None, 5042, "x")
        self.assertIsNone(cfg.bridge[bridge].segment)
        self.assertEqual(1, len(devices))


class ServicePortTestCase(unittest.TestCase):
    def test_dhcp_port_is_attached_hardware_without_policy(self):
        p = port(device_owner="network:dhcp")
        cfg, devices = port_config.build([p], {}, {})
        bridge = names.bridge_name(
            "local", None, None, "b716de99-4bd1-4b58-a52e-b0b8ab779b74"
        )
        member = cfg.bridge[bridge].member[names.dhcp_if_name(p["port_id"])]
        self.assertIsNone(member.type, "the dhcp agent manufactures the epair, not us")
        self.assertIsNone(member.filter)
        self.assertIsNone(member.bind)
        self.assertEqual({}, cfg.filter)
        self.assertEqual([p["port_id"]], devices)

    def test_router_ports_are_attached_hardware_without_policy(self):
        for owner in ("network:router_interface", "network:router_gateway"):
            p = port(device_owner=owner)
            cfg, devices = port_config.build([p], {}, {})
            bridge = names.bridge_name(
                "local", None, None, "b716de99-4bd1-4b58-a52e-b0b8ab779b74"
            )
            member = cfg.bridge[bridge].member[names.router_if_name(p["port_id"])]
            self.assertIsNone(member.type, "the l3 agent manufactures the epair")
            self.assertIsNone(member.filter)
            self.assertIsNone(member.bind)
            self.assertEqual({}, cfg.filter)
            self.assertEqual([p["port_id"]], devices)

    def test_port_security_disabled_means_plain_switching(self):
        p = port(port_security_enabled=False)
        cfg, _ = port_config.build([p], SG_INFO, {})
        member = next(iter(cfg.bridge.values())).member["tap3fb01977-a4"]
        self.assertEqual("tap", member.type)
        self.assertIsNone(member.filter)
        self.assertIsNone(member.bind)
        self.assertEqual({}, cfg.filter)

"""Desired-state builder fixtures: neutron RPC shapes in, the model out."""

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
                "remote_ip_prefix": "10.0.0.0/8",
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

    def test_ipv6_tcp_is_skipped_fail_closed(self):
        info = {
            "devices": {
                "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d": {"security_groups": ["sg-one"]}
            },
            "security_groups": {
                "sg-one": [
                    {
                        "direction": "ingress",
                        "ethertype": "IPv6",
                        "protocol": "tcp",
                        "port_range_min": 80,
                        "port_range_max": 80,
                    }
                ]
            },
            "sg_member_ips": {},
        }
        cfg, _ = port_config.build([port()], info, {})
        f = cfg.filter[names.filter_name("3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d")]
        sg_rules = {k: v for k, v in f.in_.items() if k >= 100}
        self.assertEqual({}, sg_rules)

    def test_infra_allowances_are_visible_rules(self):
        f = self._filter()
        self.assertEqual("udp", f.in_[10].proto)
        self.assertEqual(68, f.in_[10].port)
        self.assertEqual("udp", f.out[10].proto)
        self.assertEqual(67, f.out[10].port)
        self.assertEqual("icmp6", f.in_[20].proto)

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

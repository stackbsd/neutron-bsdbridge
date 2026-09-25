"""Names must agree across three processes that never confer."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import names  # noqa: E402


class NamesTestCase(unittest.TestCase):
    def test_bridge_names_fit_ifnamsiz(self):
        for args in (
            ("vlan", "phys0", 210, "net"),
            ("flat", "phys0", None, "net"),
            ("local", None, None, "b716de99-1" * 4),
        ):
            self.assertLessEqual(len(names.bridge_name(*args)), 15)

    def test_vlan_bridges_key_on_physnet_and_vid_only(self):
        # the network id must not leak into the name
        a = names.bridge_name("vlan", "phys0", 210, "net-a")
        b = names.bridge_name("vlan", "phys0", 210, "net-b")
        self.assertEqual(a, b)
        self.assertNotEqual(a, names.bridge_name("vlan", "phys0", 211, "net-a"))

    def test_local_bridges_key_on_the_network(self):
        a = names.bridge_name("local", None, None, "net-a")
        b = names.bridge_name("local", None, None, "net-b")
        self.assertNotEqual(a, b)

    def test_bridge_names_are_stable(self):
        # three processes compute this independently: never move it
        self.assertEqual(
            "pbd1da5680bffb",
            names.bridge_name(
                "local", None, None, "b716de99-4bd1-4b58-a52e-b0b8ab779b74"
            ),
        )

    def test_tap_name_is_the_shared_convention(self):
        self.assertEqual("tap3fb01977-a4", names.tap_name("3fb01977-a4e2-4a28-9a6f-x"))


class DhcpNamesTestCase(unittest.TestCase):
    def test_dhcp_if_name_fits_ifnamsiz(self):
        name = names.dhcp_if_name("3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d")
        self.assertEqual("dh3fb01977-a4e2", name)
        self.assertLessEqual(len(name), 15)

    def test_router_if_name_fits_ifnamsiz_and_differs_from_dhcp(self):
        port_id = "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d"
        name = names.router_if_name(port_id)
        self.assertEqual("rt3fb01977-a4e2", name)
        self.assertLessEqual(len(name), 15)
        self.assertNotEqual(name, names.dhcp_if_name(port_id))

    def test_jail_name_is_undashed_hex(self):
        self.assertEqual(
            "qdhcp-590dc57a8b5e",
            names.dhcp_jail_name("590dc57a-8b5e-4b94-b743-74e7d9a1b792"),
        )

    def test_device_id_ignores_the_domain_part_of_the_host(self):
        # neutron hashes only the short hostname
        a = names.dhcp_device_id("net-1", "bsddev.novalocal")
        b = names.dhcp_device_id("net-1", "bsddev")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("dhcp"))
        self.assertTrue(a.endswith("-net-1"))

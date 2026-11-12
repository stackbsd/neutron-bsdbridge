"""Mech driver tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_lib.plugins.ml2 import api
except ImportError:
    raise unittest.SkipTest("needs neutron; run under the neutron venv")

from neutron_bsdbridge import mech, names  # noqa: E402


def segment(network_type="local", physnet=None, seg_id=None):
    return {
        api.ID: "seg-uuid",
        api.NETWORK_TYPE: network_type,
        api.PHYSICAL_NETWORK: physnet,
        api.SEGMENTATION_ID: seg_id,
    }


def agent(mappings=None, tunnel_types=None):
    configurations = {"physical_interface_mappings": mappings or {}}
    if tunnel_types is not None:
        configurations["tunnel_types"] = tunnel_types
    return {"configurations": configurations, "alive": True}


class FakeContext:
    current = {"network_id": "b716de99-4bd1-4b58-a52e-b0b8ab779b74"}


class MechTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.driver = mech.BsdBridgeMechanismDriver()

    def test_local_segment_needs_no_mapping(self):
        self.assertTrue(self.driver.check_segment_for_agent(segment("local"), agent()))

    def test_vlan_segment_needs_its_physnet_mapped(self):
        seg = segment("vlan", "physnet1", 210)
        self.assertFalse(self.driver.check_segment_for_agent(seg, agent()))
        self.assertTrue(
            self.driver.check_segment_for_agent(seg, agent({"physnet1": "ix0"}))
        )

    def test_vxlan_needs_the_agent_to_advertise_it(self):
        seg = segment("vxlan", seg_id=5042)
        self.assertFalse(self.driver.check_segment_for_agent(seg, agent()))
        self.assertFalse(
            self.driver.check_segment_for_agent(seg, agent(tunnel_types=[]))
        )
        self.assertTrue(
            self.driver.check_segment_for_agent(seg, agent(tunnel_types=["vxlan"]))
        )

    def test_unsupported_type_refused(self):
        self.assertFalse(
            self.driver.check_segment_for_agent(
                segment("geneve", seg_id=5042), agent(tunnel_types=["vxlan"])
            )
        )

    def test_vif_details_carry_the_computed_bridge(self):
        details = self.driver.get_vif_details(FakeContext(), agent(), segment("local"))
        self.assertEqual(
            names.bridge_name("local", None, None, FakeContext.current["network_id"]),
            details["bridge_name"],
        )
        self.assertEqual("l2-neutron", details["interface_group"])
        self.assertTrue(details["port_filter"])

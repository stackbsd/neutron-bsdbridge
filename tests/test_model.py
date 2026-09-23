"""Tests for the model: canonicalization and the loud-error contract."""

import os
import sys
import unittest
from typing import ClassVar

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


from neutron_bsdbridge.l2_agent import model


class CanonicalizationTestCase(unittest.TestCase):
    """Canonical forms on the way into the model."""

    def test_macs_lowercase(self):
        """MACs canonicalize to lowercase."""
        b = model.Bind(mac="58:9C:FC:10:AA:01", address="10.0.0.1")
        self.assertEqual("58:9c:fc:10:aa:01", b.mac)

    def test_bad_mac_is_refused(self):
        """Malformed MACs are refused."""
        for bad in ("not-a-mac", "58:9c:fc:10:aa", "58:9c:fc:10:aa:zz"):
            self.assertRaises(ValueError, model.Bind, mac=bad, address="10.0.0.1")

    def test_table_members_sorted_and_deduplicated(self):
        """Table members canonicalize to a sorted, de-duplicated list."""
        t = model.Table(members=["10.0.0.2", "10.0.0.1", "10.0.0.2"])
        self.assertEqual(["10.0.0.1", "10.0.0.2"], t.members)


class LoudErrorTestCase(unittest.TestCase):
    """A malformed desired build must surface as a validation error."""

    def test_unknown_keys_are_refused(self):
        """A typo'd key is a validation error, not silently ignored config."""
        self.assertRaises(model.SchemaError, model.Member.from_tree, {"typ": "tap"})

    def test_wrong_shapes_are_loud(self):
        """A list where a scalar belongs fails the type check."""
        self.assertRaises(
            model.SchemaError, model.Member.from_tree, {"filter": ["a", "b"]}
        )

    def test_member_type_is_closed(self):
        """Member type accepts only tap and epair."""
        self.assertRaises(model.SchemaError, model.Member.from_tree, {"type": "veth"})

    def test_duplicate_rule_number_is_refused(self):
        """Two spellings of one rule number are a validation error."""
        self.assertRaises(
            model.SchemaError,
            model.Filter.from_tree,
            {"in": {"10": {"action": "pass"}, "010": {"action": "block"}}},
        )

    def test_member_name_must_fit_ifnamsiz(self):
        """A member name longer than IFNAMSIZ is refused."""
        self.assertRaises(
            model.SchemaError,
            model.Bridge.from_tree,
            {"member": {"tap0123456789abc": {"type": "tap"}}},
        )


class SegmentTestCase(unittest.TestCase):
    """Segment realization forms."""

    def test_vlan_needs_physnet(self):
        """A vlan segment without its physnet is refused."""
        self.assertRaises(model.SchemaError, model.Segment.from_tree, {"vlan": 210})

    def test_flat_is_physnet_alone(self):
        """A physnet alone is a flat segment."""
        seg = model.Segment.from_tree({"physnet": "p0"})
        self.assertIsNone(seg.vlan)

    def test_vxlan_excludes_the_others(self):
        """A vxlan segment cannot also name a physnet."""
        self.assertRaises(
            model.SchemaError,
            model.Segment.from_tree,
            {"physnet": "p0", "vxlan": {"vni": 5042, "local": "10.255.0.11"}},
        )

    def test_empty_segment_is_refused(self):
        """An empty segment stanza is refused."""
        self.assertRaises(model.SchemaError, model.Segment.from_tree, {})


class ReferenceTestCase(unittest.TestCase):
    """Dangling references are sync errors, not reconcile surprises."""

    BASE: ClassVar[dict] = {
        "physnet": {"p0": {"trunk": "em0"}},
        "bridge": {
            "blue": {
                "segment": {"physnet": "p0", "vlan": 210},
                "member": {"tap0": {"type": "tap"}},
            }
        },
    }

    def test_valid_config_passes(self):
        """A config with resolvable references validates."""
        model.Config.from_tree(self.BASE)

    def test_unknown_physnet(self):
        """A segment naming an unknown physnet is refused."""
        bad = {"bridge": {"b": {"segment": {"physnet": "ghost", "vlan": 1}}}}
        self.assertRaisesRegex(
            model.SchemaError, "unknown physnet", model.Config.from_tree, bad
        )

    def test_unknown_filter(self):
        """A member naming an unknown filter is refused."""
        bad = dict(self.BASE)
        bad["bridge"] = {"blue": {"member": {"tap0": {"filter": "ghost"}}}}
        self.assertRaisesRegex(
            model.SchemaError, "unknown filter", model.Config.from_tree, bad
        )

    def test_unknown_table_in_rule(self):
        """A rule referencing an unknown table is refused."""
        bad = {"filter": {"f": {"in": {"10": {"action": "pass", "from": "@ghost"}}}}}
        self.assertRaisesRegex(
            model.SchemaError, "unknown table", model.Config.from_tree, bad
        )

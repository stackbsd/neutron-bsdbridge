"""Planner tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import ifconfig, names
from neutron_bsdbridge.l2_agent import model, plan


def iface(
    name, groups=(), members=(), up=True, maxaddr=None, vlan=None, parent=None, **kw
):
    """Build an Interface fixture."""
    return ifconfig.Interface(
        name=name,
        flags=frozenset({"UP"} if up else ()),
        groups=tuple(groups),
        members=tuple(members),
        maxaddr=maxaddr,
        vlan=vlan,
        vlan_parent=parent,
        **kw,
    )


def kernel(*interfaces):
    """Build a KernelInterfaces from Interface fixtures."""
    table = {i.name: i for i in interfaces}
    owned = [
        i.name
        for i in interfaces
        if "l2-neutron" in i.groups and "bridge" not in i.groups
    ]
    return ifconfig.KernelInterfaces(table, owned)


def cfg(**tree):
    """Build a Config with the shared physnet plus the given sections."""
    base = {"physnet": {"phys0": {"trunk": "vtnet0"}}}
    base.update(tree)
    return model.Config.from_tree(base)


BLUE = {
    "blue": {
        "segment": {"physnet": "phys0", "vlan": 210},
        "member": {"tap00000000-01": {"type": "tap", "description": "vm nic"}},
    }
}


def reconciled_blue():
    """Build the kernel state that matches the BLUE config."""
    return kernel(
        iface(
            "blue",
            groups=("bridge", "l2-neutron"),
            members=("vtnet0.210", "tap00000000-01"),
            maxaddr=2000,
        ),
        iface("vtnet0.210", groups=("vlan", "l2-neutron"), vlan=210, parent="vtnet0"),
        iface("tap00000000-01", groups=("tap", "l2-neutron")),
    )


class ContractTestCase(unittest.TestCase):
    """The empty-plan contract."""

    def test_reconciled_state_plans_to_nothing(self):
        """A reconciled kernel plans to nothing."""
        p = plan.diff(cfg(bridge=BLUE), reconciled_blue())
        self.assertTrue(p.empty, [str(o) for o in p.ops])

    def test_empty_config_and_empty_kernel_plan_to_nothing(self):
        """An empty config against an empty kernel plans to nothing."""
        p = plan.diff(cfg(), kernel())
        self.assertTrue(p.empty)


class CreateTestCase(unittest.TestCase):
    """Creation planning."""

    def test_cold_start_builds_everything_in_phase_order(self):
        """A cold start plans creates, then the manufactured-member adds."""
        p = plan.diff(cfg(bridge=BLUE), kernel())
        self.assertEqual(
            [
                plan.CreateBridge(name="blue", maxaddr=2000),
                plan.CreateVlan(name="vtnet0.210", parent="vtnet0", vid=210),
            ],
            p.creates,
        )
        # create then addm, no filter here
        self.assertEqual(
            [
                plan.CreateTap(name="tap00000000-01", description="vm nic"),
                plan.AddMember(bridge="blue", member="tap00000000-01"),
                plan.AddMember(bridge="blue", member="vtnet0.210"),
            ],
            p.adds,
        )
        self.assertEqual([], p.removes)
        self.assertEqual([], p.destroys)

    def test_policy_precedes_membership_for_filtered_members(self):
        """A filtered member's anchor loads before its addm."""
        tree = {
            "blue": {
                "segment": {"physnet": "phys0", "vlan": 210},
                "member": {"tap00000000-01": {"type": "tap", "filter": "web"}},
            }
        }
        c = cfg(bridge=tree, filter={"web": {"in": {"10": {"action": "pass"}}}})
        p = plan.diff(c, kernel())
        kinds = [type(o).__name__ for o in p.adds]
        self.assertEqual(["CreateTap", "LoadAnchor", "AddMember", "AddMember"], kinds)
        self.assertLess(
            kinds.index("LoadAnchor"),
            kinds.index("AddMember"),
            "the anchor must load before the tap can be opened",
        )

    def test_create_tap_carries_the_member_mtu(self):
        """A manufactured tap is created at its member mtu."""
        tree = {"blue": {"member": {"tap00000000-01": {"type": "tap", "mtu": 1450}}}}
        p = plan.diff(cfg(bridge=tree), kernel())
        self.assertIn(
            plan.CreateTap(name="tap00000000-01", description="", mtu=1450), p.adds
        )

    def test_flat_segment_members_the_nic_without_creating_it(self):
        """A flat segment members the physnet NIC without creating anything."""
        tree = {"flatnet": {"segment": {"physnet": "phys0"}}}
        p = plan.diff(cfg(bridge=tree), kernel(iface("vtnet0")))
        self.assertEqual([plan.CreateBridge(name="flatnet", maxaddr=2000)], p.creates)
        self.assertEqual([plan.AddMember(bridge="flatnet", member="vtnet0")], p.adds)

    def test_maxaddr_drift_is_a_set_not_a_recreate(self):
        """Drifted maxaddr plans a SetMaxaddr, never a recreate."""
        o = reconciled_blue()
        tree = {"blue": dict(BLUE["blue"], **{"max-addresses": 500})}
        p = plan.diff(cfg(bridge=tree), o)
        self.assertEqual([plan.SetMaxaddr(bridge="blue", maxaddr=500)], p.creates)


VX = names.vxlan_if_name(5042)
VXLAN = {
    "net42": {
        "segment": {
            "vxlan": {
                "vni": 5042,
                "local": "10.255.0.11",
                "remote_port": 61234,
                "mtu": 1450,
            }
        },
        "member": {"tap00000000-01": {"type": "tap", "mtu": 1450}},
    }
}


def vxlan_kernel(discover=frozenset(), **drift):
    """Build the VXLAN kernel state with the given drift."""
    fields = {
        "vni": 5042,
        "vxlan_local": "10.255.0.11",
        "vxlan_remote": "127.0.0.1",
        "vxlan_port": 4789,
        "vxlan_remote_port": 61234,
        "mtu": 1450,
    }
    fields.update(drift)
    return kernel(
        iface(
            "net42",
            groups=("bridge", "l2-neutron"),
            members=("tap00000000-01", VX),
            maxaddr=2000,
            member_flags=(
                ("tap00000000-01", frozenset({"LEARNING", "DISCOVER"})),
                (VX, frozenset({"LEARNING"}) | discover),
            ),
        ),
        iface(VX, groups=("vxlan", "l2-neutron"), **fields),
        iface("tap00000000-01", groups=("tap", "l2-neutron")),
    )


class VxlanTestCase(unittest.TestCase):
    """Unicast vxlan uplinks."""

    def test_one_vxlan_under_the_hashed_name(self):
        """A vxlan segment creates one interface and members it."""
        p = plan.diff(cfg(bridge=VXLAN), kernel())
        self.assertEqual(
            [
                plan.CreateBridge(name="net42", maxaddr=2000),
                plan.CreateVxlan(
                    name=VX,
                    vni=5042,
                    local="10.255.0.11",
                    port=4789,
                    remote_port=61234,
                    ttl=64,
                    mtu=1450,
                ),
            ],
            p.creates,
        )
        self.assertEqual(
            [
                plan.AddMember(bridge="net42", member=VX),
                plan.ClearDiscover(bridge="net42", member=VX),
            ],
            p.adds[-2:],
        )

    def test_reconciled_vxlan_plans_to_nothing(self):
        """A matching vxlan plans to nothing."""
        p = plan.diff(cfg(bridge=VXLAN), vxlan_kernel())
        self.assertTrue(p.empty, [str(o) for o in p.ops])

    def test_drift_recreates_the_interface(self):
        """Drift on vni, local, remote or either port plans a recreate."""
        for drift in (
            {"vni": 5043},
            {"vxlan_local": "10.255.0.12"},
            {"vxlan_remote": "239.1.19.178"},
            {"vxlan_port": 8472},
            {"vxlan_remote_port": 61235},
        ):
            p = plan.diff(cfg(bridge=VXLAN), vxlan_kernel(**drift))
            self.assertEqual(
                [plan.RemoveMember, plan.DestroyIface, plan.CreateVxlan],
                [type(o) for o in p.creates],
                drift,
            )
            self.assertEqual(VX, p.creates[1].name)
            self.assertEqual(
                [
                    plan.AddMember(bridge="net42", member=VX),
                    plan.ClearDiscover(bridge="net42", member=VX),
                ],
                p.adds,
            )
            self.assertEqual([], p.destroys)

    def test_discover_left_on_the_vxlan_member_is_cleared(self):
        """A vxlan member flooding unknown unicast gets the flag cleared."""
        p = plan.diff(cfg(bridge=VXLAN), vxlan_kernel(discover={"DISCOVER"}))
        self.assertEqual([plan.ClearDiscover(bridge="net42", member=VX)], p.ops)

    def test_mtu_drift_is_a_note_not_a_recreate(self):
        """An mtu the bridge forced on the vxlan is noted, never recreated."""
        p = plan.diff(cfg(bridge=VXLAN), vxlan_kernel(mtu=1500))
        self.assertTrue(p.empty, [str(o) for o in p.ops])
        self.assertEqual(
            [f"{VX}: mtu 1500 is not the network mtu 1450 (net42)"], p.notes
        )

    def test_unowned_vxlan_under_the_derived_name_is_an_error(self):
        """A vxlan under the derived name without the group is a PlanError."""
        o = kernel(iface(VX, groups=("vxlan",), vni=5042))
        self.assertRaises(plan.PlanError, plan.diff, cfg(bridge=VXLAN), o)


class OwnershipTestCase(unittest.TestCase):
    """The ownership rules."""

    def test_foreign_member_is_removed_never_destroyed(self):
        """A foreign member of an owned bridge is removed, never destroyed."""
        o = kernel(
            iface(
                "blue",
                groups=("bridge", "l2-neutron"),
                members=("vtnet0.210", "tap00000000-01", "em1"),
                maxaddr=2000,
            ),
            iface(
                "vtnet0.210", groups=("vlan", "l2-neutron"), vlan=210, parent="vtnet0"
            ),
            iface("tap00000000-01", groups=("tap", "l2-neutron")),
            iface("em1"),  # no l2-neutron group: foreign
        )
        p = plan.diff(cfg(bridge=BLUE), o)
        self.assertEqual([plan.RemoveMember(bridge="blue", member="em1")], p.removes)
        self.assertEqual([], p.destroys)

    def test_unwanted_owned_member_is_removed_and_destroyed(self):
        """An owned member the config no longer wants is removed and destroyed."""
        o = kernel(
            iface(
                "blue",
                groups=("bridge", "l2-neutron"),
                members=("vtnet0.210", "tap00000000-01", "tapdeadbeef-99"),
                maxaddr=2000,
            ),
            iface(
                "vtnet0.210", groups=("vlan", "l2-neutron"), vlan=210, parent="vtnet0"
            ),
            iface("tap00000000-01", groups=("tap", "l2-neutron")),
            iface("tapdeadbeef-99", groups=("tap", "l2-neutron")),
        )
        p = plan.diff(cfg(bridge=BLUE), o)
        self.assertIn(
            plan.RemoveMember(bridge="blue", member="tapdeadbeef-99"), p.removes
        )
        self.assertIn(plan.DestroyIface(name="tapdeadbeef-99"), p.destroys)

    def test_orphaned_owned_tap_is_collected(self):
        """An owned tap referenced by nothing is destroyed."""
        p = plan.diff(
            cfg(), kernel(iface("tapffffffff-00", groups=("tap", "l2-neutron")))
        )
        self.assertEqual([plan.DestroyIface(name="tapffffffff-00")], p.destroys)

    def test_desired_name_without_the_group_is_a_conflict(self):
        """A desired member that exists without the group is a PlanError."""
        o = kernel(
            iface(
                "blue",
                groups=("bridge", "l2-neutron"),
                maxaddr=2000,
                members=("vtnet0.210",),
            ),
            iface(
                "vtnet0.210", groups=("vlan", "l2-neutron"), vlan=210, parent="vtnet0"
            ),
            iface("tap00000000-01", groups=("tap",)),  # exists, not ours
        )
        self.assertRaisesRegex(
            plan.PlanError,
            "without the l2-neutron group",
            plan.diff,
            cfg(bridge=BLUE),
            o,
        )

    def test_desired_bridge_without_the_group_is_a_conflict(self):
        """A desired bridge that exists without the group is a PlanError."""
        o = kernel(iface("blue", groups=("bridge",), maxaddr=2000))
        self.assertRaisesRegex(
            plan.PlanError,
            "without the l2-neutron group",
            plan.diff,
            cfg(bridge=BLUE),
            o,
        )

    def test_desired_bridge_name_on_a_non_bridge_is_a_conflict(self):
        """A desired bridge name held by a non-bridge is a PlanError."""
        o = kernel(iface("blue", groups=("tap", "l2-neutron")))
        self.assertRaisesRegex(
            plan.PlanError, "not a.*bridge", plan.diff, cfg(bridge=BLUE), o
        )


class RemovalTestCase(unittest.TestCase):
    """Teardown planning."""

    def test_unconfigured_owned_bridge_tears_down_in_reverse(self):
        """An unconfigured owned bridge removes members first, itself last."""
        o = kernel(
            iface(
                "gone",
                groups=("bridge", "l2-neutron"),
                members=("vtnet0.99", "tapaaaaaaaa-00"),
                maxaddr=2000,
            ),
            iface("vtnet0.99", groups=("vlan", "l2-neutron"), vlan=99, parent="vtnet0"),
            iface("tapaaaaaaaa-00", groups=("tap", "l2-neutron")),
        )
        p = plan.diff(cfg(), o)
        self.assertEqual(
            {
                plan.RemoveMember(bridge="gone", member="vtnet0.99"),
                plan.RemoveMember(bridge="gone", member="tapaaaaaaaa-00"),
            },
            set(p.removes),
        )
        self.assertEqual("DestroyBridge", type(p.destroys[-1]).__name__)

    def test_foreign_bridge_is_left_entirely_alone(self):
        """A bridge without the ownership group is untouched, members and all."""
        p = plan.diff(
            cfg(), kernel(iface("bridge0", groups=("bridge",), members=("em1",)))
        )
        self.assertTrue(p.empty)


class DedupTestCase(unittest.TestCase):
    """Destroy deduplication across GC paths."""

    def test_one_destroy_per_interface_across_gc_paths(self):
        """A tap seen by both the bridge GC and the orphan GC is destroyed once."""
        o = kernel(
            iface(
                "gone",
                groups=("bridge", "l2-neutron"),
                members=("tapaaaaaaaa-00",),
                maxaddr=2000,
            ),
            iface("tapaaaaaaaa-00", groups=("tap", "l2-neutron")),
        )
        p = plan.diff(cfg(), o)
        names = [op.name for op in p.destroys]
        self.assertEqual(len(names), len(set(names)), names)


class AwaitingAttachTestCase(unittest.TestCase):
    """Attached-hardware members that may lag their config."""

    def test_absent_hardware_is_a_note_not_an_op(self):
        """A typeless member the kernel lacks becomes a note, not an op."""
        tree = {"mgmt": {"member": {"ue0": {}}}}
        p = plan.diff(cfg(bridge=tree), kernel())
        self.assertEqual([plan.CreateBridge(name="mgmt", maxaddr=2000)], p.creates)
        self.assertEqual([], p.adds)
        self.assertIn("ue0: awaiting-attach (mgmt)", p.notes)

    def test_hardware_arrival_becomes_a_plain_add(self):
        """Arrived hardware plans a plain AddMember and clears the note."""
        tree = {"mgmt": {"member": {"ue0": {}}}}
        o = kernel(
            iface("mgmt", groups=("bridge", "l2-neutron"), maxaddr=2000), iface("ue0")
        )
        p = plan.diff(cfg(bridge=tree), o)
        self.assertEqual([plan.AddMember(bridge="mgmt", member="ue0")], p.adds)
        self.assertEqual([], p.notes)

"""pf renderer and pf-plane planner tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


from neutron_bsdbridge import ifconfig
from neutron_bsdbridge.l2_agent import model, pf, plan


def make_filter(**sections):
    """Build a Filter from keyword rule sections."""
    return model.Filter.from_tree(sections)


WEB = {
    "in": {
        "10": {"action": "pass", "proto": "tcp", "port": 443},
        "20": {"action": "pass", "proto": "tcp", "port": 22, "from": "@web-members"},
    },
    "out": {"10": {"action": "pass"}},
}


class RenderTestCase(unittest.TestCase):
    """Anchor-text rendering."""

    def test_direction_flips_at_the_hook(self):
        """Config in renders as pf out on the tap, and config out as pf in."""
        text, _ = pf.render("tap0", make_filter(**WEB))
        self.assertIn(
            "pass out quick on tap0 inet proto tcp from any to any port 443", text
        )
        self.assertIn("pass in quick on tap0 all keep state (if-bound)", text)

    def test_implicit_deny_is_rendered_both_directions(self):
        """The anchor ends with explicit block rules in both directions."""
        text, _ = pf.render(
            "tap0", None, model.Bind(mac="aa:bb:cc:dd:ee:ff", addresses=["10.0.0.5"])
        )
        self.assertIn("block drop out quick on tap0 all", text)
        self.assertIn('block drop in quick on tap0 all label "l2-neutron:cfg:', text)

    def test_empty_filter_blocks_everything(self):
        """A member with an empty filter is deny-all, not plain switching."""
        text, _ = pf.render("tap0", make_filter())
        lines = [line for line in text.splitlines() if line]
        self.assertEqual(2, len(lines))
        self.assertTrue(all(line.startswith("block drop") for line in lines))

    def test_table_reference_renders_angle_brackets(self):
        """An @name reference renders as a pf table and a persist line."""
        text, _ = pf.render(
            "tap0", make_filter(**WEB), tables={"web-members": ["10.10.20.11"]}
        )
        self.assertIn("from <web-members> to any port 22", text)
        self.assertIn("table <web-members> persist { 10.10.20.11 }", text)

    def test_hash_ignores_table_membership(self):
        """The cfg hash is the same regardless of table membership."""
        f = make_filter(**WEB)
        _, h1 = pf.render("tap0", f, tables={"web-members": ["10.0.0.1"]})
        _, h2 = pf.render("tap0", f, tables={"web-members": ["10.9.9.9", "10.0.0.2"]})
        self.assertEqual(h1, h2, "membership churn must never reload the ruleset")

    def test_hash_changes_when_a_rule_changes(self):
        """The cfg hash changes when a rule is added."""
        _, h1 = pf.render("tap0", make_filter(**WEB))
        changed = dict(WEB)
        changed["in"] = dict(WEB["in"], **{"30": {"action": "pass", "proto": "icmp"}})
        _, h2 = pf.render("tap0", make_filter(**changed))
        self.assertNotEqual(h1, h2)

    def test_bind_renders_the_inet_source_lock_only(self):
        """bind{} renders the inet source lock and no ether rules."""
        # the mac half is the bridge's LockMemberMac op
        text, _ = pf.render(
            "tap0", None, model.Bind(mac="58:9C:FC:10:AA:01", addresses=["10.10.20.11"])
        )
        self.assertIn("table <source4> const { 10.10.20.11 }", text)
        self.assertIn("block drop in quick on tap0 inet from ! <source4>", text)
        self.assertNotIn("ether", text)


class ReadbackTestCase(unittest.TestCase):
    """Readback parsing against the captured pfctl samples."""

    def _sample(self, name):
        """Read one sample file's text."""
        path = os.path.join(os.path.dirname(__file__), "samples", name)
        with open(path) as f:
            return f.read()

    def test_hash_parses_from_sr_output(self):
        """The cfg hash parses out of pfctl -sr output."""
        self.assertEqual(
            "16ad57d372cb4efb", pf.parse_rules_hash(self._sample("pfctl-sr-anchor.txt"))
        )

    def test_table_show_parses(self):
        """Table members parse out of pfctl -T show output."""
        self.assertEqual(
            frozenset({"10.10.20.11", "10.10.20.12"}),
            pf.parse_table_show(self._sample("pfctl-T-show.txt")),
        )

    def test_read_anchor_from_samples(self):
        """A loaded anchor reads back its hash and table members."""

        def run(argv):
            """Serve the samples for the three readback queries."""
            if argv[-1] == "-sr":
                return 0, self._sample("pfctl-sr-anchor.txt"), ""
            if argv[-1] == "-sT":
                return 0, self._sample("pfctl-sT-anchor.txt"), ""
            if argv[-2:] == ("-T", "show"):
                return 0, self._sample("pfctl-T-show.txt"), ""
            raise AssertionError(argv)

        state = pf.read_anchor("tapdeadbeef-00", run)
        self.assertTrue(state.exists)
        self.assertEqual("16ad57d372cb4efb", state.cfg_hash)
        self.assertEqual(
            {"web-members": frozenset({"10.10.20.11", "10.10.20.12"})}, state.tables
        )

    def test_read_anchor_absent(self):
        """A missing anchor reads back as exists=False."""
        # pfctl exits 0 and prints "Anchor does not exist" to stderr
        self.assertFalse(pf.read_anchor("tapx", lambda argv: (0, "", "")).exists)
        self.assertFalse(pf.read_anchor("tapx", lambda argv: (1, "", "")).exists)


def iface(name, groups=(), members=(), maxaddr=None, vlan=None, parent=None):
    """Build an up Interface fixture."""
    return ifconfig.Interface(
        name=name,
        flags=frozenset({"UP"}),
        groups=tuple(groups),
        members=tuple(members),
        maxaddr=maxaddr,
        vlan=vlan,
        vlan_parent=parent,
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


CFG = {
    "physnet": {"phys0": {"trunk": "vtnet0"}},
    "table": {"web-members": {"members": ["10.10.20.11"]}},
    "filter": {"web": WEB},
    "bridge": {
        "blue": {
            "segment": {"physnet": "phys0", "vlan": 210},
            "member": {"tap00000000-01": {"type": "tap", "filter": "web"}},
        }
    },
}


def reconciled_kernel():
    """Build the kernel state that matches the CFG config."""
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


def desired_hash():
    """Render the CFG member's anchor and return its cfg hash."""
    cfg = model.Config.from_tree(CFG)
    _, h = pf.render(
        "tap00000000-01",
        cfg.filter["web"],
        None,
        pf.wanted_tables(cfg.filter["web"], cfg),
    )
    return h


class MacLockPlanTestCase(unittest.TestCase):
    """Planning of the bridge-native MAC lock."""

    def _cfg(self):
        """Build the CFG config with a bind{} on the member."""
        tree = dict(CFG)
        tree["bridge"] = {
            "blue": {
                "segment": {"physnet": "phys0", "vlan": 210},
                "member": {
                    "tap00000000-01": {
                        "type": "tap",
                        "filter": "web",
                        "bind": {
                            "mac": "aa:bb:cc:dd:ee:01",
                            "addresses": ["10.10.20.11"],
                        },
                    }
                },
            }
        }
        return model.Config.from_tree(tree)

    def _hash(self):
        """Render the bound member's anchor and return its cfg hash."""
        cfg = self._cfg()
        m = cfg.bridge["blue"].member["tap00000000-01"]
        _, h = pf.render(
            "tap00000000-01",
            cfg.filter["web"],
            m.bind,
            pf.wanted_tables(cfg.filter["web"], cfg),
        )
        return h

    def test_unlocked_member_gets_a_lock(self):
        """An unlocked bound member plans exactly one LockMemberMac."""
        p = plan.diff(
            self._cfg(),
            reconciled_kernel(),
            pf_state={
                "tap00000000-01": pf.AnchorState(
                    True,
                    cfg_hash=self._hash(),
                    tables={"web-members": frozenset({"10.10.20.11"})},
                )
            },
        )
        self.assertEqual(
            [
                plan.LockMemberMac(
                    bridge="blue", member="tap00000000-01", mac="aa:bb:cc:dd:ee:01"
                )
            ],
            p.ops,
        )

    def test_locked_member_plans_nothing(self):
        """A member already locked to the bound MAC plans nothing."""
        o = reconciled_kernel()
        o.addrs = {"blue": [("aa:bb:cc:dd:ee:01", "tap00000000-01", True)]}
        p = plan.diff(
            self._cfg(),
            o,
            pf_state={
                "tap00000000-01": pf.AnchorState(
                    True,
                    cfg_hash=self._hash(),
                    tables={"web-members": frozenset({"10.10.20.11"})},
                )
            },
        )
        self.assertTrue(p.empty, [str(x) for x in p.ops])

    def test_changed_bind_mac_relocks(self):
        """A member locked to a stale MAC plans a fresh LockMemberMac."""
        o = reconciled_kernel()
        o.addrs = {"blue": [("aa:bb:cc:dd:ee:99", "tap00000000-01", True)]}
        p = plan.diff(
            self._cfg(),
            o,
            pf_state={
                "tap00000000-01": pf.AnchorState(
                    True,
                    cfg_hash=self._hash(),
                    tables={"web-members": frozenset({"10.10.20.11"})},
                )
            },
        )
        self.assertEqual(["LockMemberMac"], [type(x).__name__ for x in p.ops])


class PfPlanTestCase(unittest.TestCase):
    """Planning of the pf plane against live anchor state."""

    def setUp(self):
        """Validate the shared CFG fixture."""
        super().setUp()
        self.cfg = model.Config.from_tree(CFG)

    def test_reconciled_everything_plans_nothing(self):
        """Matching interface and pf state plans nothing."""
        state = {
            "tap00000000-01": pf.AnchorState(
                True,
                cfg_hash=desired_hash(),
                tables={"web-members": frozenset({"10.10.20.11"})},
            )
        }
        p = plan.diff(self.cfg, reconciled_kernel(), pf_state=state)
        self.assertTrue(p.empty, [str(o) for o in p.ops])

    def test_hash_drift_reloads_the_anchor(self):
        """A stale cfg hash plans exactly one LoadAnchor."""
        state = {"tap00000000-01": pf.AnchorState(True, cfg_hash="stale000", tables={})}
        p = plan.diff(self.cfg, reconciled_kernel(), pf_state=state)
        kinds = [type(o).__name__ for o in p.ops]
        self.assertEqual(["LoadAnchor"], kinds)

    def test_membership_drift_is_a_replace_never_a_reload(self):
        """Table membership drift plans a ReplaceTable, not a LoadAnchor."""
        state = {
            "tap00000000-01": pf.AnchorState(
                True,
                cfg_hash=desired_hash(),
                tables={"web-members": frozenset({"10.9.9.9"})},
            )
        }
        p = plan.diff(self.cfg, reconciled_kernel(), pf_state=state)
        self.assertEqual(
            [
                plan.ReplaceTable(
                    ifname="tap00000000-01",
                    table="web-members",
                    members=("10.10.20.11",),
                )
            ],
            p.ops,
        )

    def test_missing_anchor_on_existing_member_loads(self):
        """A missing anchor on an existing member plans a LoadAnchor."""
        p = plan.diff(
            self.cfg,
            reconciled_kernel(),
            pf_state={"tap00000000-01": pf.AnchorState(False)},
        )
        self.assertEqual(["LoadAnchor"], [type(o).__name__ for o in p.ops])

    def test_policy_removal_flushes_the_anchor(self):
        """A member whose policy went away plans a FlushAnchor."""
        bare = dict(CFG)
        bare["bridge"] = {
            "blue": {
                "segment": {"physnet": "phys0", "vlan": 210},
                "member": {"tap00000000-01": {"type": "tap"}},
            }
        }
        cfg = model.Config.from_tree(bare)
        state = {"tap00000000-01": pf.AnchorState(True, cfg_hash="whatever", tables={})}
        p = plan.diff(cfg, reconciled_kernel(), pf_state=state)
        self.assertEqual([plan.FlushAnchor(ifname="tap00000000-01")], p.ops)

    def test_destroyed_member_flushes_before_destroy(self):
        """A departing member's anchor flushes before its destroy."""
        state = {"tapgone00000-0": pf.AnchorState(True, cfg_hash="x", tables={})}
        o = kernel(iface("tapgone00000-0", groups=("tap", "l2-neutron")))
        p = plan.diff(model.Config.from_tree({}), o, pf_state=state)
        self.assertEqual(
            ["FlushAnchor", "DestroyIface"], [type(op).__name__ for op in p.destroys]
        )

    def test_no_pf_state_still_loads_on_manufacture(self):
        """With no pf state, a brand-new tap still gets its anchor before addm."""
        p = plan.diff(self.cfg, kernel(), pf_state=None)
        kinds = [type(o).__name__ for o in p.adds]
        self.assertEqual(["CreateTap", "LoadAnchor", "AddMember", "AddMember"], kinds)


class PortRangeTestCase(unittest.TestCase):
    """Port ranges in filter rules."""

    def test_range_renders_with_a_colon(self):
        """An inclusive range renders in pf's colon syntax."""
        f = make_filter(
            **{"in": {"10": {"action": "pass", "proto": "tcp", "port": "1000-2000"}}}
        )
        text, _ = pf.render("tap0", f)
        self.assertIn("port 1000:2000", text)

    def test_degenerate_range_collapses_to_the_int(self):
        """A range with equal ends canonicalizes to the single int."""
        self.assertEqual(
            443,
            model.FilterRule.from_tree(
                {"action": "pass", "proto": "tcp", "port": "443-443"}
            ).port,
        )

    def test_inverted_or_oversized_ranges_are_refused(self):
        """Inverted and out-of-range ports are validation errors."""
        # "70000" regressed once: a string port skipped the range check
        for bad in ("2000-1000", "0-5", "1-70000", "70000", 70000, 0):
            self.assertRaises(
                model.SchemaError,
                model.FilterRule.from_tree,
                {"action": "pass", "port": bad},
            )


class FamilyTestCase(unittest.TestCase):
    """Address-family selection per protocol."""

    def test_icmp6_renders_inet6(self):
        """An icmp6 rule renders with the inet6 family."""
        f = make_filter(**{"in": {"10": {"action": "pass", "proto": "icmp6"}}})
        text, _ = pf.render("tap0", f)
        self.assertIn("inet6 proto icmp6", text)
        self.assertNotIn("inet proto icmp6", text)

    def test_family_renders_without_a_protocol(self):
        """A rule for every protocol of one family names only the family."""
        f = make_filter(**{"out": {"10": {"action": "pass", "family": "inet6"}}})
        text, _ = pf.render("tap0", f)
        self.assertIn("pass in quick on tap0 inet6 all keep state", text)

    def test_ipv6_tcp_renders_inet6(self):
        """A tcp rule with the inet6 family is not forced to inet."""
        rule = {"action": "pass", "family": "inet6", "proto": "tcp", "port": 22}
        text, _ = pf.render("tap0", make_filter(**{"in": {"10": rule}}))
        self.assertIn("inet6 proto tcp from any to any port 22", text)

    def test_icmp_type_and_code_render(self):
        """An icmp rule renders its type and code in the protocol's spelling."""
        rules = {
            "10": {"action": "pass", "proto": "icmp", "icmp-type": 3, "icmp-code": 4},
            "20": {"action": "pass", "proto": "icmp6", "icmp-type": 135},
        }
        text, _ = pf.render("tap0", make_filter(**{"in": rules}))
        self.assertIn("inet proto icmp from any to any icmp-type 3 code 4", text)
        self.assertIn("inet6 proto icmp6 from any to any icmp6-type 135", text)


class Source6TestCase(unittest.TestCase):
    """IPv6 half of the port-security source lock."""

    def render(self, **kwargs):
        """Render a bind-only anchor."""
        bind = model.Bind(mac="aa:bb:cc:dd:ee:ff", **kwargs)
        return pf.render("tap0", None, bind)

    def test_sources_are_locked_to_the_table(self):
        """IPv6 from the workload must come from its own addresses."""
        text, _ = self.render(addresses6=["fe80::1", "2001:db8::5"])
        self.assertIn("table <source6> const { 2001:db8::5, fe80::1 }", text)
        self.assertIn("block drop in quick on tap0 inet6 from ! <source6>", text)

    def test_address_detection_passes_before_the_lock(self):
        """The unspecified-source neighbor solicitation is not locked out."""
        lines = self.render(addresses6=["fe80::1"])[0].splitlines()
        dad = next(i for i, line in enumerate(lines) if "from :: to ff02::/16" in line)
        lock = next(i for i, line in enumerate(lines) if "from ! <source6>" in line)
        self.assertLess(dad, lock)

    def test_workload_cannot_act_as_router_or_dhcpv6_server(self):
        """Router advertisements and dhcpv6 replies from the port are dropped."""
        text, _ = self.render(addresses6=["fe80::1"])
        self.assertIn("icmp6-type routeradv", text)
        self.assertIn("from any port 547 to any port 546", text)

    def test_port_without_an_ipv4_address_sends_no_ipv4(self):
        """A bind with only IPv6 addresses drops every IPv4 packet sent."""
        text, _ = self.render(addresses6=["fe80::1"])
        self.assertIn("block drop in quick on tap0 inet all", text)

    def test_every_ipv4_address_is_a_source(self):
        """IPv4 from the workload may come from any of its addresses."""
        text, _ = self.render(addresses=["10.0.0.6", "10.0.0.5"])
        self.assertIn("table <source4> const { 10.0.0.5, 10.0.0.6 }", text)
        self.assertIn("block drop in quick on tap0 inet from ! <source4>", text)

    def test_ipv4_addresses_change_the_hash(self):
        """A changed IPv4 address reloads the anchor."""
        _, h1 = self.render(addresses=["10.0.0.5"])
        _, h2 = self.render(addresses=["10.0.0.5", "10.0.0.6"])
        self.assertNotEqual(h1, h2)

    def test_addresses_change_the_hash(self):
        """A changed IPv6 address reloads the anchor."""
        _, h1 = self.render(addresses6=["fe80::1"])
        _, h2 = self.render(addresses6=["fe80::1", "2001:db8::5"])
        self.assertNotEqual(h1, h2)

    def test_ipv4_only_bind_is_unchanged(self):
        """A bind with no IPv6 addresses renders no IPv6 lock."""
        text, _ = self.render(addresses=["10.0.0.5"])
        self.assertNotIn("inet6", text)


class StateLabelTestCase(unittest.TestCase):
    """State labels on rendered rules."""

    def test_pass_rules_carry_the_port_label(self):
        """Every pass rule carries the port's state label."""
        f = make_filter(**{"in": {"10": {"action": "pass", "proto": "icmp"}}})
        text, _ = pf.render("tap0", f)
        self.assertIn('label "l2-neutron:tap0"', text)

    def test_block_rules_do_not(self):
        """Only the cfg-hash marker labels a block rule."""
        text, _ = pf.render("tap0", make_filter())
        labels = [line for line in text.splitlines() if "label" in line]
        self.assertEqual(1, len(labels))
        self.assertIn("l2-neutron:cfg:", labels[0])


class DhcpClientTestCase(unittest.TestCase):
    """DHCP client traffic vs the port-security source lock."""

    def test_dhcp_client_passes_before_the_source_lock(self):
        """The 0.0.0.0-sourced DHCP request passes ahead of the lock."""
        text, _ = pf.render(
            "tap0", None, model.Bind(mac="aa:bb:cc:dd:ee:ff", addresses=["10.0.0.5"])
        )
        lines = text.splitlines()
        dhcp = next(
            i
            for i, line in enumerate(lines)
            if "from 0.0.0.0 to 255.255.255.255 port 67" in line
        )
        lock = next(
            i
            for i, line in enumerate(lines)
            if "block drop in quick on tap0 inet from !" in line
        )
        self.assertLess(dhcp, lock, "the lock would eat every DHCPDISCOVER otherwise")
        self.assertIn("pass in quick on tap0 inet proto udp", lines[dhcp])


class VxlanUplinkTestCase(unittest.TestCase):
    def test_dhcp_and_neighbour_discovery_pass_before_the_blocks(self):
        text, cfg_hash = pf.render_vxlan("vx1")
        lines = text.splitlines()
        self.assertEqual(5, len(lines))
        self.assertIn("port 68 to 255.255.255.255 port 67 no state", lines[0])
        self.assertIn("port 67 to 255.255.255.255 port 68 no state", lines[1])
        self.assertEqual(
            "block drop out quick on vx1 inet from any "
            "to { 224.0.0.0/4, 255.255.255.255 }",
            lines[2],
        )
        self.assertIn("icmp6-type { neighbrsol, neighbradv, routersol", lines[3])
        self.assertEqual(
            "block drop out quick on vx1 inet6 from any to ff00::/8 "
            f'label "l2-neutron:cfg:{cfg_hash}"',
            lines[4],
        )
        self.assertEqual(cfg_hash, pf.parse_rules_hash(text))

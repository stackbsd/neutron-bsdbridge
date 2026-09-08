"""Sample-file tests for the ifconfig reader and parser."""

# assertions run against tests/samples/, never live output; when the
# format changes, recapture first, then fix the parser

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import (
    ifconfig,
)

SAMPLES = os.path.join(os.path.dirname(__file__), "samples")


def sample(name):
    """Read one sample file's text."""
    with open(os.path.join(SAMPLES, name)) as f:
        return f.read()


class TapTestCase(unittest.TestCase):
    """Tap blocks."""

    def test_up_tap_member(self):
        """An up, owned tap parses with its groups and description."""
        i = ifconfig.parse(sample("ifconfig-tap-member.txt"))["tapdeadbeef-00"]
        self.assertTrue(i.up)
        self.assertTrue(i.is_owned)
        self.assertIn("tap", i.groups)
        self.assertEqual(
            "neutron port 99999999-8888-7777-6666-555555555555", i.description
        )

    def test_down_tap(self):
        """A tap created without up parses as down but still owned."""
        i = ifconfig.parse(sample("ifconfig-tap-down.txt"))["tapcafecafe-01"]
        self.assertFalse(i.up)
        self.assertTrue(i.is_owned)

    def test_description_with_colons_survives(self):
        """A description value containing colons parses intact."""
        i = ifconfig.parse(sample("ifconfig-vlan-child.txt"))["vtnet0.210"]
        self.assertEqual("segment realization: physnet1 vlan 210", i.description)


class VlanTestCase(unittest.TestCase):
    """Vlan-child blocks."""

    def test_vid_and_parent(self):
        """A vlan child parses its vid, parent, status, and ownership."""
        i = ifconfig.parse(sample("ifconfig-vlan-child.txt"))["vtnet0.210"]
        self.assertEqual(210, i.vlan)
        self.assertEqual("vtnet0", i.vlan_parent)
        self.assertEqual("active", i.status)
        self.assertTrue(i.is_owned)


class BridgeTestCase(unittest.TestCase):
    """Bridge blocks."""

    def test_members_and_maxaddr(self):
        """A bridge parses its member list and maxaddr."""
        i = ifconfig.parse(sample("ifconfig-bridge-with-member.txt"))["pbd2db231d54fe"]
        self.assertTrue(i.is_bridge)
        self.assertTrue(i.is_owned)
        self.assertEqual({"tapdeadbeef-00", "tapcafecafe-01"}, set(i.members))
        self.assertEqual(2000, i.maxaddr)

    def test_vlan_child_as_member(self):
        """A bridge with a vlan-child member parses that member."""
        i = ifconfig.parse(sample("ifconfig-bridge-with-vlan.txt"))["pb813cccc1f779"]
        self.assertEqual(("vtnet0.210",), i.members)

    def test_plain_nic_is_not_a_bridge_and_not_owned(self):
        """A plain hardware NIC parses as neither a bridge nor owned."""
        i = ifconfig.parse(sample("ifconfig-plain-nic.txt"))["vtnet0"]
        self.assertFalse(i.is_bridge)
        self.assertFalse(i.is_owned)
        self.assertEqual((), i.members)

    def test_addr_list_static_entries(self):
        """A bridge addr listing parses macs, members, and the static flag."""
        entries = ifconfig.parse_addr_list(sample("ifconfig-bridge-addr.txt"))
        self.assertEqual([("58:9c:fc:10:ff:01", "tapdeadbeef-00", True)], entries)


class StructureTestCase(unittest.TestCase):
    """Block splitting and lenient line handling."""

    def test_concatenated_output_parses_like_separate(self):
        """Concatenated per-interface output splits into the same interfaces."""
        combined = "".join(
            sample(n)
            for n in (
                "ifconfig-tap-member.txt",
                "ifconfig-bridge-with-member.txt",
                "ifconfig-vlan-child.txt",
                "ifconfig-plain-nic.txt",
            )
        )
        parsed = ifconfig.parse(combined)
        self.assertEqual(
            {"tapdeadbeef-00", "pbd2db231d54fe", "vtnet0.210", "vtnet0"}, set(parsed)
        )

    def test_unknown_lines_are_ignored_not_fatal(self):
        """Unrecognized detail lines are skipped without breaking the block."""
        text = (
            sample("ifconfig-tap-member.txt")
            + "\tfrobnication: maximum\n\tnew-freebsd-16-line here\n"
        )
        i = ifconfig.parse(text)["tapdeadbeef-00"]
        self.assertTrue(i.up)

    def test_group_list(self):
        """A group listing parses to interface names in kernel order."""
        # bridges carry the group too
        names = ifconfig.parse_group_list(sample("ifconfig-g-l2-neutron.txt"))
        self.assertEqual(
            [
                "pbd2db231d54fe",
                "pb813cccc1f779",
                "tapdeadbeef-00",
                "tapcafecafe-01",
                "vtnet0.210",
            ],
            names,
        )

    def test_empty_group_list(self):
        """An empty group listing parses to an empty list."""
        self.assertEqual([], ifconfig.parse_group_list(""))


class ReadInterfacesTestCase(unittest.TestCase):
    """read_interfaces() against a fake runner serving the samples."""

    def _runner(self):
        """Build a runner serving the samples plus its recorded call list."""
        by_iface = {
            "tapdeadbeef-00": sample("ifconfig-tap-member.txt"),
            "tapcafecafe-01": sample("ifconfig-tap-down.txt"),
            "vtnet0.210": sample("ifconfig-vlan-child.txt"),
            "pbd2db231d54fe": sample("ifconfig-bridge-with-member.txt"),
            "pb813cccc1f779": sample("ifconfig-bridge-with-vlan.txt"),
            "vtnet0": sample("ifconfig-plain-nic.txt"),
        }
        calls = []

        def run(argv):
            """Record the argv and serve the matching sample."""
            calls.append(argv)
            if argv == ifconfig.group_argv():
                return sample("ifconfig-g-l2-neutron.txt")
            return by_iface.get(argv[-1])

        return run, calls

    def test_owned_plus_bridges_plus_members(self):
        """The kernel view covers the owned set, named bridges, and their members."""
        run, _ = self._runner()
        kernel = ifconfig.read_interfaces(
            ["pbd2db231d54fe", "pb813cccc1f779"], runner=run
        )
        self.assertEqual(
            {
                "tapdeadbeef-00",
                "tapcafecafe-01",
                "vtnet0.210",
                "pbd2db231d54fe",
                "pb813cccc1f779",
            },
            set(kernel.interfaces),
        )
        self.assertEqual({"pbd2db231d54fe", "pb813cccc1f779"}, set(kernel.bridges()))

    def test_absent_bridge_is_absent_not_an_error(self):
        """A configured bridge the kernel does not have is simply absent."""
        run, _ = self._runner()
        kernel = ifconfig.read_interfaces(["pbffffffffffff"], runner=run)
        self.assertNotIn("pbffffffffffff", kernel)

    def test_each_interface_queried_once(self):
        """Each interface is queried at most once."""
        run, calls = self._runner()
        ifconfig.read_interfaces(["pbd2db231d54fe", "pb813cccc1f779"], runner=run)
        detail = [
            argv[-1]
            for argv in calls
            if argv != ifconfig.group_argv() and argv[-1] != "addr"
        ]
        self.assertEqual(len(detail), len(set(detail)))

    def test_bridges_get_their_address_tables_read(self):
        """Each bridge gets its address table read."""
        run, calls = self._runner()
        kernel = ifconfig.read_interfaces(["pbd2db231d54fe"], runner=run)
        addr_queries = [argv[1] for argv in calls if argv[-1] == "addr"]
        self.assertIn("pbd2db231d54fe", addr_queries)
        self.assertIn("pbd2db231d54fe", kernel.addrs)

    def test_foreign_member_is_queried(self):
        """A member that is neither owned nor configured still gets queried."""
        run, _calls = self._runner()
        text = sample("ifconfig-bridge-with-member.txt").replace(
            "member: tapcafecafe-01", "member: vtnet0"
        )

        def patched(argv):
            """Serve the edited bridge block, otherwise defer to the runner."""
            if argv[-1] == "pbd2db231d54fe":
                return text
            return run(argv)

        kernel = ifconfig.read_interfaces(["pbd2db231d54fe"], runner=patched)
        self.assertIn("vtnet0", kernel)
        self.assertFalse(kernel.interfaces["vtnet0"].is_owned)


class InetTestCase(unittest.TestCase):
    """inet address parsing, for the dhcp jail readback."""

    def test_inet_lines_parse_with_prefix_length(self):
        """Inet lines parse to (address, prefixlen) pairs."""
        i = ifconfig.parse(sample("ifconfig-plain-nic.txt"))["vtnet0"]
        self.assertEqual((("192.168.50.150", 24),), i.inets)

    def test_interfaces_without_inet_parse_empty(self):
        """A tap without addresses parses with no inets."""
        i = ifconfig.parse(sample("ifconfig-tap-member.txt"))["tapdeadbeef-00"]
        self.assertEqual((), i.inets)

"""Writer tests: argv emission, the destroy guard, and parking."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge import (
    plan,
    reconcile,
    writer,
)


class ArgvTestCase(unittest.TestCase):
    """The op-to-argv mapping."""

    def test_create_bridge_carries_group_and_maxaddr(self):
        """CreateBridge names, group-tags, sizes, and ups the bridge in one call."""
        argv = writer.argv_for(plan.CreateBridge(name="pbaaaa", maxaddr=500))
        self.assertEqual(
            (
                "/sbin/ifconfig",
                "bridge",
                "create",
                "name",
                "pbaaaa",
                "group",
                "l2-neutron",
                "maxaddr",
                "500",
                "up",
            ),
            argv,
        )

    def test_create_vlan_is_the_probed_syntax(self):
        """CreateVlan creates the child with vlandev, vid, name, and group."""
        argv = writer.argv_for(
            plan.CreateVlan(name="vtnet0.220", parent="vtnet0", vid=220)
        )
        self.assertEqual(
            (
                "/sbin/ifconfig",
                "vlan",
                "create",
                "vlandev",
                "vtnet0",
                "vlan",
                "220",
                "name",
                "vtnet0.220",
                "group",
                "l2-neutron",
                "up",
            ),
            argv,
        )

    def test_create_tap_without_description_omits_descr(self):
        """CreateTap leaves descr out of the argv when the description is empty."""
        argv = writer.argv_for(plan.CreateTap(name="tapx", description=""))
        self.assertNotIn("descr", argv)

    def test_load_anchor_feeds_pfctl_stdin(self):
        """LoadAnchor maps to pfctl -f - so the ruleset arrives on stdin."""
        argv = writer.argv_for(
            plan.LoadAnchor(ifname="tapx", filter="web", text="pass\n", cfg_hash="aa")
        )
        self.assertEqual(("/sbin/pfctl", "-a", "l2-neutron/port/tapx", "-f", "-"), argv)

    def test_replace_table_argv(self):
        """ReplaceTable maps to an atomic pfctl -T replace with the members."""
        argv = writer.argv_for(
            plan.ReplaceTable(
                ifname="tapx", table="web", members=("10.0.0.1", "10.0.0.2")
            )
        )
        self.assertEqual(
            (
                "/sbin/pfctl",
                "-a",
                "l2-neutron/port/tapx",
                "-t",
                "web",
                "-T",
                "replace",
                "10.0.0.1",
                "10.0.0.2",
            ),
            argv,
        )

    def test_empty_table_replace_is_a_flush(self):
        """ReplaceTable with no members maps to pfctl -T flush."""
        argv = writer.argv_for(
            plan.ReplaceTable(ifname="tapx", table="web", members=())
        )
        self.assertEqual(
            ("/sbin/pfctl", "-a", "l2-neutron/port/tapx", "-t", "web", "-T", "flush"),
            argv,
        )

    def test_flush_anchor_argv(self):
        """FlushAnchor maps to pfctl -F all on the port's anchor."""
        argv = writer.argv_for(plan.FlushAnchor(ifname="tapx"))
        self.assertEqual(
            ("/sbin/pfctl", "-a", "l2-neutron/port/tapx", "-F", "all"), argv
        )

    def test_unknown_op_is_loud(self):
        """An unmapped op raises ValueError."""
        self.assertRaises(ValueError, writer.argv_for, object())


class FakeRunner:
    """Scripted kernel: records argv, serves canned responses."""

    def __init__(self, iface_text=None, fail=(), hang=()):
        """Configure canned interface text and the failing or hanging targets."""
        self.calls = []
        self.iface_text = iface_text or {}
        self.fail = set(fail)
        self.hang = set(hang)

    def __call__(self, argv, timeout=None, input=None):
        """Record the argv and answer from the script."""
        self.calls.append(argv)
        self.stdin = input
        name = argv[1] if len(argv) == 2 else None
        if name is not None:  # bare query
            text = self.iface_text.get(name)
            return (0, text, "") if text else (1, "", "does not exist")
        target = argv[1]
        if target in self.hang:
            return (writer.TIMEOUT, "", "")
        if target in self.fail:
            return (1, "", "refused")
        return (0, "", "")


OWNED_TAP = (
    "tapaaaaaaaa-00: flags=8943<UP> metric 0 mtu 1500\n\tgroups: tap l2-neutron\n"
)
FOREIGN_TAP = "tapaaaaaaaa-00: flags=8943<UP> metric 0 mtu 1500\n\tgroups: tap\n"


class DryRunTestCase(unittest.TestCase):
    """Dry-run behaviour."""

    def test_dry_run_executes_nothing(self):
        """A dry-run apply emits an ok receipt without running anything."""
        run = FakeRunner()
        e = writer.Writer(dry_run=True, run=run)
        r = e.apply(plan.CreateTap(name="tapx", description="d"))
        self.assertFalse(r.executed)
        self.assertTrue(r.ok)
        self.assertEqual([], run.calls)


class DestroyGuardTestCase(unittest.TestCase):
    """The kernel-side ownership re-check before any destroy."""

    def test_owned_interface_is_destroyed(self):
        """An owned interface is destroyed."""
        run = FakeRunner(iface_text={"tapaaaaaaaa-00": OWNED_TAP})
        e = writer.Writer(dry_run=False, run=run)
        r = e.apply(plan.DestroyIface(name="tapaaaaaaaa-00"))
        self.assertTrue(r.ok)
        self.assertIn(("/sbin/ifconfig", "tapaaaaaaaa-00", "destroy"), run.calls)

    def test_foreign_interface_is_refused_whatever_the_plan_says(self):
        """An interface without the group is refused, never destroyed."""
        run = FakeRunner(iface_text={"tapaaaaaaaa-00": FOREIGN_TAP})
        e = writer.Writer(dry_run=False, run=run)
        r = e.apply(plan.DestroyIface(name="tapaaaaaaaa-00"))
        self.assertFalse(r.ok)
        self.assertFalse(r.executed)
        self.assertIn("REFUSED", r.note)
        self.assertNotIn(("/sbin/ifconfig", "tapaaaaaaaa-00", "destroy"), run.calls)

    def test_absent_interface_is_success(self):
        """Destroying an interface that is already gone succeeds without executing."""
        run = FakeRunner()
        e = writer.Writer(dry_run=False, run=run)
        r = e.apply(plan.DestroyIface(name="tapaaaaaaaa-00"))
        self.assertTrue(r.ok)
        self.assertIn("absent", r.note)


class ParkingTestCase(unittest.TestCase):
    """Blocked destroys and continuing past failures."""

    def test_blocked_destroy_parks_instead_of_failing_the_reconcile(self):
        """A destroy that times out parks its receipt."""
        run = FakeRunner(
            iface_text={"tapaaaaaaaa-00": OWNED_TAP}, hang={"tapaaaaaaaa-00"}
        )
        e = writer.Writer(dry_run=False, run=run)
        r = e.apply(plan.DestroyIface(name="tapaaaaaaaa-00"))
        self.assertTrue(r.parked)
        self.assertFalse(r.ok)
        self.assertIn("blocked", r.note)

    def test_apply_plan_continues_past_a_failure(self):
        """apply_plan runs every op even after an earlier one fails."""
        run = FakeRunner(fail={"bridge"})  # bridge create refused
        e = writer.Writer(dry_run=False, run=run)
        p = plan.Plan()
        p.creates.append(plan.CreateBridge(name="pbaaaa", maxaddr=2000))
        p.adds.append(plan.AddMember(bridge="pbaaaa", member="tapx"))
        receipts = e.apply_plan(p)
        self.assertEqual([False, True], [r.ok for r in receipts])
        self.assertEqual(2, len(receipts), "never stops early")


class ReconcileWiringTestCase(unittest.TestCase):
    """reconcile() wiring across read, diff, and apply."""

    def test_reconcile_is_read_diff_apply(self):
        """The reconcile pass reads the config's names, diffs, and applies."""
        from neutron_bsdbridge import ifconfig, model

        cfg = model.Config.from_tree({"bridge": {"lone": {"member": {}}}})
        calls = []

        def reader(bridges):
            """Record the queried names and serve an empty kernel."""
            calls.append(("read", tuple(bridges)))
            return ifconfig.KernelInterfaces({}, ())

        e = writer.Writer(dry_run=True)
        result = reconcile.reconcile(
            cfg, writer=e, reader=reader, pf_reader=lambda names: {}
        )
        self.assertEqual([("read", ("lone",))], calls)
        self.assertEqual(1, len(result.plan.creates))
        self.assertTrue(result.reconciled)
        self.assertEqual([], result.parked)
        self.assertEqual([], result.failed)

    def test_parked_receipts_are_not_failures(self):
        """Result.failed excludes parked receipts."""
        parked = writer.Receipt(
            op=plan.DestroyIface(name="tapx"),
            argv=(),
            executed=True,
            ok=False,
            parked=True,
        )
        failed = writer.Receipt(
            op=plan.CreateTap(name="tapy", description=""),
            argv=(),
            executed=True,
            ok=False,
        )
        result = reconcile.Result(
            plan=plan.Plan(), receipts=[parked, failed], kernel=None
        )
        self.assertEqual([failed], result.failed)
        self.assertEqual([parked], result.parked)
        self.assertFalse(result.reconciled)


class StateKillTestCase(unittest.TestCase):
    """State teardown after an anchor reload."""

    def test_anchor_reload_kills_the_ports_states_by_id(self):
        """A LoadAnchor kills exactly the loaded port's states, by id."""
        run = FakeRunner()
        vvss = (
            "tapx icmp 1.1.1.1:8 -> 2.2.2.2:8\n"
            "   age 00:00:01\n"
            "   id: aabbccdd00000000 creatorid: 1\n"
            "other tcp 3.3.3.3:1 -> 4.4.4.4:2\n"
            "   id: 9999999900000000 creatorid: 1\n"
        )
        real = run.__call__

        def patched(argv, timeout=None, input=None):
            """Serve the canned state listing for pfctl -vvss."""
            if argv == ("/sbin/pfctl", "-vvss"):
                run.calls.append(argv)
                return (0, vvss, "")
            return real(argv, timeout=timeout, input=input)

        e = writer.Writer(dry_run=False, run=patched)
        r = e.apply(
            plan.LoadAnchor(ifname="tapx", filter="f", text="pass\n", cfg_hash="aa")
        )
        self.assertIn(("/sbin/pfctl", "-k", "id", "-k", "aabbccdd00000000"), run.calls)
        self.assertNotIn(
            ("/sbin/pfctl", "-k", "id", "-k", "9999999900000000"),
            run.calls,
            "only THIS ports states die",
        )
        self.assertIn("1 state(s) killed", r.note)

"""Agent tests: the sync path, cold-start recovery, and the devd filter."""

import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_bsdbridge.l2_agent import agent as agent_mod
except ImportError:
    raise unittest.SkipTest("needs neutron libs; run under the neutron venv")

from neutron_bsdbridge import ifconfig  # noqa: E402
from neutron_bsdbridge.l2_agent import writer  # noqa: E402

PORT_ID = "3fb01977-a4e2-4a28-9a6f-1f0a3a2b4c5d"


def details_for(port_id):
    return {
        "port_id": port_id,
        "device": port_id,
        "network_id": "b716de99-4bd1-4b58-a52e-b0b8ab779b74",
        "network_type": "local",
        "physical_network": None,
        "segmentation_id": None,
        "mac_address": "fa:16:3e:aa:bb:01",
        "fixed_ips": [{"subnet_id": "s1", "ip_address": "10.99.0.5"}],
    }


class FakePluginRpc:
    def __init__(self, devices):
        self.devices = devices
        self.ups = []
        self.downs = []

    def get_devices_details_list_and_failed_devices(
        self, context, devices, agent_id, host=None
    ):
        found = [details_for(d) for d in devices if d in self.devices]
        missing = [{"device": d} for d in devices if d not in self.devices]
        return {"devices": found + missing, "failed_devices": []}

    def update_device_list(self, context, devices_up, devices_down, agent_id, host):
        self.ups.extend(devices_up)
        self.downs.extend(devices_down)
        return {"failed_devices_up": [], "failed_devices_down": []}


class FakeSgRpc:
    def security_group_info_for_devices(self, context, devices):
        return {"devices": {}, "security_groups": {}, "sg_member_ips": {}}


def make_agent(tmpdir, devices, writer_obj=None, reader=None):
    """Assemble an agent instance with fakes in every collaborator seat."""
    a = agent_mod.BsdBridgeAgent.__new__(agent_mod.BsdBridgeAgent)
    a.conf = types.SimpleNamespace(
        host="testhost",
        bsdbridge=types.SimpleNamespace(
            physical_interface_mappings={},
            state_path=tmpdir,
            sync_interval=30,
            devd_pipe="",
        ),
    )
    a.host = "testhost"
    a.agent_id = "bsdbridge-testhost"
    a.context = None
    a.plugin_rpc = FakePluginRpc(devices)
    a.sg_plugin_rpc = FakeSgRpc()
    a._writer = writer_obj or writer.Writer(
        dry_run=True, run=lambda argv, **kw: (1, "", "")
    )
    a._reader = reader or (lambda names: ifconfig.KernelInterfaces({}, ()))
    a._runner = lambda argv: None
    a._dirty = True
    a._failures = 0
    a._devices_up = set()
    a._misses = {}
    a._candidates = set()
    return a


class SyncTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_bound_port_reconciles_and_reports_up(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        self.assertEqual([PORT_ID], a.plugin_rpc.ups)
        self.assertEqual({PORT_ID}, a._devices_up)
        self.assertEqual({PORT_ID}, a._candidates)
        with open(os.path.join(self.tmp.name, "devices.json")) as f:
            self.assertEqual({"devices": [PORT_ID]}, json.load(f))

    def test_unchanged_port_is_reported_up_every_pass(self):
        # the server resets a port to BUILD on every details fetch
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a._sync()
        self.assertEqual([PORT_ID, PORT_ID], a.plugin_rpc.ups)
        self.assertEqual([], a.plugin_rpc.downs)

    def test_departed_port_reports_down_and_stops_tracking(self):
        a = make_agent(self.tmp.name, devices=set())
        a._candidates = {PORT_ID}
        a._devices_up = {PORT_ID}
        a._sync()
        self.assertEqual([PORT_ID], a.plugin_rpc.downs)
        self.assertEqual(set(), a._devices_up)
        for _ in range(agent_mod.BINDING_MISS_LIMIT):
            a._sync()
        self.assertEqual(
            set(), a._candidates, "a departed port is dropped after the miss limit"
        )

    def test_failed_reconcile_raises_and_reports_nothing(self):
        broken = writer.Writer(
            dry_run=False, run=lambda argv, **kw: (1, "", "kernel says no")
        )
        a = make_agent(self.tmp.name, devices={PORT_ID}, writer_obj=broken)
        a._candidates = {PORT_ID}
        self.assertRaises(agent_mod.ReconcileError, a._sync)
        self.assertEqual([], a.plugin_rpc.ups)
        self.assertFalse(
            os.path.exists(os.path.join(self.tmp.name, "devices.json")),
            "a failed reconcile must not overwrite the recovery record",
        )

    def test_unbound_candidate_drops_out_after_the_limit(self):
        a = make_agent(self.tmp.name, devices=set())
        a._candidates = {"not-ours-anymore"}
        for _ in range(agent_mod.BINDING_MISS_LIMIT):
            a._sync()
        self.assertEqual(set(), a._candidates)
        self.assertEqual([], a.plugin_rpc.ups)


class RecoveryTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_device_file_round_trips(self):
        a = make_agent(self.tmp.name, devices=set())
        a._save_devices([PORT_ID, "aaa"])
        self.assertEqual(sorted(["aaa", PORT_ID]), a._devices_from_state())

    def test_missing_device_file_is_empty(self):
        a = make_agent(self.tmp.name, devices=set())
        self.assertEqual([], a._devices_from_state())

    def test_kernel_scan_reads_tap_descriptions(self):
        tap = ifconfig.Interface(
            name="tap3fb01977-a4",
            flags=frozenset({"UP"}),
            groups=("tap", "l2-neutron"),
            description="neutron port " + PORT_ID,
        )
        foreign = ifconfig.Interface(
            name="tap999",
            flags=frozenset({"UP"}),
            groups=("tap",),
            description="neutron port not-ours",
        )
        undescribed = ifconfig.Interface(
            name="vx5042p0", flags=frozenset({"UP"}), groups=("vxlan", "l2-neutron")
        )

        def reader(names):
            return ifconfig.KernelInterfaces(
                {i.name: i for i in (tap, foreign, undescribed)},
                ("tap3fb01977-a4", "vx5042p0"),
            )

        a = make_agent(self.tmp.name, devices=set(), reader=reader)
        self.assertEqual([PORT_ID], a._devices_from_kernel())

    def test_recovery_unions_file_and_kernel(self):
        tap = ifconfig.Interface(
            name="tap3fb01977-a4",
            flags=frozenset({"UP"}),
            groups=("tap", "l2-neutron"),
            description="neutron port " + PORT_ID,
        )

        def reader(names):
            return ifconfig.KernelInterfaces({tap.name: tap}, (tap.name,))

        a = make_agent(self.tmp.name, devices=set(), reader=reader)
        a._save_devices(["from-file"])
        self.assertEqual({"from-file", PORT_ID}, a._recover_devices())


class DevdTestCase(unittest.TestCase):
    def test_ifnet_attach_and_detach_match(self):
        f = agent_mod.BsdBridgeAgent.is_ifnet_event
        self.assertTrue(f("!system=IFNET subsystem=tap0 type=ATTACH"))
        self.assertTrue(f("!system=IFNET subsystem=tap0 type=DETACH"))
        self.assertFalse(f("!system=IFNET subsystem=vtnet0 type=LINK_UP"))
        self.assertFalse(f("!system=DEVFS subsystem=CDEV type=CREATE"))


class AwaitingAttachTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_awaiting_attach_port_is_not_reported_up(self):
        # not up until the dhcp agent manufactures the epair
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a.plugin_rpc.devices = {PORT_ID}
        original = details_for

        def dhcp_details(port_id):
            d = original(port_id)
            d["device_owner"] = "network:dhcp"
            return d

        a.plugin_rpc.get_devices_details_list_and_failed_devices = (
            lambda ctx, devs, agent_id, host=None: {
                "devices": [dhcp_details(d) for d in devs],
                "failed_devices": [],
            }
        )
        a._candidates = {PORT_ID}
        a._sync()
        self.assertEqual([], a.plugin_rpc.ups, "awaiting-attach must not report up")
        self.assertEqual(
            {PORT_ID}, a._candidates, "the port stays tracked for the next pass"
        )


class DhcpIfDiscoveryTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_dhcp_if_description_feeds_the_candidate_set(self):
        # no port_update fanout for dhcp ports; the epair is the announcement
        a = make_agent(self.tmp.name, devices={PORT_ID})

        def runner(argv):
            if argv[-2:] == ("-g", "dhcp-neutron"):
                return "dh3fb01977-a4e\n"
            if argv[-1] == "dh3fb01977-a4e":
                return (
                    "dh3fb01977-a4e: flags=8843<UP> metric 0 mtu 1500\n"
                    "\tdescription: neutron port " + PORT_ID + "\n"
                    "\tgroups: epair dhcp-neutron\n"
                )
            return None

        a._runner = runner
        a._sync()
        self.assertIn(PORT_ID, a._candidates)


class BindingRaceTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_unresolved_candidate_survives_and_marks_dirty(self):
        # a candidate answering without a port_id stays tracked and retries fast
        a = make_agent(self.tmp.name, devices=set())
        a._candidates = {PORT_ID}
        a._dirty = False
        a._sync()
        self.assertIn(PORT_ID, a._candidates)
        self.assertTrue(a._dirty, "a pending bind retries at loop speed")
        # the bind commits
        a.plugin_rpc.devices = {PORT_ID}
        a._sync()
        self.assertEqual([PORT_ID], a.plugin_rpc.ups)
        self.assertEqual({}, a._misses)

    def test_candidate_added_mid_sync_survives_the_rebuild(self):
        # a candidate that lands while the sync's RPC calls yield was never
        # queried; the rebuild at the end of the pass must keep it
        a = make_agent(self.tmp.name, devices=set())
        late = "9e21ca2b-0259-4373-ca72-5045456a9848"
        real_rpc = a.plugin_rpc.get_devices_details_list_and_failed_devices

        def rpc_with_interleaved_update(context, devices, agent_id, host=None):
            a.port_update(None, port={"id": late})
            return real_rpc(context, devices, agent_id, host=host)

        a.plugin_rpc.get_devices_details_list_and_failed_devices = (
            rpc_with_interleaved_update
        )
        a._candidates = {PORT_ID}
        a._sync()
        self.assertIn(late, a._candidates)
        self.assertTrue(a._dirty, "the late candidate syncs at the next tick")

    def test_never_resolving_candidate_is_dropped_at_the_limit(self):
        a = make_agent(self.tmp.name, devices=set())
        a._candidates = {PORT_ID}
        for _ in range(agent_mod.BINDING_MISS_LIMIT):
            a._sync()
        self.assertNotIn(PORT_ID, a._candidates)
        self.assertEqual({}, a._misses)


class PortDeleteTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_port_delete_is_the_definitive_drop(self):
        a = make_agent(self.tmp.name, devices=set())
        a._candidates = {PORT_ID}
        a._misses = {PORT_ID: 3}
        a.port_delete(None, port_id=PORT_ID)
        self.assertNotIn(PORT_ID, a._candidates)
        self.assertEqual({}, a._misses)
        self.assertTrue(a._dirty)

    def test_slow_bind_falls_back_to_the_periodic_sync(self):
        # after the fast retries the candidate stays tracked but stops
        # holding the loop at 1s
        a = make_agent(self.tmp.name, devices=set())
        a._candidates = {PORT_ID}
        for _ in range(agent_mod.FAST_RETRY_MISSES + 2):
            a._sync()
        a._dirty = False
        a._sync()
        self.assertIn(PORT_ID, a._candidates)
        self.assertFalse(a._dirty, "past the fast window, only the tick retries")
        # the bind lands
        a.plugin_rpc.devices = {PORT_ID}
        a._sync()
        self.assertEqual([PORT_ID], a.plugin_rpc.ups)

"""L2 agent tests."""

import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_bsdbridge.l2_agent import agent as agent_mod
except ImportError:
    raise unittest.SkipTest("needs neutron libs; run under the neutron venv")

from neutron_bsdbridge import ifconfig  # noqa: E402
from neutron_bsdbridge.constants import PFCTL  # noqa: E402
from neutron_bsdbridge.l2_agent import model, writer  # noqa: E402

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
        self.fetches = []
        self.ups = []
        self.downs = []
        self.refreshes = []

    def get_devices_details_list_and_failed_devices(
        self, context, devices, agent_id, host=None
    ):
        self.fetches.append(list(devices))
        found = [details_for(d) for d in devices if d in self.devices]
        missing = [{"device": d} for d in devices if d not in self.devices]
        return {"devices": found + missing, "failed_devices": []}

    def update_device_list(
        self, context, devices_up, devices_down, agent_id, host, refresh_tunnels=False
    ):
        self.refreshes.append(refresh_tunnels)
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
    a._run = lambda argv: (1, "", "")
    a._vxlan = None
    a._fdb = {}
    a._fdb_lock = threading.Lock()
    a._installed = {}
    a._fdb_ctl = None
    a._relay = None
    a._refresh_tunnels = True
    a._fdb_asked = None
    a._vtep_warned = False
    a._dirty = True
    a._failures = 0
    a._devices_up = set()
    a._misses = {}
    a._candidates = set()
    a._details = {}
    a._stale = set()
    a._unreported = set()
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

    def test_unchanged_port_is_fetched_and_reported_once(self):
        # the server resets a port to BUILD on every details fetch
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a._sync()
        self.assertEqual([[PORT_ID]], a.plugin_rpc.fetches)
        self.assertEqual([PORT_ID], a.plugin_rpc.ups)
        self.assertEqual([], a.plugin_rpc.downs)

    def test_an_updated_port_is_the_only_one_fetched_and_reported_again(self):
        other = "9a8b7c6d-0000-4000-8000-000000000002"
        a = make_agent(self.tmp.name, devices={PORT_ID, other})
        a._candidates = {PORT_ID, other}
        a._sync()
        a.port_update(None, port={"id": other})
        a._sync()
        self.assertEqual([other], a.plugin_rpc.fetches[-1])
        self.assertEqual([*sorted([PORT_ID, other]), other], a.plugin_rpc.ups)

    def test_a_network_update_fetches_every_port(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a.network_update(None, network={"id": "n1"})
        a._sync()
        self.assertEqual([[PORT_ID], [PORT_ID]], a.plugin_rpc.fetches)
        self.assertEqual([PORT_ID, PORT_ID], a.plugin_rpc.ups)

    def test_a_revived_agent_fetches_every_port(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a._dirty = False
        a.agent_state = {"configurations": {}}
        a.state_rpc = types.SimpleNamespace(
            report_state=lambda context, state, use_call: "revived"
        )
        a._report_state()
        self.assertTrue(a._dirty)
        a._sync()
        self.assertEqual([[PORT_ID], [PORT_ID]], a.plugin_rpc.fetches)

    def test_a_port_fetched_in_a_failed_pass_is_still_reported_up(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        working = a._writer
        a._writer = writer.Writer(
            dry_run=False, run=lambda argv, **kw: (1, "", "kernel says no")
        )
        a.port_update(None, port={"id": PORT_ID})
        self.assertRaises(agent_mod.ReconcileError, a._sync)
        a._writer = working
        a._sync()
        self.assertEqual(2, len(a.plugin_rpc.fetches))
        self.assertEqual([PORT_ID, PORT_ID], a.plugin_rpc.ups)

    def test_a_failed_fetch_is_retried_for_the_same_ports(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a.port_update(None, port={"id": PORT_ID})
        fetch = a.plugin_rpc.get_devices_details_list_and_failed_devices

        def broken(*args, **kwargs):
            raise OSError("rpc down")

        a.plugin_rpc.get_devices_details_list_and_failed_devices = broken
        self.assertRaises(OSError, a._sync)
        a.plugin_rpc.get_devices_details_list_and_failed_devices = fetch
        a._sync()
        self.assertEqual([PORT_ID], a.plugin_rpc.fetches[-1])

    def test_a_deleted_port_leaves_the_cache(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a.port_delete(None, port_id=PORT_ID)
        self.assertEqual({}, a._details)

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
            name="vx1f5a50665c03",
            flags=frozenset({"UP"}),
            groups=("vxlan", "l2-neutron"),
        )

        def reader(names):
            return ifconfig.KernelInterfaces(
                {i.name: i for i in (tap, foreign, undescribed)},
                ("tap3fb01977-a4", "vx1f5a50665c03"),
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


def vxlan_section(**kw):
    base = {
        "local_ip": "192.168.50.150",
        "udp_port": 4789,
        "ttl": 64,
        "relay_rate": 100,
    }
    base.update(kw)
    return types.SimpleNamespace(
        bsdbridge=types.SimpleNamespace(physical_interface_mappings={"p": "ix0"}),
        vxlan=types.SimpleNamespace(**base),
    )


def nic_run(argv):
    if argv == ("/sbin/ifconfig",):
        return (
            0,
            "vtnet0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.50.150 netmask 0xffffff00 broadcast 192.168.50.255\n",
            "",
        )
    return 1, "", "does not exist"


class VxlanConfTestCase(unittest.TestCase):
    def test_unset_local_ip_disables_vxlan(self):
        conf = vxlan_section(local_ip=None)
        self.assertIsNone(agent_mod.vxlan_conf(conf, nic_run))
        self.assertNotIn("tunnel_types", agent_mod.configurations(conf, None))

    def test_settings_come_from_the_section(self):
        vx = agent_mod.vxlan_conf(vxlan_section(), nic_run)
        self.assertEqual(
            {"local": "192.168.50.150", "port": 4789, "ttl": 64, "rate": 100}, vx
        )

    def test_local_ip_not_on_an_interface_is_refused(self):
        self.assertRaises(
            ValueError,
            agent_mod.vxlan_conf,
            vxlan_section(local_ip="192.168.50.151"),
            nic_run,
        )

    def test_enabled_vxlan_is_advertised(self):
        conf = vxlan_section()
        configurations = agent_mod.configurations(
            conf, agent_mod.vxlan_conf(conf, nic_run)
        )
        self.assertEqual(["vxlan"], configurations["tunnel_types"])
        self.assertEqual("192.168.50.150", configurations["tunneling_ip"])
        self.assertTrue(configurations["l2_population"])
        self.assertEqual({"p": "ix0"}, configurations["physical_interface_mappings"])


NET = "c4b288d4-8089-4959-b8c3-4eaf1cd6edf0"
FLOOD = ["00:00:00:00:00:00", "0.0.0.0"]
VM_B = ["fa:16:3e:00:00:0b", "10.42.0.11"]
VM_C = ["fa:16:3e:00:00:0c", "10.42.0.12"]


def fdb(ports, network_type="vxlan"):
    return {NET: {"segment_id": 5042, "network_type": network_type, "ports": ports}}


class FakeFdbCtl:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def _do(self, *call):
        if self.fail and call[0] == self.fail:
            raise OSError(6, "Device not configured")
        self.calls.append(call)

    def flush(self, ifname):
        self._do("flush", ifname)

    def add_entry(self, ifname, mac, ip, port):
        self._do("add", ifname, mac, ip, port)

    def remove_entry(self, ifname, mac):
        self._do("remove", ifname, mac)


class FakeRelay:
    def __init__(self):
        self.tables = None
        self.wanted = None

    def ports_for(self, vnis):
        self.wanted = list(vnis)
        return {vni: 61234 + i for i, vni in enumerate(vnis)}

    def update(self, tables):
        self.tables = tables

    def stats(self):
        return {"alive": True}


class FakeRun:
    """ifconfig with a bridge whose static entries it remembers."""

    def __init__(self):
        self.calls = []
        self.statics = set()

    def __call__(self, argv):
        self.calls.append(argv[1:])
        if argv[2] == "addr":
            text = "".join(
                f"{mac} Vlan0 {member} 0 flags=1<STATIC>\n"
                for mac, member in sorted(self.statics)
            )
            return 0, text, ""
        if argv[2] == "static":
            self.statics.add((argv[4], argv[3]))
        if argv[2] == "deladdr":
            self.statics = {e for e in self.statics if e[0] != argv[3]}
        return 0, "", ""


def vxlan_config(vni=5042, member=None):
    bridge = {
        "segment": {"vxlan": {"vni": vni, "local": "192.0.2.1", "remote_port": 61234}}
    }
    if member is not None:
        bridge["member"] = member
    return model.Config.from_tree({"bridge": {"pb1": bridge}})


def vxlan_agent(tmpdir, ctl=None):
    a = make_agent(tmpdir, devices=set())
    a._vxlan = {"local": "192.0.2.1", "port": 4789, "ttl": 64, "rate": 100}
    a._fdb_ctl = ctl or FakeFdbCtl()
    a._relay = FakeRelay()
    a._run = FakeRun()
    return a


class FdbTablesTestCase(unittest.TestCase):
    def test_flooding_entries_are_peers_and_the_rest_are_entries(self):
        entries, peers, arp = agent_mod.fdb_tables(
            {
                "192.0.2.2": {tuple(FLOOD), tuple(VM_B)},
                "192.0.2.3": {tuple(FLOOD), tuple(VM_C)},
                "192.0.2.1": {tuple(FLOOD), ("fa:16:3e:00:00:0a", "10.42.0.10")},
                "192.0.2.4": {("fa:16:3e:00:00:0d", "2001:db8::d")},
            },
            "192.0.2.1",
        )
        self.assertEqual(
            {
                "fa:16:3e:00:00:0b": "192.0.2.2",
                "fa:16:3e:00:00:0c": "192.0.2.3",
                "fa:16:3e:00:00:0d": "192.0.2.4",
            },
            entries,
        )
        self.assertEqual(["192.0.2.2", "192.0.2.3"], peers)
        self.assertEqual(
            {"10.42.0.11": "fa:16:3e:00:00:0b", "10.42.0.12": "fa:16:3e:00:00:0c"},
            arp,
        )


class L2popTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_add_remove_and_update_track_the_ports(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        a.add_fdb_entries(None, fdb({"192.0.2.3": [FLOOD, VM_C]}))
        a.remove_fdb_entries(None, fdb({"192.0.2.3": [FLOOD, VM_C]}))
        a.update_fdb_entries(
            None,
            {
                "chg_ip": {
                    NET: {"192.0.2.2": {"before": [VM_B], "after": [VM_C]}},
                }
            },
        )
        self.assertEqual(
            {
                NET: {
                    "vni": 5042,
                    "ports": {"192.0.2.2": {tuple(FLOOD), tuple(VM_C)}},
                }
            },
            a._fdb,
        )
        self.assertTrue(a._dirty)

    def test_only_a_changed_table_marks_state_dirty(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        self.assertTrue(a._dirty)
        a._dirty = False
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        a.remove_fdb_entries(None, fdb({"192.0.2.3": [VM_C]}))
        a.update_fdb_entries(
            None, {"chg_ip": {NET: {"192.0.2.2": {"before": [VM_C], "after": [VM_B]}}}}
        )
        self.assertFalse(a._dirty)
        a.remove_fdb_entries(None, fdb({"192.0.2.2": [VM_B]}))
        self.assertTrue(a._dirty)

    def test_other_network_types_and_hosts_are_ignored(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}, network_type="vlan"))
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}), host="otherhost")
        self.assertEqual({}, a._fdb)

    def test_first_program_flushes_then_installs_both_entries_and_the_tables(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        vx = agent_mod.names.vxlan_if_name(5042)
        self.assertEqual(
            [
                ("flush", vx),
                ("add", vx, "fa:16:3e:00:00:0b", "192.0.2.2", 4789),
            ],
            a._fdb_ctl.calls,
        )
        self.assertEqual(
            [("pb1", "addr"), ("pb1", "static", vx, "fa:16:3e:00:00:0b")],
            a._run.calls,
        )
        self.assertEqual(
            {5042: (["192.0.2.2"], {"10.42.0.11": "fa:16:3e:00:00:0b"}, [])},
            a._relay.tables,
        )

    def test_first_program_clears_static_entries_left_on_the_uplink(self):
        a = vxlan_agent(self.tmp.name)
        vx = agent_mod.names.vxlan_if_name(5042)
        a._run.statics = {("fa:16:3e:00:00:0e", vx), ("fa:16:3e:00:00:0a", "tap1")}
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        self.assertEqual(
            [("pb1", "addr"), ("pb1", "deladdr", "fa:16:3e:00:00:0e")], a._run.calls
        )

    def test_bound_members_are_the_networks_local_addresses(self):
        a = vxlan_agent(self.tmp.name)
        member = {
            "tap1": {
                "type": "tap",
                "bind": {"mac": "fa:16:3e:00:00:0a", "addresses": ["10.42.0.10"]},
            }
        }
        a._program_vxlan(vxlan_config(member=member), agent_mod.plan_mod.Plan())
        self.assertEqual({5042: ([], {}, ["10.42.0.10"])}, a._relay.tables)

    def test_every_ipv4_address_of_a_member_is_local(self):
        a = vxlan_agent(self.tmp.name)
        bind = {"mac": "fa:16:3e:00:00:0a", "addresses": ["10.42.0.11", "10.42.0.10"]}
        member = {"tap1": {"type": "tap", "bind": bind}}
        a._program_vxlan(vxlan_config(member=member), agent_mod.plan_mod.Plan())
        self.assertEqual(
            {5042: ([], {}, ["10.42.0.10", "10.42.0.11"])}, a._relay.tables
        )

    def test_an_allowed_address_is_not_a_local_address(self):
        a = vxlan_agent(self.tmp.name)
        bind = {
            "mac": "fa:16:3e:00:00:0a",
            "addresses": ["10.42.0.10"],
            "allowed": ["10.42.0.0/24"],
        }
        member = {"tap1": {"type": "tap", "bind": bind}}
        a._program_vxlan(vxlan_config(member=member), agent_mod.plan_mod.Plan())
        self.assertEqual({5042: ([], {}, ["10.42.0.10"])}, a._relay.tables)

    def test_a_member_without_an_ipv4_address_is_not_a_local_address(self):
        a = vxlan_agent(self.tmp.name)
        member = {
            "tap1": {
                "type": "tap",
                "bind": {"mac": "fa:16:3e:00:00:0a", "addresses": ["10.42.0.10"]},
            },
            "tap2": {
                "type": "tap",
                "bind": {"mac": "fa:16:3e:00:00:0b", "addresses6": ["2001:db8::b"]},
            },
        }
        a._program_vxlan(vxlan_config(member=member), agent_mod.plan_mod.Plan())
        self.assertEqual({5042: ([], {}, ["10.42.0.10"])}, a._relay.tables)

    def test_reprogramming_applies_only_the_difference(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        a._fdb_ctl.calls.clear()
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        self.assertEqual([], a._fdb_ctl.calls)
        a.remove_fdb_entries(None, fdb({"192.0.2.2": [VM_B]}))
        a.add_fdb_entries(None, fdb({"192.0.2.3": [FLOOD, VM_C]}))
        a._run.calls.clear()
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        vx = agent_mod.names.vxlan_if_name(5042)
        self.assertEqual(
            [
                ("remove", vx, "fa:16:3e:00:00:0b"),
                ("add", vx, "fa:16:3e:00:00:0c", "192.0.2.3", 4789),
            ],
            a._fdb_ctl.calls,
        )
        self.assertEqual(
            [
                ("pb1", "addr"),
                ("pb1", "deladdr", "fa:16:3e:00:00:0b"),
                ("pb1", "static", vx, "fa:16:3e:00:00:0c"),
            ],
            a._run.calls,
        )

    def test_a_mac_locked_to_a_local_port_keeps_its_bridge_entry(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        a._run.statics = {("fa:16:3e:00:00:0b", "tap1")}
        a._run.calls.clear()
        a.remove_fdb_entries(None, fdb({"192.0.2.2": [VM_B]}))
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        self.assertEqual([("pb1", "addr")], a._run.calls)

    def test_recreated_interface_is_flushed_and_refilled(self):
        a = vxlan_agent(self.tmp.name)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        a._fdb_ctl.calls.clear()
        vx = agent_mod.names.vxlan_if_name(5042)
        recreate = agent_mod.plan_mod.Plan()
        recreate.creates.append(
            agent_mod.plan_mod.CreateVxlan(
                name=vx, vni=5042, local="192.0.2.1", port=4789, remote_port=1, ttl=64
            )
        )
        a._program_vxlan(vxlan_config(), recreate)
        self.assertEqual(
            [("flush", vx), ("add", vx, "fa:16:3e:00:00:0b", "192.0.2.2", 4789)],
            a._fdb_ctl.calls,
        )

    def test_failure_raises_and_forces_a_flush_next_pass(self):
        a = vxlan_agent(self.tmp.name, ctl=FakeFdbCtl(fail="add"))
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD, VM_B]}))
        self.assertRaises(
            agent_mod.ReconcileError,
            a._program_vxlan,
            vxlan_config(),
            agent_mod.plan_mod.Plan(),
        )
        self.assertEqual({}, a._installed)

    def test_departed_vni_is_forgotten(self):
        a = vxlan_agent(self.tmp.name)
        a._program_vxlan(vxlan_config(), agent_mod.plan_mod.Plan())
        a._program_vxlan(vxlan_config(vni=6000), agent_mod.plan_mod.Plan())
        self.assertEqual([agent_mod.names.vxlan_if_name(6000)], list(a._installed))

    def test_sync_asks_the_relay_for_the_ports_before_building(self):
        a = vxlan_agent(self.tmp.name)
        a.plugin_rpc.devices = {PORT_ID}

        def vxlan_details(port_id):
            d = details_for(port_id)
            d.update(network_type="vxlan", segmentation_id=5042, mtu=1450)
            return d

        a.plugin_rpc.get_devices_details_list_and_failed_devices = (
            lambda ctx, devs, agent_id, host=None: {
                "devices": [vxlan_details(d) for d in devs],
                "failed_devices": [],
            }
        )
        a._candidates = {PORT_ID}
        a._sync()
        self.assertEqual([5042], a._relay.wanted)
        self.assertEqual([5042], list(a._relay.tables))
        self.assertEqual([PORT_ID], a.plugin_rpc.ups)

    def test_first_report_asks_for_a_tunnel_refresh(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        a.port_update(None, port={"id": PORT_ID})
        a._sync()
        self.assertEqual([True, False], a.plugin_rpc.refreshes)


class FakePfTable:
    """pfctl with one main ruleset table."""

    def __init__(self, members=(), exists=True):
        self.members = set(members)
        self.exists = exists
        self.writes = []

    def __call__(self, argv):
        assert argv[:4] == (PFCTL, "-t", "l2-neutron-vtep", "-T"), argv
        if not self.exists:
            return 255, "", "pfctl: Table does not exist.\n"
        if argv[4] == "show":
            return 0, "".join(f"   {m}\n" for m in sorted(self.members)), ""
        self.writes.append(argv[4:])
        self.members = set(argv[5:])
        return 0, "", ""


class EndpointTableTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def agent(self, table, settled=True):
        a = vxlan_agent(self.tmp.name)
        a._run = table
        if settled:
            a._fdb_asked = time.monotonic() - agent_mod.FDB_SETTLE
        return a

    def test_remote_endpoints_of_every_network_fill_the_table(self):
        table = FakePfTable()
        a = self.agent(table)
        a.add_fdb_entries(
            None,
            {
                NET: {
                    "segment_id": 5042,
                    "network_type": "vxlan",
                    "ports": {"192.0.2.1": [FLOOD], "192.0.2.2": [FLOOD, VM_B]},
                },
                "other-net": {
                    "segment_id": 6000,
                    "network_type": "vxlan",
                    "ports": {"192.0.2.3": [FLOOD]},
                },
            },
        )
        a._sync_endpoints()
        self.assertEqual([("replace", "192.0.2.2", "192.0.2.3")], table.writes)

    def test_an_unchanged_table_is_left_alone(self):
        table = FakePfTable({"192.0.2.2"})
        a = self.agent(table)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}))
        a._sync_endpoints()
        self.assertEqual([], table.writes)

    def test_a_departed_endpoint_leaves_the_table(self):
        table = FakePfTable({"192.0.2.2", "192.0.2.3"})
        a = self.agent(table)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}))
        a._sync_endpoints()
        self.assertEqual([("replace", "192.0.2.2")], table.writes)

    def test_the_last_endpoint_leaving_flushes_the_table(self):
        table = FakePfTable({"192.0.2.2"})
        a = self.agent(table)
        a._sync_endpoints()
        self.assertEqual([("flush",)], table.writes)

    def test_a_restarted_agent_keeps_the_members_it_found(self):
        table = FakePfTable({"192.0.2.2", "192.0.2.3"})
        a = self.agent(table, settled=False)
        a._sync_endpoints()
        self.assertEqual([], table.writes)
        a.add_fdb_entries(None, fdb({"192.0.2.4": [FLOOD]}))
        a._sync_endpoints()
        self.assertEqual({"192.0.2.2", "192.0.2.3", "192.0.2.4"}, table.members)

    def test_members_are_kept_until_the_tunnel_refresh_has_settled(self):
        table = FakePfTable({"192.0.2.3"})
        a = self.agent(table, settled=False)
        a._fdb_asked = time.monotonic()
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}))
        a._sync_endpoints()
        self.assertEqual({"192.0.2.2", "192.0.2.3"}, table.members)
        a._fdb_asked -= agent_mod.FDB_SETTLE
        a._sync_endpoints()
        self.assertEqual({"192.0.2.2"}, table.members)

    def test_a_missing_table_warns_once_and_writes_nothing(self):
        table = FakePfTable(exists=False)
        a = self.agent(table)
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}))
        with self.assertLogs(agent_mod.LOG.logger, "WARNING") as logs:
            a._sync_endpoints()
            a._sync_endpoints()
        self.assertEqual(1, len(logs.records))
        self.assertEqual([], table.writes)

    def test_a_failed_write_does_not_raise(self):
        table = FakePfTable()
        a = self.agent(table)
        a._run = lambda argv: (
            table(argv) if argv[4] == "show" else (1, "", "pfctl: denied\n")
        )
        a.add_fdb_entries(None, fdb({"192.0.2.2": [FLOOD]}))
        a._sync_endpoints()

    def test_the_first_tunnel_refresh_starts_the_settle_time(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})
        a._candidates = {PORT_ID}
        a._sync()
        self.assertIsNotNone(a._fdb_asked)


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

        def run(argv):
            if argv[-2:] == ("-g", "dhcp-neutron"):
                return 0, "dh3fb01977-a4e\n", ""
            if argv[-1] == "dh3fb01977-a4e":
                text = (
                    "dh3fb01977-a4e: flags=8843<UP> metric 0 mtu 1500\n"
                    "\tdescription: neutron port " + PORT_ID + "\n"
                    "\tgroups: epair dhcp-neutron\n"
                )
                return 0, text, ""
            return 1, "", ""

        a._run = run
        a._sync()
        self.assertIn(PORT_ID, a._candidates)

    def test_router_if_description_feeds_the_candidate_set(self):
        a = make_agent(self.tmp.name, devices={PORT_ID})

        def run(argv):
            if argv[-2:] == ("-g", "l3-neutron"):
                return 0, "rt3fb01977-a4e\n", ""
            if argv[-1] == "rt3fb01977-a4e":
                text = (
                    "rt3fb01977-a4e: flags=8843<UP> metric 0 mtu 1500\n"
                    "\tdescription: neutron port " + PORT_ID + "\n"
                    "\tgroups: epair l3-neutron\n"
                )
                return 0, text, ""
            return 1, "", ""

        a._run = run
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

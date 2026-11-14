"""l3 agent tests."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_bsdbridge.l3_agent import agent as l3_agent_mod
except ImportError:
    raise unittest.SkipTest("needs neutron libs; run under the neutron venv")

from neutron_bsdbridge import jail  # noqa: E402
from neutron_bsdbridge.utils import Receipt  # noqa: E402
from tests.test_router import fip, rpc_router  # noqa: E402

HOST = "testhost.example.org"


class FakePluginRpc:
    def __init__(self, routers):
        self.routers = routers
        self.statuses = []

    def get_routers(self):
        return self.routers

    def update_floatingip_statuses(self, router_id, fip_statuses):
        self.statuses.append((router_id, dict(fip_statuses)))


class ReconcileRecorder:
    def __init__(self, receipts=()):
        self.calls = []
        self.receipts = list(receipts)

    def __call__(self, desired, base):
        self.calls.append(desired)
        return jail.Result(list(self.receipts))


def make_agent(routers, receipts=()):
    a = l3_agent_mod.BsdBridgeL3Agent.__new__(l3_agent_mod.BsdBridgeL3Agent)
    a.conf = types.SimpleNamespace(
        host=HOST,
        bsdbridge=types.SimpleNamespace(state_path="/nonexistent", sync_interval=30),
    )
    a.host = HOST
    a.plugin_rpc = FakePluginRpc(routers)
    a.context = None
    a._reconcile = ReconcileRecorder(receipts)
    a._dirty = True
    a._failures = 0
    a._fip_statuses = {}
    a._counts = {"routers": 0, "interfaces": 0, "floating_ips": 0}
    return a


class SyncTestCase(unittest.TestCase):
    def test_routers_become_specs_and_fips_report_active_once(self):
        body = rpc_router()
        a = make_agent([body])
        a._sync()
        (desired,) = a._reconcile.calls
        (spec,) = desired
        self.assertEqual(body["id"], spec.id)
        self.assertEqual([(body["id"], {fip()["id"]: "ACTIVE"})], a.plugin_rpc.statuses)
        a._sync()
        self.assertEqual(1, len(a.plugin_rpc.statuses), "unchanged status is quiet")
        self.assertEqual({"routers": 1, "interfaces": 2, "floating_ips": 1}, a._counts)

    def test_distributed_and_ha_routers_are_skipped(self):
        a = make_agent([rpc_router(distributed=True), rpc_router(ha=True)])
        a._sync()
        self.assertEqual([[]], a._reconcile.calls)
        self.assertEqual([], a.plugin_rpc.statuses)

    def test_last_fip_leaving_reports_an_empty_map_once(self):
        body = rpc_router()
        a = make_agent([body])
        a._sync()
        a.plugin_rpc.routers = [rpc_router(_floatingips=[])]
        a._sync()
        self.assertEqual((body["id"], {}), a.plugin_rpc.statuses[-1])
        a._sync()
        self.assertEqual(2, len(a.plugin_rpc.statuses))

    def test_fip_on_a_router_without_gateway_is_an_error(self):
        body = rpc_router(gw_port=None)
        a = make_agent([body])
        a._sync()
        self.assertEqual([(body["id"], {fip()["id"]: "ERROR"})], a.plugin_rpc.statuses)

    def test_failed_receipt_raises_before_any_report(self):
        failed = Receipt(op="LoadPf", argv=("pfctl",), executed=True, ok=False)
        a = make_agent([rpc_router()], receipts=[failed])
        with self.assertRaises(l3_agent_mod.ReconcileError):
            a._sync()
        self.assertEqual([], a.plugin_rpc.statuses)

    def test_state_report_carries_counts_and_drops_start_flag(self):
        a = make_agent([rpc_router()])
        sent = []
        a.state_rpc = types.SimpleNamespace(
            report_state=lambda ctx, state: sent.append(dict(state))
        )
        a.agent_state = {"configurations": {"agent_mode": "legacy"}, "start_flag": True}
        a._sync()
        a._report_state()
        a._report_state()
        self.assertEqual(2, len(sent))
        self.assertEqual(1, sent[0]["configurations"]["routers"])
        self.assertEqual(2, sent[0]["configurations"]["interfaces"])
        self.assertEqual("legacy", sent[0]["configurations"]["agent_mode"])
        self.assertNotIn("start_flag", sent[1])


class RpcEndpointTestCase(unittest.TestCase):
    def test_update_casts_mark_the_agent_dirty(self):
        casts = (
            ("routers_updated", {"routers": ["r1"]}),
            ("router_deleted", {"router_id": "r1"}),
            ("router_added_to_agent", {"payload": ["r1"]}),
            ("router_removed_from_agent", {"payload": {"router_id": "r1"}}),
            ("network_update", {"network": {"id": "n1"}}),
            ("agent_updated", {"payload": {"admin_state_up": True}}),
        )
        for method, kwargs in casts:
            a = make_agent([])
            a._dirty = False
            getattr(a, method)(None, **kwargs)
            self.assertTrue(a._dirty, method)

    def test_distributed_router_casts_are_ignored(self):
        arp = {"router_id": "r1", "arp_table": {"ip_address": "10.0.0.5"}}
        casts = (
            ("fipnamespace_delete_on_ext_net", {"ext_net_id": "ext"}),
            ("add_arp_entry", {"payload": arp}),
            ("del_arp_entry", {"payload": arp}),
        )
        for method, kwargs in casts:
            a = make_agent([])
            a._dirty = False
            self.assertIsNone(getattr(a, method)(None, **kwargs))
            self.assertFalse(a._dirty, method)

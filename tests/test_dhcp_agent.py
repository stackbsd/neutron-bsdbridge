"""dhcp agent tests: port reconciliation, spec building, readiness."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from neutron_bsdbridge import dhcp_agent as dhcp_agent_mod
except ImportError:
    raise unittest.SkipTest("needs neutron libs; run under the neutron venv")

from neutron_bsdbridge import dhcp_reconcile, names  # noqa: E402

NET_ID = "590dc57a-8b5e-4b94-b743-74e7d9a1b792"
SUBNET_ID = "daa048b5-450c-4c4b-97a6-c5f5542289c4"
HOST = "testhost.example.org"
DEVICE_ID = names.dhcp_device_id(NET_ID, HOST)


def subnet(**kw):
    base = {
        "id": SUBNET_ID,
        "ip_version": 4,
        "cidr": "10.99.0.0/24",
        "gateway_ip": "10.99.0.1",
        "dns_nameservers": [],
        "enable_dhcp": True,
    }
    base.update(kw)
    return base


def dhcp_port(**kw):
    base = {
        "id": "dddd0000-1111-2222-3333-444455556666",
        "device_id": DEVICE_ID,
        "device_owner": "network:dhcp",
        "mac_address": "FA:16:3E:00:00:01",
        "fixed_ips": [{"subnet_id": SUBNET_ID, "ip_address": "10.99.0.2"}],
    }
    base.update(kw)
    return base


def vm_port(**kw):
    base = {
        "id": "aaaa0000-1111-2222-3333-444455556666",
        "device_id": "some-vm",
        "device_owner": "compute:nova",
        "mac_address": "fa:16:3e:aa:bb:01",
        "fixed_ips": [{"subnet_id": SUBNET_ID, "ip_address": "10.99.0.5"}],
    }
    base.update(kw)
    return base


def network(subnets=None, ports=None, **kw):
    base = {
        "id": NET_ID,
        "project_id": "proj",
        "admin_state_up": True,
        "subnets": [subnet()] if subnets is None else subnets,
        "ports": [] if ports is None else ports,
    }
    base.update(kw)
    return base


class FakePluginRpc:
    def __init__(self, networks):
        self.networks = networks
        self.created = []
        self.updated = []
        self.released = []
        self.ready = []

    def get_active_networks_info(self):
        return self.networks

    def create_dhcp_port(self, port):
        self.created.append(port)
        body = port["port"]
        return dhcp_port(
            device_id=body["device_id"],
            fixed_ips=[
                {"subnet_id": f["subnet_id"], "ip_address": "10.99.0.2"}
                for f in body["fixed_ips"]
            ],
        )

    def update_dhcp_port(self, port_id, port):
        self.updated.append((port_id, port))
        return dhcp_port(
            fixed_ips=[
                {"subnet_id": f["subnet_id"], "ip_address": "10.99.0.2"}
                for f in port["port"]["fixed_ips"]
            ]
        )

    def release_dhcp_port(self, network_id, device_id):
        self.released.append((network_id, device_id))

    def dhcp_ready_on_ports(self, port_ids):
        self.ready.append(list(port_ids))


class ReconcileRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, desired, base, dnsmasq_path=None):
        self.calls.append(desired)
        return dhcp_reconcile.Result([])


def make_agent(networks):
    a = dhcp_agent_mod.BsdBridgeDhcpAgent.__new__(dhcp_agent_mod.BsdBridgeDhcpAgent)
    a.conf = types.SimpleNamespace(
        host=HOST,
        bsdbridge=types.SimpleNamespace(
            state_path="/nonexistent",
            sync_interval=30,
            dnsmasq_path="/usr/local/sbin/dnsmasq",
        ),
    )
    a.host = HOST
    a.plugin_rpc = FakePluginRpc(networks)
    a.context = None
    a._reconcile = ReconcileRecorder()
    a._dirty = True
    a._failures = 0
    a._ready = set()
    a._network_count = 0
    return a


class DeviceIdTestCase(unittest.TestCase):
    def test_matches_neutrons_own_convention(self):
        # update_dhcp_port refuses any other device_id
        from neutron.common import utils as n_utils

        self.assertEqual(
            n_utils.get_dhcp_agent_device_id(NET_ID, HOST),
            names.dhcp_device_id(NET_ID, HOST),
        )


class SyncTestCase(unittest.TestCase):
    def test_missing_dhcp_port_is_created_and_spec_built(self):
        a = make_agent([network(ports=[vm_port()])])
        a._sync()
        self.assertEqual(1, len(a.plugin_rpc.created))
        body = a.plugin_rpc.created[0]["port"]
        self.assertEqual(DEVICE_ID, body["device_id"])
        self.assertEqual([{"subnet_id": SUBNET_ID}], body["fixed_ips"])
        (desired,) = a._reconcile.calls
        (spec,) = desired
        self.assertEqual(NET_ID, spec.network_id)
        self.assertEqual(
            "fa:16:3e:00:00:01", spec.mac, "the port MAC canonicalizes to lowercase"
        )
        self.assertEqual((("10.99.0.2", 24),), spec.ips)
        self.assertEqual(1, len(spec.hosts))
        self.assertEqual("10.99.0.5", spec.hosts[0].ip)

    def test_existing_port_is_reused_untouched(self):
        a = make_agent([network(ports=[dhcp_port(), vm_port()])])
        a._sync()
        self.assertEqual([], a.plugin_rpc.created)
        self.assertEqual([], a.plugin_rpc.updated)
        (spec,) = a._reconcile.calls[0]
        self.assertEqual(dhcp_port()["id"], spec.port_id)

    def test_dhcp_port_excluded_from_its_own_hosts_file(self):
        a = make_agent([network(ports=[dhcp_port(), vm_port()])])
        a._sync()
        (spec,) = a._reconcile.calls[0]
        self.assertEqual(["10.99.0.5"], [h.ip for h in spec.hosts])

    def test_subnet_mismatch_refits_the_port(self):
        stale = dhcp_port(
            fixed_ips=[{"subnet_id": "old-subnet", "ip_address": "10.98.0.2"}]
        )
        a = make_agent([network(ports=[stale])])
        a._sync()
        self.assertEqual(1, len(a.plugin_rpc.updated))
        port_id, body = a.plugin_rpc.updated[0]
        self.assertEqual(stale["id"], port_id)
        self.assertEqual([{"subnet_id": SUBNET_ID}], body["port"]["fixed_ips"])

    def test_no_dhcp_subnets_releases_the_port(self):
        a = make_agent([network(subnets=[], ports=[dhcp_port()])])
        a._sync()
        self.assertEqual([(NET_ID, DEVICE_ID)], a.plugin_rpc.released)
        self.assertEqual([[]], a._reconcile.calls, "the network reconciles to nothing")

    def test_ready_reported_once_per_port(self):
        a = make_agent([network(ports=[dhcp_port(), vm_port()])])
        a._sync()
        self.assertEqual(1, len(a.plugin_rpc.ready))
        self.assertEqual(
            sorted([dhcp_port()["id"], vm_port()["id"]]), a.plugin_rpc.ready[0]
        )
        a._sync()
        self.assertEqual(
            1, len(a.plugin_rpc.ready), "already-ready ports are not re-reported"
        )

    def test_ipv6_only_subnets_mean_no_service(self):
        v6 = subnet(id="v6sub", ip_version=6, cidr="fd00::/64")
        a = make_agent([network(subnets=[v6])])
        a._sync()
        self.assertEqual([], a.plugin_rpc.created)
        self.assertEqual([[]], a._reconcile.calls)

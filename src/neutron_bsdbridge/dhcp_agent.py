"""Dhcp agent running a dnsmasq per network in a VNET jail."""

# monkey-patch before anything imports threading or sockets, or the
# oslo hub never runs and no RPC is dispatched
import eventlet

eventlet.monkey_patch()

import sys
import threading
import time

import oslo_messaging
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_common_config
from neutron_lib import context as n_context
from neutron_lib import rpc as n_rpc
from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_log import log as logging

from neutron_bsdbridge import config as bsdbridge_config
from neutron_bsdbridge import constants, dhcp_reconcile, names
from neutron_bsdbridge import dnsmasq as dnsmasq_mod

LOG = logging.getLogger(__name__)

bsdbridge_config.register()


class ReconcileError(Exception):
    """A dhcp reconcile pass left failed receipts."""


class DhcpPluginApi:
    """Neutron dhcp RPC API used by the agent."""

    def __init__(self, host):
        """Prepare a client on the plugin topic."""
        self.host = host
        target = oslo_messaging.Target(topic=topics.PLUGIN, version="1.0")
        self.client = n_rpc.get_client(target)

    @property
    def context(self):
        """Return a fresh admin context."""
        return n_context.get_admin_context_without_session()

    def get_active_networks_info(self):
        """Fetch the networks scheduled to this host with their ports and subnets."""
        cctxt = self.client.prepare(version="1.1")
        return cctxt.call(
            self.context,
            "get_active_networks_info",
            host=self.host,
            enable_dhcp_filter=True,
        )

    def create_dhcp_port(self, port):
        """Create this host's dhcp port on a network."""
        cctxt = self.client.prepare(version="1.1")
        return cctxt.call(self.context, "create_dhcp_port", host=self.host, port=port)

    def update_dhcp_port(self, port_id, port):
        """Update this host's dhcp port."""
        cctxt = self.client.prepare(version="1.1")
        return cctxt.call(
            self.context, "update_dhcp_port", host=self.host, port_id=port_id, port=port
        )

    def release_dhcp_port(self, network_id, device_id):
        """Release this host's dhcp port on a network."""
        cctxt = self.client.prepare()
        return cctxt.call(
            self.context,
            "release_dhcp_port",
            host=self.host,
            network_id=network_id,
            device_id=device_id,
        )

    def dhcp_ready_on_ports(self, port_ids):
        """Report ports whose dhcp service is in place."""
        cctxt = self.client.prepare(version="1.5")
        return cctxt.call(self.context, "dhcp_ready_on_ports", port_ids=port_ids)


class BsdBridgeDhcpAgent:
    """bsdbridge dhcp agent."""

    # the server casts every *_end method at 1.0
    target = oslo_messaging.Target(version="1.0")

    def __init__(self, conf, plugin_rpc=None, reconcile=None):
        """Set up dhcp agent RPC."""
        self.conf = conf
        self.host = conf.host
        self.plugin_rpc = plugin_rpc or DhcpPluginApi(conf.host)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.context = n_context.get_admin_context_without_session()
        self._reconcile = reconcile or dhcp_reconcile.reconcile
        self._dirty = True
        self._failures = 0
        self._ready = set()
        self._network_count = 0
        self.agent_state = {
            "binary": constants.DHCP_AGENT_BINARY,
            "host": self.host,
            "topic": topics.DHCP_AGENT,
            "agent_type": constants.AGENT_TYPE_DHCP,
            "configurations": {"dhcp_driver": "dnsmasq (vnet jail)"},
            "start_flag": True,
        }

    def network_create_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def network_update_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def network_delete_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def subnet_create_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def subnet_update_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def subnet_delete_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def port_create_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def port_update_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def port_delete_end(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def agent_updated(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def _own_port(self, net):
        """Return this host's dhcp port on a network, or None."""
        device_id = names.dhcp_device_id(net["id"], self.host)
        for port in net.get("ports", []):
            if port.get("device_id") == device_id:
                return port
        return None

    def _ensure_port(self, net, v4_subnets):
        """Return this network's dhcp port, creating or refitting it."""
        wanted = sorted(s["id"] for s in v4_subnets)
        port = self._own_port(net)
        if port is None:
            LOG.info("creating dhcp port for network %s", net["id"])
            port = self.plugin_rpc.create_dhcp_port(
                {
                    "port": {
                        "name": "",
                        "admin_state_up": True,
                        "device_id": names.dhcp_device_id(net["id"], self.host),
                        "network_id": net["id"],
                        "tenant_id": net.get("project_id", ""),
                        "fixed_ips": [{"subnet_id": sid} for sid in wanted],
                    }
                }
            )
            if port is None:
                LOG.warning("no dhcp port for network %s; will retry", net["id"])
            return port
        have = sorted(
            {
                f["subnet_id"]
                for f in port.get("fixed_ips", [])
                if f["subnet_id"] in set(wanted)
            }
        )
        all_have = sorted({f["subnet_id"] for f in port.get("fixed_ips", [])})
        if have != wanted or all_have != wanted:
            LOG.info("refitting dhcp port %s to subnets %s", port["id"], wanted)
            updated = self.plugin_rpc.update_dhcp_port(
                port["id"],
                {
                    "port": {
                        "network_id": net["id"],
                        "fixed_ips": [{"subnet_id": sid} for sid in wanted],
                    }
                },
            )
            if updated is not None:
                port = updated
        return port

    def _spec_for(self, net, v4_subnets, port):
        """Build the DhcpNetwork spec one network reconciles to."""
        subnet_by_id = {s["id"]: s for s in v4_subnets}
        ips = []
        for fixed in port.get("fixed_ips", []):
            subnet = subnet_by_id.get(fixed["subnet_id"])
            if subnet is None:
                continue
            prefixlen = int(subnet["cidr"].split("/")[1])
            ips.append((fixed["ip_address"], prefixlen))
        hosts = []
        for other in net.get("ports", []):
            owner = other.get("device_owner") or ""
            if owner.startswith(constants.DEVICE_OWNER_DHCP):
                continue
            if not other.get("mac_address"):
                continue
            for fixed in other.get("fixed_ips", []):
                if fixed["subnet_id"] not in subnet_by_id:
                    continue
                if ":" in fixed["ip_address"]:
                    continue
                hosts.append(
                    dnsmasq_mod.HostEntry(
                        mac=other["mac_address"], ip=fixed["ip_address"]
                    )
                )
        subnets = tuple(
            dnsmasq_mod.Subnet(
                id=s["id"],
                cidr=s["cidr"],
                gateway_ip=s.get("gateway_ip"),
                dns=tuple(s.get("dns_nameservers") or ()),
            )
            for s in v4_subnets
        )
        return dnsmasq_mod.DhcpNetwork(
            network_id=net["id"],
            port_id=port["id"],
            mac=port["mac_address"].lower(),
            ips=tuple(ips),
            subnets=subnets,
            hosts=tuple(sorted(hosts, key=lambda h: (h.ip, h.mac))),
        )

    def _sync(self):
        """Fetch, ensure the dhcp ports, reconcile, and report one pass."""
        networks = self.plugin_rpc.get_active_networks_info()
        desired = []
        ready = set()
        for net in networks:
            v4 = [s for s in net.get("subnets", []) if s.get("ip_version") == 4]
            if not v4 or not net.get("admin_state_up", True):
                if self._own_port(net) is not None:
                    LOG.info("releasing dhcp port on %s", net["id"])
                    self.plugin_rpc.release_dhcp_port(
                        net["id"], names.dhcp_device_id(net["id"], self.host)
                    )
                continue
            port = self._ensure_port(net, v4)
            if port is None:
                continue
            desired.append(self._spec_for(net, v4, port))
            v4_ids = {s["id"] for s in v4}
            ready |= {
                p["id"]
                for p in net.get("ports", [])
                if any(f["subnet_id"] in v4_ids for f in p.get("fixed_ips", []))
            }

        result = self._reconcile(
            desired,
            self.conf.bsdbridge.state_path,
            dnsmasq_path=self.conf.bsdbridge.dnsmasq_path,
        )
        if result.changed:
            LOG.info(
                "reconciled %d receipt(s) for %d network(s)",
                len(result.receipts),
                len(desired),
            )
            for receipt in result.receipts:
                LOG.info("  %s", receipt)
        if result.failed:
            raise ReconcileError(
                "%d action(s) failed, first: %s"
                % (len(result.failed), result.failed[0])
            )
        self._network_count = len(desired)

        newly_ready = ready - self._ready
        if newly_ready:
            self.plugin_rpc.dhcp_ready_on_ports(sorted(newly_ready))
            LOG.info("%d port(s) reported dhcp-ready", len(newly_ready))
        self._ready = ready

    def sync_if_needed(self, force=False):
        """Run a sync when dirty or forced, backing off on failure."""
        if not (self._dirty or force):
            return
        self._dirty = False
        try:
            self._sync()
            self._failures = 0
        except ReconcileError as err:
            LOG.error("%s (will retry)", err)
            self._retry()
        except oslo_messaging.MessagingException as err:
            LOG.error("%s (rpc failure, will retry)", err)
            self._retry()
        except Exception:
            LOG.exception("sync failed (will retry)")
            self._retry()

    def _retry(self):
        """Mark dirty and back off exponentially."""
        self._dirty = True
        self._failures += 1
        time.sleep(min(30, 2 ** min(self._failures, 5)))

    def _report_state(self):
        """Send the agent state report to the server."""
        try:
            self.agent_state["configurations"]["networks"] = self._network_count
            self.state_rpc.report_state(self.context, self.agent_state)
            self.agent_state.pop("start_flag", None)
        except Exception:
            LOG.exception("state report failed")

    def run(self):
        """Start the agent main loop."""

        def report_loop():
            """Report state every 30 seconds."""
            while True:
                self._report_state()
                time.sleep(30)

        threading.Thread(target=report_loop, daemon=True).start()

        # one consumer hears both the host-directed and the fanout casts
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(topics.DHCP_AGENT, [self], fanout=False)
        self.conn.consume_in_threads()

        LOG.info("started on %s (state %s)", self.host, self.conf.bsdbridge.state_path)
        interval = self.conf.bsdbridge.sync_interval
        last_full = 0.0
        while True:
            force = (time.time() - last_full) >= interval
            if force:
                last_full = time.time()
            self.sync_if_needed(force=force)
            time.sleep(1)


def main():
    """Console entrypoint for the dhcp agent."""
    common_config.register_common_config_options()
    agent_common_config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent = BsdBridgeDhcpAgent(cfg.CONF)
    agent.run()


if __name__ == "__main__":
    sys.exit(main())

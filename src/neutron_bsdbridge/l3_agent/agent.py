"""L3 agent running each router in a VNET jail."""

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
from neutron_lib import constants as lib_constants
from neutron_lib import context as n_context
from neutron_lib import rpc as n_rpc
from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_log import log as logging

from neutron_bsdbridge import config as bsdbridge_config
from neutron_bsdbridge import constants
from neutron_bsdbridge.l3_agent import reconcile as reconcile_mod
from neutron_bsdbridge.l3_agent import router as router_mod

LOG = logging.getLogger(__name__)

bsdbridge_config.register()


class ReconcileError(Exception):
    """An l3 reconcile pass left failed receipts."""


class L3PluginApi:
    """Neutron l3 RPC API used by the agent."""

    def __init__(self, host):
        """Prepare a client on the l3 plugin topic."""
        self.host = host
        target = oslo_messaging.Target(topic=topics.L3PLUGIN, version="1.0")
        self.client = n_rpc.get_client(target)

    @property
    def context(self):
        """Return a fresh admin context."""
        return n_context.get_admin_context_without_session()

    def get_routers(self):
        """Fetch the routers scheduled to this host with their ports and fips."""
        # the server binds every router port to this host on the way out
        cctxt = self.client.prepare()
        return cctxt.call(self.context, "sync_routers", host=self.host, router_ids=None)

    def update_floatingip_statuses(self, router_id, fip_statuses):
        """Report the status of every floating ip on one router."""
        cctxt = self.client.prepare(version="1.1")
        return cctxt.call(
            self.context,
            "update_floatingip_statuses",
            router_id=router_id,
            fip_statuses=fip_statuses,
        )


class BsdBridgeL3Agent:
    """bsdbridge l3 agent."""

    # the server casts network_update at 1.4
    target = oslo_messaging.Target(version="1.4")

    def __init__(self, conf, plugin_rpc=None, reconcile=None):
        """Set up l3 agent RPC."""
        self.conf = conf
        self.host = conf.host
        self.plugin_rpc = plugin_rpc or L3PluginApi(conf.host)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.context = n_context.get_admin_context_without_session()
        self._reconcile = reconcile or reconcile_mod.reconcile
        self._dirty = True
        self._failures = 0
        self._fip_statuses = {}
        self._counts = {"routers": 0, "interfaces": 0, "floating_ips": 0}
        self.agent_state = {
            "binary": constants.L3_AGENT_BINARY,
            "host": self.host,
            "availability_zone": conf.AGENT.availability_zone,
            "topic": topics.L3_AGENT,
            "agent_type": constants.AGENT_TYPE_L3,
            "configurations": {
                lib_constants.L3_AGENT_MODE: lib_constants.L3_AGENT_MODE_LEGACY,
                "handle_internal_only_routers": True,
                "interface_driver": "epair (vnet jail)",
            },
            "start_flag": True,
        }

    def routers_updated(self, context, routers=None):
        """Mark state dirty."""
        self._dirty = True

    def router_deleted(self, context, router_id=None):
        """Mark state dirty."""
        self._dirty = True

    def router_added_to_agent(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def router_removed_from_agent(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def network_update(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def agent_updated(self, context, payload=None):
        """Mark state dirty."""
        self._dirty = True

    def _sync(self):
        """Fetch, reconcile, and report one pass."""
        desired = []
        fip_statuses = {}
        for body in self.plugin_rpc.get_routers():
            if body.get("distributed") or body.get("ha"):
                LOG.warning(
                    "skipping router %s: distributed and ha routers are unsupported",
                    body["id"],
                )
                continue
            spec = router_mod.from_rpc(body)
            desired.append(spec)
            status = (
                lib_constants.FLOATINGIP_STATUS_ACTIVE
                if spec.gateway is not None
                else lib_constants.FLOATINGIP_STATUS_ERROR
            )
            fip_statuses[spec.id] = {fip.id: status for fip in spec.floating_ips}

        result = self._reconcile(desired, self.conf.bsdbridge.state_path)
        if result.changed:
            LOG.info(
                "reconciled %d receipt(s) for %d router(s)",
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
        self._counts = {
            "routers": len(desired),
            "interfaces": sum(len(spec.ports) for spec in desired),
            "floating_ips": sum(len(spec.floating_ips) for spec in desired),
        }

        # the server marks any fip left out of a router's report DOWN, so a
        # router whose last fip went away reports an empty map once
        for router_id, statuses in fip_statuses.items():
            if self._fip_statuses.get(router_id, {}) != statuses:
                self.plugin_rpc.update_floatingip_statuses(router_id, statuses)
                LOG.info("%d fip status(es) reported for %s", len(statuses), router_id)
        self._fip_statuses = fip_statuses

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
            self.agent_state["configurations"].update(self._counts)
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
        self.conn.create_consumer(topics.L3_AGENT, [self], fanout=False)
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
    """Console entrypoint for the l3 agent."""
    common_config.register_common_config_options()
    agent_common_config.register_agent_state_opts_helper(cfg.CONF)
    agent_common_config.register_availability_zone_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent = BsdBridgeL3Agent(cfg.CONF)
    agent.run()


if __name__ == "__main__":
    sys.exit(main())

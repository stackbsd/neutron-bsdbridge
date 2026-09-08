"""bsdbridge L2 agent."""

# monkey-patch before anything imports threading or sockets, or the
# oslo hub never runs and no RPC is dispatched
import eventlet

eventlet.monkey_patch()

import json
import os
import socket
import sys
import threading
import time

import oslo_messaging
from neutron.agent import rpc as agent_rpc
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_common_config
from neutron_lib import context as n_context
from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_log import log as logging

from neutron_bsdbridge import config as bsdbridge_config
from neutron_bsdbridge import constants, desired, ifconfig, names
from neutron_bsdbridge import reconcile as reconcile_mod
from neutron_bsdbridge import writer as writer_mod
from neutron_bsdbridge.utils import default_runner

LOG = logging.getLogger(__name__)

bsdbridge_config.register()

# an unresolved candidate retries at loop speed, then on full syncs, then drops
FAST_RETRY_MISSES = 10
BINDING_MISS_LIMIT = 60


class ReconcileError(Exception):
    """A reconcile pass left failed receipts."""


class BsdBridgeAgent:
    """bsdbridge L2 agent main class."""

    # need binding_activate at 1.5
    target = oslo_messaging.Target(version="1.5")

    def __init__(self, conf, writer=None, reader=None, runner=None):
        """Set up agent RPC and recover port candidates."""
        self.conf = conf
        self.host = conf.host
        self.agent_id = "bsdbridge-%s" % self.host
        self.context = n_context.get_admin_context_without_session()
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self._writer = writer or writer_mod.Writer(dry_run=False)
        self._reader = reader
        self._runner = runner or default_runner
        self._dirty = True
        self._failures = 0
        self._devices_up = set()
        self._misses = {}
        self._candidates = set(self._recover_devices())
        self.agent_state = {
            "binary": constants.AGENT_BINARY,
            "host": self.host,
            "topic": "N/A",
            "agent_type": constants.AGENT_TYPE_BSDBRIDGE,
            "configurations": {
                "physical_interface_mappings": dict(
                    conf.bsdbridge.physical_interface_mappings
                ),
            },
            "start_flag": True,
        }

    def _save_devices(self, devices):
        """Persist the synced port set for boot-time recovery."""
        path = os.path.join(self.conf.bsdbridge.state_path, "devices.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"devices": sorted(devices)}, f, indent=1)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, path)

    def _devices_from_state(self):
        """Read the durable device set."""
        path = os.path.join(self.conf.bsdbridge.state_path, "devices.json")
        try:
            with open(path) as f:
                return [str(d) for d in json.load(f).get("devices", [])]
        except (OSError, ValueError):
            return []

    def _devices_from_kernel(self):
        """Recover port uuids from tap interface descriptions."""
        reader = self._reader or ifconfig.read_interfaces
        try:
            kernel = reader([])
        except Exception:
            LOG.exception("kernel scan failed")
            return []
        out = []
        for iface in kernel.interfaces.values():
            if iface.is_owned and iface.description.startswith(
                constants.DESCRIPTION_PREFIX
            ):
                out.append(iface.description[len(constants.DESCRIPTION_PREFIX) :])
        return out

    def _devices_from_dhcp_ifs(self):
        """Discover dhcp ports from the dhcp agent's epairs on this host."""
        # no port_update fanout announces a dhcp port; the epair is the announcement
        scan = ifconfig.scan_group(constants.DHCP_GROUP, self._runner)
        return {
            iface.description[len(constants.DESCRIPTION_PREFIX) :]
            for iface in scan.values()
            if iface.description.startswith(constants.DESCRIPTION_PREFIX)
        }

    def _recover_devices(self):
        """Return the cold-start candidates from the device file and the kernel."""
        return (
            set(self._devices_from_state())
            | set(self._devices_from_kernel())
            | self._devices_from_dhcp_ifs()
        )

    def port_update(self, context, **kwargs):
        """Track the port and mark state dirty."""
        port = kwargs.get("port") or {}
        LOG.info("rpc port_update %s", port.get("id"))
        if port.get("id"):
            self._candidates.add(port["id"])
        self._dirty = True

    def port_delete(self, context, **kwargs):
        """Drop the port and mark state dirty."""
        port_id = kwargs.get("port_id")
        if port_id:
            self._candidates.discard(port_id)
            self._misses.pop(port_id, None)
        self._dirty = True

    def network_update(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def security_groups_rule_updated(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def security_groups_member_updated(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def binding_deactivate(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def binding_activate(self, context, **kwargs):
        """Track the port and mark state dirty."""
        port_id = kwargs.get("port_id")
        if port_id:
            self._candidates.add(port_id)
        self._dirty = True

    def _sync(self):
        """Fetch, build, reconcile, and report one pass."""
        self._candidates |= self._devices_from_dhcp_ifs()
        devices = sorted(self._candidates)
        details = []
        pending = set()

        def miss(device):
            """Count a miss for a candidate, dropping it at the limit."""
            if device is None:
                return
            count = self._misses.get(device, 0) + 1
            if count == 1:
                LOG.info("%s not resolvable yet; retrying", device)
            if count >= BINDING_MISS_LIMIT:
                LOG.warning("giving up on %s after %d attempts", device, count)
                self._candidates.discard(device)
                self._misses.pop(device, None)
            else:
                self._misses[device] = count
                pending.add(device)

        # an entry without a port_id is a bind still in flight
        if devices:
            result = self.plugin_rpc.get_devices_details_list_and_failed_devices(
                self.context, devices, self.agent_id, host=self.host
            )
            for entry in result.get("devices", []):
                if entry.get("port_id"):
                    details.append(entry)
                    self._misses.pop(entry["port_id"], None)
                else:
                    miss(entry.get("device"))
            for device in result.get("failed_devices", []):
                miss(device)
        our_devices = [d["port_id"] for d in details]
        sg_info = {}
        if our_devices:
            sg_info = self.sg_plugin_rpc.security_group_info_for_devices(
                self.context, devices=our_devices
            )

        # build and reconcile
        config, rendered_devices = desired.build(
            details, sg_info, self.conf.bsdbridge.physical_interface_mappings
        )
        result = reconcile_mod.reconcile(
            config, writer=self._writer, reader=self._reader, runner=self._runner
        )
        if result.plan.ops:
            LOG.info(
                "reconciled %d op(s) for %d port(s)",
                len(result.plan.ops),
                len(rendered_devices),
            )
            for receipt in result.receipts:
                LOG.info("  %s", receipt)
        for note in result.plan.notes:
            LOG.info("  note: %s", note)
        if result.failed:
            raise ReconcileError(
                "%d op(s) failed, first: %s" % (len(result.failed), result.failed[0])
            )

        self._save_devices(our_devices)

        # a member still awaiting-attach is not up
        waiting = {
            note.split(":", 1)[0]
            for note in result.plan.notes
            if "awaiting-attach" in note
        }
        now_up = {
            device
            for device in rendered_devices
            if names.tap_name(device) not in waiting
            and names.dhcp_if_name(device) not in waiting
        }
        for device in sorted(now_up - self._devices_up):
            LOG.info("%s reported up", device)
        down = sorted(self._devices_up - now_up)
        for device in down:
            LOG.info("%s reported down", device)

        # report every up device every pass since neutron server resets
        # a port back to BUILD each time details are fetched
        if now_up or down:
            self.plugin_rpc.update_device_list(
                self.context, sorted(now_up), down, self.agent_id, self.host
            )
        self._devices_up = now_up

        # keep candidates that arrived while the RPC calls above yielded,
        # or a port announced mid-sync is silently orphaned
        unseen = self._candidates - set(devices)
        self._candidates = (
            set(our_devices) | (self._candidates & now_up) | pending | unseen
        )
        if any(self._misses.get(device, 0) <= FAST_RETRY_MISSES for device in pending):
            self._dirty = True

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

    @staticmethod
    def is_ifnet_event(line):
        """Return whether a devd line is an IFNET attach or detach event."""
        return line.startswith("!system=IFNET") and (
            "type=ATTACH" in line or "type=DETACH" in line
        )

    def _devd_loop(self):
        """Mark state dirty on every devd IFNET event."""
        pipe = self.conf.bsdbridge.devd_pipe
        while True:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                sock.connect(pipe)
                LOG.info("listening to devd at %s", pipe)
                while True:
                    data = sock.recv(8192)
                    if not data:
                        break
                    if self.is_ifnet_event(data.decode("utf-8", "replace")):
                        self._dirty = True
            except OSError as err:
                LOG.warning("devd unavailable (%s); retrying", err)
            time.sleep(5)

    def _report_state(self):
        """Send the agent state report to the server."""
        try:
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
        if self.conf.bsdbridge.devd_pipe:
            threading.Thread(target=self._devd_loop, daemon=True).start()

        consumers = [
            [topics.PORT, topics.UPDATE],
            [topics.PORT, topics.DELETE],
            [topics.NETWORK, topics.UPDATE],
            [topics.SECURITY_GROUP, topics.UPDATE],
            [topics.PORT_BINDING, topics.DEACTIVATE],
            [topics.PORT_BINDING, topics.ACTIVATE],
        ]
        self.connection = agent_rpc.create_consumers(
            [self], topics.AGENT, consumers, start_listening=True
        )

        LOG.info(
            "started on %s (%d recovered device(s), mappings %s)",
            self.host,
            len(self._candidates),
            dict(self.conf.bsdbridge.physical_interface_mappings),
        )
        interval = self.conf.bsdbridge.sync_interval
        last_full = 0.0
        while True:
            force = (time.time() - last_full) >= interval
            if force:
                last_full = time.time()
            self.sync_if_needed(force=force)
            time.sleep(1)


def main():
    """Console entrypoint for the l2 agent."""
    common_config.register_common_config_options()
    agent_common_config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent = BsdBridgeAgent(cfg.CONF)
    agent.run()


if __name__ == "__main__":
    sys.exit(main())

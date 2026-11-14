"""bsdbridge L2 agent."""

# monkey-patch before anything imports threading or sockets, or the
# oslo hub never runs and no RPC is dispatched
import eventlet

eventlet.monkey_patch()

import contextlib
import copy
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
from neutron.conf import service as service_config
from neutron.conf.agent import common as agent_common_config
from neutron_lib import constants as lib_constants
from neutron_lib import context as n_context
from neutron_lib.agent import constants as agent_consts
from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_log import log as logging

from neutron_bsdbridge import config as bsdbridge_config
from neutron_bsdbridge import constants, ifconfig, names
from neutron_bsdbridge.l2_agent import pf, port_config, relay_client
from neutron_bsdbridge.l2_agent import plan as plan_mod
from neutron_bsdbridge.l2_agent import reconcile as reconcile_mod
from neutron_bsdbridge.l2_agent import vxlan as vxlan_mod
from neutron_bsdbridge.l2_agent import writer as writer_mod
from neutron_bsdbridge.utils import default_run

LOG = logging.getLogger(__name__)

bsdbridge_config.register()

# an unresolved candidate retries at loop speed, then on full syncs, then drops
FAST_RETRY_MISSES = 10
BINDING_MISS_LIMIT = 60
# seconds the server is given to answer a tunnel refresh
FDB_SETTLE = 60


def vxlan_conf(conf, run=default_run):
    """Return the resolved vxlan settings."""
    vx = conf.vxlan
    if not vx.local_ip:
        return None
    if ifconfig.owner_of(vx.local_ip, run) is None:
        raise ValueError(
            f"vxlan local_ip {vx.local_ip} is not assigned to any interface. "
            "Assign it to the underlay interface or correct local_ip."
        )
    return {
        "local": str(vx.local_ip),
        "port": vx.udp_port,
        "ttl": vx.ttl,
        "rate": vx.relay_rate,
    }


def configurations(conf, vxlan):
    """Return the configurations the agent reports to the server."""
    out = {
        "physical_interface_mappings": dict(conf.bsdbridge.physical_interface_mappings)
    }
    if vxlan is not None:
        out["tunnel_types"] = ["vxlan"]
        out["tunneling_ip"] = vxlan["local"]
        out["l2_population"] = True
    return out


def scan_relay_ports(run=default_run):
    """Return the loopback port every existing vxlan interface sends to."""
    return {
        iface.vni: iface.vxlan_remote_port
        for iface in ifconfig.scan_group(constants.OWNED_GROUP, run).values()
        if iface.vni is not None and iface.vxlan_remote == constants.RELAY_ADDR
    }


def fdb_tables(ports, local):
    """Return one VNI's forwarding entries, flood peers and ARP table."""
    entries = {}
    peers = set()
    arp = {}
    for agent_ip, infos in ports.items():
        if agent_ip == local:
            continue
        for mac, ip in infos:
            if (mac, ip) == tuple(lib_constants.FLOODING_ENTRY):
                peers.add(agent_ip)
                continue
            entries[mac] = agent_ip
            if ip and ":" not in ip:
                arp[ip] = mac
    return entries, sorted(peers), arp


class ReconcileError(Exception):
    """A reconcile pass left failed receipts."""


class BsdBridgeAgent:
    """bsdbridge L2 agent main class."""

    # need binding_activate at 1.5
    target = oslo_messaging.Target(version="1.5")

    def __init__(self, conf, writer=None, reader=None, run=None):
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
        self._run = run or default_run
        self._vxlan = vxlan_conf(conf, self._run)
        self._fdb = {}
        self._fdb_lock = threading.Lock()
        self._installed = {}
        self._fdb_ctl = vxlan_mod
        self._relay = None
        if self._vxlan is not None:
            self._relay = relay_client.RelayClient(
                constants.RELAY_SOCKET,
                self._vxlan["local"],
                self._vxlan["port"],
                self._vxlan["rate"],
                ports=scan_relay_ports(self._run),
            )
        # ask l2pop for every forwarding entry on the first report
        self._refresh_tunnels = True
        self._fdb_asked = None
        self._vtep_warned = False
        self._dirty = True
        self._failures = 0
        self._devices_up = set()
        self._misses = {}
        self._candidates = set(self._recover_devices())
        self._details = {}
        self._stale = set()
        self._unreported = set()
        self.agent_state = {
            "binary": constants.AGENT_BINARY,
            "host": self.host,
            "availability_zone": conf.AGENT.availability_zone,
            "topic": "N/A",
            "agent_type": constants.AGENT_TYPE_BSDBRIDGE,
            "configurations": configurations(conf, self._vxlan),
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

    def _devices_from_service_ifs(self):
        """Discover dhcp and router ports from the other agents' epairs."""
        # no port_update fanout announces a service port; the epair is
        # the announcement
        found = set()
        for group in constants.SERVICE_GROUPS:
            for iface in ifconfig.scan_group(group, self._run).values():
                if iface.description.startswith(constants.DESCRIPTION_PREFIX):
                    found.add(iface.description[len(constants.DESCRIPTION_PREFIX) :])
        return found

    def _recover_devices(self):
        """Return the cold-start candidates from the device file and the kernel."""
        return (
            set(self._devices_from_state())
            | set(self._devices_from_kernel())
            | self._devices_from_service_ifs()
        )

    def port_update(self, context, **kwargs):
        """Track the port and mark state dirty."""
        port = kwargs.get("port") or {}
        LOG.info("rpc port_update %s", port.get("id"))
        if port.get("id"):
            self._candidates.add(port["id"])
            self._stale.add(port["id"])
        self._dirty = True

    def port_delete(self, context, **kwargs):
        """Drop the port and mark state dirty."""
        port_id = kwargs.get("port_id")
        if port_id:
            self._candidates.discard(port_id)
            self._misses.pop(port_id, None)
            self._details.pop(port_id, None)
        self._dirty = True

    def network_update(self, context, **kwargs):
        """Refetch every port and mark state dirty."""
        self._stale.update(self._details)
        self._dirty = True

    def security_groups_rule_updated(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def security_groups_member_updated(self, context, **kwargs):
        """Mark state dirty."""
        self._dirty = True

    def binding_deactivate(self, context, **kwargs):
        """Refetch the port and mark state dirty."""
        if kwargs.get("port_id"):
            self._stale.add(kwargs["port_id"])
        self._dirty = True

    def binding_activate(self, context, **kwargs):
        """Track the port and mark state dirty."""
        port_id = kwargs.get("port_id")
        if port_id:
            self._candidates.add(port_id)
            self._stale.add(port_id)
        self._dirty = True

    @contextlib.contextmanager
    def _fdb_edit(self):
        """Lock the l2pop table and mark state dirty if an edit changes it."""
        with self._fdb_lock:
            before = copy.deepcopy(self._fdb)
            yield
            # the server repeats entries whenever a port's status changes
            if self._fdb != before:
                self._dirty = True

    def add_fdb_entries(self, context, fdb_entries, host=None):
        """Merge l2pop forwarding entries."""
        if host and host != self.host:
            return
        with self._fdb_edit():
            for network_id, body in fdb_entries.items():
                if network_id == "chg_ip" or body.get("network_type") != "vxlan":
                    continue
                net = self._fdb.setdefault(
                    network_id, {"vni": body["segment_id"], "ports": {}}
                )
                for agent_ip, infos in body.get("ports", {}).items():
                    have = net["ports"].setdefault(agent_ip, set())
                    have.update(tuple(info) for info in infos)

    def remove_fdb_entries(self, context, fdb_entries, host=None):
        """Drop l2pop forwarding entries."""
        if host and host != self.host:
            return
        with self._fdb_edit():
            for network_id, body in fdb_entries.items():
                net = self._fdb.get(network_id)
                if net is None or network_id == "chg_ip":
                    continue
                for agent_ip, infos in body.get("ports", {}).items():
                    have = net["ports"].get(agent_ip, set())
                    have.difference_update(tuple(info) for info in infos)
                    if not have:
                        net["ports"].pop(agent_ip, None)
                if not net["ports"]:
                    del self._fdb[network_id]

    def update_fdb_entries(self, context, fdb_entries, host=None):
        """Apply l2pop address changes."""
        if host and host != self.host:
            return
        with self._fdb_edit():
            for network_id, agents in fdb_entries.get("chg_ip", {}).items():
                net = self._fdb.get(network_id)
                if net is None:
                    continue
                for agent_ip, change in agents.items():
                    have = net["ports"].setdefault(agent_ip, set())
                    have.difference_update(tuple(i) for i in change.get("before", []))
                    have.update(tuple(i) for i in change.get("after", []))

    def _bridge_entries(self, bridge):
        """Return a bridge's static entries as (mac, member) pairs."""
        _rc, text, _err = self._run((constants.IFCONFIG, bridge, "addr"))
        return {
            (mac, member)
            for mac, member, static in ifconfig.parse_addr_list(text)
            if static
        }

    def _bridge_static(self, bridge, member, mac, add):
        """Add or remove the static bridge entry steering a MAC to a member."""
        if add:
            argv = (constants.IFCONFIG, bridge, "static", member, mac)
        else:
            argv = (constants.IFCONFIG, bridge, "deladdr", mac)
        rc, _out, err = self._run(argv)
        if rc != 0:
            raise OSError(f"{' '.join(argv[1:])}: {err.strip()}")

    def _sync_endpoints(self):
        """Fill the pf table of remote tunnel endpoints from l2pop."""
        table = (constants.PFCTL, "-t", pf.VTEP_TABLE, "-T")
        rc, out, _err = self._run((*table, "show"))
        if rc != 0:
            if not self._vtep_warned:
                LOG.warning(
                    "pf table %s does not exist. Declare it in pf.conf to "
                    "accept vxlan only from known tunnel endpoints.",
                    pf.VTEP_TABLE,
                )
            self._vtep_warned = True
            return
        have = pf.parse_table_show(out)
        with self._fdb_lock:
            wanted = {ip for net in self._fdb.values() for ip in net["ports"]}
        wanted.discard(self._vxlan["local"])
        # a restarted agent would cut the tunnels the relay still serves
        if self._fdb_asked is None or time.monotonic() - self._fdb_asked < FDB_SETTLE:
            wanted |= have
        if wanted == have:
            return
        argv = (*table, "replace", *sorted(wanted)) if wanted else (*table, "flush")
        rc, _out, err = self._run(argv)
        if rc != 0:
            LOG.warning("%s: %s", " ".join(argv[1:]), err.strip())
            return
        LOG.info("tunnel endpoints now %s", ", ".join(sorted(wanted)) or "none")

    def _program_vxlan(self, config, the_plan):
        """Program the forwarding tables and the relay from l2pop."""
        with self._fdb_lock:
            by_vni = {
                net["vni"]: {ip: set(infos) for ip, infos in net["ports"].items()}
                for net in self._fdb.values()
            }
        recreated = {
            op.name for op in the_plan.ops if isinstance(op, plan_mod.CreateVxlan)
        }
        port = self._vxlan["port"]
        tables = {}
        failed = []
        wanted_ifs = set()
        for bname, bridge in sorted(config.bridge.items()):
            if bridge.segment is None or bridge.segment.vxlan is None:
                continue
            vni = bridge.segment.vxlan.vni
            ifname = names.vxlan_if_name(vni)
            wanted_ifs.add(ifname)
            wanted, peers, arp = fdb_tables(by_vni.get(vni, {}), self._vxlan["local"])
            installed = self._installed.get(ifname)
            try:
                # start from flushed tables as the kernel cannot list entries
                if installed is None or ifname in recreated:
                    self._fdb_ctl.flush(ifname)
                    for mac, member in sorted(self._bridge_entries(bname)):
                        if member == ifname:
                            self._bridge_static(bname, ifname, mac, add=False)
                    installed = {}
                stale = sorted(set(installed) - set(wanted))
                # a MAC that moved to a local port is locked there by now
                entries = self._bridge_entries(bname) if stale else set()
                for mac in stale:
                    self._fdb_ctl.remove_entry(ifname, mac)
                    if (mac, ifname) in entries:
                        self._bridge_static(bname, ifname, mac, add=False)
                    del installed[mac]
                for mac, ip in sorted(wanted.items()):
                    if installed.get(mac) != ip:
                        self._fdb_ctl.add_entry(ifname, mac, ip, port)
                        self._bridge_static(bname, ifname, mac, add=True)
                        installed[mac] = ip
            except OSError as exc:
                failed.append(f"{ifname}: {exc}")
                self._installed.pop(ifname, None)
                continue
            self._installed[ifname] = installed
            local = sorted(
                {
                    address
                    for m in bridge.member.values()
                    if m.bind
                    for address in m.bind.addresses
                }
            )
            tables[vni] = (peers, arp, local)
        for ifname in set(self._installed) - wanted_ifs:
            del self._installed[ifname]
        self._relay.update(tables)
        if failed:
            raise ReconcileError(
                "%d forwarding table(s) failed, first: %s" % (len(failed), failed[0])
            )

    def _sync(self):
        """Fetch, build, reconcile, and report one pass."""
        self._candidates |= self._devices_from_service_ifs()
        devices = sorted(self._candidates)
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

        # the server sets a port to BUILD whenever its details are fetched
        # a port updated during the fetch stays stale for the next pass
        stale = self._stale
        self._stale = set()
        wanted = [d for d in devices if d in stale or d not in self._details]
        # an entry without a port_id is a bind still in flight
        if wanted:
            try:
                result = self.plugin_rpc.get_devices_details_list_and_failed_devices(
                    self.context, wanted, self.agent_id, host=self.host
                )
            except Exception:
                self._stale.update(stale)
                raise
            self._unreported.update(wanted)
            for entry in result.get("devices", []):
                if entry.get("port_id"):
                    self._details[entry["port_id"]] = entry
                    self._misses.pop(entry["port_id"], None)
                else:
                    self._details.pop(entry.get("device"), None)
                    miss(entry.get("device"))
            for device in result.get("failed_devices", []):
                self._details.pop(device, None)
                miss(device)
        details = [self._details[d] for d in devices if d in self._details]
        our_devices = [d["port_id"] for d in details]
        sg_info = {}
        if our_devices:
            sg_info = self.sg_plugin_rpc.security_group_info_for_devices(
                self.context, devices=our_devices
            )

        # the uplink of a vxlan network sends to its relay socket
        relay_ports = None
        if self._vxlan is not None:
            vnis = {
                d["segmentation_id"]
                for d in details
                if d.get("network_type") == "vxlan"
            }
            relay_ports = self._relay.ports_for(sorted(vnis))
            self._sync_endpoints()

        # build and reconcile
        config, rendered_devices = port_config.build(
            details,
            sg_info,
            self.conf.bsdbridge.physical_interface_mappings,
            self._vxlan,
            relay_ports,
        )
        result = reconcile_mod.reconcile(
            config, writer=self._writer, reader=self._reader, run=self._run
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

        if self._vxlan is not None:
            self._program_vxlan(config, result.plan)

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
            and names.router_if_name(device) not in waiting
        }
        came_up = now_up - self._devices_up
        went_down = sorted(self._devices_up - now_up)
        for device in sorted(came_up):
            LOG.info("%s reported up", device)
        for device in went_down:
            LOG.info("%s reported down", device)

        # a fetched port waits in BUILD until it is reported up again
        report_up = sorted(now_up & (self._unreported | came_up))
        if report_up or went_down:
            self.plugin_rpc.update_device_list(
                self.context,
                report_up,
                went_down,
                self.agent_id,
                self.host,
                refresh_tunnels=self._refresh_tunnels,
            )
            if self._refresh_tunnels:
                self._fdb_asked = time.monotonic()
            self._refresh_tunnels = False
        self._devices_up = now_up

        # keep candidates that arrived while the RPC calls above yielded,
        # or a port announced mid-sync is silently orphaned
        unseen = self._candidates - set(devices)
        self._candidates = (
            set(our_devices) | (self._candidates & now_up) | pending | unseen
        )
        # forget ports that are gone and ports now reported
        for device in set(self._details) - self._candidates:
            del self._details[device]
        self._unreported = (self._unreported & self._candidates) - now_up
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
            if self._relay is not None:
                self.agent_state["configurations"]["vxlan_relay"] = self._relay.stats()
            status = self.state_rpc.report_state(self.context, self.agent_state, True)
            self.agent_state.pop("start_flag", None)
            # the server may have missed our reports and so may we its casts
            if status == agent_consts.AGENT_REVIVED:
                LOG.info("agent revived, refetching every port")
                self._stale.update(self._details)
                self._dirty = True
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
        if self._vxlan is not None:
            consumers.append([topics.L2POPULATION, topics.UPDATE, self.host])
        self.connection = agent_rpc.create_consumers(
            [self], topics.AGENT, consumers, start_listening=True
        )

        LOG.info(
            "started on %s (%d recovered device(s), mappings %s, vxlan %s)",
            self.host,
            len(self._candidates),
            dict(self.conf.bsdbridge.physical_interface_mappings),
            self._vxlan or "disabled",
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
    service_config.register_service_opts(service_config.RPC_EXTRA_OPTS, cfg.CONF)
    agent_common_config.register_agent_state_opts_helper(cfg.CONF)
    agent_common_config.register_availability_zone_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    agent = BsdBridgeAgent(cfg.CONF)
    agent.run()


if __name__ == "__main__":
    sys.exit(main())

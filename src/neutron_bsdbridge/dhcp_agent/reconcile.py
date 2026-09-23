"""Dhcp jails, epairs, files and dnsmasq config reconciler."""

import os
import re
import shutil

from neutron_bsdbridge import constants, jail
from neutron_bsdbridge.constants import JEXEC, KILL, PS
from neutron_bsdbridge.dhcp_agent import dnsmasq as dnsmasq_mod
from neutron_bsdbridge.utils import default_run, write_if_changed

JAIL_RE = re.compile(r"^qdhcp-[0-9a-f]{12}$")


def reconcile(desired, base, run=default_run, dnsmasq_path=constants.DNSMASQ):
    """Reconcile the dhcp plane to a list of DhcpNetwork specs."""
    acts = jail.Actions(run)
    jails = set(jail.list_jails(run, JAIL_RE))
    dhcp_ifs = set(jail.list_group(run, constants.DHCP_GROUP))

    for net in desired:
        # hosts and opts files
        directory = dnsmasq_mod.state_dir(base, net.network_id)
        os.makedirs(directory, exist_ok=True)
        dirty = write_if_changed(
            os.path.join(directory, "hosts"), dnsmasq_mod.hosts_text(net)
        )
        if dirty:
            acts.note("WriteHosts", f"{net.network_id}: {len(net.hosts)} entries")
        if write_if_changed(
            os.path.join(directory, "opts"), dnsmasq_mod.opts_text(net)
        ):
            dirty = True
            acts.note("WriteOpts", f"{net.network_id}: {len(net.subnets)} subnet(s)")

        # jail and epair
        if not jail.ensure_jail(acts, net.jail, jails):
            continue
        jail_if_text = jail.ensure_epair(
            acts,
            net.jail,
            net.dhcp_if,
            constants.DHCP_JAIL_IF,
            net.port_id,
            constants.DHCP_GROUP,
            dhcp_ifs,
        )
        if jail_if_text is None:
            continue
        jail.ensure_addrs(
            acts, net.jail, constants.DHCP_JAIL_IF, jail_if_text, net.mac, net.ips
        )

        # dnsmasq: restart on a changed argv, HUP on changed files
        wanted = dnsmasq_mod.argv(net, base, dnsmasq_path)
        cmd_path = os.path.join(directory, "cmd")
        try:
            with open(cmd_path) as f:
                stored = f.read()
        except OSError:
            stored = ""
        pid = None
        try:
            with open(os.path.join(directory, "pid")) as f:
                pid = int(f.read().strip())
        except (OSError, ValueError):
            pass
        alive = False
        if pid:
            rc, out, _err = run((PS, "-p", str(pid), "-o", "command="))
            alive = rc == 0 and "dnsmasq" in (out or "")
        if alive and stored != " ".join(wanted):
            acts.do("StopDnsmasq", (KILL, str(pid)))
            alive = False
        if not alive:
            write_if_changed(cmd_path, " ".join(wanted))
            acts.do("StartDnsmasq", (JEXEC, net.jail, *wanted))
        elif dirty:
            acts.do("ReloadDnsmasq", (KILL, "-HUP", str(pid)))

    # gc: processes, then epairs, then jails, then state directories
    jail.collect(
        acts,
        jails,
        {net.jail for net in desired},
        dhcp_ifs,
        {net.dhcp_if for net in desired},
    )
    desired_dirs = {net.network_id for net in desired}
    dhcp_base = os.path.join(base, "dhcp")
    try:
        stale = sorted(set(os.listdir(dhcp_base)) - desired_dirs)
    except OSError:
        stale = []
    for entry in stale:
        shutil.rmtree(os.path.join(dhcp_base, entry), ignore_errors=True)
        acts.note("RemoveState", entry)

    return acts.result()

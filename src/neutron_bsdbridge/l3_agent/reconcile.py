"""Router jails, epairs, addresses, routes and pf reconciler."""

import os
import re
import shutil

from neutron_bsdbridge import constants, jail
from neutron_bsdbridge.constants import PFCTL
from neutron_bsdbridge.jail import JEXEC
from neutron_bsdbridge.l3_agent import router as router_mod
from neutron_bsdbridge.utils import default_run, write_if_changed

SYSCTL = "/sbin/sysctl"
ROUTE = "/sbin/route"
NETSTAT = "/usr/bin/netstat"

FORWARDING = "net.inet.ip.forwarding"

JAIL_RE = re.compile(r"^qrouter-[0-9a-f]{12}$")
CFG_RE = re.compile(r'label "l3-neutron:cfg:(?P<hash>[0-9a-f]{16})"')
ROUTE_RE = re.compile(r"^(?P<dest>\S+)\s+(?P<gw>\d+\.\d+\.\d+\.\d+)\s+(?P<flags>\S+)")
PF_ENABLED_RE = re.compile(r"^Status: Enabled", re.M)


def parse_routes(text):
    """Parse netstat -rn -f inet output into the (destination, nexthop) set."""
    routes = set()
    for line in (text or "").splitlines():
        m = ROUTE_RE.match(line)
        if m is None or "G" not in m.group("flags"):
            continue
        routes.add((router_mod.normalize_destination(m.group("dest")), m.group("gw")))
    return routes


def route_arg(destination):
    """Return a destination as route(8) spells it."""
    return "default" if destination == router_mod.DEFAULT_ROUTE else destination


def reconcile(desired, base, run=default_run):
    """Reconcile the l3 plane to a list of Router specs."""
    acts = jail.Actions(run)
    jails = set(jail.list_jails(run, JAIL_RE))
    l3_ifs = set(jail.list_group(run, constants.L3_GROUP))

    for rtr in desired:
        directory = router_mod.state_dir(base, rtr.id)
        os.makedirs(directory, exist_ok=True)
        if not jail.ensure_jail(acts, rtr.jail, jails):
            continue

        # forwarding
        rc, out, _err = run((JEXEC, rtr.jail, SYSCTL, "-n", FORWARDING))
        if rc != 0 or (out or "").strip() != "1":
            acts.do("EnableForwarding", (JEXEC, rtr.jail, SYSCTL, FORWARDING + "=1"))

        # ports
        addrs = router_mod.addresses(rtr)
        complete = True
        for port in rtr.ports:
            jail_if = rtr.jail_if(port)
            text = jail.ensure_epair(
                acts,
                rtr.jail,
                port.host_if,
                jail_if,
                port.id,
                constants.L3_GROUP,
                l3_ifs,
            )
            if text is None:
                complete = False
                continue
            jail.ensure_addrs(acts, rtr.jail, jail_if, text, port.mac, addrs[jail_if])

        # routes: a route needs its interface, so only once every port exists
        if complete:
            rc, out, _err = run((JEXEC, rtr.jail, NETSTAT, "-rn", "-f", "inet"))
            have = parse_routes(out) if rc == 0 else set()
            wanted = set(router_mod.routes(rtr))
            for dest, _gw in sorted(have - wanted):
                acts.do(
                    "DeleteRoute",
                    (JEXEC, rtr.jail, ROUTE, "-n", "delete", route_arg(dest)),
                )
            for dest, gw in sorted(wanted - have):
                acts.do(
                    "AddRoute",
                    (JEXEC, rtr.jail, ROUTE, "-n", "add", route_arg(dest), gw),
                )

        # pf: enable once, load on a changed hash
        text, cfg_hash = router_mod.pf_text(rtr)
        path = os.path.join(directory, "pf.conf")
        if write_if_changed(path, text):
            acts.note("WritePf", f"{rtr.id}: {cfg_hash}")
        rc, out, _err = run((JEXEC, rtr.jail, PFCTL, "-si"))
        if rc != 0 or not PF_ENABLED_RE.search(out or ""):
            acts.do("EnablePf", (JEXEC, rtr.jail, PFCTL, "-e"))
        rc, out, _err = run((JEXEC, rtr.jail, PFCTL, "-sr"))
        m = CFG_RE.search(out or "") if rc == 0 else None
        if m is None or m.group("hash") != cfg_hash:
            acts.do("LoadPf", (JEXEC, rtr.jail, PFCTL, "-f", path))

    # gc: processes, then epairs, then jails, then state directories
    jail.collect(
        acts,
        jails,
        {rtr.jail for rtr in desired},
        l3_ifs,
        {port.host_if for rtr in desired for port in rtr.ports},
    )
    desired_dirs = {rtr.id for rtr in desired}
    l3_base = os.path.join(base, "l3")
    try:
        stale = sorted(set(os.listdir(l3_base)) - desired_dirs)
    except OSError:
        stale = []
    for entry in stale:
        shutil.rmtree(os.path.join(l3_base, entry), ignore_errors=True)
        acts.note("RemoveState", entry)

    return acts.result()

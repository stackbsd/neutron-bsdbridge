"""Router jails, epairs, addresses, routes and pf reconciler."""

import os
import re
import shutil

from neutron_bsdbridge import constants, jail
from neutron_bsdbridge.constants import (
    JEXEC,
    KILL,
    NETSTAT,
    PFCTL,
    PS,
    ROUTE,
    RTADVD,
    SYSCTL,
)
from neutron_bsdbridge.l3_agent import router as router_mod
from neutron_bsdbridge.utils import default_run, write_if_changed

FORWARDING = ("net.inet.ip.forwarding", "net.inet6.ip6.forwarding")
FAMILIES = ("inet", "inet6")
RTADVD_PREFIX = "rtadvd-"

JAIL_RE = re.compile(r"^qrouter-[0-9a-f]{12}$")
CFG_RE = re.compile(r'label "l3-neutron:cfg:(?P<hash>[0-9a-f]{16})"')
ROUTE_RE = re.compile(
    r"^(?P<dest>\S+)\s+(?P<gw>\d+\.\d+\.\d+\.\d+|[0-9a-f]*:[0-9a-f:]*(?:%\S+)?)"
    r"\s+(?P<flags>\S+)"
)
PF_ENABLED_RE = re.compile(r"^Status: Enabled", re.M)
DEFAULTS = {"inet": router_mod.DEFAULT_ROUTE, "inet6": router_mod.DEFAULT_ROUTE6}


def parse_routes(text, family="inet"):
    """Parse netstat -rn output into the (destination, nexthop) set."""
    routes = set()
    for line in (text or "").splitlines():
        m = ROUTE_RE.match(line)
        if m is None or "G" not in m.group("flags"):
            continue
        dest = m.group("dest")
        if dest == "default":
            dest = DEFAULTS[family]
        routes.add((router_mod.normalize_destination(dest), m.group("gw")))
    return routes


def rtadvd_pid(run, path):
    """Return the pid of the rtadvd a pidfile names if it is running."""
    try:
        with open(path) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return None
    rc, out, _err = run((PS, "-p", str(pid), "-o", "command="))
    return pid if rc == 0 and "rtadvd" in (out or "") else None


def route_args(destination):
    """Return a destination as route(8) spells it with its family."""
    family = "-inet6" if ":" in destination else "-inet"
    if destination in DEFAULTS.values():
        return (family, "default")
    return (family, destination)


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
        for knob in FORWARDING:
            rc, out, _err = run((JEXEC, rtr.jail, SYSCTL, "-n", knob))
            if rc != 0 or (out or "").strip() != "1":
                acts.do("EnableForwarding", (JEXEC, rtr.jail, SYSCTL, knob + "=1"))

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
                port.mtu,
            )
            if text is None:
                complete = False
                continue
            jail.ensure_addrs(acts, rtr.jail, jail_if, text, port.mac, addrs[jail_if])

        # routes: a route needs its interface, so only once every port exists
        if complete:
            have = set()
            for family in FAMILIES:
                rc, out, _err = run((JEXEC, rtr.jail, NETSTAT, "-rn", "-f", family))
                if rc == 0:
                    have |= parse_routes(out, family)
            wanted = set(router_mod.routes(rtr))
            for dest, _gw in sorted(have - wanted):
                acts.do(
                    "DeleteRoute",
                    (JEXEC, rtr.jail, ROUTE, "-n", "delete", *route_args(dest)),
                )
            for dest, gw in sorted(wanted - have):
                acts.do(
                    "AddRoute",
                    (JEXEC, rtr.jail, ROUTE, "-n", "add", *route_args(dest), gw),
                )

        # rtadvd: one per interface, HUP on a changed file
        if complete:
            confs = router_mod.rtadvd_confs(rtr)
            for jail_if, text in sorted(confs.items()):
                stem = os.path.join(directory, RTADVD_PREFIX + jail_if)
                dirty = write_if_changed(stem + ".conf", text)
                pid = rtadvd_pid(run, stem + ".pid")
                if pid is None:
                    argv = (RTADVD, "-s", "-c", stem + ".conf", "-p", stem + ".pid")
                    argv += ("-C", stem + ".sock", jail_if)
                    acts.do("StartRtadvd", (JEXEC, rtr.jail, *argv))
                elif dirty:
                    acts.do("ReloadRtadvd", (KILL, "-HUP", str(pid)))
            for name in sorted(os.listdir(directory)):
                stem, ext = os.path.splitext(name)
                if not stem.startswith(RTADVD_PREFIX) or ext != ".conf":
                    continue
                if stem[len(RTADVD_PREFIX) :] in confs:
                    continue
                stem = os.path.join(directory, stem)
                pid = rtadvd_pid(run, stem + ".pid")
                if pid is not None:
                    acts.do("StopRtadvd", (KILL, str(pid)))
                os.unlink(stem + ".conf")

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

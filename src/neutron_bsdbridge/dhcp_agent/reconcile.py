"""Dhcp jails, epairs, files and dnsmasq config reconciler."""

import os
import re
import shutil

from neutron_bsdbridge import constants, ifconfig
from neutron_bsdbridge.dhcp_agent import dnsmasq as dnsmasq_mod
from neutron_bsdbridge.ifconfig import IFCONFIG
from neutron_bsdbridge.utils import Receipt, default_run

JLS = "/usr/sbin/jls"
JAIL = "/usr/sbin/jail"
JEXEC = "/usr/sbin/jexec"
KILL = "/bin/kill"
PKILL = "/bin/pkill"
PS = "/bin/ps"

JAIL_RE = re.compile(r"^qdhcp-[0-9a-f]{12}$")


class Result:
    """One dhcp reconcile pass: its receipts."""

    def __init__(self, receipts):
        """Hold the pass's receipts."""
        self.receipts = receipts

    @property
    def failed(self):
        """Return the receipts that failed."""
        return [r for r in self.receipts if not r.ok]

    @property
    def changed(self):
        """Return whether the pass did anything."""
        return bool(self.receipts)


def list_jails(run):
    """Return the qdhcp-named jails present right now."""
    rc, out, _err = run((JLS, "name"))
    if rc != 0:
        return []
    return [name for name in (out or "").split() if JAIL_RE.match(name)]


def list_dhcp_ifs(run):
    """Return the host-side epairs carrying the dhcp ownership group."""
    rc, out, _err = run((IFCONFIG, "-g", constants.DHCP_GROUP))
    if rc != 0:
        return []
    return ifconfig.parse_group_list(out or "")


def write_if_changed(path, text):
    """Atomically write a file when its content differs."""
    try:
        with open(path) as f:
            if f.read() == text:
                return False
    except OSError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, path)
    return True


def reconcile(desired, base, run=default_run, dnsmasq_path=constants.DNSMASQ):
    """Reconcile the dhcp plane to a list of DhcpNetwork specs."""
    receipts = []

    def do(label, argv, ok_rcs=(0,)):
        """Run one argv and record its receipt."""
        rc, out, err = run(argv)
        good = rc in ok_rcs
        receipts.append(
            Receipt(
                op=label,
                argv=argv,
                executed=True,
                ok=good,
                note="" if good else (err or "").strip(),
            )
        )
        return good, out

    def note(label, text):
        """Record a file action as an ok receipt."""
        receipts.append(Receipt(op=label, argv=(), executed=True, ok=True, note=text))

    jails = set(list_jails(run))
    dhcp_ifs = set(list_dhcp_ifs(run))

    for net in desired:
        # hosts and opts files
        directory = dnsmasq_mod.state_dir(base, net.network_id)
        os.makedirs(directory, exist_ok=True)
        dirty = write_if_changed(
            os.path.join(directory, "hosts"), dnsmasq_mod.hosts_text(net)
        )
        if dirty:
            note("WriteHosts", f"{net.network_id}: {len(net.hosts)} entries")
        if write_if_changed(
            os.path.join(directory, "opts"), dnsmasq_mod.opts_text(net)
        ):
            dirty = True
            note("WriteOpts", f"{net.network_id}: {len(net.subnets)} subnet(s)")

        # jail
        if net.jail not in jails:
            ok, _ = do(
                "CreateJail",
                (JAIL, "-c", "name=" + net.jail, "vnet", "persist", "path=/"),
            )
            if not ok:
                continue
            jails.add(net.jail)
            do("JailLoopback", (JEXEC, net.jail, IFCONFIG, "lo0", "up"))

        # epair: destroying either end kills the pair, so a half-state is
        # repaired by destroying the surviving half
        rc, host_if_text, _err = run((IFCONFIG, net.dhcp_if))
        host_if = rc == 0
        rc, jail_if_text, _err = run(
            (JEXEC, net.jail, IFCONFIG, constants.DHCP_JAIL_IF)
        )
        jail_if = rc == 0
        if host_if and not jail_if:
            do("DestroyBrokenEpair", (IFCONFIG, net.dhcp_if, "destroy"))
            dhcp_ifs.discard(net.dhcp_if)
            host_if = False
        if host_if:
            # the L2 agent discovers this port from the description
            host_info = ifconfig.parse(host_if_text or "").get(net.dhcp_if)
            wanted_descr = constants.DESCRIPTION_PREFIX + net.port_id
            if host_info is not None and host_info.description != wanted_descr:
                do("FixEpairDescr", (IFCONFIG, net.dhcp_if, "descr", wanted_descr))
        if jail_if and not host_if:
            do(
                "DestroyBrokenJailIf",
                (JEXEC, net.jail, IFCONFIG, constants.DHCP_JAIL_IF, "destroy"),
            )
            jail_if = False
        if not host_if:
            ok, out = do("CreateEpair", (IFCONFIG, "epair", "create"))
            if not ok:
                continue
            a_end = out.strip()
            b_end = a_end[:-1] + "b"
            do(
                "NameHostIf",
                (
                    IFCONFIG,
                    a_end,
                    "name",
                    net.dhcp_if,
                    "descr",
                    constants.DESCRIPTION_PREFIX + net.port_id,
                    "group",
                    constants.DHCP_GROUP,
                    "up",
                ),
            )
            dhcp_ifs.add(net.dhcp_if)
            do("MoveJailIf", (IFCONFIG, b_end, "vnet", net.jail))
            do(
                "NameJailIf",
                (JEXEC, net.jail, IFCONFIG, b_end, "name", constants.DHCP_JAIL_IF),
            )
            rc, jail_if_text, _err = run(
                (JEXEC, net.jail, IFCONFIG, constants.DHCP_JAIL_IF)
            )
            jail_if = rc == 0

        # mac and addresses, on drift only; ether and inet cannot share
        # one ifconfig invocation or the mac is silently not set
        if jail_if:
            info = ifconfig.parse(jail_if_text or "").get(constants.DHCP_JAIL_IF)
            if info is not None:
                if info.ether != net.mac:
                    do(
                        "SetJailIfMac",
                        (
                            JEXEC,
                            net.jail,
                            IFCONFIG,
                            constants.DHCP_JAIL_IF,
                            "ether",
                            net.mac,
                        ),
                    )
                have = set(info.inets)
                first = not info.inets
                for addr, prefixlen in net.ips:
                    if (addr, prefixlen) in have:
                        continue
                    argv = [
                        JEXEC,
                        net.jail,
                        IFCONFIG,
                        constants.DHCP_JAIL_IF,
                        "inet",
                        f"{addr}/{prefixlen}",
                    ]
                    argv += ["up"] if first else ["alias"]
                    first = False
                    do("SetJailIfInet", tuple(argv))

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
            do("StopDnsmasq", (KILL, str(pid)))
            alive = False
        if not alive:
            write_if_changed(cmd_path, " ".join(wanted))
            do("StartDnsmasq", (JEXEC, net.jail, *wanted))
        elif dirty:
            do("ReloadDnsmasq", (KILL, "-HUP", str(pid)))

    # gc: processes, then epairs, then jails, then state directories
    desired_jails = {net.jail for net in desired}
    desired_ifs = {net.dhcp_if for net in desired}
    desired_dirs = {net.network_id for net in desired}
    for jail in sorted(jails - desired_jails):
        rc, out, _err = run((JLS, "-j", jail, "jid"))
        if rc == 0 and (out or "").strip():
            # pkill exits 1 when nothing matched
            do("KillJailProcs", (PKILL, "-j", (out or "").strip()), ok_rcs=(0, 1))
    for name in sorted(dhcp_ifs - desired_ifs):
        do("DestroyEpair", (IFCONFIG, name, "destroy"))
    for jail in sorted(jails - desired_jails):
        do("RemoveJail", (JAIL, "-r", jail))
    dhcp_base = os.path.join(base, "dhcp")
    try:
        stale = sorted(set(os.listdir(dhcp_base)) - desired_dirs)
    except OSError:
        stale = []
    for entry in stale:
        shutil.rmtree(os.path.join(dhcp_base, entry), ignore_errors=True)
        note("RemoveState", entry)

    return Result(receipts)

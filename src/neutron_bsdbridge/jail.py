"""VNET jail and epair plumbing shared by the dhcp and l3 reconcilers."""

from neutron_bsdbridge import constants, ifconfig
from neutron_bsdbridge.ifconfig import IFCONFIG
from neutron_bsdbridge.utils import Receipt, default_run

JLS = "/usr/sbin/jls"
JAIL = "/usr/sbin/jail"
JEXEC = "/usr/sbin/jexec"
PKILL = "/bin/pkill"


class Result:
    """One reconcile pass: its receipts."""

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


class Actions:
    """Runner that records a receipt for every command of one pass."""

    def __init__(self, run=default_run):
        """Wrap a runner and start with no receipts."""
        self.run = run
        self.receipts = []

    def do(self, label, argv, ok_rcs=(0,)):
        """Run one argv and record its receipt."""
        rc, out, err = self.run(argv)
        good = rc in ok_rcs
        self.receipts.append(
            Receipt(
                op=label,
                argv=argv,
                executed=True,
                ok=good,
                note="" if good else (err or "").strip(),
            )
        )
        return good, out

    def note(self, label, text):
        """Record a file action as an ok receipt."""
        self.receipts.append(
            Receipt(op=label, argv=(), executed=True, ok=True, note=text)
        )

    def result(self):
        """Return the pass's receipts as a Result."""
        return Result(self.receipts)


def list_jails(run, pattern):
    """Return the present jails whose name matches a pattern."""
    rc, out, _err = run((JLS, "name"))
    if rc != 0:
        return []
    return [name for name in (out or "").split() if pattern.match(name)]


def list_group(run, group):
    """Return the host interfaces carrying an ownership group."""
    rc, out, _err = run((IFCONFIG, "-g", group))
    if rc != 0:
        return []
    return ifconfig.parse_group_list(out or "")


def ensure_jail(acts, name, jails):
    """Create a persistent VNET jail when absent and return whether it exists."""
    if name in jails:
        return True
    ok, _ = acts.do(
        "CreateJail", (JAIL, "-c", "name=" + name, "vnet", "persist", "path=/")
    )
    if not ok:
        return False
    jails.add(name)
    acts.do("JailLoopback", (JEXEC, name, IFCONFIG, "lo0", "up"))
    return True


def ensure_epair(acts, jail, host_if, jail_if, port_id, group, host_ifs):
    """Ensure one epair spans the host and a jail, returning the jail end's text."""
    rc, host_if_text, _err = acts.run((IFCONFIG, host_if))
    have_host = rc == 0
    rc, jail_if_text, _err = acts.run((JEXEC, jail, IFCONFIG, jail_if))
    have_jail = rc == 0
    # destroying either end kills the pair, so a half-state is
    # repaired by destroying the surviving half
    if have_host and not have_jail:
        acts.do("DestroyBrokenEpair", (IFCONFIG, host_if, "destroy"))
        host_ifs.discard(host_if)
        have_host = False
    if have_host:
        # the L2 agent discovers this port from the description
        host_info = ifconfig.parse(host_if_text or "").get(host_if)
        wanted_descr = constants.DESCRIPTION_PREFIX + port_id
        if host_info is not None and host_info.description != wanted_descr:
            acts.do("FixEpairDescr", (IFCONFIG, host_if, "descr", wanted_descr))
    if have_jail and not have_host:
        acts.do("DestroyBrokenJailIf", (JEXEC, jail, IFCONFIG, jail_if, "destroy"))
        have_jail = False
    if not have_host:
        ok, out = acts.do("CreateEpair", (IFCONFIG, "epair", "create"))
        if not ok:
            return None
        a_end = out.strip()
        b_end = a_end[:-1] + "b"
        acts.do(
            "NameHostIf",
            (
                IFCONFIG,
                a_end,
                "name",
                host_if,
                "descr",
                constants.DESCRIPTION_PREFIX + port_id,
                "group",
                group,
                "up",
            ),
        )
        host_ifs.add(host_if)
        acts.do("MoveJailIf", (IFCONFIG, b_end, "vnet", jail))
        acts.do("NameJailIf", (JEXEC, jail, IFCONFIG, b_end, "name", jail_if))
        rc, jail_if_text, _err = acts.run((JEXEC, jail, IFCONFIG, jail_if))
        have_jail = rc == 0
    return jail_if_text if have_jail else None


def ensure_addrs(acts, jail, jail_if, jail_if_text, mac, ips):
    """Set a jail interface's mac and inet addresses on drift only."""
    # ether and inet cannot share one ifconfig invocation or the mac
    # is silently not set
    info = ifconfig.parse(jail_if_text or "").get(jail_if)
    if info is None:
        return
    if info.ether != mac:
        acts.do("SetJailIfMac", (JEXEC, jail, IFCONFIG, jail_if, "ether", mac))
    have = set(info.inets)
    first = not info.inets
    for addr, prefixlen in ips:
        if (addr, prefixlen) in have:
            continue
        argv = [JEXEC, jail, IFCONFIG, jail_if, "inet", f"{addr}/{prefixlen}"]
        argv += ["up"] if first else ["alias"]
        first = False
        acts.do("SetJailIfInet", tuple(argv))


def collect(acts, jails, desired_jails, host_ifs, desired_ifs):
    """Tear down undesired jails: processes, then epairs, then the jails."""
    for jail in sorted(jails - desired_jails):
        rc, out, _err = acts.run((JLS, "-j", jail, "jid"))
        if rc == 0 and (out or "").strip():
            # pkill exits 1 when nothing matched
            acts.do("KillJailProcs", (PKILL, "-j", (out or "").strip()), ok_rcs=(0, 1))
    for name in sorted(host_ifs - desired_ifs):
        acts.do("DestroyEpair", (IFCONFIG, name, "destroy"))
    for jail in sorted(jails - desired_jails):
        acts.do("RemoveJail", (JAIL, "-r", jail))

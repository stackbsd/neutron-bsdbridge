"""ifconfig(8) reader and parser."""

import dataclasses
import re

from neutron_bsdbridge.constants import IFCONFIG, OWNED_GROUP
from neutron_bsdbridge.utils import default_run

HEADER_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.:-]+): flags=[0-9a-fA-Fx]*<(?P<flags>[^>]*)>"
    r"(?: metric (?P<metric>\d+))?(?: mtu (?P<mtu>\d+))?"
)
MEMBER_RE = re.compile(r"^\s+member: (?P<name>\S+) flags=")
VLAN_RE = re.compile(r"^\s+vlan: (?P<vid>\d+) .*parent interface: (?P<parent>\S+)")
MAXADDR_RE = re.compile(r"\bmaxaddr (?P<maxaddr>\d+)\b")
ETHER_RE = re.compile(r"^\s+ether (?P<ether>[0-9a-f:]{17})")
INET_RE = re.compile(r"^\s+inet (?P<addr>\S+) netmask (?P<mask>0x[0-9a-f]{8})")
GROUPS_RE = re.compile(r"^\s+groups: (?P<groups>.+)$")
DESCR_RE = re.compile(r"^\s+description: (?P<descr>.*)$")
STATUS_RE = re.compile(r"^\s+status: (?P<status>.+)$")


@dataclasses.dataclass(frozen=True)
class Interface:
    """One kernel interface, as ifconfig reported it."""

    name: str
    flags: frozenset
    mtu: int | None = None
    metric: int | None = None
    ether: str | None = None
    inets: tuple = ()
    description: str = ""
    groups: tuple = ()
    status: str | None = None
    members: tuple = ()
    maxaddr: int | None = None
    vlan: int | None = None
    vlan_parent: str | None = None

    @property
    def up(self):
        """Return whether the interface carries the UP flag."""
        return "UP" in self.flags

    @property
    def is_bridge(self):
        """Return whether the interface is in the bridge group."""
        return "bridge" in self.groups

    @property
    def is_owned(self):
        """Return whether the interface carries the ownership group."""
        return OWNED_GROUP in self.groups


class KernelInterfaces:
    """The kernel's interfaces, owned names, and bridge address tables."""

    def __init__(self, interfaces, owned, addrs=None):
        """Hold interfaces by name, owned names in kernel order, bridge addrs."""
        self.interfaces = interfaces
        self.owned = tuple(owned)
        self.addrs = addrs or {}

    def static_lock(self, bridge, member):
        """Return the statically locked MAC for a member, or None."""
        for mac, mem, static in self.addrs.get(bridge, []):
            if mem == member and static:
                return mac
        return None

    def bridges(self):
        """Return the bridges by name."""
        return {n: i for n, i in self.interfaces.items() if i.is_bridge}

    def members_of(self, bridge):
        """Return a bridge's member names, or () when it is absent."""
        iface = self.interfaces.get(bridge)
        return iface.members if iface else ()

    def __contains__(self, name):
        """Return whether the kernel has an interface."""
        return name in self.interfaces


def split_blocks(text):
    """Split ifconfig output into per-interface line lists."""
    # anything before the first header is discarded
    blocks = []
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace() and HEADER_RE.match(line):
            current = [line]
            blocks.append(current)
        elif current is not None and line.strip():
            current.append(line)
    return blocks


def parse_block(lines):
    """Parse one block of lines into an Interface."""
    header = HEADER_RE.match(lines[0])
    fields = {
        "name": header.group("name"),
        "flags": frozenset(f for f in header.group("flags").split(",") if f),
        "metric": int(header.group("metric")) if header.group("metric") else None,
        "mtu": int(header.group("mtu")) if header.group("mtu") else None,
    }
    members = []
    inets = []
    for line in lines[1:]:
        m = MEMBER_RE.match(line)
        if m:
            members.append(m.group("name"))
            continue
        m = INET_RE.match(line)
        if m:
            prefixlen = bin(int(m.group("mask"), 16)).count("1")
            inets.append((m.group("addr"), prefixlen))
            continue
        m = VLAN_RE.match(line)
        if m:
            fields["vlan"] = int(m.group("vid"))
            fields["vlan_parent"] = m.group("parent")
            continue
        m = ETHER_RE.match(line)
        if m:
            fields["ether"] = m.group("ether")
            continue
        m = GROUPS_RE.match(line)
        if m:
            fields["groups"] = tuple(m.group("groups").split())
            continue
        m = DESCR_RE.match(line)
        if m:
            fields["descr"] = m.group("descr")
            continue
        m = STATUS_RE.match(line)
        if m:
            fields["status"] = m.group("status")
            continue
        m = MAXADDR_RE.search(line)
        if m and line.lstrip().startswith("maxage"):
            fields["maxaddr"] = int(m.group("maxaddr"))
    if "descr" in fields:
        fields["description"] = fields.pop("descr")
    fields["members"] = tuple(members)
    fields["inets"] = tuple(inets)
    return Interface(**fields)


def parse(text):
    """Parse full or concatenated ifconfig output into {name: Interface}."""
    out = {}
    for block in split_blocks(text):
        iface = parse_block(block)
        out[iface.name] = iface
    return out


def parse_addr_list(text):
    """Parse bridge addr output into (mac, member, static) entries."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and ":" in parts[0]:
            out.append((parts[0].lower(), parts[2], "STATIC" in parts[4]))
    return out


def parse_group_list(text):
    """Parse ifconfig -g output into interface names, in kernel order."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def group_argv():
    """Return the argv that lists every owned interface."""
    return (IFCONFIG, "-g", OWNED_GROUP)


def scan_group(group, run=default_run):
    """Return {name: Interface} for one interface group's members."""
    _rc, text, _err = run((IFCONFIG, "-g", group))
    out = {}
    for name in parse_group_list(text):
        rc, text, _err = run((IFCONFIG, name))
        if rc == 0:
            out.update(parse(text))
    return out


def read_interfaces(names, run=default_run):
    """Read the owned interfaces plus the named ones."""
    _rc, text, _err = run(group_argv())
    owned = parse_group_list(text)
    interfaces = {}

    def query(name):
        """Read and parse one interface, once."""
        if name in interfaces:
            return
        rc, text, _err = run((IFCONFIG, name))
        if rc != 0:
            return
        interfaces.update(parse(text))

    for name in owned:
        query(name)
    for name in names:
        query(name)
    # foreign members too: the differ needs them present to remove them
    for bridge in list(interfaces.values()):
        for member in bridge.members:
            query(member)
    addrs = {}
    for name, iface in interfaces.items():
        if iface.is_bridge:
            _rc, text, _err = run((IFCONFIG, name, "addr"))
            addrs[name] = parse_addr_list(text)
    return KernelInterfaces(interfaces, owned, addrs)

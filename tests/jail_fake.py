"""A stateful scripted kernel for the jail plane, shared by reconcile tests."""

from neutron_bsdbridge import jail
from neutron_bsdbridge.ifconfig import IFCONFIG


def netmask(prefixlen):
    """Render a prefix length the way ifconfig prints a netmask."""
    bits = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    return f"0x{bits:08x}"


class FakeKernel:
    """Jails, host epairs and jail interfaces that answer like the real tools."""

    def __init__(self):
        self.jails = {}  # name -> jid
        self.host_ifaces = {}  # name -> {groups, descr}
        self.jail_ifaces = {}  # (jail, name) -> {mac, inets}
        self.calls = []
        self._epair_seq = 0
        self._jid_seq = 10

    def _jail_if_text(self, jail_name, name):
        entry = self.jail_ifaces[(jail_name, name)]
        lines = [
            f"{name}: flags=8843<UP,BROADCAST> metric 0 mtu 1500",
            f"\tether {entry['mac']}",
        ]
        for addr, prefixlen in entry["inets"]:
            lines.append(f"\tinet {addr} netmask {netmask(prefixlen)}")
        lines.append("\tgroups: epair")
        return "\n".join(lines) + "\n"

    def __call__(self, argv, timeout=None, input=None):
        self.calls.append(argv)
        prog = argv[0]
        if prog == jail.JLS:
            if argv[1] == "name":
                return 0, "".join(j + "\n" for j in self.jails), ""
            if argv[1] == "-j":
                name = argv[2]
                if name in self.jails:
                    return 0, str(self.jails[name]) + "\n", ""
                return 1, "", "no such jail"
        if prog == jail.JAIL:
            if argv[1] == "-c":
                name = argv[2].split("=", 1)[1]
                self._jid_seq += 1
                self.jails[name] = self._jid_seq
                return 0, "", ""
            if argv[1] == "-r":
                self.jails.pop(argv[2], None)
                return 0, "", ""
        if prog == jail.PKILL:
            return self.pkill(argv)
        if prog == jail.JEXEC:
            name = argv[1]
            inner = argv[2:]
            if name not in self.jails:
                return 1, "", "jail not found"
            if inner[0] == IFCONFIG:
                return self._ifconfig(inner[1:], jail_name=name)
            return self.jexec(name, inner)
        if prog == IFCONFIG:
            return self._ifconfig(argv[1:], jail_name=None)
        return self.host(argv)

    def pkill(self, argv):
        """Answer pkill for a jail with nothing to kill."""
        return 1, "", ""

    def jexec(self, jail_name, inner):
        """Answer a non-ifconfig command run inside a jail."""
        raise AssertionError(f"unscripted jexec: {jail_name} {inner}")

    def host(self, argv):
        """Answer a host command outside the jail plane."""
        raise AssertionError(f"unscripted argv: {argv}")

    def _ifconfig(self, args, jail_name):
        ifaces = self.host_ifaces
        if args[0] == "-g":
            names = [n for n, entry in ifaces.items() if args[1] in entry["groups"]]
            return 0, "".join(n + "\n" for n in names), ""
        if args[0] == "epair" and args[1] == "create":
            a_end = f"epair{self._epair_seq}a"
            b_end = f"epair{self._epair_seq}b"
            self._epair_seq += 1
            ifaces[a_end] = {"groups": set(), "descr": ""}
            ifaces[b_end] = {"groups": set(), "descr": ""}
            return 0, a_end + "\n", ""
        name = args[0]
        rest = args[1:]
        if name == "lo0":
            return 0, "", ""
        if jail_name is None:
            if name not in ifaces:
                return 1, "", "does not exist"
            if not rest:
                entry = ifaces[name]
                text = f"{name}: flags=8843<UP> metric 0 mtu 1500\n"
                if entry["descr"]:
                    text += f"\tdescription: {entry['descr']}\n"
                return 0, text, ""
            if rest[0] == "destroy":
                del ifaces[name]
                other = (name[:-1] + "b") if name.endswith("a") else None
                if other:
                    ifaces.pop(other, None)
                return 0, "", ""
            if rest[0] == "descr":
                ifaces[name]["descr"] = rest[1]
                return 0, "", ""
            if rest[0] == "name":
                entry = ifaces.pop(name)
                new = rest[1]
                if "group" in rest:
                    entry["groups"].add(rest[rest.index("group") + 1])
                if "descr" in rest:
                    entry["descr"] = rest[rest.index("descr") + 1]
                ifaces[new] = entry
                return 0, new + "\n", ""
            if rest[0] == "vnet":
                ifaces.pop(name)
                self.jail_ifaces[(rest[1], name)] = {
                    "mac": "58:9c:fc:00:00:99",
                    "inets": [],
                }
                return 0, "", ""
        else:
            key = (jail_name, name)
            if key not in self.jail_ifaces:
                return 1, "", "does not exist"
            if not rest:
                return 0, self._jail_if_text(jail_name, name), ""
            if rest[0] == "name":
                self.jail_ifaces[(jail_name, rest[1])] = self.jail_ifaces.pop(key)
                return 0, rest[1] + "\n", ""
            if rest[0] == "destroy":
                del self.jail_ifaces[key]
                return 0, "", ""
            if rest[0] == "ether":
                self.jail_ifaces[key]["mac"] = rest[1]
                return 0, "", ""
            if rest[0] == "inet":
                addr, _, prefixlen = rest[1].partition("/")
                entry = (addr, int(prefixlen or 32))
                if rest[2:3] == ("-alias",):
                    self.jail_ifaces[key]["inets"].remove(entry)
                else:
                    self.jail_ifaces[key]["inets"].append(entry)
                return 0, "", ""
        raise AssertionError(f"unscripted ifconfig: {args} jail={jail_name}")

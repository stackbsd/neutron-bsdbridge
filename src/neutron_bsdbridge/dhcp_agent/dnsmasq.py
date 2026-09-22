"""Dnsmasq config rendering."""

import dataclasses
import ipaddress
import os

from neutron_bsdbridge import constants, names

LEASE_TIME = "86400s"


@dataclasses.dataclass(frozen=True)
class Subnet:
    """One dhcp-enabled IPv4 subnet."""

    id: str
    cidr: str
    gateway_ip: str | None = None
    dns: tuple = ()


@dataclasses.dataclass(frozen=True)
class HostEntry:
    """One reservation: a port's allocation in one subnet."""

    mac: str
    ip: str


@dataclasses.dataclass(frozen=True)
class DhcpNetwork:
    """One network's desired dhcp service."""

    network_id: str
    port_id: str
    mac: str
    ips: tuple
    subnets: tuple
    hosts: tuple

    @property
    def jail(self):
        """Return the network's jail name."""
        return names.dhcp_jail_name(self.network_id)

    @property
    def dhcp_if(self):
        """Return the host-side epair name."""
        return names.dhcp_if_name(self.port_id)


def state_dir(base, network_id):
    """Return the per-network state directory path."""
    return os.path.join(base, "dhcp", network_id)


def hosts_text(net):
    """Render the dhcp-hostsfile, one reservation per line."""
    lines = [
        f"{entry.mac},host-{entry.ip.replace('.', '-')},{entry.ip}"
        for entry in net.hosts
    ]
    return "".join(line + "\n" for line in sorted(lines))


def opts_text(net):
    """Render the dhcp-optsfile with per-subnet router and dns options."""
    # an option with no value makes dnsmasq send nothing instead of itself
    lines = []
    for subnet in net.subnets:
        if subnet.gateway_ip:
            lines.append(f"tag:{subnet.id},option:router,{subnet.gateway_ip}")
        else:
            lines.append(f"tag:{subnet.id},option:router")
        if subnet.dns:
            lines.append(f"tag:{subnet.id},option:dns-server,{','.join(subnet.dns)}")
        else:
            lines.append(f"tag:{subnet.id},option:dns-server")
    return "".join(line + "\n" for line in lines)


def argv(net, base, dnsmasq_path=constants.DNSMASQ):
    """Return the dnsmasq argv for one network."""
    directory = state_dir(base, net.network_id)
    parts = [
        dnsmasq_path,
        "--conf-file=/dev/null",
        "--no-hosts",
        "--no-resolv",
        "--port=0",
        "--interface=" + constants.DHCP_JAIL_IF,
        "--bind-interfaces",
        f"--pid-file={directory}/pid",
        f"--dhcp-hostsfile={directory}/hosts",
        f"--dhcp-optsfile={directory}/opts",
        f"--dhcp-leasefile={directory}/leases",
        "--dhcp-authoritative",
    ]
    for subnet in net.subnets:
        network = ipaddress.ip_network(subnet.cidr)
        parts.append(
            f"--dhcp-range=set:{subnet.id},{network.network_address},"
            f"static,{network.netmask},{LEASE_TIME}"
        )
    return tuple(parts)

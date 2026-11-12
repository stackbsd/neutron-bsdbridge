"""Router spec and its pf, route and address rendering."""

import dataclasses
import hashlib
import ipaddress
import os

from neutron_bsdbridge import names

CFG_LABEL = "l3-neutron:cfg:"
DEFAULT_ROUTE = "0.0.0.0/0"
DEFAULT_ROUTE6 = "::/0"
STATEFUL = "dhcpv6-stateful"
STATELESS = "dhcpv6-stateless"
RDNSS_MAX = 3


@dataclasses.dataclass(frozen=True)
class Prefix:
    """One IPv6 prefix a router port advertises."""

    cidr: str
    mode: str
    dns: tuple = ()


@dataclasses.dataclass(frozen=True)
class Port:
    """One router port: its addresses and the subnets behind it."""

    id: str
    mac: str
    ips: tuple
    cidrs: tuple
    gateway_ip: str | None = None
    gateway_ip6: str | None = None
    prefixes: tuple = ()
    scope4: str | None = None
    scope6: str | None = None

    @property
    def host_if(self):
        """Return the host-side epair name."""
        return names.router_if_name(self.id)


@dataclasses.dataclass(frozen=True)
class FloatingIp:
    """One floating ip and the fixed address it fronts."""

    id: str
    floating: str
    fixed: str


@dataclasses.dataclass(frozen=True)
class Router:
    """One router's desired jail, ports, routes and translation."""

    id: str
    gateway: Port | None
    interfaces: tuple
    floating_ips: tuple
    routes: tuple
    enable_snat: bool = True

    @property
    def jail(self):
        """Return the router's jail name."""
        return names.router_jail_name(self.id)

    @property
    def ports(self):
        """Return every port with the gateway first."""
        return ((self.gateway,) if self.gateway else ()) + self.interfaces

    def jail_if(self, port):
        """Return a port's jail-side interface name."""
        return names.router_jail_if_name(port.id, gateway=port is self.gateway)


def state_dir(base, router_id):
    """Return the per-router state directory path."""
    return os.path.join(base, "l3", router_id)


def port_from_rpc(port):
    """Build a Port from a router port dict, or None without an address."""
    subnets = {s["id"]: s for s in port.get("subnets", [])}
    ips = []
    gateways = {}
    for fixed in port.get("fixed_ips", []):
        subnet = subnets.get(fixed["subnet_id"])
        if subnet is None:
            continue
        ips.append((fixed["ip_address"], int(subnet["cidr"].split("/")[1])))
        if subnet.get("gateway_ip"):
            family = "inet6" if ":" in subnet["cidr"] else "inet"
            gateways.setdefault(family, subnet["gateway_ip"])
    if not ips:
        return None
    cidrs = tuple(sorted(s["cidr"] for s in subnets.values() if ":" not in s["cidr"]))
    prefixes = tuple(
        Prefix(
            cidr=s["cidr"],
            mode=s["ipv6_ra_mode"],
            dns=tuple(d for d in s.get("dns_nameservers") or () if ":" in d),
        )
        for s in sorted(subnets.values(), key=lambda s: s["cidr"])
        if ":" in s["cidr"] and s.get("ipv6_ra_mode")
    )
    scopes = {str(k): v for k, v in (port.get("address_scopes") or {}).items()}
    return Port(
        id=port["id"],
        mac=port["mac_address"].lower(),
        ips=tuple(ips),
        cidrs=cidrs,
        gateway_ip=gateways.get("inet"),
        gateway_ip6=gateways.get("inet6"),
        prefixes=prefixes,
        scope4=scopes.get("4"),
        scope6=scopes.get("6"),
    )


def from_rpc(router):
    """Build the Router spec one sync_routers entry reconciles to."""
    gateway = port_from_rpc(router["gw_port"]) if router.get("gw_port") else None
    interfaces = []
    for port in router.get("_interfaces", []):
        spec = port_from_rpc(port)
        if spec is not None:
            interfaces.append(spec)
    interfaces.sort(key=lambda p: p.id)
    fips = []
    for fip in router.get("_floatingips", []):
        if not fip.get("fixed_ip_address") or ":" in fip["floating_ip_address"]:
            continue
        fips.append(
            FloatingIp(
                id=fip["id"],
                floating=fip["floating_ip_address"],
                fixed=fip["fixed_ip_address"],
            )
        )
    fips.sort(key=lambda f: f.floating)
    routes = []
    for route in router.get("routes", []):
        routes.append((normalize_destination(route["destination"]), route["nexthop"]))
    gw_info = router.get("external_gateway_info") or {}
    return Router(
        id=router["id"],
        gateway=gateway,
        interfaces=tuple(interfaces),
        floating_ips=tuple(fips),
        routes=tuple(sorted(routes)),
        enable_snat=bool(router.get("enable_snat", gw_info.get("enable_snat", True))),
    )


def normalize_destination(text):
    """Return a route destination as a canonical prefix string."""
    if text == "default":
        return DEFAULT_ROUTE
    return str(ipaddress.ip_network(text, strict=False))


def addresses(router):
    """Return jail interface name to the addresses it carries."""
    out = {}
    for port in router.ports:
        ips = list(port.ips)
        if port is router.gateway:
            ips += [(fip.floating, 32) for fip in router.floating_ips]
        out[router.jail_if(port)] = tuple(ips)
    return out


def routes(router):
    """Return the gateway routes the jail must carry as (destination, nexthop)."""
    wanted = []
    gateway = router.gateway
    if gateway is not None and gateway.gateway_ip:
        wanted.append((DEFAULT_ROUTE, gateway.gateway_ip))
    if gateway is not None and gateway.gateway_ip6:
        nexthop = gateway.gateway_ip6
        if ipaddress.ip_address(nexthop).is_link_local:
            nexthop += "%" + router.jail_if(gateway)
        wanted.append((DEFAULT_ROUTE6, nexthop))
    wanted.extend(router.routes)
    return tuple(sorted(set(wanted)))


def rtadvd_confs(router):
    """Return jail interface name to the rtadvd.conf it advertises from."""
    confs = {}
    for port in router.interfaces:
        if not port.prefixes:
            continue
        modes = {prefix.mode for prefix in port.prefixes}
        flags = ("m" if STATEFUL in modes else "") + ("o" if STATELESS in modes else "")
        fields = [f'raflags="{flags}"' if flags else "raflags#0"]
        for index, prefix in enumerate(port.prefixes):
            network = ipaddress.ip_network(prefix.cidr)
            pinfo = "l" if prefix.mode == STATEFUL else "la"
            fields += [
                f'addr{index}="{network.network_address}"',
                f"prefixlen{index}#{network.prefixlen}",
                f'pinfoflags{index}="{pinfo}"',
            ]
        dns = sorted({server for prefix in port.prefixes for server in prefix.dns})
        if dns:
            fields.append(f'rdnss="{",".join(dns[:RDNSS_MAX])}"')
        jail_if = router.jail_if(port)
        confs[jail_if] = f"{jail_if}:\\\n\t:{':'.join(fields)}:\n"
    return confs


def scope_rules(router):
    """Return the pf rules that keep forwarding inside one address scope."""
    gateway = router.gateway
    blocks = {"inet": [], "inet6": []}
    for family, attr in (("inet", "scope4"), ("inet6", "scope6")):
        for out in router.ports:
            # snat moves the source into the gateway's scope
            if family == "inet" and out is gateway and router.enable_snat:
                continue
            for src in router.ports:
                if getattr(src, attr) != getattr(out, attr):
                    blocks[family].append(
                        f"block drop out quick on {router.jail_if(out)} {family} "
                        f"received-on {router.jail_if(src)}"
                    )
    passes = []
    if blocks["inet"] and gateway is not None:
        qg = router.jail_if(gateway)
        for fip in router.floating_ips:
            passes += [
                f"pass out quick inet to {fip.fixed} received-on {qg}",
                f"pass out quick on {qg} inet from {fip.floating}",
            ]
    return passes + blocks["inet"] + blocks["inet6"]


def pf_text(router):
    """Render the jail's pf.conf and its cfg hash."""
    lines = ["set skip on lo0"]
    gateway = router.gateway
    if gateway is not None:
        qg = router.jail_if(gateway)
        for fip in router.floating_ips:
            lines.append(
                f"binat on {qg} inet from {fip.fixed} to any -> {fip.floating}"
            )
        internal = sorted({c for port in router.interfaces for c in port.cidrs})
        source = next((ip for ip, _ in gateway.ips if ":" not in ip), None)
        if router.enable_snat and internal and source:
            lines.append(
                f"nat on {qg} inet from {{ {', '.join(internal)} }} to any -> {source}"
            )
    lines += scope_rules(router)
    cfg_hash = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]
    lines.append(f'pass quick all label "{CFG_LABEL}{cfg_hash}"')
    return "\n".join(lines) + "\n", cfg_hash

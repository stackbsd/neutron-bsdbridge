"""Router spec and its pf, route and address rendering."""

import dataclasses
import hashlib
import ipaddress
import os

from neutron_bsdbridge import names

CFG_LABEL = "l3-neutron:cfg:"
DEFAULT_ROUTE = "0.0.0.0/0"


@dataclasses.dataclass(frozen=True)
class Port:
    """One router port: its addresses and the subnets behind it."""

    id: str
    mac: str
    ips: tuple
    cidrs: tuple
    gateway_ip: str | None = None

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
    """Build a Port from a router port dict, or None without an IPv4 address."""
    subnets = {s["id"]: s for s in port.get("subnets", [])}
    ips = []
    gateway_ip = None
    for fixed in port.get("fixed_ips", []):
        subnet = subnets.get(fixed["subnet_id"])
        if subnet is None or ":" in fixed["ip_address"]:
            continue
        ips.append((fixed["ip_address"], int(subnet["cidr"].split("/")[1])))
        if gateway_ip is None:
            gateway_ip = subnet.get("gateway_ip")
    if not ips:
        return None
    cidrs = tuple(sorted(s["cidr"] for s in subnets.values() if ":" not in s["cidr"]))
    return Port(
        id=port["id"],
        mac=port["mac_address"].lower(),
        ips=tuple(ips),
        cidrs=cidrs,
        gateway_ip=gateway_ip,
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
        if ":" in route["destination"] or ":" in route["nexthop"]:
            continue
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
    """Return a route destination as a canonical IPv4 prefix string."""
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
    if router.gateway is not None and router.gateway.gateway_ip:
        wanted.append((DEFAULT_ROUTE, router.gateway.gateway_ip))
    wanted.extend(router.routes)
    return tuple(sorted(set(wanted)))


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
        if router.enable_snat and internal:
            lines.append(
                f"nat on {qg} inet from {{ {', '.join(internal)} }} to any "
                f"-> {gateway.ips[0][0]}"
            )
    cfg_hash = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]
    lines.append(f'pass quick all label "{CFG_LABEL}{cfg_hash}"')
    return "\n".join(lines) + "\n", cfg_hash

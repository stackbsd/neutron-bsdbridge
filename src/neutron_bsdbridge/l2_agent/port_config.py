"""Port config built from neutron RPC data."""

from oslo_log import log as logging

from neutron_bsdbridge import constants, names
from neutron_bsdbridge.l2_agent import model

LOG = logging.getLogger(__name__)

PROTO = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "ipv6-icmp": "icmp6",
    "icmpv6": "icmp6",
    "icmp6": "icmp6",
}

FAMILY = {"IPv4": "inet", "IPv6": "inet6"}

# what a workload needs from its link whatever its security groups say
ICMP6_IN = (130, 134, 135, 136)
ICMP6_OUT = (131, 132, 133, 135, 136, 143)

# the sg rpc renames remote_ip_prefix by direction
PREFIX_KEY = {"ingress": "source_ip_prefix", "egress": "dest_ip_prefix"}

# infra allowances occupy 10-90
SG_RULE_BASE = 100

# service ports are epairs another agent manufactures, named by owner
SERVICE_IF_NAME = {
    constants.DEVICE_OWNER_DHCP: names.dhcp_if_name,
    constants.DEVICE_OWNER_ROUTER_INTF: names.router_if_name,
    constants.DEVICE_OWNER_ROUTER_GW: names.router_if_name,
}


def port_value(rule):
    """Return an SG rule's port as an int, a range string, or None."""
    lo, hi = rule.get("port_range_min"), rule.get("port_range_max")
    if lo is None:
        return None
    if hi is None or lo == hi:
        return int(lo)
    return "%d-%d" % (lo, hi)


def remote(rule, tables_used):
    """Return an SG rule's remote as a CIDR, a table reference, or any."""
    prefix = rule.get(PREFIX_KEY[rule["direction"]])
    if prefix:
        return str(prefix)
    if rule.get("remote_group_id"):
        tables_used.add(rule["remote_group_id"])
        return "@" + names.table_name(rule["remote_group_id"])
    return "any"


def sg_rules_for_port(port, sg_info, tables_used):
    """Flatten a port's SGs into numbered in and out rule tables."""
    # membership comes from sg_info's devices map
    security_groups = (sg_info or {}).get("security_groups", {})
    sg_port = (sg_info or {}).get("devices", {}).get(port["port_id"], {})
    rules = []
    for sg_id in sg_port.get("security_groups", []):
        rules.extend(security_groups.get(sg_id, []))

    # skip what pf cannot express, which blocks that traffic
    rendered = {"in": [], "out": []}
    for rule in rules:
        direction = "in" if rule["direction"] == "ingress" else "out"
        proto = rule.get("protocol")
        if proto is not None and proto not in PROTO:
            LOG.warning(
                "cannot express SG rule proto %r on port %s; traffic stays blocked",
                proto,
                port["port_id"],
            )
            continue
        body = {"action": "pass"}
        family = FAMILY.get(rule.get("ethertype"))
        if family is not None:
            body["family"] = family
        if proto is not None:
            body["proto"] = PROTO[proto]
            if family == "inet6" and body["proto"] == "icmp":
                body["proto"] = "icmp6"
        if body.get("proto") in ("icmp", "icmp6"):
            # the sg api carries the icmp type and code in the port range
            if rule.get("port_range_min") is not None:
                body["icmp-type"] = int(rule["port_range_min"])
                if rule.get("port_range_max") is not None:
                    body["icmp-code"] = int(rule["port_range_max"])
        else:
            port_spec = port_value(rule)
            if port_spec is not None:
                body["port"] = port_spec
        remote_ref = remote(rule, tables_used)
        if direction == "in":
            if remote_ref != "any":
                body["from"] = remote_ref
        else:
            if remote_ref != "any":
                body["to"] = remote_ref
        rendered[direction].append(body)

    def numbered(bodies):
        """Assign rule numbers to bodies in a canonical order."""
        # port mixes int and range str so type ranks before value
        ordered = sorted(
            bodies,
            key=lambda b: sorted((k, isinstance(v, str), v) for k, v in b.items()),
        )
        return {str(SG_RULE_BASE + 10 * i): b for i, b in enumerate(ordered)}

    return numbered(rendered["in"]), numbered(rendered["out"])


def infra_rules():
    """Return the per-port allowances for DHCP clients and neighbor discovery."""
    tables = []
    for ports, types in (((68, 546), ICMP6_IN), ((67, 547), ICMP6_OUT)):
        bodies = [
            {"action": "pass", "family": "inet", "proto": "udp", "port": ports[0]},
            {"action": "pass", "family": "inet6", "proto": "udp", "port": ports[1]},
        ]
        bodies += [
            {"action": "pass", "proto": "icmp6", "icmp-type": icmp_type}
            for icmp_type in types
        ]
        tables.append({str(10 * (i + 1)): body for i, body in enumerate(bodies)})
    return tuple(tables)


def build(ports, sg_info, interface_mappings):
    """Build a validated Config plus the sorted port uuids it covers."""
    member_ips = (sg_info or {}).get("sg_member_ips", {})

    physnets = {}
    bridges = {}
    filters = {}
    tables_used = set()

    for port in ports:
        owner = port.get("device_owner") or ""
        service_if = next(
            (fn for prefix, fn in SERVICE_IF_NAME.items() if owner.startswith(prefix)),
            None,
        )
        tap = (service_if or names.tap_name)(port["port_id"])
        bridge = names.bridge_name(
            port.get("network_type"),
            port.get("physical_network"),
            port.get("segmentation_id"),
            port["network_id"],
        )

        # local networks get an isolated bridge
        stanza = bridges.setdefault(bridge, {"member": {}})
        if port.get("network_type") in ("vlan", "flat"):
            physical_network = port.get("physical_network")
            trunk = interface_mappings.get(physical_network)
            if trunk is None:
                LOG.warning(
                    "no physical_interface_mapping for %r; port %s renders "
                    "without its uplink",
                    physical_network,
                    port["port_id"],
                )
            else:
                physnets[physical_network] = {"trunk": trunk}
                segment = {"physnet": physical_network}
                if port.get("network_type") == "vlan":
                    segment["vlan"] = port["segmentation_id"]
                stanza["segment"] = segment

        # member: a service epair is attached hardware with no policy
        member = {"description": constants.DESCRIPTION_PREFIX + port["port_id"]}
        if service_if is not None:
            pass
        elif port.get("port_security_enabled", True) is False:
            member["type"] = "tap"
        else:
            fname = names.filter_name(port["port_id"])
            in_rules, out_rules = sg_rules_for_port(port, sg_info, tables_used)
            infra_in, infra_out = infra_rules()
            filters[fname] = {
                "in": {**infra_in, **in_rules},
                "out": {**infra_out, **out_rules},
            }
            member["type"] = "tap"
            member["filter"] = fname
            v4 = [
                ip["ip_address"]
                for ip in port.get("fixed_ips", [])
                if ":" not in ip["ip_address"]
            ]
            if v4 and port.get("mac_address"):
                member["bind"] = {"mac": port["mac_address"], "address": v4[0]}
        stanza["member"][tap] = member

    tables = {}
    for sg_id in sorted(tables_used):
        families = member_ips.get(sg_id, {})
        ips = [e[0] for family in ("IPv4", "IPv6") for e in families.get(family, [])]
        tables[names.table_name(sg_id)] = {"members": sorted(ips)}

    tree = {}
    if physnets:
        tree["physnet"] = physnets
    if bridges:
        tree["bridge"] = bridges
    if filters:
        tree["filter"] = filters
    if tables:
        tree["table"] = tables
    devices = sorted(p["port_id"] for p in ports)
    return model.Config.from_tree(tree), devices

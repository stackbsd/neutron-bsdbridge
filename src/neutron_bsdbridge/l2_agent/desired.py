"""Desired-state model from neutron RPC data."""

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

# infra allowances occupy 10-90
SG_RULE_BASE = 100


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
    if rule.get("remote_ip_prefix"):
        return str(rule["remote_ip_prefix"])
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
        if rule.get("ethertype") == "IPv6" and PROTO.get(proto) not in (None, "icmp6"):
            LOG.warning(
                "cannot express IPv6 %s rule on port %s; traffic stays blocked",
                proto,
                port["port_id"],
            )
            continue
        body = {"action": "pass"}
        if proto is not None:
            body["proto"] = PROTO[proto]
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
        ordered = sorted(bodies, key=lambda b: sorted(b.items()))
        return {str(SG_RULE_BASE + 10 * i): b for i, b in enumerate(ordered)}

    return numbered(rendered["in"]), numbered(rendered["out"])


def infra_rules():
    """Return the per-port allowances for DHCP client traffic and ICMPv6."""
    return (
        {
            "10": {"action": "pass", "proto": "udp", "port": 68},
            "20": {"action": "pass", "proto": "icmp6"},
        },
        {
            "10": {"action": "pass", "proto": "udp", "port": 67},
            "20": {"action": "pass", "proto": "icmp6"},
        },
    )


def build(ports, sg_info, interface_mappings):
    """Build a validated Config plus the sorted port uuids it covers."""
    member_ips = (sg_info or {}).get("sg_member_ips", {})

    physnets = {}
    bridges = {}
    filters = {}
    tables_used = set()

    for port in ports:
        is_dhcp = (port.get("device_owner") or "").startswith(
            constants.DEVICE_OWNER_DHCP
        )
        tap = (
            names.dhcp_if_name(port["port_id"])
            if is_dhcp
            else names.tap_name(port["port_id"])
        )
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

        # member: a dhcp epair is attached hardware with no policy
        member = {"description": constants.DESCRIPTION_PREFIX + port["port_id"]}
        if is_dhcp:
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
        ips = [entry[0] for entry in (member_ips.get(sg_id, {}).get("IPv4", []))]
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

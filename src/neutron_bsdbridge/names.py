"""Deterministic bridge, tap and filter names."""

import hashlib
import uuid

BRIDGE_PREFIX = "pb"
BRIDGE_HASH_LEN = 12


def bridge_name(network_type, physical_network, segmentation_id, network_id):
    """Return the per-segment bridge name."""
    if network_type == "vlan":
        key = f"vlan/{physical_network}/{segmentation_id}"
    elif network_type == "flat":
        key = f"flat/{physical_network}"
    else:  # local
        key = f"{network_type}/{segmentation_id or network_id}"
    digest = hashlib.sha256(key.encode()).hexdigest()
    return BRIDGE_PREFIX + digest[:BRIDGE_HASH_LEN]


def tap_name(port_id):
    """Return the tap name neutron, nova and os-vif share for a port."""
    return "tap" + port_id[:11]


def filter_name(port_id):
    """Return the name of a port's flattened SG filter."""
    return "sg-" + port_id[:12]


def table_name(sg_id):
    """Return the name of a remote group's membership table."""
    return "rg-" + sg_id[:12]


def dhcp_if_name(port_id):
    """Return the host-side epair name for a network's dhcp port."""
    return "dh" + port_id[:13]


def router_if_name(port_id):
    """Return the host-side epair name for a router port."""
    return "rt" + port_id[:13]


def dhcp_jail_name(network_id):
    """Return the name of the VNET jail a network's dhcp server runs in."""
    return "qdhcp-" + network_id.replace("-", "")[:12]


def dhcp_device_id(network_id, host):
    """Return the dhcp port's device_id in neutron's own convention."""
    # must match neutron.common.utils.get_dhcp_agent_device_id or the
    # server refuses update_dhcp_port
    local_hostname = host.split(".")[0]
    host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, str(local_hostname))
    return f"dhcp{host_uuid}-{network_id}"

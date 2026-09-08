"""Shared constants."""

AGENT_TYPE_BSDBRIDGE = "BSD bridge agent"
AGENT_BINARY = "neutron-bsdbridge-l2-agent"

AGENT_TYPE_DHCP = "DHCP agent"
DHCP_AGENT_BINARY = "neutron-bsdbridge-dhcp-agent"

SUPPORTED_NETWORK_TYPES = ("local", "flat", "vlan")

# the kernel refuses group names ending in a digit
OWNED_GROUP = "l2-neutron"
DHCP_GROUP = "dhcp-neutron"
DHCP_JAIL_IF = "dhcp0"

DESCRIPTION_PREFIX = "neutron port "
DEVICE_OWNER_DHCP = "network:dhcp"

DNSMASQ = "/usr/local/sbin/dnsmasq"
STATE_PATH = "/var/db/neutron-bsdbridge"
DEVD_PIPE = "/var/run/devd.seqpacket.pipe"

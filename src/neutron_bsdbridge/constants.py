"""Shared constants."""

AGENT_TYPE_BSDBRIDGE = "BSD bridge agent"
AGENT_BINARY = "neutron-bsdbridge-l2-agent"

AGENT_TYPE_DHCP = "DHCP agent"
DHCP_AGENT_BINARY = "neutron-bsdbridge-dhcp-agent"

AGENT_TYPE_L3 = "L3 agent"
L3_AGENT_BINARY = "neutron-bsdbridge-l3-agent"

SUPPORTED_NETWORK_TYPES = ("local", "flat", "vlan")

# the kernel refuses group names ending in a digit
OWNED_GROUP = "l2-neutron"
DHCP_GROUP = "dhcp-neutron"
L3_GROUP = "l3-neutron"
SERVICE_GROUPS = (DHCP_GROUP, L3_GROUP)
DHCP_JAIL_IF = "dhcp0"

DESCRIPTION_PREFIX = "neutron port "
DEVICE_OWNER_DHCP = "network:dhcp"
DEVICE_OWNER_ROUTER_INTF = "network:router_interface"
DEVICE_OWNER_ROUTER_GW = "network:router_gateway"

IFCONFIG = "/sbin/ifconfig"
PFCTL = "/sbin/pfctl"
ROUTE = "/sbin/route"
SYSCTL = "/sbin/sysctl"
NETSTAT = "/usr/bin/netstat"
JAIL = "/usr/sbin/jail"
JEXEC = "/usr/sbin/jexec"
JLS = "/usr/sbin/jls"
KILL = "/bin/kill"
PKILL = "/bin/pkill"
PS = "/bin/ps"
DNSMASQ = "/usr/local/sbin/dnsmasq"
STATE_PATH = "/var/db/neutron-bsdbridge"
DEVD_PIPE = "/var/run/devd.seqpacket.pipe"

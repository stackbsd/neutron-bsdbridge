"""Config options used by the agents."""

from oslo_config import cfg

from neutron_bsdbridge import constants

OPTS = [
    cfg.DictOpt(
        "physical_interface_mappings",
        default={},
        help="Map of neutron physical_network to the trunk interface carrying it.",
    ),
    cfg.StrOpt(
        "state_path",
        default=constants.STATE_PATH,
        help="Directory the agents keep their state in.",
    ),
    cfg.IntOpt(
        "sync_interval",
        default=30,
        help="Seconds between full syncs.",
    ),
    cfg.StrOpt(
        "devd_pipe",
        default=constants.DEVD_PIPE,
        help="devd seqpacket pipe to watch for IFNET events, empty to disable.",
    ),
    cfg.StrOpt(
        "dnsmasq_path",
        default=constants.DNSMASQ,
        help="dnsmasq binary the dhcp agent launches in each network jail.",
    ),
]

VXLAN_OPTS = [
    cfg.IPOpt(
        "local_ip",
        version=4,
        help="Local VTEP address for vxlan networks, unset to disable vxlan.",
    ),
    cfg.PortOpt(
        "udp_port",
        default=constants.VXLAN_PORT,
        help="UDP port vxlan traffic is sent from and to.",
    ),
    cfg.IntOpt(
        "ttl",
        default=constants.VXLAN_TTL,
        min=1,
        max=255,
        help="TTL of encapsulated vxlan packets.",
    ),
]


def register(conf=cfg.CONF):
    """Register the shared and vxlan option groups."""
    conf.register_opts(OPTS, group="bsdbridge")
    conf.register_opts(VXLAN_OPTS, group="vxlan")

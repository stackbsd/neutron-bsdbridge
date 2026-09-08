"""Config options used by the L2 and dhcp agents."""

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


def register(conf=cfg.CONF):
    """Register the shared option group."""
    conf.register_opts(OPTS, group="bsdbridge")

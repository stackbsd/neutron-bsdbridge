"""bsdbridge ML2 mechanism driver."""

from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

from neutron_bsdbridge import constants, names

LOG = logging.getLogger(__name__)


class BsdBridgeMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Bind ports as bridge VIFs on hosts with a live bsdbridge agent."""

    def __init__(self):
        """Register the agent type and VIF type with the base driver."""
        super().__init__(
            constants.AGENT_TYPE_BSDBRIDGE,
            portbindings.VIF_TYPE_BRIDGE,
            {portbindings.CAP_PORT_FILTER: True},
        )

    def get_allowed_network_types(self, agent=None):
        """Return the network types this driver binds."""
        return constants.SUPPORTED_NETWORK_TYPES

    def get_mappings(self, agent):
        """Return the physnet to trunk mappings an agent advertised."""
        return agent["configurations"].get("physical_interface_mappings", {})

    def check_segment_for_agent(self, segment, agent):
        """Return whether an agent can carry a segment."""
        network_type = segment[api.NETWORK_TYPE]
        if network_type not in self.get_allowed_network_types(agent):
            return False
        if network_type == "local":
            return True
        return segment[api.PHYSICAL_NETWORK] in self.get_mappings(agent)

    def get_vif_details(self, context, agent, segment):
        """Return the VIF details, including the computed bridge name."""
        details = dict(self.vif_details)
        details["bridge_name"] = names.bridge_name(
            segment[api.NETWORK_TYPE],
            segment.get(api.PHYSICAL_NETWORK),
            segment.get(api.SEGMENTATION_ID),
            context.current["network_id"],
        )
        details["interface_group"] = constants.OWNED_GROUP
        return details

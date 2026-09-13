# neutron-bsdbridge

Neutron ML2 mechanism driver, L2 agent, and DHCP agent for FreeBSD based on `if_bridge(4)` and `pf(4)`.

## Status

### Features

- ML2 mechanism driver that binds ports with `vif_type=bridge` and publishes to Nova
- Implements one bridge per Neutron segment for vlan, flat and local networks.
- L2 agent to manage bridge, taps and security group rules
- Port security
- DHCP agent running one dnsmasq per network inside separate VNET jails

### Roadmap

- L3 agent for gateway and NAT support
- vxlan segments
- IPv6 tcp and udp security group rules
- metadata agent

### Limitations

- IPv6 tcp and udp rules are skipped and this traffic stays blocked
- ARP is not inspected
- Only IPv4 subnets are served by the DHCP agent

## Host requirements

Make sure to configure `net.link.bridge.pfil_member=1` on the host.

Add to the host `pf.conf`:

```
set state-policy if-bound
ether anchor "l2-neutron/port/*"
anchor "l2-neutron/port/*"
```

## Configuration

`ml2_conf.ini`

```ini
[ml2]
mechanism_drivers = bsdbridge
```

`bsdbridge_agent.ini`

```ini
[bsdbridge]
physical_interface_mappings = physnet1:ix0
```

Map the physical network name in OpenStack to the actual uplink/trunk interfaces on the host.

For vlan networks, the L2 agent will create a vlan interface on top of the mapped physical interface and plug it to the respective bridge for you, but make sure that the actual network trunks those VLAN between hosts.

You can enable self-service/tenant networks based on VLANs by configuring a range of IDs that can be used:

``` ini
[ml2]
tenant_network_types = vlan

[ml2_type_vlan]
network_vlan_ranges = physnet1:100:199
```

Now any networks created in non-admin projects will be allocated a vlan segment automatically (the `ix0.<vid>` uplink is created and plugged by the L2 agent).
Same as above, ensure that the network fabric actually trunks this range of VLAN IDs to the interface on each host which is mapped in `physical_interface_mappings`.

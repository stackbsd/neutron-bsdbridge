# neutron-bsdbridge

Neutron ML2 mechanism driver, L2 agent, DHCP agent and L3 agent for FreeBSD based on `if_bridge(4)` and `pf(4)`.

## Status

### Features

- ML2 mechanism driver that binds ports with `vif_type=bridge` and publishes to Nova
- Implements one bridge per Neutron segment for vlan, flat and local networks.
- L2 agent to manage bridge, taps and security group rules
- Port security
- DHCP agent running one dnsmasq per network inside separate VNET jails
- L3 agent running each router inside a VNET jail with SNAT and floating IPs
- IPv6 subnets in SLAAC, DHCPv6 stateless and DHCPv6 stateful modes, with router advertisements from `rtadvd(8)` in the router jail
- IPv6 security group rules and source address filtering

### Roadmap

- vxlan segments
- metadata agent
- HA routers (CARP+pfsync)

### Limitations

- ARP is not inspected
- A port with port security sends IPv6 only from its fixed addresses and the link-local address derived from its MAC
- A router takes its IPv6 default route from the gateway of the external subnet, not from router advertisements
- Distributed routers probably won't be supported

## Host requirements

Make sure to configure `net.link.bridge.pfil_member=1` on the host.

Add to the host `pf.conf`:

```
set state-policy if-bound
ether anchor "l2-neutron/port/*"
anchor "l2-neutron/port/*"
```

## Configuration

`neutron.conf`

```ini
[DEFAULT]
service_plugins = router
```

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

## IPv6

Tenant IPv6 subnets are routed without translation, so there is no SNAT and no floating IPs for IPv6.

The external network has to route tenant prefixes to the router, either with static routes or with BGP using `neutron-dynamic-routing`.

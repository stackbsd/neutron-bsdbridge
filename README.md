# neutron-bsdbridge

Neutron ML2 mechanism driver, L2 agent, DHCP agent and L3 agent for FreeBSD based on `if_bridge(4)` and `pf(4)`.

## Status

### Features

- ML2 mechanism driver that binds ports with `vif_type=bridge` and publishes to Nova
- Implements one bridge per Neutron segment for vlan, flat and local networks.
- L2 agent to manage bridge, taps and security group rules
- Port security
- DHCP agent running one dnsmasq per network inside separate VNET jails
- L3 agent running each router inside a VNET jail with SNAT and floating IPs on `pf(4)`

### Roadmap

- vxlan segments
- IPv6 tcp and udp security group rules
- metadata agent

### Limitations

- IPv6 tcp and udp rules are skipped and this traffic stays blocked
- ARP is not inspected
- Only IPv4 subnets are served by the DHCP agent
- Only IPv4 subnets, routes and floating IPs are handled by the L3 agent
- Distributed and HA routers are not supported and are skipped by the L3 agent

## Host requirements

Make sure to configure `net.link.bridge.pfil_member=1` on the host.

Add to the host `pf.conf`:

```
set state-policy if-bound
ether anchor "l2-neutron/port/*"
anchor "l2-neutron/port/*"
```

The DHCP and L3 agents plug their jails into the bridges through epairs in the `dhcp-neutron` and `l3-neutron` interface groups. The host `pf.conf` must pass traffic on those interfaces.

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

### Routers

Enable the router service plugin in `neutron.conf` on the server:

```ini
[DEFAULT]
service_plugins = router
```

Run `neutron-bsdbridge-l3-agent` with the same `bsdbridge_agent.ini` as the L2 agent on every host that should carry routers. The L2 agent must run on the same host. The external network must be a flat or vlan network on a physical network mapped in `physical_interface_mappings` on that host.

The L3 agent creates one VNET jail per router, plugs a router port into each of its networks, enables forwarding, and loads `pf` rules inside the jail for SNAT and floating IPs.

## Tests

```
python3 -m unittest discover -s tests -t .
```

The agent tests skip unless neutron is importable, so run them under the interpreter the deployed neutron uses.

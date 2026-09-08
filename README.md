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

neutron-server (`ml2_conf.ini`):

```ini
[ml2]
mechanism_drivers = bsdbridge
```

The agents (`bsdbridge_agent.ini`, a full sample is in `etc/`):

```ini
[bsdbridge]
physical_interface_mappings = physnet1:ix0
```

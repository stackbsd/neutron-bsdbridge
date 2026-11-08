# neutron-bsdbridge

Neutron ML2 mechanism driver, L2 agent, DHCP agent and L3 agent for FreeBSD based on `if_bridge(4)` and `pf(4)`.

## Status

### Features

- ML2 mechanism driver that binds ports with `vif_type=bridge` and publishes to Nova
- Implements one bridge per Neutron segment for vlan, flat, vxlan and local networks.
- L2 agent to manage bridge, taps and security group rules
- Port security
- DHCP agent running one dnsmasq per network inside separate VNET jails
- L3 agent running each router inside a VNET jail with SNAT and floating IPs
- IPv6 subnets in SLAAC, DHCPv6 stateless and DHCPv6 stateful modes, with router advertisements from `rtadvd(8)` in the router jail
- IPv6 security group rules and source address filtering

### Roadmap

- metadata agent
- HA routers (CARP+pfsync)

### Limitations

- ARP is not inspected
- A port with port security sends IPv6 only from its fixed addresses and the link-local address derived from its MAC
- A router takes its IPv6 default route from the gateway of the external subnet, not from router advertisements
- Distributed routers probably won't be supported
- On vxlan networks only ARP, DHCP and IPv6 neighbour discovery reach other hosts, through the L2 agent, so they pause while it restarts; other broadcast and multicast stays on the sending host

## Host requirements

Make sure to configure `net.link.bridge.pfil_member=1` on the host.

Add to the host `pf.conf`:

```
set state-policy if-bound
ether anchor "l2-neutron/port/*"
anchor "l2-neutron/port/*"
```

For vxlan networks, also pass the vxlan port on the underlay interface, pass the loopback traffic the L2 agent handles ARP and DHCP with (unless `lo0` is skipped), and keep other broadcast and multicast off the overlay:

```
pass on vtnet0 proto udp to port 4789
pass on lo0 proto udp to 127.0.0.1
pass out quick on vxlan inet proto udp from port 68 to 255.255.255.255 port 67 no state
pass out quick on vxlan inet proto udp from port 67 to 255.255.255.255 port 68 no state
block out quick on vxlan inet to { 224.0.0.0/4, 255.255.255.255 }
pass out quick on vxlan inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, routeradv } no state
block out quick on vxlan inet6 to ff00::/8
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

### Tenant networks with vlan

You can enable self-service/tenant networks based on VLANs by configuring a range of IDs that can be used:

``` ini
[ml2]
tenant_network_types = vlan

[ml2_type_vlan]
network_vlan_ranges = physnet1:100:199
```

Now any networks created in non-admin projects will be allocated a vlan segment automatically (the `ix0.<vid>` uplink is created and plugged by the L2 agent).
Same as above, ensure that the network fabric actually trunks this range of VLAN IDs to the interface on each host which is mapped in `physical_interface_mappings`.

### Tenant networks with vxlan

It is usually better to enable self-service/tenant networks using vxlan, the only requirement is that the hosts can reach each other on UDP port 4789, routed or not.

Set `local_ip` to the IP assigned to the underlay network interface:

`bsdbridge_agent.ini`

```ini
[vxlan]
local_ip = 192.168.50.150
```

Enable the l2population mechanism driver, set the tenant network type to vxlan and configure the VNI range:

`ml2_conf.ini`

```ini
[ml2]
mechanism_drivers = bsdbridge,l2population
type_drivers = local,flat,vlan,vxlan
tenant_network_types = vxlan

[ml2_type_vxlan]
vni_ranges = 1:65535
```

Note that the MTU in a vxlan neutron network is 1450. If you need a 1500 MTU inside the guests, you can do it by setting `global_physnet_mtu = 1550` and enable jumbo frames on the underlay network.

## IPv6

Tenant IPv6 subnets are routed without translation, so there is no SNAT and no floating IPs for IPv6.

The external network has to route tenant prefixes to the router, either with static routes or with BGP using `neutron-dynamic-routing`.

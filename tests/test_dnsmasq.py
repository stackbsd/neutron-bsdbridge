"""dnsmasq rendering tests: the address plan in, files and argv out."""

import dataclasses
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge.dhcp_agent import dnsmasq

NET = dnsmasq.DhcpNetwork(
    network_id="590dc57a-8b5e-4b94-b743-74e7d9a1b792",
    port_id="aaaa1111-2222-3333-4444-555566667777",
    mac="fa:16:3e:00:00:01",
    ips=(("10.99.0.2", 24),),
    subnets=(
        dnsmasq.Subnet(
            id="daa048b5-450c-4c4b-97a6-c5f5542289c4",
            cidr="10.99.0.0/24",
            gateway_ip="10.99.0.1",
            dns=("8.8.8.8",),
        ),
    ),
    hosts=(
        dnsmasq.HostEntry(mac="fa:16:3e:aa:bb:01", ip="10.99.0.5"),
        dnsmasq.HostEntry(mac="fa:16:3e:aa:bb:02", ip="10.99.0.6"),
    ),
)


V6_ID = "6f1e0d7c-2b3a-4c5d-8e9f-0a1b2c3d4e5f"
NET6 = dnsmasq.DhcpNetwork(
    network_id=NET.network_id,
    port_id=NET.port_id,
    mac=NET.mac,
    ips=(("2001:db8::2", 64),),
    subnets=(dnsmasq.Subnet(id=V6_ID, cidr="2001:db8::/64", dns=("2001:db8::53",)),),
    hosts=(dnsmasq.HostEntry(mac="fa:16:3e:aa:bb:01", ip="2001:db8::5"),),
)


class Ipv6TestCase(unittest.TestCase):
    """The IPv6 forms of the hosts file, options file and range."""

    def test_reservation_brackets_the_address(self):
        """An IPv6 reservation renders its address in brackets."""
        self.assertEqual(
            "fa:16:3e:aa:bb:01,host-2001-db8--5,[2001:db8::5]\n",
            dnsmasq.hosts_text(NET6),
        )

    def test_dns_is_a_dhcpv6_option(self):
        """An IPv6 subnet sends dns as option6 and no router option."""
        self.assertEqual(
            f"tag:{V6_ID},option6:dns-server,[2001:db8::53]\n",
            dnsmasq.opts_text(NET6),
        )

    def test_range_uses_the_prefix_length(self):
        """An IPv6 range is static with the prefix length as its size."""
        self.assertIn(
            f"--dhcp-range=set:{V6_ID},2001:db8::,static,64,86400s",
            dnsmasq.argv(NET6, "/var/db/x"),
        )


class HostsTestCase(unittest.TestCase):
    """The dhcp-hostsfile rendering."""

    def test_one_reservation_per_line(self):
        """Each entry renders mac, a derived hostname, and the address."""
        text = dnsmasq.hosts_text(NET)
        self.assertIn("fa:16:3e:aa:bb:01,host-10-99-0-5,10.99.0.5\n", text)
        self.assertIn("fa:16:3e:aa:bb:02,host-10-99-0-6,10.99.0.6\n", text)
        self.assertEqual(2, len(text.splitlines()))

    def test_lines_are_sorted(self):
        """Rendering is order-independent so file diffs mean real change."""
        shuffled = dnsmasq.DhcpNetwork(
            network_id=NET.network_id,
            port_id=NET.port_id,
            mac=NET.mac,
            ips=NET.ips,
            subnets=NET.subnets,
            hosts=tuple(reversed(NET.hosts)),
        )
        self.assertEqual(dnsmasq.hosts_text(NET), dnsmasq.hosts_text(shuffled))


class OptsTestCase(unittest.TestCase):
    """The dhcp-optsfile rendering."""

    def test_router_and_dns_carry_the_subnet_tag(self):
        """Router and dns options are tagged with their subnet."""
        text = dnsmasq.opts_text(NET)
        tag = "tag:daa048b5-450c-4c4b-97a6-c5f5542289c4"
        self.assertIn(f"{tag},option:router,10.99.0.1\n", text)
        self.assertIn(f"{tag},option:dns-server,8.8.8.8\n", text)

    def test_absent_gateway_and_dns_are_suppressed_explicitly(self):
        """No gateway/dns renders the empty option, never dnsmasq's default."""
        bare = dnsmasq.DhcpNetwork(
            network_id=NET.network_id,
            port_id=NET.port_id,
            mac=NET.mac,
            ips=NET.ips,
            hosts=(),
            subnets=(dnsmasq.Subnet(id="s1", cidr="10.0.0.0/24"),),
        )
        text = dnsmasq.opts_text(bare)
        self.assertIn("tag:s1,option:router\n", text)
        self.assertIn("tag:s1,option:dns-server\n", text)

    def test_network_mtu_is_sent_per_subnet(self):
        """Each subnet carries the network mtu as option 26."""
        net = dataclasses.replace(
            NET,
            mtu=1450,
            subnets=(*NET.subnets, dnsmasq.Subnet(id="s2", cidr="10.1.0.0/24")),
        )
        text = dnsmasq.opts_text(net)
        self.assertIn(
            "tag:daa048b5-450c-4c4b-97a6-c5f5542289c4,option:mtu,1450\n", text
        )
        self.assertIn("tag:s2,option:mtu,1450\n", text)

    def test_unknown_mtu_is_not_sent(self):
        """A network without an mtu sends no mtu option."""
        self.assertNotIn("option:mtu", dnsmasq.opts_text(NET))


class ArgvTestCase(unittest.TestCase):
    """The dnsmasq invocation."""

    def test_static_range_per_subnet(self):
        """Each subnet renders a tagged static range: serve, never invent."""
        argv = dnsmasq.argv(NET, "/var/db/x")
        self.assertIn(
            "--dhcp-range=set:daa048b5-450c-4c4b-97a6-c5f5542289c4,"
            "10.99.0.0,static,255.255.255.0,86400s",
            argv,
        )

    def test_hermetic_and_dns_free(self):
        """The host dnsmasq.conf never leaks in and DNS is off."""
        argv = dnsmasq.argv(NET, "/var/db/x")
        self.assertIn("--conf-file=/dev/null", argv)
        self.assertIn("--port=0", argv)
        self.assertIn("--interface=dhcp0", argv)

    def test_state_files_live_under_the_network_dir(self):
        """pid, hosts, opts and leases all live in the per-network dir."""
        argv = dnsmasq.argv(NET, "/var/db/x")
        directory = f"/var/db/x/dhcp/{NET.network_id}"
        for name in ("pid", "hosts", "opts", "leases"):
            self.assertTrue(
                any(arg.endswith(f"{directory}/{name}") for arg in argv),
                name,
            )


class NamesTestCase(unittest.TestCase):
    """The derived jail and epair names."""

    def test_jail_and_epair_names(self):
        """Jail and epair names derive from network and port ids."""
        self.assertEqual("qdhcp-590dc57a8b5e", NET.jail)
        self.assertEqual("dhaaaa1111-2222", NET.dhcp_if)
        self.assertLessEqual(len(NET.dhcp_if), 15)

"""dnsmasq rendering tests: the address plan in, files and argv out."""

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

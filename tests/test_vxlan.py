"""vxlan forwarding table control tests."""

import ctypes
import errno
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neutron_bsdbridge.l2_agent import vxlan


class FakeIoctl:
    """Record each command as the kernel would read it."""

    def __init__(self, fail=None):
        self.calls = []
        self.fail = list(fail or [])

    def __call__(self, fd, request, buf):
        drv = vxlan.IfDrv.from_buffer_copy(bytes(buf))
        data = vxlan.IfVxlanCmd.from_buffer_copy(ctypes.string_at(drv.data, drv.len))
        self.calls.append((request, drv.name.decode(), drv.cmd, data))
        if self.fail:
            code = self.fail.pop(0)
            if code:
                raise OSError(code, os.strerror(code))


class LayoutTestCase(unittest.TestCase):
    def test_structs_match_the_kernel_layout(self):
        # offsets from sys/net/if_vxlan.h and sys/net/if.h on amd64
        self.assertEqual(28, ctypes.sizeof(vxlan.Sockaddr))
        self.assertEqual(4, ctypes.alignment(vxlan.Sockaddr))
        self.assertEqual(32, vxlan.IfVxlanCmd.sa.offset)
        self.assertEqual(60, vxlan.IfVxlanCmd.ifname.offset)
        self.assertEqual(76, ctypes.sizeof(vxlan.IfVxlanCmd))
        self.assertEqual(40, ctypes.sizeof(vxlan.IfDrv))

    def test_request_is_iow_i_123_ifdrv(self):
        self.assertEqual(0x8028697B, vxlan.SIOCSDRVSPEC)


class EntryTestCase(unittest.TestCase):
    def test_add_packs_mac_address_and_port(self):
        fake = FakeIoctl()
        vxlan.add_entry("vx0", "fa:16:3e:aa:bb:01", "192.0.2.2", 4789, fake)
        ((request, name, cmd, data),) = fake.calls
        self.assertEqual(vxlan.SIOCSDRVSPEC, request)
        self.assertEqual("vx0", name)
        self.assertEqual(vxlan.VXLAN_CMD_FTABLE_ENTRY_ADD, cmd)
        self.assertEqual("fa:16:3e:aa:bb:01", bytes(data.mac).hex(":"))
        self.assertEqual(socket.AF_INET, data.sa.family)
        self.assertEqual(4789, socket.ntohs(data.sa.port))
        self.assertEqual("192.0.2.2", socket.inet_ntoa(bytes(data.sa.addr)))

    def test_existing_entry_is_replaced(self):
        fake = FakeIoctl(fail=[errno.EEXIST])
        vxlan.add_entry("vx0", "fa:16:3e:aa:bb:01", "192.0.2.3", 4789, fake)
        self.assertEqual(
            [
                vxlan.VXLAN_CMD_FTABLE_ENTRY_ADD,
                vxlan.VXLAN_CMD_FTABLE_ENTRY_REM,
                vxlan.VXLAN_CMD_FTABLE_ENTRY_ADD,
            ],
            [c[2] for c in fake.calls],
        )

    def test_removing_an_absent_entry_is_not_an_error(self):
        vxlan.remove_entry("vx0", "fa:16:3e:aa:bb:01", FakeIoctl(fail=[errno.ENOENT]))

    def test_other_errors_raise(self):
        self.assertRaises(
            OSError,
            vxlan.add_entry,
            "vx0",
            "fa:16:3e:aa:bb:01",
            "192.0.2.2",
            4789,
            FakeIoctl(fail=[errno.ENXIO]),
        )

    def test_flush_removes_static_entries_too(self):
        fake = FakeIoctl()
        vxlan.flush("vx0", fake)
        ((_request, _name, cmd, data),) = fake.calls
        self.assertEqual(vxlan.VXLAN_CMD_FLUSH, cmd)
        self.assertEqual(vxlan.VXLAN_CMD_FLAG_FLUSH_ALL, data.flags)

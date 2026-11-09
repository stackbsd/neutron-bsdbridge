"""vxlan(4) forwarding table control."""

import ctypes
import errno
import fcntl
import socket

IFNAMSIZ = 16
VXLAN_CMD_FTABLE_ENTRY_ADD = 13
VXLAN_CMD_FTABLE_ENTRY_REM = 14
VXLAN_CMD_FLUSH = 15
VXLAN_CMD_FLAG_FLUSH_ALL = 0x0001
IOC_IN = 0x80000000
IOCPARM_MASK = 0x1FFF


class Sockaddr(ctypes.Structure):
    """union vxlan_sockaddr holding a sockaddr_in."""

    # 28 bytes and 4-byte aligned as the union holds a sockaddr_in6
    _fields_ = (
        ("len", ctypes.c_uint8),
        ("family", ctypes.c_uint8),
        ("port", ctypes.c_uint16),
        ("addr", ctypes.c_uint8 * 4),
        ("pad", ctypes.c_uint32 * 5),
    )


class IfVxlanCmd(ctypes.Structure):
    """struct ifvxlancmd."""

    _fields_ = (
        ("flags", ctypes.c_uint32),
        ("vni", ctypes.c_uint32),
        ("ftable_timeout", ctypes.c_uint32),
        ("ftable_max", ctypes.c_uint32),
        ("port", ctypes.c_uint16),
        ("port_min", ctypes.c_uint16),
        ("port_max", ctypes.c_uint16),
        ("mac", ctypes.c_uint8 * 6),
        ("ttl", ctypes.c_uint8),
        ("sa", Sockaddr),
        ("ifname", ctypes.c_char * IFNAMSIZ),
    )


class IfDrv(ctypes.Structure):
    """struct ifdrv."""

    _fields_ = (
        ("name", ctypes.c_char * IFNAMSIZ),
        ("cmd", ctypes.c_ulong),
        ("len", ctypes.c_size_t),
        ("data", ctypes.c_void_p),
    )


# _IOW('i', 123, struct ifdrv)
SIOCSDRVSPEC = (
    IOC_IN | ((ctypes.sizeof(IfDrv) & IOCPARM_MASK) << 16) | (ord("i") << 8) | 123
)


def control(ifname, cmd, data, ioctl=fcntl.ioctl):
    """Send one driver-specific command to a vxlan interface."""
    drv = IfDrv(ifname.encode(), cmd, ctypes.sizeof(data), ctypes.addressof(data))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ioctl(sock.fileno(), SIOCSDRVSPEC, bytearray(bytes(drv)))


def entry(mac, address=None, port=0):
    """Return the command for one forwarding entry."""
    data = IfVxlanCmd()
    data.mac[:] = bytes.fromhex(mac.replace(":", ""))
    if address is not None:
        data.sa.len = 16
        data.sa.family = socket.AF_INET
        data.sa.port = socket.htons(port)
        data.sa.addr[:] = socket.inet_aton(address)
    return data


def add_entry(ifname, mac, address, port, ioctl=fcntl.ioctl):
    """Install a static forwarding entry, replacing one for the same MAC."""
    try:
        control(ifname, VXLAN_CMD_FTABLE_ENTRY_ADD, entry(mac, address, port), ioctl)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
        # the kernel refuses to overwrite an entry
        remove_entry(ifname, mac, ioctl)
        control(ifname, VXLAN_CMD_FTABLE_ENTRY_ADD, entry(mac, address, port), ioctl)


def remove_entry(ifname, mac, ioctl=fcntl.ioctl):
    """Remove a forwarding entry if present."""
    try:
        control(ifname, VXLAN_CMD_FTABLE_ENTRY_REM, entry(mac), ioctl)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise


def flush(ifname, ioctl=fcntl.ioctl):
    """Remove every forwarding entry including static ones."""
    data = IfVxlanCmd(flags=VXLAN_CMD_FLAG_FLUSH_ALL)
    control(ifname, VXLAN_CMD_FLUSH, data, ioctl)

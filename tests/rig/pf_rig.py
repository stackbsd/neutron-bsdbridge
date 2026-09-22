#!/usr/local/bin/python3.12
"""Live pf enforcement rig against a real kernel."""

# run as root with the L2 agent stopped, or its orphan gc collects the
# rig's interfaces mid-run; not part of unittest discovery

import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from neutron_bsdbridge import ifconfig
from neutron_bsdbridge.l2_agent import model, pf, reconcile, writer

JAIL = "bsdbridgerig"
BR = "rigbr"
HOST_IP, JAIL_IP, SPOOF_IP = "10.77.0.1", "10.77.0.2", "10.77.0.99"
FAILS = []


def sh(*argv):
    """Run one command, capturing its output."""
    return subprocess.run(argv, capture_output=True, text=True)


def check(label, cond, detail=""):
    """Print one check result and record a failure."""
    print(f"  {label:56} {'ok' if cond else 'FAIL'} {detail}")
    if not cond:
        FAILS.append(label)


def ping(target, source=None, via_jail=False):
    """Ping a target, optionally from a source address or inside the jail."""
    argv = ["ping", "-c", "2", "-t", "2", target]
    if source:
        argv = ["ping", "-c", "2", "-t", "2", "-S", source, target]
    if via_jail:
        argv = ["jexec", JAIL, *argv]
    return sh(*argv).returncode == 0


def tcp_probe(port, timeout=2.0):
    """Probe a jail TCP port and return connected, refused, or filtered."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((JAIL_IP, port))
        return "connected"
    except ConnectionRefusedError:
        return "refused"
    except TimeoutError:
        return "filtered"
    finally:
        s.close()


def cfg(filter_rules):
    """Build the rig Config: one bridge, a filtered+bound member, a plain one."""
    return model.Config.from_tree(
        {
            "filter": {"rigf": filter_rules},
            "bridge": {
                BR: {
                    "member": {
                        VM_IF: {
                            "filter": "rigf",
                            "bind": {"mac": B_MAC, "address": JAIL_IP},
                        },
                        # plain switching, like a vlan uplink
                        UPLINK_IF: {},
                    }
                }
            },
        }
    )


live = writer.Writer(dry_run=False)

print("== setup: consumer jail on one epair, host uplink on another ==")
VM_IF = sh("ifconfig", "epair", "create").stdout.strip()
VM_B = VM_IF[:-1] + "b"
UPLINK_IF = sh("ifconfig", "epair", "create").stdout.strip()
UPLINK_B = UPLINK_IF[:-1] + "b"
sh("jail", "-c", "name=" + JAIL, "vnet", "persist", "path=/")
sh("ifconfig", VM_B, "vnet", JAIL)
sh("jexec", JAIL, "ifconfig", VM_B, "inet", JAIL_IP + "/24", "up")
sh("jexec", JAIL, "ifconfig", "lo0", "up")
sh("ifconfig", VM_IF, "up")
sh("ifconfig", UPLINK_IF, "up")
sh("ifconfig", UPLINK_B, "inet", HOST_IP + "/24", "up")
B_MAC = re.search(r"ether (\S+)", sh("jexec", JAIL, "ifconfig", VM_B).stdout).group(1)
print(f"   vm if {VM_IF} (jail mac {B_MAC}), uplink if {UPLINK_IF}")

print("== reconcile: bridge + members + policy + mac lock ==")
c1 = cfg({"in": {"10": {"action": "pass", "proto": "icmp"}}})
r1 = reconcile.reconcile(c1, writer=live)
for r in r1.receipts:
    print("   ", r)
for n in r1.plan.notes:
    print("    note:", n)
check("build reconciled", r1.reconciled)
check("no awaiting-attach notes", not r1.plan.notes)
check(
    "mac lock was planned and applied",
    any(type(r.op).__name__ == "LockMemberMac" for r in r1.receipts),
)

print("== enforcement, with real packets ==")
check("toward-VM icmp passes (the rule)", ping(JAIL_IP))
check("toward-VM tcp is filtered (implicit deny)", tcp_probe(7777) == "filtered")
check(
    "from-VM icmp is blocked (implicit deny, no out rule)",
    not ping(HOST_IP, via_jail=True),
)

print("== drift: widen the filter, expect exactly one anchor reload ==")
c2 = cfg(
    {
        "in": {
            "10": {"action": "pass", "proto": "icmp"},
            "20": {"action": "pass", "proto": "tcp", "port": 7777},
        },
        "out": {"10": {"action": "pass", "proto": "icmp"}},
    }
)
r2 = reconcile.reconcile(c2, writer=live)
for r in r2.receipts:
    print("   ", r)
kinds = [type(r.op).__name__ for r in r2.receipts]
check("drift is one LoadAnchor and nothing else", kinds == ["LoadAnchor"], kinds)
check("from-VM icmp now passes", ping(HOST_IP, via_jail=True))
check(
    "toward-VM tcp 7777 now reaches the jail (refused, not filtered)",
    tcp_probe(7777) == "refused",
)

print("== port security ==")
sh("jexec", JAIL, "ifconfig", VM_B, "inet", SPOOF_IP + "/24", "alias")
check(
    "spoofed source IP is blocked (pf inet lock)",
    not ping(HOST_IP, source=SPOOF_IP, via_jail=True),
)
check("bound source IP still passes", ping(HOST_IP, source=JAIL_IP, via_jail=True))
sh("jexec", JAIL, "ifconfig", VM_B, "ether", "02:00:00:00:00:99")
time.sleep(1)
check("spoofed MAC is blocked (bridge lock)", not ping(HOST_IP, via_jail=True))
sh("jexec", JAIL, "ifconfig", VM_B, "ether", B_MAC)
time.sleep(1)
check("restored MAC passes again", ping(HOST_IP, via_jail=True))

print("== the contract, all planes ==")
r3 = reconcile.reconcile(c2, writer=live)
check("reconcile again plans nothing", r3.plan.empty, [str(o) for o in r3.plan.ops])

print("== teardown: empty config ==")
r4 = reconcile.reconcile(model.Config.from_tree({}), writer=live)
for r in r4.receipts:
    print("   ", r)
check("teardown reconciled", r4.reconciled)
check("anchor gone", not pf.read_anchor(VM_IF).exists)
check("no l2-neutron anchors remain", pf.list_anchors() == [])
post = ifconfig.read_interfaces([BR])
check("bridge gone", BR not in post)
check(
    "both epairs survive (attached hardware)",
    sh("ifconfig", VM_IF).returncode == 0 and sh("ifconfig", UPLINK_IF).returncode == 0,
)

sh("jail", "-r", JAIL)
sh("ifconfig", VM_IF, "destroy")
sh("ifconfig", UPLINK_IF, "destroy")
print(f"\nRIG {'PASSED' if not FAILS else f'FAILED: {FAILS}'}")
sys.exit(1 if FAILS else 0)
